# data_manager.py

import json
import os
import platform
import stat
from pathlib import Path
from .encryption_utils import (
    generate_key, 
    encrypt_data, 
    decrypt_data, 
    generate_salt,
    secure_memory_wipe,
    SALT_SIZE
)
from .audit_logger import AuditLogger
import win32security
import win32api
import ntsecuritycon as con

# --- Constants ---
APP_NAME = "LCGPasswordManager"
DEFAULT_VAULT_FILENAME = "user_vault.dat"
MAX_ENTRY_LENGTH = 1024  # Maximum length for any field
MAX_ENTRIES = 1000  # Maximum number of entries

# Global audit logger instance
_audit_logger = None

def initialize_audit_logger(master_password: str, salt: bytes) -> None:
    """Initialize the audit logger with the master password and salt."""
    global _audit_logger
    _audit_logger = AuditLogger(master_password, salt)

def get_audit_logger() -> AuditLogger:
    """Get the audit logger instance."""
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialized")
    return _audit_logger

def secure_file_permissions(filepath: Path) -> None:
    """Set secure file permissions based on platform."""
    if platform.system() == "Windows":
        # Windows: Set to owner-only access
        # Get current user's SID
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
            win32security.TokenUser
        )[0]
        
        # Create DACL with only owner access
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_ALL_ACCESS,
            user_sid
        )
        
        # Apply DACL to file
        security_descriptor = win32security.SECURITY_DESCRIPTOR()
        security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            str(filepath),
            win32security.DACL_SECURITY_INFORMATION,
            security_descriptor
        )
    else:
        # Unix-like: Set to 600 (owner read/write only)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)

def get_app_data_dir() -> Path:
    """Gets the platform-specific application data directory with secure permissions."""
    system = platform.system()
    if system == "Windows":
        base_path = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif system == "Darwin":
        base_path = Path.home() / "Library" / "Application Support"
    else:
        base_path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        
    app_dir = base_path / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True)
    
    # Set secure directory permissions
    if platform.system() == "Windows":
        set_windows_permissions(app_dir)
    else:
        # Unix-like: 700 (owner read/write/execute only)
        os.chmod(app_dir, stat.S_IRWXU)
    
    return app_dir

DEFAULT_VAULT_PATH = get_app_data_dir() / DEFAULT_VAULT_FILENAME

def validate_entry(entry: dict) -> bool:
    """Validate entry data before saving."""
    if not isinstance(entry, dict):
        return False
        
    required_fields = {'service', 'username', 'password'}
    if not all(field in entry for field in required_fields):
        return False
        
    # Check field lengths
    if any(len(str(entry[field])) > MAX_ENTRY_LENGTH for field in required_fields):
        return False
        
    return True

def vault_exists(filepath: Path = DEFAULT_VAULT_PATH) -> bool:
    """Check if the vault file exists and has valid permissions."""
    if not filepath.exists():
        return False
        
    # Check file size
    if filepath.stat().st_size <= SALT_SIZE:
        return False
        
    # Verify file permissions
    try:
        if platform.system() == "Windows":
            security = win32security.GetFileSecurity(
                str(filepath),
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = security.GetSecurityDescriptorDacl()
            if dacl is None:
                return False
        else:
            mode = filepath.stat().st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                return False
    except Exception:
        return False
        
    return True

def set_windows_permissions(path):
    """Set Windows file/directory permissions to owner-only access."""
    user_sid = win32security.GetTokenInformation(
        win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
        win32security.TokenUser
    )[0]

    # Create a new DACL with owner-only access
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        con.FILE_ALL_ACCESS,
        user_sid
    )

    # Apply the DACL
    security_descriptor = win32security.SECURITY_DESCRIPTOR()
    security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(
        path,
        win32security.DACL_SECURITY_INFORMATION,
        security_descriptor
    )

def create_vault(vault_path):
    """Create a new vault directory with secure permissions."""
    if os.path.exists(vault_path):
        raise ValueError("Vault already exists")
    
    os.makedirs(vault_path)
    
    if platform.system() == "Windows":
        set_windows_permissions(vault_path)
    else:
        os.chmod(vault_path, 0o700)  # Unix: rwx------ permissions

def save_data(data: list, master_password: str, filepath: Path = DEFAULT_VAULT_PATH):
    """Saves the password data with enhanced security measures."""
    filepath = Path(filepath)
    
    # Initialize audit logger if not already initialized
    if _audit_logger is None:
        initialize_audit_logger(master_password, generate_salt())
    
    # Log the save operation
    get_audit_logger().log_event(
        "DATA_SAVE",
        f"Saving {len(data)} entries to vault",
        sensitive=True
    )
    
    # Validate data
    if not isinstance(data, list):
        get_audit_logger().log_event("DATA_SAVE_ERROR", "Invalid data type: not a list")
        raise ValueError("Data must be a list")
    if len(data) > MAX_ENTRIES:
        get_audit_logger().log_event("DATA_SAVE_ERROR", f"Too many entries: {len(data)} > {MAX_ENTRIES}")
        raise ValueError(f"Too many entries. Maximum allowed: {MAX_ENTRIES}")
    if not all(validate_entry(entry) for entry in data):
        get_audit_logger().log_event("DATA_SAVE_ERROR", "Invalid entry format detected")
        raise ValueError("Invalid entry format")
    
    try:
        salt: bytes
        if vault_exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    salt = f.read(SALT_SIZE)
                    if len(salt) != SALT_SIZE:
                        salt = generate_salt()
            except IOError:
                salt = generate_salt()
        else:
            salt = generate_salt()

        key = generate_key(master_password, salt)
        
        # Serialize data to JSON bytes
        data_bytes = json.dumps(data, indent=4).encode('utf-8')
        
        encrypted_data = encrypt_data(data_bytes, key)
        
        # Ensure parent directory exists
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temporary file first
        temp_filepath = filepath.with_suffix('.tmp')
        with open(temp_filepath, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)
        
        # Set secure permissions on temp file
        secure_file_permissions(temp_filepath)
        
        # Atomic rename
        temp_filepath.replace(filepath)
        
        # Securely wipe sensitive data
        secure_memory_wipe(data_bytes)
        secure_memory_wipe(key)
        
        get_audit_logger().log_event("DATA_SAVE_SUCCESS", f"Successfully saved {len(data)} entries")
            
    except Exception as e:
        if temp_filepath.exists():
            temp_filepath.unlink()
        get_audit_logger().log_event("DATA_SAVE_ERROR", f"Failed to save data: {str(e)}")
        raise ValueError("Failed to save data") from e

def load_data(master_password: str, filepath: Path = DEFAULT_VAULT_PATH) -> list:
    """Loads and decrypts password data with enhanced security measures."""
    filepath = Path(filepath)
    
    # Initialize audit logger if not already initialized
    if _audit_logger is None:
        initialize_audit_logger(master_password, generate_salt())
    
    if not vault_exists(filepath):
        get_audit_logger().log_event("DATA_LOAD", "No vault file found, returning empty list")
        return []
        
    try:
        with open(filepath, 'rb') as f:
            salt = f.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                get_audit_logger().log_event("DATA_LOAD_ERROR", "Invalid vault file format: incorrect salt size")
                raise ValueError("Invalid vault file format")
            
            encrypted_data = f.read()
            
        key = generate_key(master_password, salt)
        decrypted_data_bytes = decrypt_data(encrypted_data, key)
        
        # Validate JSON structure
        data = json.loads(decrypted_data_bytes.decode('utf-8'))
        if not isinstance(data, list):
            get_audit_logger().log_event("DATA_LOAD_ERROR", "Invalid data format: not a list")
            raise ValueError("Invalid data format")
        if len(data) > MAX_ENTRIES:
            get_audit_logger().log_event("DATA_LOAD_ERROR", f"Invalid entry count: {len(data)} > {MAX_ENTRIES}")
            raise ValueError("Invalid entry count")
        if not all(validate_entry(entry) for entry in data):
            get_audit_logger().log_event("DATA_LOAD_ERROR", "Invalid entry format detected")
            raise ValueError("Invalid entry format")
            
        # Securely wipe sensitive data
        secure_memory_wipe(decrypted_data_bytes)
        secure_memory_wipe(key)
        
        get_audit_logger().log_event(
            "DATA_LOAD_SUCCESS",
            f"Successfully loaded {len(data)} entries",
            sensitive=True
        )
            
        return data
        
    except Exception as e:
        get_audit_logger().log_event("DATA_LOAD_ERROR", f"Failed to load data: {str(e)}")
        raise ValueError("Failed to load data") from e

print(f"Password Manager - Data Manager Module Loaded. Vault location: {DEFAULT_VAULT_PATH}") 