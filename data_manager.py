# data_manager.py

import json
import os
import platform
from pathlib import Path
from encryption_utils import (
    generate_key, 
    encrypt_data, 
    decrypt_data, 
    generate_salt, 
    SALT_SIZE
)

# --- Determine App Data Directory ---
APP_NAME = "LCGPasswordManager"

def get_app_data_dir() -> Path:
    """Gets the platform-specific application data directory."""
    system = platform.system()
    if system == "Windows":
        # %APPDATA%
        base_path = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif system == "Darwin": # macOS
        # ~/Library/Application Support/
        base_path = Path.home() / "Library" / "Application Support"
    else: # Linux and other Unix-like
        # ~/.local/share/ or ~/.config/ (using .local/share as per XDG Base Dir Spec)
        base_path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        
    app_dir = base_path / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True) # Ensure the directory exists
    return app_dir

# --- Constants ---
DEFAULT_VAULT_FILENAME = "user_vault.dat"
DEFAULT_VAULT_PATH = get_app_data_dir() / DEFAULT_VAULT_FILENAME

def vault_exists(filepath: Path = DEFAULT_VAULT_PATH) -> bool:
    """Check if the vault file exists."""
    return filepath.exists() and filepath.stat().st_size > SALT_SIZE

def save_data(data: list, master_password: str, filepath: Path = DEFAULT_VAULT_PATH):
    """
    Saves the password data to an encrypted file in the app data directory.
    The file format is: SALT (SALT_SIZE bytes) + Encrypted Data.
    Generates a new salt if the file doesn't exist or is empty/invalid.
    """
    filepath = Path(filepath)
    
    try:
        salt: bytes
        # Check if file exists and retrieve existing salt if possible
        if vault_exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    salt = f.read(SALT_SIZE)
                    if len(salt) != SALT_SIZE:
                        print("Warning: Existing vault file has invalid salt size. Generating new salt.")
                        salt = generate_salt()
            except IOError as e:
                print(f"Warning: Could not read existing salt from {filepath}. Generating new salt. Error: {e}")
                salt = generate_salt()
        else:
            # File doesn't exist or is too small, generate new salt
            salt = generate_salt()

        key = generate_key(master_password, salt)
        
        # Serialize data to JSON bytes
        data_bytes = json.dumps(data, indent=4).encode('utf-8')
        
        encrypted_data = encrypt_data(data_bytes, key)
        
        # Ensure parent directory exists before writing
        filepath.parent.mkdir(parents=True, exist_ok=True) 
        
        # Write salt + encrypted data
        with open(filepath, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)
            
    except (IOError, ValueError, TypeError) as e:
        print(f"Error saving data: {e}")
        # Re-raise or handle more gracefully depending on application flow
        raise

def load_data(master_password: str, filepath: Path = DEFAULT_VAULT_PATH) -> list:
    """
    Loads and decrypts password data from the specified file in the app data directory.
    Returns an empty list if the file doesn't exist (first run).
    Raises ValueError on decryption failure (wrong password/corrupt data).
    """
    filepath = Path(filepath)
    
    if not vault_exists(filepath):
        # Treat as first run, return empty data structure
        return [] 
        
    try:
        with open(filepath, 'rb') as f:
            salt = f.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise ValueError("Invalid vault file format: incorrect salt size.")
            
            encrypted_data = f.read()
            
        key = generate_key(master_password, salt)
        decrypted_data_bytes = decrypt_data(encrypted_data, key)
        
        # Deserialize JSON bytes to Python list
        data = json.loads(decrypted_data_bytes.decode('utf-8'))
        if not isinstance(data, list):
             raise TypeError("Decrypted data is not in the expected list format.")
             
        return data
        
    except FileNotFoundError:
         # Should be caught by vault_exists, but good practice
         return []
    except (IOError, ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"Error loading data: {e}")
        # Let calling code handle specific errors (like wrong password from decrypt_data)
        raise

print(f"Password Manager - Data Manager Module Loaded. Vault location: {DEFAULT_VAULT_PATH}") 