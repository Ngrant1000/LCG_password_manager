# audit_logger.py

import os
import json
import time
import hashlib
import hmac
import base64
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AuditLogger:
    """Secure audit logging with tamper detection and automatic rotation."""
    
    # Constants
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_LOG_AGE = 30  # days
    MAX_ENTRIES = 10000  # Maximum number of entries to keep
    
    def __init__(self, master_password: str, salt: bytes):
        """Initialize the audit logger."""
        self._master_password = master_password
        self._salt = salt
        self._log_file = None
        self._log_key = None
        self._log_entries = []
        self._initialized = False
        
        # Initialize the logger
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize the audit logger."""
        # Get the app data directory based on platform
        if os.name == 'nt':  # Windows
            app_data_dir = Path(os.path.expanduser("~")) / "AppData" / "Roaming" / "LCGPasswordManager"
        else:  # macOS and Linux
            app_data_dir = Path(os.path.expanduser("~")) / ".lcg_password_manager"
            
        app_data_dir.mkdir(parents=True, exist_ok=True)
        
        # Set the log file path
        self._log_file = app_data_dir / "audit.log"
        
        # Generate a key for the log file
        self._generate_log_key()
        
        # Load existing log entries
        self._load_log_entries()
        
        # Clean up old logs
        self._cleanup_old_logs()
        
        self._initialized = True
    
    def _generate_log_key(self) -> None:
        """Generate a key for encrypting the log file."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
        )
        key = kdf.derive(self._master_password.encode('utf-8'))
        self._log_key = base64.urlsafe_b64encode(key)
    
    def _load_log_entries(self) -> None:
        """Load existing log entries from the log file."""
        if not self._log_file.exists():
            return
            
        try:
            # Read the log file
            with open(self._log_file, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt the log file
            f = Fernet(self._log_key)
            decrypted_data = f.decrypt(encrypted_data)
            
            # Parse the log entries
            self._log_entries = json.loads(decrypted_data.decode('utf-8'))
            
            # Verify the integrity of the log entries
            if not self._verify_log_integrity():
                # If integrity check fails, reset the log
                self._log_entries = []
                self._log_event("LOG_INTEGRITY_FAILURE", "Log integrity check failed, resetting log")
                
            # Trim entries if exceeding maximum
            if len(self._log_entries) > self.MAX_ENTRIES:
                self._log_entries = self._log_entries[-self.MAX_ENTRIES:]
                
        except Exception as e:
            # If there's an error, reset the log
            self._log_entries = []
            self._log_event("LOG_LOAD_ERROR", "Error loading log file")
    
    def _verify_log_integrity(self) -> bool:
        """Verify the integrity of the log entries."""
        if not self._log_entries:
            return True
            
        # Check if each entry has the required fields
        required_fields = ['timestamp', 'event_type', 'details', 'hash']
        for entry in self._log_entries:
            if not all(field in entry for field in required_fields):
                return False
                
            # Verify the hash of each entry
            entry_hash = entry.pop('hash', None)
            if entry_hash != self._calculate_entry_hash(entry):
                # Restore the hash
                entry['hash'] = entry_hash
                return False
            # Restore the hash
            entry['hash'] = entry_hash
            
        return True
    
    def _calculate_entry_hash(self, entry: Dict[str, Any]) -> str:
        """Calculate the hash of a log entry."""
        # Create a copy of the entry without the hash
        entry_copy = entry.copy()
        if 'hash' in entry_copy:
            del entry_copy['hash']
            
        # Convert the entry to a JSON string
        entry_json = json.dumps(entry_copy, sort_keys=True)
        
        # Calculate the hash
        return hashlib.sha256(entry_json.encode('utf-8')).hexdigest()
    
    def _save_log_entries(self) -> None:
        """Save log entries to the log file."""
        if not self._initialized:
            return
            
        try:
            # Check if log file size exceeds maximum
            if self._log_file.exists() and self._log_file.stat().st_size > self.MAX_LOG_SIZE:
                self._rotate_log()
            
            # Calculate the hash of each entry
            for entry in self._log_entries:
                entry['hash'] = self._calculate_entry_hash(entry)
                
            # Convert the log entries to a JSON string
            log_json = json.dumps(self._log_entries)
            
            # Encrypt the log file
            f = Fernet(self._log_key)
            encrypted_data = f.encrypt(log_json.encode('utf-8'))
            
            # Write the encrypted data to the log file
            with open(self._log_file, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            # Log the error silently - we don't want to create an infinite loop
            pass
    
    def _rotate_log(self) -> None:
        """Rotate the log file."""
        if not self._log_file.exists():
            return
            
        try:
            # Create a backup of the current log file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self._log_file.parent / f"audit_{timestamp}.log.gz"
            
            # Compress and save the current log
            with open(self._log_file, 'rb') as f_in:
                with gzip.open(backup_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Clear the current log file
            self._log_entries = []
            self._save_log_entries()
            
        except Exception:
            # If rotation fails, just clear the log
            self._log_entries = []
            self._save_log_entries()
    
    def _cleanup_old_logs(self) -> None:
        """Clean up old log files."""
        try:
            log_dir = self._log_file.parent
            cutoff_date = datetime.now() - timedelta(days=self.MAX_LOG_AGE)
            
            for log_file in log_dir.glob("audit_*.log.gz"):
                try:
                    # Extract date from filename
                    date_str = log_file.stem.split('_')[1]
                    file_date = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                    
                    # Delete if older than MAX_LOG_AGE
                    if file_date < cutoff_date:
                        log_file.unlink()
                except Exception:
                    # If we can't parse the date, keep the file
                    continue
                    
        except Exception:
            # If cleanup fails, just continue
            pass
    
    def log_event(self, event_type: str, details: str, sensitive: bool = False) -> None:
        """Log a security event."""
        if not self._initialized:
            return
            
        # Create a new log entry
        entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'event_type': event_type,
            'details': '[REDACTED]' if sensitive else details,
            'pid': os.getpid(),
            'username': os.getenv("USERNAME") or os.getenv("USER"),
            'sensitive': sensitive
        }
        
        # Add the entry to the log
        self._log_entries.append(entry)
        
        # Trim entries if exceeding maximum
        if len(self._log_entries) > self.MAX_ENTRIES:
            self._log_entries = self._log_entries[-self.MAX_ENTRIES:]
        
        # Save the log entries
        self._save_log_entries()
    
    def get_log_entries(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get log entries, optionally filtered by event type."""
        if not self._initialized:
            return []
            
        # Filter entries by event type if specified
        if event_type:
            entries = [entry for entry in self._log_entries if entry['event_type'] == event_type]
        else:
            entries = self._log_entries.copy()
            
        # Limit the number of entries
        if limit > 0:
            entries = entries[-limit:]
            
        return entries
    
    def clear_log(self) -> None:
        """Clear the log entries."""
        if not self._initialized:
            return
            
        # Log the event
        self.log_event("LOG_CLEARED", "Audit log cleared")
        
        # Clear the log entries
        self._log_entries = []
        
        # Save the log entries
        self._save_log_entries()
    
    def export_log(self, filepath: Path) -> bool:
        """Export the log entries to a file."""
        if not self._initialized:
            return False
            
        try:
            # Get the log entries
            entries = self.get_log_entries(limit=0)  # Get all entries
            
            # Convert the log entries to a JSON string
            log_json = json.dumps(entries, indent=2)
            
            # Write the log entries to the file
            with open(filepath, 'w') as f:
                f.write(log_json)
                
            # Log the event
            self.log_event("LOG_EXPORTED", f"Audit log exported to {filepath}")
            
            return True
        except Exception as e:
            # Log the error
            self.log_event("LOG_EXPORT_ERROR", "Error exporting log file")
            return False 