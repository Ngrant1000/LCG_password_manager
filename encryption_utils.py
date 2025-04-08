# encryption_utils.py

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
# Recommended by OWASP as of 2021/2022 for PBKDF2-HMAC-SHA256
# Can be adjusted based on performance needs vs security level
KEY_ITERATIONS = 390000 

def generate_key(password: str, salt: bytes) -> bytes:
    """Derive a secure Fernet key from the password and salt using PBKDF2."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be bytes of length {SALT_SIZE}")
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key length
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    # Fernet keys must be url-safe base64 encoded
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be bytes")
    if not isinstance(key, bytes):
         raise TypeError("Key must be bytes")
         
    try:
        f = Fernet(key)
        return f.encrypt(data)
    except Exception as e:
        # Consider more specific exception handling or logging
        print(f"Encryption failed: {e}")
        raise

def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypt data using Fernet symmetric encryption."""
    if not isinstance(token, bytes):
        raise TypeError("Token to decrypt must be bytes")
    if not isinstance(key, bytes):
         raise TypeError("Key must be bytes")
         
    try:
        f = Fernet(key)
        return f.decrypt(token)
    except Exception as e: # Catches InvalidToken, etc.
        # Handle decryption errors (e.g., wrong password/key, corrupted data)
        # Avoid leaking specific error details that might help attackers
        print(f"Decryption failed. Check master password or data integrity.")
        raise ValueError("Decryption failed") from e # Re-raise as a more generic error

def generate_salt() -> bytes:
    """Generate a cryptographically secure salt."""
    return os.urandom(SALT_SIZE)

# Remove the placeholder print statement if it exists
# print("Password Manager Initial Setup - Encryption Utilities") 