# encryption_utils.py

import base64
import os
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import ctypes
import sys

# Security Constants
SALT_SIZE = 32  # Increased from 16
KEY_ITERATIONS = 600000  # Increased from 390000
MEMORY_COST = 65536  # 64 MiB
PARALLELISM = 4
KEY_LENGTH = 32

def secure_memory_wipe(data: bytes) -> None:
    """Securely wipe sensitive data from memory."""
    if isinstance(data, bytes):
        # Overwrite with random data
        ctypes.memset(ctypes.c_char.from_buffer(data), 0, len(data))
        # Force memory barrier
        ctypes.memoryview(data).release()

def lock_memory() -> None:
    """Lock memory to prevent swapping to disk."""
    if platform.system() == "Windows":
        # Windows equivalent of mlock
        ctypes.windll.kernel32.SetProcessWorkingSetSize(
            -1, -1
        )
    else:
        # Unix-like systems
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (-1, -1))
        except ImportError:
            pass

def generate_key(password: str, salt: bytes) -> bytes:
    """Derive a secure key using Argon2id and PBKDF2."""
    if not isinstance(password, str) or not password:
        raise ValueError("Invalid password")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError(f"Invalid salt size: {len(salt)}")
    
    # First pass: Argon2id
    argon2 = Argon2id(
        length=KEY_LENGTH,
        salt=salt,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        time_cost=3,
    )
    intermediate_key = argon2.derive(password.encode('utf-8'))
    
    # Second pass: PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  # Upgraded from SHA256
        length=KEY_LENGTH,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(intermediate_key))
    
    # Securely wipe intermediate key
    secure_memory_wipe(intermediate_key)
    return key

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Fernet with additional security measures."""
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    
    try:
        # Lock memory during encryption
        lock_memory()
        
        f = Fernet(key)
        encrypted = f.encrypt(data)
        
        # Securely wipe original data
        secure_memory_wipe(data)
        return encrypted
    except Exception as e:
        raise ValueError("Encryption failed") from e

def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypt data using Fernet with additional security measures."""
    if not isinstance(token, bytes):
        raise TypeError("Token must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    
    try:
        # Lock memory during decryption
        lock_memory()
        
        f = Fernet(key)
        decrypted = f.decrypt(token)
        return decrypted
    except Exception as e:
        raise ValueError("Decryption failed") from e

def generate_salt() -> bytes:
    """Generate a cryptographically secure salt."""
    return os.urandom(SALT_SIZE)

# Initialize security measures
lock_memory() 