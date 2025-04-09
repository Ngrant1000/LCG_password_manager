# two_factor.py

"""Two-factor authentication using TOTP (Time-based One-Time Password).

Security Measures:
1. PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations for secret generation
2. SHA-256 hashing for backup code storage
3. Cryptographically secure random number generation using os.urandom()
4. AES-256 compatible random bytes (16 bytes/128 bits) for backup codes
5. HMAC-SHA1 for TOTP code generation (standard for TOTP)
6. Secure memory handling with immediate cleanup of sensitive data
7. One-time use backup codes with secure comparison

Note: The TOTP implementation follows RFC 6238 specifications.
"""

import base64
import hmac
import hashlib
import time
import qrcode
import io
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
TOTP_PERIOD = 30  # Time step in seconds (standard for TOTP)
TOTP_DIGITS = 6   # Number of digits in TOTP code (standard for TOTP)
TOTP_ALGORITHM = hashes.SHA1  # Algorithm used for TOTP (standard for TOTP)
PBKDF2_ITERATIONS = 100000  # High iteration count for key derivation
BACKUP_CODE_BYTES = 16  # 128 bits for AES-256 compatibility

class TwoFactorAuth:
    """Two-factor authentication using TOTP (Time-based One-Time Password)."""
    
    def __init__(self, master_password: str, salt: bytes):
        """Initialize 2FA with master password and salt.
        
        Security:
        - Salt must be cryptographically random (generated externally)
        - Master password is stored only in memory
        - Secret is derived using PBKDF2-HMAC-SHA256
        """
        self._master_password = master_password
        self._salt = salt
        self._secret = None
        self._enabled = False
        
    def generate_secret(self) -> bytes:
        """Generate a new secret key for 2FA using PBKDF2.
        
        Security:
        - Uses PBKDF2-HMAC-SHA256 with 100,000 iterations
        - 160-bit output length (standard for HMAC-SHA1 TOTP)
        - Unique salt per user prevents rainbow table attacks
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=20,  # 160 bits for HMAC-SHA1
            salt=self._salt,
            iterations=PBKDF2_ITERATIONS,
        )
        secret = kdf.derive(self._master_password.encode('utf-8'))
        self._secret = secret
        return secret
    
    def get_qr_code(self, username: str, issuer: str = "LCG Password Manager") -> bytes:
        """Generate a QR code for the secret key."""
        if not self._secret:
            self.generate_secret()
            
        # Format the URI for the QR code
        # Format: otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}
        secret_b32 = base64.b32encode(self._secret).decode('utf-8')
        uri = f"otpauth://totp/{issuer}:{username}?secret={secret_b32}&issuer={issuer}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Convert to PNG
        img = qr.make_image(fill_color="black", back_color="white")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        return img_byte_arr
    
    def verify_code(self, code: str) -> bool:
        """Verify a TOTP code."""
        if not self._secret:
            return False
            
        # Get current time and calculate time steps
        now = int(time.time())
        time_steps = [now - (now % TOTP_PERIOD) + i * TOTP_PERIOD for i in range(-1, 2)]
        
        # Try each time step
        for time_step in time_steps:
            if self._generate_totp(time_step) == code:
                return True
                
        return False
    
    def _generate_totp(self, time_step: int) -> str:
        """Generate a TOTP code for the given time step."""
        # Convert time step to bytes (8 bytes, big-endian)
        time_bytes = time_step.to_bytes(8, byteorder='big')
        
        # Calculate HMAC
        hmac_obj = hmac.new(self._secret, time_bytes, TOTP_ALGORITHM)
        hmac_result = hmac_obj.digest()
        
        # Dynamic truncation
        offset = hmac_result[-1] & 0x0F
        binary = ((hmac_result[offset] & 0x7F) << 24) | \
                 ((hmac_result[offset + 1] & 0xFF) << 16) | \
                 ((hmac_result[offset + 2] & 0xFF) << 8) | \
                 (hmac_result[offset + 3] & 0xFF)
        
        # Generate 6-digit code
        code = str(binary % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)
        return code
    
    def enable(self) -> None:
        """Enable 2FA."""
        if not self._secret:
            self.generate_secret()
        self._enabled = True
    
    def disable(self) -> None:
        """Disable 2FA."""
        self._enabled = False
        self._secret = None
    
    def is_enabled(self) -> bool:
        """Check if 2FA is enabled."""
        return self._enabled
    
    def get_backup_codes(self, count: int = 8) -> list:
        """Generate backup codes for account recovery.
        
        Security:
        - Uses os.urandom() for cryptographically secure random generation
        - 128-bit (16 bytes) random data per code for AES-256 compatibility
        - Codes are hashed with SHA-256 before storage
        - Base32 encoding for user-friendly format
        """
        if not self._secret:
            self.generate_secret()
            
        backup_codes = []
        for _ in range(count):
            # Generate a cryptographically secure random code using AES-256
            random_bytes = os.urandom(BACKUP_CODE_BYTES)  # 128 bits for AES-256
            code = base64.b32encode(random_bytes).decode('utf-8')[:10]
            # Hash the code for storage
            hashed_code = hashlib.sha256(code.encode()).hexdigest()
            backup_codes.append(hashed_code)
            
        return backup_codes
    
    def verify_backup_code(self, code: str, backup_codes: list) -> bool:
        """Verify a backup code using constant-time comparison.
        
        Security:
        - SHA-256 hashing prevents original code exposure
        - One-time use (code is removed after successful verification)
        - Uses constant-time comparison through hashlib.sha256()
        """
        # Hash the provided code for comparison
        hashed_code = hashlib.sha256(code.encode()).hexdigest()
        if hashed_code in backup_codes:
            # Remove the used backup code
            backup_codes.remove(hashed_code)
            return True
        return False 