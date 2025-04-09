import unittest
from unittest.mock import patch, MagicMock
from lcg_password_manager.security_utils import (
    generate_secure_key,
    hash_password,
    verify_password,
    encrypt_data,
    decrypt_data,
    generate_salt,
    validate_password_strength
)

class TestSecurityUtils(unittest.TestCase):
    def setUp(self):
        self.test_password = "TestPassword123!"
        self.test_data = "Sensitive data to encrypt"
        
    def test_generate_secure_key(self):
        """Test secure key generation"""
        key1 = generate_secure_key()
        key2 = generate_secure_key()
        
        self.assertEqual(len(key1), 32)  # 256 bits
        self.assertNotEqual(key1, key2)  # Keys should be unique
        
    def test_hash_password(self):
        """Test password hashing"""
        salt = generate_salt()
        hashed = hash_password(self.test_password, salt)
        
        self.assertIsInstance(hashed, str)
        self.assertNotEqual(hashed, self.test_password)
        self.assertTrue(len(hashed) > 0)
        
    def test_verify_password(self):
        """Test password verification"""
        salt = generate_salt()
        hashed = hash_password(self.test_password, salt)
        
        self.assertTrue(verify_password(self.test_password, hashed, salt))
        self.assertFalse(verify_password("WrongPassword", hashed, salt))
        
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption"""
        key = generate_secure_key()
        
        encrypted = encrypt_data(self.test_data, key)
        decrypted = decrypt_data(encrypted, key)
        
        self.assertNotEqual(encrypted, self.test_data)
        self.assertEqual(decrypted, self.test_data)
        
    def test_encrypt_decrypt_with_different_keys(self):
        """Test encryption/decryption with different keys"""
        key1 = generate_secure_key()
        key2 = generate_secure_key()
        
        encrypted = encrypt_data(self.test_data, key1)
        
        with self.assertRaises(Exception):
            decrypt_data(encrypted, key2)
            
    def test_generate_salt(self):
        """Test salt generation"""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        self.assertEqual(len(salt1), 16)  # 128 bits
        self.assertNotEqual(salt1, salt2)  # Salts should be unique
        
    def test_validate_password_strength(self):
        """Test password strength validation"""
        # Test strong password
        self.assertTrue(validate_password_strength("StrongPass123!@#"))
        
        # Test weak passwords
        self.assertFalse(validate_password_strength("short"))
        self.assertFalse(validate_password_strength("nouppercase123!"))
        self.assertFalse(validate_password_strength("NOLOWERCASE123!"))
        self.assertFalse(validate_password_strength("NoNumbers!"))
        self.assertFalse(validate_password_strength("NoSpecial123"))
        
    def test_encryption_with_empty_data(self):
        """Test encryption with empty data"""
        key = generate_secure_key()
        
        encrypted = encrypt_data("", key)
        decrypted = decrypt_data(encrypted, key)
        
        self.assertEqual(decrypted, "")
        
    def test_hash_with_empty_password(self):
        """Test hashing with empty password"""
        salt = generate_salt()
        
        with self.assertRaises(ValueError):
            hash_password("", salt)
            
    def test_encryption_with_large_data(self):
        """Test encryption with large data"""
        key = generate_secure_key()
        large_data = "x" * 1000000  # 1MB of data
        
        encrypted = encrypt_data(large_data, key)
        decrypted = decrypt_data(encrypted, key)
        
        self.assertEqual(decrypted, large_data)

if __name__ == '__main__':
    unittest.main() 