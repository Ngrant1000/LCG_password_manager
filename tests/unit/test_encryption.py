import unittest
import os
from unittest.mock import patch, mock_open
from cryptography.fernet import Fernet
from lcg_password_manager.encryption import EncryptionManager

class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.encryption_manager = EncryptionManager()
        self.test_data = "Test data for encryption"
        self.test_key = Fernet.generate_key()
        
    def test_key_generation(self):
        """Test key generation"""
        key = self.encryption_manager.generate_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # Fernet keys are 32 bytes
        
    def test_key_derivation(self):
        """Test key derivation from password"""
        password = "testpass123"
        salt = self.encryption_manager.generate_salt()
        
        key = self.encryption_manager.derive_key(password, salt)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)
        
        # Verify same password and salt produce same key
        key2 = self.encryption_manager.derive_key(password, salt)
        self.assertEqual(key, key2)
        
        # Verify different password produces different key
        key3 = self.encryption_manager.derive_key("differentpass", salt)
        self.assertNotEqual(key, key3)
        
    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        # Encrypt data
        encrypted_data = self.encryption_manager.encrypt_data(
            self.test_data,
            self.test_key
        )
        
        # Verify encrypted data is different from original
        self.assertNotEqual(encrypted_data, self.test_data)
        
        # Decrypt data
        decrypted_data = self.encryption_manager.decrypt_data(
            encrypted_data,
            self.test_key
        )
        
        # Verify decrypted data matches original
        self.assertEqual(decrypted_data, self.test_data)
        
    def test_invalid_key_decryption(self):
        """Test decryption with invalid key"""
        # Encrypt data
        encrypted_data = self.encryption_manager.encrypt_data(
            self.test_data,
            self.test_key
        )
        
        # Generate different key
        different_key = Fernet.generate_key()
        
        # Attempt decryption with different key
        with self.assertRaises(Exception):
            self.encryption_manager.decrypt_data(
                encrypted_data,
                different_key
            )
            
    def test_salt_generation(self):
        """Test salt generation"""
        salt = self.encryption_manager.generate_salt()
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)  # Standard salt length
        
        # Verify multiple salts are different
        salt2 = self.encryption_manager.generate_salt()
        self.assertNotEqual(salt, salt2)
        
    def test_key_stretching(self):
        """Test key stretching functionality"""
        password = "testpass123"
        salt = self.encryption_manager.generate_salt()
        
        # Get stretched key
        stretched_key = self.encryption_manager.stretch_key(password, salt)
        self.assertIsInstance(stretched_key, bytes)
        self.assertEqual(len(stretched_key), 32)
        
        # Verify stretching is deterministic
        stretched_key2 = self.encryption_manager.stretch_key(password, salt)
        self.assertEqual(stretched_key, stretched_key2)
        
    def test_secure_compare(self):
        """Test secure string comparison"""
        # Test equal strings
        self.assertTrue(
            self.encryption_manager.secure_compare("test", "test")
        )
        
        # Test different strings
        self.assertFalse(
            self.encryption_manager.secure_compare("test1", "test2")
        )
        
        # Test strings of different lengths
        self.assertFalse(
            self.encryption_manager.secure_compare("test", "test1")
        )
        
    def test_encryption_with_metadata(self):
        """Test encryption with metadata"""
        metadata = {
            "version": "1.0",
            "timestamp": "2024-01-01",
            "algorithm": "AES-256"
        }
        
        # Encrypt data with metadata
        encrypted_data = self.encryption_manager.encrypt_data_with_metadata(
            self.test_data,
            self.test_key,
            metadata
        )
        
        # Decrypt data and verify metadata
        decrypted_data, decrypted_metadata = self.encryption_manager.decrypt_data_with_metadata(
            encrypted_data,
            self.test_key
        )
        
        self.assertEqual(decrypted_data, self.test_data)
        self.assertEqual(decrypted_metadata, metadata)
        
    def test_encryption_rotation(self):
        """Test encryption key rotation"""
        # Create initial key
        old_key = self.encryption_manager.generate_key()
        
        # Encrypt data with old key
        encrypted_data = self.encryption_manager.encrypt_data(
            self.test_data,
            old_key
        )
        
        # Generate new key
        new_key = self.encryption_manager.generate_key()
        
        # Re-encrypt data with new key
        reencrypted_data = self.encryption_manager.rotate_key(
            encrypted_data,
            old_key,
            new_key
        )
        
        # Verify data can be decrypted with new key
        decrypted_data = self.encryption_manager.decrypt_data(
            reencrypted_data,
            new_key
        )
        
        self.assertEqual(decrypted_data, self.test_data)
        
    def test_encryption_error_handling(self):
        """Test encryption error handling"""
        # Test with invalid data
        with self.assertRaises(Exception):
            self.encryption_manager.encrypt_data(None, self.test_key)
            
        # Test with invalid key
        with self.assertRaises(Exception):
            self.encryption_manager.encrypt_data(self.test_data, None)
            
        # Test with corrupted data
        corrupted_data = b"corrupted data"
        with self.assertRaises(Exception):
            self.encryption_manager.decrypt_data(corrupted_data, self.test_key)
            
    def test_encrypt_file(self):
        """Test file encryption"""
        test_file = "test.txt"
        mock_file = mock_open(read_data=self.test_data.encode())
        with patch("builtins.open", mock_file):
            encrypted_data = self.encryption_manager.encrypt_file(test_file, self.test_key)
            self.assertIsInstance(encrypted_data, bytes)
            self.assertNotEqual(encrypted_data, self.test_data.encode())
            
    def test_decrypt_file(self):
        """Test file decryption"""
        test_file = "test.txt"
        encrypted_data = self.encryption_manager.encrypt_data(self.test_data, self.test_key)
        mock_file = mock_open(read_data=encrypted_data)
        with patch("builtins.open", mock_file):
            decrypted_data = self.encryption_manager.decrypt_file(test_file, self.test_key)
            self.assertEqual(decrypted_data, self.test_data)
            
    def test_rotate_key(self):
        """Test key rotation"""
        new_key = self.encryption_manager.rotate_key(self.test_key)
        self.assertIsInstance(new_key, bytes)
        self.assertNotEqual(new_key, self.test_key)
        
    def test_validate_key(self):
        """Test key validation"""
        # Valid key
        self.assertTrue(self.encryption_manager.validate_key(self.test_key))
        
        # Invalid key
        invalid_key = b"invalid_key"
        self.assertFalse(self.encryption_manager.validate_key(invalid_key))
        
    def test_encrypt_with_salt(self):
        """Test encryption with salt"""
        salt = os.urandom(16)
        encrypted_data = self.encryption_manager.encrypt_with_salt(self.test_data, self.test_key, salt)
        decrypted_data = self.encryption_manager.decrypt_with_salt(encrypted_data, self.test_key, salt)
        self.assertEqual(decrypted_data, self.test_data)
        
    def test_encrypt_large_data(self):
        """Test encryption of large data"""
        large_data = "x" * 1000000  # 1MB of data
        encrypted_data = self.encryption_manager.encrypt_data(large_data, self.test_key)
        decrypted_data = self.encryption_manager.decrypt_data(encrypted_data, self.test_key)
        self.assertEqual(decrypted_data, large_data)
        
    def test_key_storage(self):
        """Test key storage and retrieval"""
        test_key_path = "test_key.key"
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.encryption_manager.store_key(self.test_key, test_key_path)
            mock_file.assert_called_once_with(test_key_path, "wb")
            
    def test_key_loading(self):
        """Test key loading"""
        test_key_path = "test_key.key"
        mock_file = mock_open(read_data=self.test_key)
        with patch("builtins.open", mock_file):
            loaded_key = self.encryption_manager.load_key(test_key_path)
            self.assertEqual(loaded_key, self.test_key)
            
if __name__ == '__main__':
    unittest.main() 