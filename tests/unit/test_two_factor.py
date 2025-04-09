import unittest
from unittest.mock import patch, MagicMock
import pyotp
from lcg_password_manager.two_factor import TwoFactorAuth

class TestTwoFactorAuth(unittest.TestCase):
    def setUp(self):
        self.two_factor = TwoFactorAuth()
        
    def test_generate_secret_key(self):
        """Test that secret key generation produces valid TOTP keys"""
        secret_key = self.two_factor.generate_secret_key()
        self.assertIsInstance(secret_key, str)
        self.assertEqual(len(secret_key), 32)  # Base32 encoded secret should be 32 chars
        
    def test_generate_qr_code(self):
        """Test QR code generation for 2FA setup"""
        secret_key = self.two_factor.generate_secret_key()
        qr_code = self.two_factor.generate_qr_code("test@example.com", secret_key)
        self.assertIsInstance(qr_code, bytes)
        self.assertTrue(len(qr_code) > 0)
        
    def test_verify_totp(self):
        """Test TOTP verification"""
        secret_key = self.two_factor.generate_secret_key()
        totp = pyotp.TOTP(secret_key)
        current_code = totp.now()
        
        # Test valid code
        self.assertTrue(self.two_factor.verify_totp(secret_key, current_code))
        
        # Test invalid code
        self.assertFalse(self.two_factor.verify_totp(secret_key, "000000"))
        
    def test_is_2fa_enabled(self):
        """Test 2FA status checking"""
        # Initially should be disabled
        self.assertFalse(self.two_factor.is_2fa_enabled())
        
        # Enable 2FA
        secret_key = self.two_factor.generate_secret_key()
        self.two_factor.enable_2fa(secret_key)
        self.assertTrue(self.two_factor.is_2fa_enabled())
        
    def test_disable_2fa(self):
        """Test disabling 2FA"""
        # Enable 2FA first
        secret_key = self.two_factor.generate_secret_key()
        self.two_factor.enable_2fa(secret_key)
        self.assertTrue(self.two_factor.is_2fa_enabled())
        
        # Disable 2FA
        self.two_factor.disable_2fa()
        self.assertFalse(self.two_factor.is_2fa_enabled())
        
    def test_backup_codes(self):
        """Test backup codes generation and verification"""
        backup_codes = self.two_factor.generate_backup_codes()
        self.assertEqual(len(backup_codes), 8)  # Should generate 8 backup codes
        
        # Test backup code verification
        self.assertTrue(self.two_factor.verify_backup_code(backup_codes[0]))
        self.assertFalse(self.two_factor.verify_backup_code("invalid-code"))
        
    @patch('pyotp.TOTP')
    def test_totp_time_window(self, mock_totp):
        """Test TOTP time window validation"""
        # Mock TOTP to return a specific code
        mock_totp.return_value.now.return_value = "123456"
        
        secret_key = self.two_factor.generate_secret_key()
        self.assertTrue(self.two_factor.verify_totp(secret_key, "123456"))
        
        # Test with a different code
        mock_totp.return_value.now.return_value = "654321"
        self.assertFalse(self.two_factor.verify_totp(secret_key, "123456"))

if __name__ == '__main__':
    unittest.main() 