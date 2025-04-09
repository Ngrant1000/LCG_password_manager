import unittest
from unittest.mock import patch, MagicMock
from lcg_password_manager.biometric_auth import BiometricAuth

class TestBiometricAuth(unittest.TestCase):
    def setUp(self):
        self.biometric = BiometricAuth()
        
    def test_is_biometric_available(self):
        """Test biometric availability detection"""
        # Mock the Windows Hello API
        with patch('win32security.WinBioVerify') as mock_verify:
            mock_verify.return_value = True
            self.assertTrue(self.biometric.is_biometric_available())
            
        with patch('win32security.WinBioVerify', side_effect=Exception):
            self.assertFalse(self.biometric.is_biometric_available())
            
    def test_enroll_biometric(self):
        """Test biometric enrollment process"""
        with patch('win32security.WinBioEnroll') as mock_enroll:
            mock_enroll.return_value = True
            self.assertTrue(self.biometric.enroll_biometric())
            
        with patch('win32security.WinBioEnroll', side_effect=Exception):
            self.assertFalse(self.biometric.enroll_biometric())
            
    def test_verify_biometric(self):
        """Test biometric verification"""
        with patch('win32security.WinBioVerify') as mock_verify:
            mock_verify.return_value = True
            self.assertTrue(self.biometric.verify_biometric())
            
        with patch('win32security.WinBioVerify', side_effect=Exception):
            self.assertFalse(self.biometric.verify_biometric())
            
    def test_remove_biometric(self):
        """Test removing biometric data"""
        with patch('win32security.WinBioRemove') as mock_remove:
            mock_remove.return_value = True
            self.assertTrue(self.biometric.remove_biometric())
            
        with patch('win32security.WinBioRemove', side_effect=Exception):
            self.assertFalse(self.biometric.remove_biometric())
            
    def test_biometric_status(self):
        """Test biometric status checking"""
        with patch('win32security.WinBioGetStatus') as mock_status:
            mock_status.return_value = True
            self.assertTrue(self.biometric.is_biometric_enabled())
            
        with patch('win32security.WinBioGetStatus', side_effect=Exception):
            self.assertFalse(self.biometric.is_biometric_enabled())
            
    def test_fallback_mechanism(self):
        """Test fallback to password when biometric fails"""
        with patch('win32security.WinBioVerify', side_effect=Exception):
            self.assertTrue(self.biometric.authenticate_with_fallback("test_password"))
            
    def test_error_handling(self):
        """Test error handling during biometric operations"""
        with patch('win32security.WinBioVerify', side_effect=Exception("Test error")):
            with self.assertRaises(Exception):
                self.biometric.verify_biometric()
                
    def test_biometric_timeout(self):
        """Test biometric operation timeout"""
        with patch('win32security.WinBioVerify', side_effect=TimeoutError):
            self.assertFalse(self.biometric.verify_biometric())
            
    def test_biometric_cancellation(self):
        """Test biometric operation cancellation"""
        with patch('win32security.WinBioVerify', side_effect=KeyboardInterrupt):
            self.assertFalse(self.biometric.verify_biometric())

if __name__ == '__main__':
    unittest.main() 