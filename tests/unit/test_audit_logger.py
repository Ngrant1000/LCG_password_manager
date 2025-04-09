import unittest
from unittest.mock import patch, mock_open
import os
import json
from datetime import datetime
from lcg_password_manager.audit_logger import AuditLogger
from lcg_password_manager.encryption_utils import generate_salt

class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.log_file = "test_audit.log"
        self.master_password = "test_password"
        self.salt = generate_salt()
        self.audit_logger = AuditLogger(self.master_password, self.salt)
        
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
            
    def test_log_login_attempt(self):
        """Test logging login attempts"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_login_attempt("testuser", True)
            mock_file.assert_called_once()
            
    def test_log_password_change(self):
        """Test logging password changes"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_password_change("testuser")
            mock_file.assert_called_once()
            
    def test_log_vault_access(self):
        """Test logging vault access"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_vault_access("testuser", "read")
            mock_file.assert_called_once()
            
    def test_log_entry_modification(self):
        """Test logging entry modifications"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_entry_modification("testuser", "add", "Test Entry")
            mock_file.assert_called_once()
            
    def test_log_export(self):
        """Test logging vault exports"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_export("testuser", "export.json")
            mock_file.assert_called_once()
            
    def test_log_import(self):
        """Test logging vault imports"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_import("testuser", "import.json")
            mock_file.assert_called_once()
            
    def test_log_security_event(self):
        """Test logging security events"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_security_event("testuser", "Failed login attempt", "warning")
            mock_file.assert_called_once()
            
    def test_log_rotation(self):
        """Test log rotation"""
        # Create a large log file
        with open(self.log_file, 'w') as f:
            f.write('x' * 1024 * 1024)  # 1MB of data
            
        with patch('os.path.getsize') as mock_getsize:
            mock_getsize.return_value = 1024 * 1024  # 1MB
            self.audit_logger.check_log_rotation()
            
        self.assertTrue(os.path.exists(f"{self.log_file}.1"))
        
    def test_log_format(self):
        """Test log entry format"""
        with patch('builtins.open', mock_open()) as mock_file:
            self.audit_logger.log_login_attempt("testuser", True)
            
            # Verify log entry format
            log_entry = mock_file.mock_calls[0][1][0]
            self.assertIn("timestamp", log_entry)
            self.assertIn("user", log_entry)
            self.assertIn("action", log_entry)
            self.assertIn("status", log_entry)
            
    def test_log_retention(self):
        """Test log retention policy"""
        # Create old log files
        for i in range(1, 6):
            with open(f"{self.log_file}.{i}", 'w') as f:
                f.write("test")
                
        self.audit_logger.cleanup_old_logs()
        
        # Verify only 5 most recent logs are kept
        self.assertFalse(os.path.exists(f"{self.log_file}.5"))
        self.assertTrue(os.path.exists(f"{self.log_file}.1"))
        
    def test_log_compression(self):
        """Test log compression"""
        # Create a log file
        with open(self.log_file, 'w') as f:
            f.write("test log content")
            
        self.audit_logger.compress_log(self.log_file)
        
        # Verify compressed file exists
        self.assertTrue(os.path.exists(f"{self.log_file}.gz"))
        
    def test_log_parsing(self):
        """Test log parsing"""
        test_log = {
            "timestamp": datetime.now().isoformat(),
            "user": "testuser",
            "action": "login",
            "status": "success"
        }
        
        with open(self.log_file, 'w') as f:
            json.dump(test_log, f)
            
        entries = self.audit_logger.parse_log(self.log_file)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["user"], "testuser")
        
    def test_log_search(self):
        """Test log searching"""
        # Create test logs
        logs = [
            {"user": "user1", "action": "login"},
            {"user": "user2", "action": "logout"},
            {"user": "user1", "action": "password_change"}
        ]
        
        with open(self.log_file, 'w') as f:
            for log in logs:
                json.dump(log, f)
                f.write('\n')
                
        results = self.audit_logger.search_logs("user1")
        self.assertEqual(len(results), 2)
        
if __name__ == '__main__':
    unittest.main() 