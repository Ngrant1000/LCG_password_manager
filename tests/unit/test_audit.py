import unittest
import os
import json
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime, timedelta
from lcg_password_manager.audit import AuditLogger

class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.audit_logger = AuditLogger()
        self.test_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "login_attempt",
            "user_id": "test_user",
            "status": "success",
            "ip_address": "127.0.0.1",
            "details": {"browser": "Chrome", "os": "Windows"}
        }
        
    def test_log_event(self):
        """Test logging an audit event"""
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.audit_logger.log_event(
                self.test_event["event_type"],
                self.test_event["user_id"],
                self.test_event["status"],
                self.test_event["details"]
            )
            mock_file.assert_called()
            
    def test_get_events(self):
        """Test retrieving audit events"""
        mock_file = mock_open(read_data=json.dumps([self.test_event]))
        with patch("builtins.open", mock_file):
            events = self.audit_logger.get_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "login_attempt")
            
    def test_filter_events(self):
        """Test filtering audit events"""
        events = [
            {"event_type": "login_attempt", "status": "success"},
            {"event_type": "login_attempt", "status": "failure"},
            {"event_type": "password_change", "status": "success"}
        ]
        
        filtered = self.audit_logger.filter_events(events, event_type="login_attempt")
        self.assertEqual(len(filtered), 2)
        
    def test_get_user_activity(self):
        """Test retrieving user activity"""
        mock_file = mock_open(read_data=json.dumps([self.test_event]))
        with patch("builtins.open", mock_file):
            activity = self.audit_logger.get_user_activity("test_user")
            self.assertEqual(len(activity), 1)
            self.assertEqual(activity[0]["user_id"], "test_user")
            
    def test_get_failed_attempts(self):
        """Test retrieving failed login attempts"""
        events = [
            {"event_type": "login_attempt", "status": "failure", "timestamp": datetime.now().isoformat()},
            {"event_type": "login_attempt", "status": "success", "timestamp": datetime.now().isoformat()}
        ]
        
        mock_file = mock_open(read_data=json.dumps(events))
        with patch("builtins.open", mock_file):
            failures = self.audit_logger.get_failed_attempts()
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["status"], "failure")
            
    def test_get_security_alerts(self):
        """Test retrieving security alerts"""
        events = [
            {"event_type": "security_alert", "severity": "high", "details": {"type": "brute_force"}},
            {"event_type": "security_alert", "severity": "low", "details": {"type": "weak_password"}}
        ]
        
        mock_file = mock_open(read_data=json.dumps(events))
        with patch("builtins.open", mock_file):
            alerts = self.audit_logger.get_security_alerts()
            self.assertEqual(len(alerts), 2)
            
    def test_export_audit_log(self):
        """Test exporting audit log"""
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.audit_logger.export_audit_log("audit_log.json")
            mock_file.assert_called_once_with("audit_log.json", "w")
            
    def test_import_audit_log(self):
        """Test importing audit log"""
        mock_file = mock_open(read_data=json.dumps([self.test_event]))
        with patch("builtins.open", mock_file):
            self.audit_logger.import_audit_log("audit_log.json")
            events = self.audit_logger.get_events()
            self.assertEqual(len(events), 1)
            
    def test_cleanup_old_logs(self):
        """Test cleaning up old audit logs"""
        old_event = {
            "timestamp": (datetime.now() - timedelta(days=31)).isoformat(),
            "event_type": "old_event"
        }
        recent_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "recent_event"
        }
        
        mock_file = mock_open(read_data=json.dumps([old_event, recent_event]))
        with patch("builtins.open", mock_file):
            self.audit_logger.cleanup_old_logs(days=30)
            events = self.audit_logger.get_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "recent_event")
            
    def test_get_audit_summary(self):
        """Test generating audit summary"""
        events = [
            {"event_type": "login_attempt", "status": "success"},
            {"event_type": "login_attempt", "status": "failure"},
            {"event_type": "password_change", "status": "success"}
        ]
        
        mock_file = mock_open(read_data=json.dumps(events))
        with patch("builtins.open", mock_file):
            summary = self.audit_logger.get_audit_summary()
            self.assertIn("login_attempt", summary)
            self.assertIn("password_change", summary)
            
    def test_validate_event(self):
        """Test event validation"""
        # Valid event
        self.assertTrue(self.audit_logger.validate_event(self.test_event))
        
        # Invalid event - missing required field
        invalid_event = self.test_event.copy()
        del invalid_event["event_type"]
        self.assertFalse(self.audit_logger.validate_event(invalid_event))
        
    def test_get_event_statistics(self):
        """Test getting event statistics"""
        events = [
            {"event_type": "login_attempt", "status": "success"},
            {"event_type": "login_attempt", "status": "failure"},
            {"event_type": "login_attempt", "status": "success"}
        ]
        
        mock_file = mock_open(read_data=json.dumps(events))
        with patch("builtins.open", mock_file):
            stats = self.audit_logger.get_event_statistics()
            self.assertEqual(stats["login_attempt"]["total"], 3)
            self.assertEqual(stats["login_attempt"]["success"], 2)
            self.assertEqual(stats["login_attempt"]["failure"], 1)
            
if __name__ == '__main__':
    unittest.main() 