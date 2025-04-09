import unittest
import os
import json
from unittest.mock import patch, mock_open
from lcg_password_manager.config import ConfigManager

class TestConfigManager(unittest.TestCase):
    def setUp(self):
        self.config_manager = ConfigManager()
        self.test_config = {
            "vault": {
                "path": "test_vault.json",
                "auto_lock": True,
                "lock_timeout": 300
            },
            "security": {
                "min_password_length": 12,
                "require_special_chars": True,
                "max_login_attempts": 3,
                "lockout_duration": 900
            },
            "logging": {
                "level": "INFO",
                "file": "test.log",
                "max_size": 1048576,
                "backup_count": 5
            }
        }
        
    def test_load_config(self):
        """Test loading configuration from file"""
        mock_file = mock_open(read_data=json.dumps(self.test_config))
        with patch("builtins.open", mock_file):
            config = self.config_manager.load_config("test_config.json")
            self.assertEqual(config, self.test_config)
            
    def test_save_config(self):
        """Test saving configuration to file"""
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.config_manager.save_config(self.test_config, "test_config.json")
            mock_file.assert_called_once_with("test_config.json", "w")
            
    def test_get_config_value(self):
        """Test retrieving configuration values"""
        self.config_manager.config = self.test_config
        value = self.config_manager.get_config_value("vault", "path")
        self.assertEqual(value, "test_vault.json")
        
    def test_set_config_value(self):
        """Test setting configuration values"""
        self.config_manager.config = self.test_config.copy()
        self.config_manager.set_config_value("vault", "path", "new_vault.json")
        self.assertEqual(self.config_manager.config["vault"]["path"], "new_vault.json")
        
    def test_validate_config(self):
        """Test configuration validation"""
        # Valid config
        self.assertTrue(self.config_manager.validate_config(self.test_config))
        
        # Invalid config - missing required section
        invalid_config = self.test_config.copy()
        del invalid_config["vault"]
        self.assertFalse(self.config_manager.validate_config(invalid_config))
        
    def test_default_config(self):
        """Test default configuration generation"""
        default_config = self.config_manager.get_default_config()
        self.assertIn("vault", default_config)
        self.assertIn("security", default_config)
        self.assertIn("logging", default_config)
        
    def test_config_encryption(self):
        """Test configuration encryption"""
        encrypted_config = self.config_manager.encrypt_config(self.test_config)
        decrypted_config = self.config_manager.decrypt_config(encrypted_config)
        self.assertEqual(self.test_config, decrypted_config)
        
    def test_config_merge(self):
        """Test merging configurations"""
        base_config = {
            "vault": {"path": "base_vault.json"},
            "security": {"min_password_length": 8}
        }
        override_config = {
            "vault": {"auto_lock": True},
            "security": {"min_password_length": 12}
        }
        
        merged_config = self.config_manager.merge_configs(base_config, override_config)
        self.assertEqual(merged_config["vault"]["path"], "base_vault.json")
        self.assertEqual(merged_config["vault"]["auto_lock"], True)
        self.assertEqual(merged_config["security"]["min_password_length"], 12)
        
    def test_config_backup(self):
        """Test configuration backup"""
        backup_path = "test_config.json.bak"
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.config_manager.backup_config("test_config.json", backup_path)
            mock_file.assert_called()
            
    def test_config_restore(self):
        """Test configuration restore"""
        mock_file = mock_open(read_data=json.dumps(self.test_config))
        with patch("builtins.open", mock_file):
            restored_config = self.config_manager.restore_config("test_config.json.bak")
            self.assertEqual(restored_config, self.test_config)
            
    def test_config_migration(self):
        """Test configuration migration"""
        old_config = {
            "vault_path": "old_vault.json",
            "security_level": "high"
        }
        
        new_config = self.config_manager.migrate_config(old_config)
        self.assertIn("vault", new_config)
        self.assertIn("security", new_config)
        
    def test_environment_override(self):
        """Test environment variable overrides"""
        with patch.dict(os.environ, {"VAULT_PATH": "env_vault.json"}):
            config = self.config_manager.load_config_with_env("test_config.json")
            self.assertEqual(config["vault"]["path"], "env_vault.json")
            
    def test_config_validation_rules(self):
        """Test configuration validation rules"""
        validation_rules = self.config_manager.get_validation_rules()
        self.assertIn("vault", validation_rules)
        self.assertIn("security", validation_rules)
        self.assertIn("logging", validation_rules)
        
    def test_config_schema(self):
        """Test configuration schema validation"""
        schema = self.config_manager.get_config_schema()
        self.assertIn("type", schema)
        self.assertIn("properties", schema)
        self.assertIn("required", schema)
        
if __name__ == '__main__':
    unittest.main() 