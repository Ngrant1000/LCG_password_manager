import unittest
import os
import json
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime
from lcg_password_manager.vault import VaultManager

class TestVaultManager(unittest.TestCase):
    def setUp(self):
        self.vault_manager = VaultManager()
        self.test_entry = {
            "id": "test_entry_1",
            "title": "Test Entry",
            "username": "testuser",
            "password": "testpass123",
            "url": "https://test.com",
            "notes": "Test notes",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "tags": ["test", "example"]
        }
        
    def test_create_entry(self):
        """Test creating a new vault entry"""
        entry_id = self.vault_manager.create_entry(self.test_entry)
        self.assertIsNotNone(entry_id)
        self.assertEqual(entry_id, self.test_entry["id"])
        
    def test_get_entry(self):
        """Test retrieving a vault entry"""
        self.vault_manager.entries = {self.test_entry["id"]: self.test_entry}
        entry = self.vault_manager.get_entry(self.test_entry["id"])
        self.assertEqual(entry, self.test_entry)
        
    def test_update_entry(self):
        """Test updating a vault entry"""
        self.vault_manager.entries = {self.test_entry["id"]: self.test_entry.copy()}
        updated_entry = self.test_entry.copy()
        updated_entry["title"] = "Updated Title"
        
        self.vault_manager.update_entry(self.test_entry["id"], updated_entry)
        entry = self.vault_manager.get_entry(self.test_entry["id"])
        self.assertEqual(entry["title"], "Updated Title")
        
    def test_delete_entry(self):
        """Test deleting a vault entry"""
        self.vault_manager.entries = {self.test_entry["id"]: self.test_entry}
        self.vault_manager.delete_entry(self.test_entry["id"])
        self.assertNotIn(self.test_entry["id"], self.vault_manager.entries)
        
    def test_search_entries(self):
        """Test searching vault entries"""
        self.vault_manager.entries = {
            "entry1": {"title": "Test Entry 1", "username": "user1"},
            "entry2": {"title": "Test Entry 2", "username": "user2"}
        }
        
        results = self.vault_manager.search_entries("Test Entry 1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "Test Entry 1")
        
    def test_filter_entries(self):
        """Test filtering vault entries"""
        self.vault_manager.entries = {
            "entry1": {"tags": ["work", "email"]},
            "entry2": {"tags": ["personal", "social"]}
        }
        
        results = self.vault_manager.filter_entries(tags=["work"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["tags"], ["work", "email"])
        
    def test_export_vault(self):
        """Test exporting vault to file"""
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.vault_manager.entries = {self.test_entry["id"]: self.test_entry}
            self.vault_manager.export_vault("test_vault.json")
            mock_file.assert_called_once_with("test_vault.json", "w")
            
    def test_import_vault(self):
        """Test importing vault from file"""
        mock_file = mock_open(read_data=json.dumps({self.test_entry["id"]: self.test_entry}))
        with patch("builtins.open", mock_file):
            self.vault_manager.import_vault("test_vault.json")
            self.assertEqual(self.vault_manager.entries, {self.test_entry["id"]: self.test_entry})
            
    def test_vault_encryption(self):
        """Test vault encryption/decryption"""
        encrypted_vault = self.vault_manager.encrypt_vault({self.test_entry["id"]: self.test_entry})
        decrypted_vault = self.vault_manager.decrypt_vault(encrypted_vault)
        self.assertEqual(decrypted_vault, {self.test_entry["id"]: self.test_entry})
        
    def test_entry_validation(self):
        """Test entry validation"""
        # Valid entry
        self.assertTrue(self.vault_manager.validate_entry(self.test_entry))
        
        # Invalid entry - missing required field
        invalid_entry = self.test_entry.copy()
        del invalid_entry["title"]
        self.assertFalse(self.vault_manager.validate_entry(invalid_entry))
        
    def test_password_strength(self):
        """Test password strength validation"""
        # Strong password
        self.assertTrue(self.vault_manager.check_password_strength("StrongPass123!@#"))
        
        # Weak password
        self.assertFalse(self.vault_manager.check_password_strength("weak"))
        
    def test_entry_history(self):
        """Test entry history tracking"""
        self.vault_manager.entries = {self.test_entry["id"]: self.test_entry}
        history = self.vault_manager.get_entry_history(self.test_entry["id"])
        self.assertIsInstance(history, list)
        
    def test_vault_backup(self):
        """Test vault backup"""
        backup_path = "test_vault.json.bak"
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.vault_manager.entries = {self.test_entry["id"]: self.test_entry}
            self.vault_manager.backup_vault(backup_path)
            mock_file.assert_called()
            
    def test_vault_restore(self):
        """Test vault restore"""
        mock_file = mock_open(read_data=json.dumps({self.test_entry["id"]: self.test_entry}))
        with patch("builtins.open", mock_file):
            self.vault_manager.restore_vault("test_vault.json.bak")
            self.assertEqual(self.vault_manager.entries, {self.test_entry["id"]: self.test_entry})
            
    def test_entry_categories(self):
        """Test entry categorization"""
        self.vault_manager.entries = {
            "entry1": {"category": "work"},
            "entry2": {"category": "personal"}
        }
        
        categories = self.vault_manager.get_categories()
        self.assertEqual(set(categories), {"work", "personal"})
        
    def test_entry_tags(self):
        """Test entry tagging"""
        self.vault_manager.entries = {
            "entry1": {"tags": ["work", "email"]},
            "entry2": {"tags": ["personal", "social"]}
        }
        
        tags = self.vault_manager.get_all_tags()
        self.assertEqual(set(tags), {"work", "email", "personal", "social"})
        
if __name__ == '__main__':
    unittest.main() 