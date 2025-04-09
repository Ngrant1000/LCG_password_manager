import unittest
import os
import tempfile
from datetime import datetime
from lcg_password_manager.vault_manager import VaultManager
from lcg_password_manager.encryption import EncryptionManager

class TestVaultManager(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.vault_path = os.path.join(self.temp_dir, "test_vault.enc")
        self.master_password = "TestMasterPass123!"
        self.vault_manager = VaultManager(self.vault_path)
        self.encryption_manager = EncryptionManager()
        
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.vault_path):
            os.remove(self.vault_path)
        os.rmdir(self.temp_dir)
        
    def test_vault_creation(self):
        """Test vault creation and initialization"""
        # Create new vault
        self.assertTrue(self.vault_manager.create_vault(self.master_password))
        self.assertTrue(os.path.exists(self.vault_path))
        
        # Verify vault structure
        vault_data = self.vault_manager.load_vault(self.master_password)
        self.assertIsNotNone(vault_data)
        self.assertIn("entries", vault_data)
        self.assertIn("metadata", vault_data)
        
    def test_entry_operations(self):
        """Test basic entry operations"""
        # Create vault and add entry
        self.vault_manager.create_vault(self.master_password)
        entry_data = {
            "title": "Test Entry",
            "username": "testuser",
            "password": "TestPass123!",
            "url": "https://test.com",
            "notes": "Test notes"
        }
        
        # Add entry
        entry_id = self.vault_manager.add_entry(entry_data, self.master_password)
        self.assertIsNotNone(entry_id)
        
        # Get entry
        retrieved_entry = self.vault_manager.get_entry(entry_id, self.master_password)
        self.assertEqual(retrieved_entry["title"], entry_data["title"])
        self.assertEqual(retrieved_entry["username"], entry_data["username"])
        self.assertEqual(retrieved_entry["password"], entry_data["password"])
        
        # Update entry
        updated_data = entry_data.copy()
        updated_data["title"] = "Updated Title"
        self.assertTrue(self.vault_manager.update_entry(entry_id, updated_data, self.master_password))
        
        # Verify update
        updated_entry = self.vault_manager.get_entry(entry_id, self.master_password)
        self.assertEqual(updated_entry["title"], "Updated Title")
        
        # Delete entry
        self.assertTrue(self.vault_manager.delete_entry(entry_id, self.master_password))
        self.assertIsNone(self.vault_manager.get_entry(entry_id, self.master_password))
        
    def test_entry_search(self):
        """Test entry search functionality"""
        # Create vault with multiple entries
        self.vault_manager.create_vault(self.master_password)
        entries = [
            {
                "title": "Gmail Account",
                "username": "user1@gmail.com",
                "password": "Pass1",
                "url": "https://gmail.com"
            },
            {
                "title": "Facebook Account",
                "username": "user2@facebook.com",
                "password": "Pass2",
                "url": "https://facebook.com"
            }
        ]
        
        for entry in entries:
            self.vault_manager.add_entry(entry, self.master_password)
            
        # Search by title
        results = self.vault_manager.search_entries("Gmail", self.master_password)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "Gmail Account")
        
        # Search by username
        results = self.vault_manager.search_entries("facebook", self.master_password)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "user2@facebook.com")
        
    def test_vault_backup_restore(self):
        """Test vault backup and restore functionality"""
        # Create and populate vault
        self.vault_manager.create_vault(self.master_password)
        entry_data = {
            "title": "Backup Test",
            "username": "testuser",
            "password": "TestPass123!"
        }
        self.vault_manager.add_entry(entry_data, self.master_password)
        
        # Create backup
        backup_path = os.path.join(self.temp_dir, "vault_backup.enc")
        self.assertTrue(self.vault_manager.create_backup(backup_path, self.master_password))
        
        # Delete original vault
        os.remove(self.vault_path)
        
        # Restore from backup
        self.assertTrue(self.vault_manager.restore_from_backup(backup_path, self.master_password))
        
        # Verify restored data
        entries = self.vault_manager.get_all_entries(self.master_password)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Backup Test")
        
    def test_password_based_access(self):
        """Test password-based access control"""
        # Create vault with password
        self.vault_manager.create_vault(self.master_password)
        
        # Test correct password
        self.assertTrue(self.vault_manager.verify_master_password(self.master_password))
        
        # Test incorrect password
        self.assertFalse(self.vault_manager.verify_master_password("WrongPassword123!"))
        
        # Test password change
        new_password = "NewMasterPass123!"
        self.assertTrue(self.vault_manager.change_master_password(self.master_password, new_password))
        self.assertTrue(self.vault_manager.verify_master_password(new_password))
        
    def test_data_integrity(self):
        """Test data integrity verification"""
        # Create vault and add entry
        self.vault_manager.create_vault(self.master_password)
        entry_data = {
            "title": "Integrity Test",
            "username": "testuser",
            "password": "TestPass123!"
        }
        entry_id = self.vault_manager.add_entry(entry_data, self.master_password)
        
        # Verify integrity
        self.assertTrue(self.vault_manager.verify_integrity(self.master_password))
        
        # Tamper with vault file
        with open(self.vault_path, "rb") as f:
            data = f.read()
        with open(self.vault_path, "wb") as f:
            f.write(data + b"tampered")
            
        # Verify integrity fails
        self.assertFalse(self.vault_manager.verify_integrity(self.master_password))
        
    def test_vault_metadata(self):
        """Test vault metadata management"""
        # Create vault
        self.vault_manager.create_vault(self.master_password)
        
        # Get metadata
        metadata = self.vault_manager.get_metadata(self.master_password)
        self.assertIn("created_at", metadata)
        self.assertIn("last_modified", metadata)
        self.assertIn("version", metadata)
        
        # Update metadata
        new_metadata = {
            "description": "Test vault",
            "owner": "Test User"
        }
        self.assertTrue(self.vault_manager.update_metadata(new_metadata, self.master_password))
        
        # Verify updated metadata
        updated_metadata = self.vault_manager.get_metadata(self.master_password)
        self.assertEqual(updated_metadata["description"], "Test vault")
        self.assertEqual(updated_metadata["owner"], "Test User")
        
    def test_entry_categories(self):
        """Test entry categorization"""
        # Create vault with categorized entries
        self.vault_manager.create_vault(self.master_password)
        entries = [
            {
                "title": "Work Email",
                "username": "work@company.com",
                "password": "Pass1",
                "category": "Work"
            },
            {
                "title": "Personal Email",
                "username": "personal@gmail.com",
                "password": "Pass2",
                "category": "Personal"
            }
        ]
        
        for entry in entries:
            self.vault_manager.add_entry(entry, self.master_password)
            
        # Get entries by category
        work_entries = self.vault_manager.get_entries_by_category("Work", self.master_password)
        self.assertEqual(len(work_entries), 1)
        self.assertEqual(work_entries[0]["title"], "Work Email")
        
        personal_entries = self.vault_manager.get_entries_by_category("Personal", self.master_password)
        self.assertEqual(len(personal_entries), 1)
        self.assertEqual(personal_entries[0]["title"], "Personal Email")
        
    def test_error_handling(self):
        """Test error handling"""
        # Test invalid vault path
        with self.assertRaises(ValueError):
            VaultManager("")
            
        # Test non-existent vault
        with self.assertRaises(FileNotFoundError):
            self.vault_manager.load_vault(self.master_password)
            
        # Test invalid master password
        self.vault_manager.create_vault(self.master_password)
        with self.assertRaises(ValueError):
            self.vault_manager.load_vault("WrongPassword123!")
            
        # Test invalid entry data
        with self.assertRaises(ValueError):
            self.vault_manager.add_entry({}, self.master_password)
            
if __name__ == '__main__':
    unittest.main() 