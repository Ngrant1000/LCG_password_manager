# tests/unit/test_data_manager.py

import pytest
import json
from pathlib import Path
import os

# Assuming the project root is added to PYTHONPATH or tests are run from root
from data_manager import save_data, load_data, vault_exists
from encryption_utils import SALT_SIZE

# --- Test Fixtures --- 

@pytest.fixture
def sample_password() -> str:
    return "test-password-for-data-manager"

@pytest.fixture
def sample_data() -> list:
    return [
        {"service": "TestSite", "username": "tester", "password": "pw1"},
        {"service": "Another One", "username": "user2", "password": "!@#$%^"}
    ]

@pytest.fixture
def temp_vault_path(tmp_path: Path) -> Path:
    """Provides a path to a temporary file within a temporary directory."""
    # tmp_path is a built-in pytest fixture providing a Path object
    # to a unique temporary directory for each test function
    return tmp_path / "test_vault.dat"

# --- Test Functions --- 

def test_vault_exists_false(temp_vault_path: Path):
    """Test vault_exists returns False if file doesn't exist."""
    assert not vault_exists(temp_vault_path)

def test_vault_exists_empty_file(temp_vault_path: Path):
    """Test vault_exists returns False if file exists but is too small (no salt)."""
    temp_vault_path.touch() # Create empty file
    assert not vault_exists(temp_vault_path)
    temp_vault_path.write_bytes(b"small") # Write less than SALT_SIZE
    assert not vault_exists(temp_vault_path)

def test_save_load_cycle(temp_vault_path: Path, sample_data: list, sample_password: str):
    """Test saving data and loading it back successfully."""
    # 1. Save data
    save_data(sample_data, sample_password, temp_vault_path)
    
    # 2. Check file exists and has minimum size
    assert vault_exists(temp_vault_path)
    assert temp_vault_path.stat().st_size > SALT_SIZE
    
    # 3. Load data back
    loaded_data = load_data(sample_password, temp_vault_path)
    
    # 4. Assert loaded data matches original data
    assert loaded_data == sample_data

def test_load_non_existent_file(temp_vault_path: Path, sample_password: str):
    """Test load_data returns an empty list if the vault file doesn't exist."""
    assert not temp_vault_path.exists() # Pre-condition
    loaded_data = load_data(sample_password, temp_vault_path)
    assert loaded_data == []

def test_load_wrong_password(temp_vault_path: Path, sample_data: list, sample_password: str):
    """Test load_data raises ValueError for an incorrect password."""
    # 1. Save data with correct password
    save_data(sample_data, sample_password, temp_vault_path)
    assert vault_exists(temp_vault_path)
    
    # 2. Attempt to load with wrong password
    wrong_password = "incorrect-" + sample_password
    with pytest.raises(ValueError, match="Decryption failed"):
        load_data(wrong_password, temp_vault_path)

def test_save_overwrite_preserves_salt(temp_vault_path: Path, sample_data: list, sample_password: str):
    """Test that saving over an existing file uses the original salt."""
    # 1. Save initial data
    save_data(sample_data, sample_password, temp_vault_path)
    assert vault_exists(temp_vault_path)
    with open(temp_vault_path, 'rb') as f:
        original_salt = f.read(SALT_SIZE)
        assert len(original_salt) == SALT_SIZE
        
    # 2. Modify data and save again
    modified_data = sample_data + [{"service": "New Entry", "username": "added", "password": "newpass"}]
    save_data(modified_data, sample_password, temp_vault_path)
    assert vault_exists(temp_vault_path)
    
    # 3. Check the salt is still the same
    with open(temp_vault_path, 'rb') as f:
        new_salt = f.read(SALT_SIZE)
        assert len(new_salt) == SALT_SIZE
        assert new_salt == original_salt
        
    # 4. Verify the new data can be loaded
    loaded_data = load_data(sample_password, temp_vault_path)
    assert loaded_data == modified_data

def test_load_corrupted_salt(temp_vault_path: Path, sample_password: str):
    """Test load_data raises error if the salt length is wrong."""
    # Write a file with insufficient salt bytes
    corrupted_content = os.urandom(SALT_SIZE - 1)
    temp_vault_path.write_bytes(corrupted_content)
    
    # Direct load should fail the salt size check
    with pytest.raises(ValueError, match="incorrect salt size"):
        load_data(sample_password, temp_vault_path)

def test_load_corrupted_data(temp_vault_path: Path, sample_data: list, sample_password: str):
    """Test load_data raises error if the encrypted data part is corrupted."""
    save_data(sample_data, sample_password, temp_vault_path)
    assert vault_exists(temp_vault_path)
    
    # Read original content and tamper with the encrypted part
    original_content = temp_vault_path.read_bytes()
    salt = original_content[:SALT_SIZE]
    encrypted_part = original_content[SALT_SIZE:]
    # Flip a bit in the encrypted data
    tampered_encrypted = encrypted_part[:-1] + bytes([(encrypted_part[-1] + 1) % 256])
    corrupted_content = salt + tampered_encrypted
    temp_vault_path.write_bytes(corrupted_content)
    
    assert vault_exists(temp_vault_path) # File should still seem valid to vault_exists
    
    # Load should fail during decryption (InvalidToken -> ValueError)
    with pytest.raises(ValueError, match="Decryption failed"):
        load_data(sample_password, temp_vault_path)

def test_load_not_json(temp_vault_path: Path, sample_password: str):
    """Test load_data raises error if decrypted data isn't valid JSON or not a list."""
    # Use encryption utils directly to create a vault with non-JSON data
    from encryption_utils import generate_key, generate_salt, encrypt_data
    salt = generate_salt()
    key = generate_key(sample_password, salt)
    non_json_bytes = b"this is not json data \x00\xff"
    encrypted_non_json = encrypt_data(non_json_bytes, key)
    temp_vault_path.write_bytes(salt + encrypted_non_json)
    
    assert vault_exists(temp_vault_path)
    # Expect JSONDecodeError (if json lib used) or TypeError (if check is manual), or UnicodeDecodeError
    with pytest.raises((json.JSONDecodeError, TypeError, UnicodeDecodeError)): 
        load_data(sample_password, temp_vault_path)

    # Test case where it is JSON but not a list
    dict_data = {"service": "SomeService"}
    json_bytes = json.dumps(dict_data).encode('utf-8')
    encrypted_json = encrypt_data(json_bytes, key)
    temp_vault_path.write_bytes(salt + encrypted_json)
    
    assert vault_exists(temp_vault_path)
    with pytest.raises(TypeError, match="not in the expected list format"):
        load_data(sample_password, temp_vault_path) 