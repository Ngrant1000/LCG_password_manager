# tests/unit/test_encryption_utils.py

import pytest
import os
# Assuming the project root is added to PYTHONPATH or tests are run from root
from encryption_utils import (
    generate_salt,
    generate_key,
    encrypt_data,
    decrypt_data,
    SALT_SIZE,
    KEY_ITERATIONS # Import if needed for specific assertions
)

# --- Test Fixtures (Optional but good practice) ---

@pytest.fixture
def sample_password() -> str:
    return "a_strong_test_password_123!@#"

@pytest.fixture
def sample_salt() -> bytes:
    return generate_salt() # Use the actual function

@pytest.fixture
def derived_key(sample_password, sample_salt) -> bytes:
    return generate_key(sample_password, sample_salt)

# --- Test Functions ---

def test_generate_salt():
    """Test that generate_salt returns bytes of the correct length."""
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == SALT_SIZE

def test_generate_key(sample_password, sample_salt):
    """Test that generate_key returns a valid Fernet key (bytes, specific length encoded)."""
    key = generate_key(sample_password, sample_salt)
    assert isinstance(key, bytes)
    # Fernet keys derived via PBKDF2(length=32) and then base64 encoded are 44 bytes long
    assert len(key) == 44 
    # Test idempotency (same password, same salt -> same key)
    key2 = generate_key(sample_password, sample_salt)
    assert key == key2
    # Test different salt yields different key
    salt2 = generate_salt()
    assert sample_salt != salt2 # Use correct fixture name
    key3 = generate_key(sample_password, salt2)
    assert key != key3

def test_generate_key_invalid_input():
    """Test generate_key raises errors for invalid input types/values."""
    salt = generate_salt()
    with pytest.raises(ValueError):
        generate_key("", salt) # Empty password
    with pytest.raises(ValueError):
        generate_key("password", b"shortsalt") # Incorrect salt length
    with pytest.raises(ValueError):
        generate_key("password", os.urandom(SALT_SIZE - 1))
    with pytest.raises(ValueError): # Changed from TypeError to ValueError
        generate_key(12345, salt) # Non-string password
    with pytest.raises(TypeError): # Expect TypeError based on type hints
        generate_key("password", "not_bytes") # Non-bytes salt

def test_encrypt_decrypt_cycle(derived_key):
    """Test that data encrypted can be decrypted correctly with the same key."""
    original_data = b"This is my secret data. \x01\x02\x03"
    encrypted_token = encrypt_data(original_data, derived_key)
    
    assert isinstance(encrypted_token, bytes)
    assert encrypted_token != original_data
    
    decrypted_data = decrypt_data(encrypted_token, derived_key)
    assert decrypted_data == original_data

def test_decrypt_with_wrong_key(sample_password, sample_salt, derived_key):
    """Test that decryption fails with an incorrect key."""
    original_data = b"Sensitive information here."
    encrypted_token = encrypt_data(original_data, derived_key)
    
    # Generate a different key (using different password or salt)
    wrong_salt = generate_salt()
    wrong_key = generate_key(sample_password, wrong_salt)
    assert derived_key != wrong_key
    
    with pytest.raises(ValueError): # Expect ValueError based on decrypt_data's exception handling
        decrypt_data(encrypted_token, wrong_key)

def test_decrypt_tampered_data(derived_key):
    """Test that decryption fails if the encrypted token is modified (due to HMAC)."""
    original_data = b"Important data."
    encrypted_token = encrypt_data(original_data, derived_key)
    
    # Tamper with the token (e.g., flip a bit or append data)
    tampered_token = encrypted_token[:-1] + bytes([(encrypted_token[-1] + 1) % 256])
    
    with pytest.raises(ValueError): # Fernet raises InvalidToken, caught as ValueError
        decrypt_data(tampered_token, derived_key) 