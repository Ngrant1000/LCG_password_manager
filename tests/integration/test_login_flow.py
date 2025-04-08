# tests/integration/test_login_flow.py

import pytest
from pytestqt.qt_compat import qt_api
from PyQt6.QtCore import Qt
from pathlib import Path
import time 

# Assuming the project root is added to PYTHONPATH or tests are run from root
from gui import LoginWindow
from data_manager import save_data, load_data, DEFAULT_VAULT_PATH # Import default path
# Import the global state we need to check/reset
import gui 

# --- Test Fixtures --- 

@pytest.fixture
def sample_password() -> str:
    return "correct_login_password"

@pytest.fixture
def sample_data() -> list:
    return [
        {"service": "LoginTest", "username": "logintester", "password": "ltpw"}
    ]

@pytest.fixture
def temp_vault_file(tmp_path: Path, sample_data: list, sample_password: str) -> Path:
    """Creates a temporary vault file for testing the login window."""
    vault_path = tmp_path / "login_test_vault.dat"
    save_data(sample_data, sample_password, vault_path)
    return vault_path

# --- Test Function --- 

# Need mark to use fixtures that require qt event loop
@pytest.mark.usefixtures("qtbot")
def test_login_correct_incorrect(qtbot, temp_vault_file: Path, sample_data: list, sample_password: str, monkeypatch):
    """Tests entering incorrect and correct passwords into the LoginWindow."""
    # Ensure FAILED_ATTEMPTS state is clean before starting
    monkeypatch.setitem(gui.FAILED_ATTEMPTS, "count", 0)
    monkeypatch.setitem(gui.FAILED_ATTEMPTS, "last_attempt_time", 0)
    
    # --- Setup --- 
    # *** Patch DEFAULT_VAULT_PATH to use the temp file for load_data ***
    monkeypatch.setattr(gui.data_manager, "DEFAULT_VAULT_PATH", temp_vault_file)
    
    login_win = LoginWindow()
    qtbot.addWidget(login_win) # Register window with qtbot
    login_win.show() # Show the window for interaction
    
    # --- Test Incorrect Password --- 
    incorrect_password = "wrong_password"
    qtbot.keyClicks(login_win.password_input, incorrect_password)
    # qtbot.mouseClick(login_win.login_button, Qt.MouseButton.LeftButton)
    # Clicking the button can be problematic if QMessageBox blocks. 
    # Let's trigger via returnPressed which is connected to the same slot.
    qtbot.keyPress(login_win.password_input, Qt.Key.Key_Return)
    
    # Wait a short moment for potential UI updates / message boxes (though we won't see them)
    qtbot.wait(100) 
    
    # Assert that the failed attempt counter was incremented
    assert gui.FAILED_ATTEMPTS["count"] == 1
    assert login_win.password_input.text() == "" # Field should be cleared on failure
    assert login_win.status_label.text() == "" # No lockout yet
    assert login_win.login_button.isEnabled() # Not locked out yet

    # --- Test Correct Password --- 
    qtbot.keyClicks(login_win.password_input, sample_password)
    
    # Use waitSignal to check if login_successful is emitted
    with qtbot.waitSignal(login_win.login_successful, timeout=1000) as blocker:
        qtbot.keyPress(login_win.password_input, Qt.Key.Key_Return)
        
    # Signal emitted, check arguments passed by the signal
    # blocker.args contains the arguments emitted with the signal: [loaded_data, password]
    assert blocker.args[0] == sample_data
    assert blocker.args[1] == sample_password
    
    # Check failed attempts were reset on success
    assert gui.FAILED_ATTEMPTS["count"] == 0
    
    # Window should close on successful login
    assert not login_win.isVisible()

@pytest.mark.usefixtures("qtbot")
def test_login_lockout(qtbot, temp_vault_file: Path, sample_password: str, monkeypatch):
    """Tests the login lockout mechanism."""
    # Reset state
    monkeypatch.setitem(gui.FAILED_ATTEMPTS, "count", 0)
    monkeypatch.setitem(gui.FAILED_ATTEMPTS, "last_attempt_time", 0)
    monkeypatch.setattr(gui, "MAX_LOGIN_ATTEMPTS", 3) # Lower max attempts for test speed
    monkeypatch.setattr(gui, "LOCKOUT_DURATION_SECONDS", 2) # Short lockout for test speed
    
    # *** Patch DEFAULT_VAULT_PATH for load_data ***
    monkeypatch.setattr(gui.data_manager, "DEFAULT_VAULT_PATH", temp_vault_file)
    
    login_win = LoginWindow()
    qtbot.addWidget(login_win)
    login_win.show()

    incorrect_password = "wrong"
    # Trigger lockout
    for i in range(gui.MAX_LOGIN_ATTEMPTS):
        qtbot.keyClicks(login_win.password_input, f"{incorrect_password}{i}")
        qtbot.keyPress(login_win.password_input, Qt.Key.Key_Return)
        qtbot.wait(50) # Small wait
        # Verify intermediate state (optional)
        if i < gui.MAX_LOGIN_ATTEMPTS - 1:
             assert gui.FAILED_ATTEMPTS["count"] == i + 1
             assert login_win.password_input.isEnabled() # Should still be enabled
             assert login_win.status_label.text() == ""
        
    # After the last failed attempt, lockout should be active
    assert gui.FAILED_ATTEMPTS["count"] == gui.MAX_LOGIN_ATTEMPTS
    assert not login_win.password_input.isEnabled() # Should be disabled
    assert not login_win.login_button.isEnabled() # Should be disabled
    assert "Try again in" in login_win.status_label.text() # Check for lockout message
    
    # Try logging in while locked out - should do nothing
    qtbot.keyClicks(login_win.password_input, sample_password)
    qtbot.keyPress(login_win.password_input, Qt.Key.Key_Return)
    qtbot.wait(50)
    # *** Check disabled state DURING lockout ***
    assert not login_win.password_input.isEnabled() # Still disabled
    
    # Wait for lockout to expire (LOCKOUT_DURATION_SECONDS + buffer)
    print(f"Waiting for lockout ({gui.LOCKOUT_DURATION_SECONDS}s)...")
    qtbot.wait((gui.LOCKOUT_DURATION_SECONDS * 1000) + 200)
    print("Lockout should have expired.")
    
    # Check if UI is re-enabled
    assert login_win.password_input.isEnabled()
    assert login_win.login_button.isEnabled()
    assert login_win.status_label.text() == ""
    assert gui.FAILED_ATTEMPTS["count"] == 0 # Counter should be reset
    
    # Try logging in successfully now
    with qtbot.waitSignal(login_win.login_successful, timeout=1000):
        qtbot.keyClicks(login_win.password_input, sample_password)
        qtbot.keyPress(login_win.password_input, Qt.Key.Key_Return)

    assert not login_win.isVisible() 