# tests/integration/test_crud_flow.py

import pytest
from pytestqt.qt_compat import qt_api
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QMessageBox # For mocking
from pathlib import Path
import time

# Assuming the project root is added to PYTHONPATH or tests are run from root
from gui import MainWindow, AddEditDialog
from data_manager import save_data, load_data, DEFAULT_VAULT_PATH

# --- Test Fixtures --- 

@pytest.fixture
def sample_password() -> str:
    return "crud_test_password"

@pytest.fixture
def initial_data() -> list:
    """Data to pre-populate the vault for delete test."""
    return [
        {"service": "ToDelete", "username": "delete_user", "password": "del_pw"},
        {"service": "ToKeep", "username": "keep_user", "password": "keep_pw"}
    ]

@pytest.fixture
def temp_vault_file_crud(tmp_path: Path, sample_password: str) -> Path:
    """Creates an empty temporary vault file for Add test."""
    vault_path = tmp_path / "crud_test_vault_empty.dat"
    # Start with an empty vault for the Add test scenario
    save_data([], sample_password, vault_path)
    return vault_path

@pytest.fixture
def temp_vault_file_crud_populated(tmp_path: Path, initial_data: list, sample_password: str) -> Path:
    """Creates a pre-populated temporary vault file for Delete test."""
    vault_path = tmp_path / "crud_test_vault_populated.dat"
    save_data(initial_data, sample_password, vault_path)
    return vault_path

@pytest.fixture
def main_window_empty(qtbot, temp_vault_file_crud: Path, sample_password: str, monkeypatch) -> MainWindow:
    """Fixture to provide MainWindow instance with empty vault."""
    # *** Patch default path for saves within MainWindow ***
    monkeypatch.setattr(gui.data_manager, "DEFAULT_VAULT_PATH", temp_vault_file_crud)
    initial_vault_data = load_data(sample_password, temp_vault_file_crud)
    assert initial_vault_data == []
    main_win = MainWindow(initial_vault_data, sample_password)
    qtbot.addWidget(main_win)
    main_win.show()
    qtbot.waitExposed(main_win) # Wait until window is actually visible
    return main_win

@pytest.fixture
def main_window_populated(qtbot, temp_vault_file_crud_populated: Path, initial_data: list, sample_password: str, monkeypatch) -> MainWindow:
    """Fixture to provide MainWindow instance with pre-populated vault."""
    # *** Patch default path for saves within MainWindow ***
    monkeypatch.setattr(gui.data_manager, "DEFAULT_VAULT_PATH", temp_vault_file_crud_populated)
    loaded_vault_data = load_data(sample_password, temp_vault_file_crud_populated)
    assert loaded_vault_data == initial_data
    main_win = MainWindow(loaded_vault_data, sample_password)
    qtbot.addWidget(main_win)
    main_win.show()
    qtbot.waitExposed(main_win)
    return main_win

# --- Test Functions --- 

@pytest.mark.usefixtures("qtbot")
def test_add_entry(qtbot, main_window_empty: MainWindow, temp_vault_file_crud: Path, sample_password: str):
    """Tests adding a new entry through the UI."""
    main_win = main_window_empty
    list_widget = main_win.entry_list_widget
    assert list_widget.count() == 0 # Start empty

    # --- Simulate Add Click --- 
    qtbot.mouseClick(main_win.add_button, Qt.MouseButton.LeftButton)
    qtbot.wait(100) # Wait for dialog to potentially appear
    
    # --- Interact with Dialog --- 
    # Find the active modal dialog (should be AddEditDialog)
    dialog = QApplication.activeModalWidget()
    assert isinstance(dialog, AddEditDialog)
    
    # Enter data
    new_service = "Test Add Service"
    new_user = "add_user"
    new_pass = "add_password!"
    qtbot.keyClicks(dialog.service_input, new_service)
    qtbot.keyClicks(dialog.username_input, new_user)
    qtbot.keyClicks(dialog.password_input, new_pass)
    
    # Click OK button
    ok_button = dialog.button_box.button(QDialogButtonBox.StandardButton.Ok)
    qtbot.mouseClick(ok_button, Qt.MouseButton.LeftButton)
    qtbot.waitSignal(dialog.accepted, timeout=1000) # Wait for dialog to close

    # --- Verify UI Update --- 
    assert list_widget.count() == 1
    assert list_widget.item(0).text() == new_service
    
    # --- Verify Data Saved --- 
    # Load data directly from the file to check persistence
    saved_data = load_data(sample_password, temp_vault_file_crud)
    assert len(saved_data) == 1
    assert saved_data[0]["service"] == new_service
    assert saved_data[0]["username"] == new_user
    assert saved_data[0]["password"] == new_pass

@pytest.mark.usefixtures("qtbot")
def test_delete_entry(qtbot, main_window_populated: MainWindow, temp_vault_file_crud_populated: Path, initial_data: list, sample_password: str, monkeypatch):
    """Tests deleting an entry through the UI."""
    main_win = main_window_populated
    list_widget = main_win.entry_list_widget
    assert list_widget.count() == len(initial_data) # Start with initial data
    
    # Find the index of the item to delete
    delete_service = "ToDelete"
    item_to_delete_index = -1
    for i in range(list_widget.count()):
        if list_widget.item(i).text() == delete_service:
            item_to_delete_index = i
            break
    assert item_to_delete_index != -1 # Make sure item exists
    
    # --- Select Item --- 
    list_widget.setCurrentRow(item_to_delete_index)
    qtbot.waitUntil(lambda: main_win.delete_button.isEnabled()) # Wait for selection to register
    assert main_win.service_label.text().endswith(delete_service)
    
    # --- Mock QMessageBox.question to automatically click Yes --- 
    # This prevents the test from blocking on the confirmation dialog
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
    
    # --- Simulate Delete Click --- 
    qtbot.mouseClick(main_win.delete_button, Qt.MouseButton.LeftButton)
    qtbot.wait(200) # Slightly longer wait to allow file I/O to potentially finish
    
    # --- Verify UI Update --- 
    assert list_widget.count() == len(initial_data) - 1
    # Check that the remaining item is the correct one
    found_kept = False
    for i in range(list_widget.count()):
        assert list_widget.item(i).text() != delete_service
        if list_widget.item(i).text() == "ToKeep":
            found_kept = True
    assert found_kept
    
    # --- Verify Data Saved --- 
    saved_data = load_data(sample_password, temp_vault_file_crud_populated)
    assert len(saved_data) == len(initial_data) - 1
    # Check the specific content of the remaining data
    assert delete_service not in [d.get("service") for d in saved_data]
    assert "ToKeep" in [d.get("service") for d in saved_data] 