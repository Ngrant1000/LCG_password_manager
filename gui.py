# gui.py

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QMessageBox, 
    QListWidget, QListWidgetItem, # Added QListWidget/Item
    QDialog, QDialogButtonBox, QSpinBox, QCheckBox, # Added QSpinBox and QCheckBox
    QMessageBox, # Added for message box
    QProgressBar, # Added for strength meter
    QStackedWidget # Added QStackedWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer # Added QTimer
from PyQt6.QtGui import QClipboard, QPalette, QColor # Added Palette/Color
import data_manager
import secrets # Added for password generation
import string # Added for character sets
from zxcvbn import zxcvbn # Added for password strength
import time # Added for login throttling

# Constants for Login Throttling
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60 # Lock out for 60 seconds after max attempts
FAILED_ATTEMPTS = {"count": 0, "last_attempt_time": 0}

class SetupWindow(QWidget):
    """Window for initial master password setup."""
    # Signal to indicate setup is complete, passing the master password
    setup_complete = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("LCG Password Manager - Setup")
        self.setGeometry(200, 200, 400, 250) # Increased height

        layout = QVBoxLayout()

        self.info_label = QLabel("Welcome! Please create a strong master password.")
        layout.addWidget(self.info_label)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Master Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.update_strength_meter)
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm Master Password")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        # Strength Meter Section
        strength_layout = QVBoxLayout()  # Changed from QHBoxLayout to QVBoxLayout
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4) # zxcvbn scores 0-4
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        strength_layout.addWidget(self.strength_bar) # Bar takes full width
        self.strength_label = QLabel("Very Weak")
        # Removed fixed width since label will be full width
        self.strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter) # Center the text
        strength_layout.addWidget(self.strength_label)
        layout.addLayout(strength_layout)

        layout.addStretch() # Add space before button

        self.submit_button = QPushButton("Create Vault")
        self.submit_button.clicked.connect(self.create_vault)
        self.submit_button.setEnabled(False) # Disabled until password is good enough
        layout.addWidget(self.submit_button)

        self.setLayout(layout)
        self.update_strength_meter("") # Initial state

    def update_strength_meter(self, password_text):
        """Updates the password strength meter based on zxcvbn score."""
        if not password_text:
            score = 0
            feedback = "Too short" 
        else:
            results = zxcvbn(password_text)
            score = results['score'] # Score 0-4
            # Use feedback suggestions if available, otherwise use score names
            if results['feedback'] and results['feedback']['warning']:
                 feedback = results['feedback']['warning']
            elif results['feedback'] and results['feedback']['suggestions']:
                 feedback = results['feedback']['suggestions'][0] # Take first suggestion
            else:
                 feedback = ["Very Weak", "Weak", "Okay", "Good", "Strong"][score]

        self.strength_bar.setValue(score)
        self.strength_label.setText(feedback)
        
        # --- Update Bar Color based on score --- 
        palette = self.strength_bar.palette()
        if score == 0:
            color = QColor("darkred")
        elif score == 1:
            color = QColor("red")
        elif score == 2:
            color = QColor("orange")
        elif score == 3:
            color = QColor("yellowgreen")
        else: # score == 4
            color = QColor("green")
        palette.setColor(QPalette.ColorRole.Highlight, color)
        self.strength_bar.setPalette(palette)
        
        # --- Enable/Disable Submit Button --- 
        # Require at least score 2 (Okay) to enable vault creation
        self.submit_button.setEnabled(score >= 2)
        
    def create_vault(self):
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        # Basic checks (redundant due to button state, but good practice)
        if not password or not confirm:
            QMessageBox.warning(self, "Input Error", "Password fields cannot be empty.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            return
            
        # Check strength score again before saving (minimum score 2)
        results = zxcvbn(password)
        if results['score'] < 2:
             QMessageBox.warning(self, "Security Warning", "Password is too weak. Please choose a stronger one.")
             return

        try:
            # Create initial empty vault
            data_manager.save_data([], password) 
            QMessageBox.information(self, "Success", f"Vault created successfully at\n{data_manager.DEFAULT_VAULT_PATH}")
            self.setup_complete.emit(password) # Emit signal with the new password
            self.close() # Close setup window
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create vault: {e}")


class LoginWindow(QWidget):
    """Window for logging in with the master password."""
    # Signal indicating successful login, passing loaded data and master password
    login_successful = pyqtSignal(list, str)
    # Signal to indicate user wants to go to setup
    show_setup = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LCG Password Manager - Login")
        self.setGeometry(200, 200, 350, 180) # Increased height for additional button

        layout = QVBoxLayout()

        self.info_label = QLabel("Enter your master password to unlock the vault.")
        layout.addWidget(self.info_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Master Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.attempt_login) 
        layout.addWidget(self.password_input)

        self.login_button = QPushButton("Unlock")
        self.login_button.clicked.connect(self.attempt_login)
        layout.addWidget(self.login_button)
        
        # Add a link/button for first-time users
        self.setup_button = QPushButton("First time? Create a new vault")
        self.setup_button.setStyleSheet("color: blue; background-color: transparent; border: none;")
        self.setup_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setup_button.clicked.connect(self.go_to_setup)
        layout.addWidget(self.setup_button)
        
        self.status_label = QLabel("") # For showing lockout status
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.check_lockout_status() # Check if currently locked out on init
        
    def go_to_setup(self):
        """Emit signal to go to setup window and close this window."""
        self.show_setup.emit()
        self.close()

    def check_lockout_status(self):
        """Checks if the lockout duration is active and updates UI."""
        global FAILED_ATTEMPTS
        current_time = time.time()
        if FAILED_ATTEMPTS["count"] >= MAX_LOGIN_ATTEMPTS:
            time_since_last = current_time - FAILED_ATTEMPTS["last_attempt_time"]
            if time_since_last < LOCKOUT_DURATION_SECONDS:
                remaining_lockout = int(LOCKOUT_DURATION_SECONDS - time_since_last)
                self.status_label.setText(f"Too many failed attempts. Try again in {remaining_lockout}s.")
                self.password_input.setEnabled(False)
                self.login_button.setEnabled(False)
                self.setup_button.setEnabled(False) # Also disable setup button during lockout
                # Reschedule check for when lockout should end
                QTimer.singleShot(remaining_lockout * 1000 + 100, self.reset_lockout) # Check slightly after lockout ends
                return True # Is locked out
            else:
                # Lockout expired, reset
                self.reset_lockout()
        return False # Not locked out

    def reset_lockout(self):
        """Resets the failed attempt counter and enables inputs."""
        global FAILED_ATTEMPTS
        print("Login lockout expired or reset.")
        FAILED_ATTEMPTS["count"] = 0
        FAILED_ATTEMPTS["last_attempt_time"] = 0
        self.status_label.setText("")
        self.password_input.setEnabled(True)
        self.login_button.setEnabled(True)
        self.setup_button.setEnabled(True) # Also re-enable setup button
        self.password_input.setFocus()
        
    def attempt_login(self):
        global FAILED_ATTEMPTS
        current_time = time.time()
        
        # Check if currently locked out
        if self.check_lockout_status():
            return

        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Input Error", "Please enter your master password.")
            return

        try:
            # Attempt to load data - this will fail if password is wrong
            loaded_data = data_manager.load_data(password)
            # Successful login - reset attempts and emit signal
            self.reset_lockout()
            self.login_successful.emit(loaded_data, password) 
            self.close() 
            
        except ValueError as e:
            # Incorrect password or corrupt vault
            error_msg = str(e)
            FAILED_ATTEMPTS["count"] += 1
            FAILED_ATTEMPTS["last_attempt_time"] = current_time
            print(f"Login failed. Attempt {FAILED_ATTEMPTS['count']} of {MAX_LOGIN_ATTEMPTS}.")
            
            # Check if this might be a first-time user who hasn't set up a master password yet
            if "Decryption failed" in error_msg and FAILED_ATTEMPTS["count"] == 1:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Question)
                msg.setWindowTitle("First-time User?")
                msg.setText("If this is your first time using the app, you need to set up a master password first.")
                msg.setInformativeText("Would you like to create a new vault?")
                msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                response = msg.exec()
                
                if response == QMessageBox.StandardButton.Yes:
                    # Go to setup window
                    self.go_to_setup()
                    return
            
            # Check if lockout should start
            if FAILED_ATTEMPTS["count"] >= MAX_LOGIN_ATTEMPTS:
                QMessageBox.critical(self, "Login Failed", f"Incorrect password. Too many failed attempts. Please wait {LOCKOUT_DURATION_SECONDS} seconds.")
                self.password_input.clear()
                self.check_lockout_status() # Update UI to show lockout
            else:
                 remaining_attempts = MAX_LOGIN_ATTEMPTS - FAILED_ATTEMPTS["count"]
                 QMessageBox.critical(self, "Login Failed", f"Incorrect master password or vault file corrupted.\n{remaining_attempts} attempts remaining.")
                 self.password_input.clear() # Clear the password field
                 
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

# --- Main Application Window ---
class MainWindow(QWidget):
    LOCK_TIMEOUT_MS = 15 * 60 * 1000 # 15 minutes

    def __init__(self, vault_data: list, master_password: str):
        super().__init__()
        self.vault_data = vault_data # List of dicts [{'service': '...', 'username': '...', 'password': '...'}]
        self.master_password = master_password # Needed to save changes
        self._is_locked = False
        
        self.setWindowTitle("LCG Password Manager")
        self.setGeometry(150, 150, 600, 400) 
        
        # --- Main Stacked Widget for Lock Screen --- 
        self.main_stack = QStackedWidget()
        self.setLayout(QVBoxLayout()) # Main window needs a layout
        self.layout().addWidget(self.main_stack)
        self.layout().setContentsMargins(0,0,0,0) # Use full window space
        
        # --- Vault View Widget --- 
        self.vault_widget = QWidget()
        main_layout = QHBoxLayout(self.vault_widget) # Apply main layout here
        
        # Left side: List of entries and search bar
        list_layout = QVBoxLayout()
        list_layout.addWidget(QLabel("Search Entries:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by service or username...")
        self.search_input.textChanged.connect(self.filter_entries)
        list_layout.addWidget(self.search_input)
        
        self.entry_list_widget = QListWidget()
        self.entry_list_widget.itemSelectionChanged.connect(self.display_entry_details) 
        list_layout.addWidget(QLabel("Entries:")) 
        list_layout.addWidget(self.entry_list_widget)
        main_layout.addLayout(list_layout, 1)

        # Right side: Details and Buttons
        details_layout = QVBoxLayout()
        self.service_label = QLabel("Service: ")
        self.username_label = QLabel("Username: ")
        password_details_layout = QHBoxLayout()
        self.password_label = QLabel("Password: [Hidden]") 
        self.password_label.setWordWrap(True) 
        password_details_layout.addWidget(self.password_label, 1) 
        self.show_hide_button = QPushButton("Show")
        self.show_hide_button.setCheckable(True)
        self.show_hide_button.setToolTip("Show/Hide the password for the selected entry")
        self.show_hide_button.toggled.connect(self.toggle_password_details_visibility)
        password_details_layout.addWidget(self.show_hide_button)
        details_layout.addWidget(self.service_label)
        details_layout.addWidget(self.username_label)
        details_layout.addLayout(password_details_layout) 
        details_layout.addStretch() 
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10) 
        self.add_button = QPushButton("Add Entry")
        self.add_button.setToolTip("Add a new password entry")
        self.add_button.clicked.connect(self.add_entry) 
        self.delete_button = QPushButton("Delete Entry")
        self.delete_button.setToolTip("Delete the selected password entry")
        self.delete_button.clicked.connect(self.delete_entry) 
        self.copy_user_button = QPushButton("Copy Username")
        self.copy_user_button.setToolTip("Copy the username of the selected entry to the clipboard")
        self.copy_user_button.clicked.connect(self.copy_username) 
        self.copy_pass_button = QPushButton("Copy Password")
        self.copy_pass_button.setToolTip("Copy the password of the selected entry to the clipboard")
        self.copy_pass_button.clicked.connect(self.copy_password) 
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.copy_user_button)
        button_layout.addWidget(self.copy_pass_button)
        details_layout.addLayout(button_layout)
        main_layout.addLayout(details_layout, 2) 
        # self.setLayout(main_layout) # Layout set on vault_widget now
        self.main_stack.addWidget(self.vault_widget) # Add vault view to stack

        # --- Lock Screen Widget --- 
        self.lock_widget = QWidget()
        lock_layout = QVBoxLayout(self.lock_widget)
        lock_layout.addStretch()
        lock_layout.addWidget(QLabel("Vault Locked"))
        self.lock_password_input = QLineEdit()
        self.lock_password_input.setPlaceholderText("Enter Master Password to Unlock")
        self.lock_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.lock_password_input.returnPressed.connect(self.attempt_unlock)
        lock_layout.addWidget(self.lock_password_input)
        unlock_button = QPushButton("Unlock")
        unlock_button.clicked.connect(self.attempt_unlock)
        lock_layout.addWidget(unlock_button)
        lock_layout.addStretch()
        self.main_stack.addWidget(self.lock_widget) # Add lock screen to stack

        # --- Auto Lock Timer --- 
        self.lock_timer = QTimer(self)
        self.lock_timer.setInterval(self.LOCK_TIMEOUT_MS)
        self.lock_timer.timeout.connect(self.lock_vault)
        self.lock_timer.start() # Start the timer
        
        # Install event filter to reset timer on user activity
        self.installEventFilter(self)

        # Initial state
        self.load_entries_into_list()
        self.update_button_states()
        self.main_stack.setCurrentWidget(self.vault_widget) # Start unlocked

    # --- Event Filter for Activity Detection --- 
    def eventFilter(self, obj, event) -> bool:
        # Reset timer on key press or mouse button press/move within the window
        # Check if vault is already locked to avoid resetting timer unnecessarily
        if not self._is_locked and event.type() in [
            event.Type.KeyPress, 
            event.Type.MouseButtonPress, 
            event.Type.MouseMove]:
            # print("Activity detected, resetting lock timer") # Debug print
            self.lock_timer.start() # Reset timer to full interval
        
        # Pass event processing down the chain
        return super().eventFilter(obj, event)

    # --- Lock/Unlock Logic --- 
    def lock_vault(self):
        """Switches to the lock screen view."""
        if not self._is_locked:
            print("Locking vault due to inactivity.")
            self._is_locked = True
            self.main_stack.setCurrentWidget(self.lock_widget)
            self.lock_password_input.clear()
            self.lock_password_input.setFocus() # Set focus to password field
            self.lock_timer.stop() # Stop timer while locked
            # Optional: Clear sensitive details from memory if possible (complex)

    def attempt_unlock(self):
        """Checks the entered password against the stored master password."""
        entered_password = self.lock_password_input.text()
        if entered_password == self.master_password:
            print("Vault unlocked.")
            self._is_locked = False
            self.lock_password_input.clear() # Clear password field
            self.main_stack.setCurrentWidget(self.vault_widget) # Switch back to vault
            self.lock_timer.start() # Restart inactivity timer
        else:
            QMessageBox.warning(self, "Unlock Failed", "Incorrect master password.")
            self.lock_password_input.clear()

    def load_entries_into_list(self):
        """Populates the QListWidget with service names from vault_data."""
        current_selection_index = -1
        selected_items = self.entry_list_widget.selectedItems()
        if selected_items:
             # Try to preserve selection if possible (by original index)
             current_selection_index = selected_items[0].data(Qt.ItemDataRole.UserRole)
             
        self.entry_list_widget.clear()
        # Store the full entry data within the list item itself
        new_selection_row = -1
        for index, entry in enumerate(self.vault_data):
            list_item = QListWidgetItem(entry.get('service', 'No Service Name'))
            list_item.setData(Qt.ItemDataRole.UserRole, index) # Store the original index
            self.entry_list_widget.addItem(list_item)
            if index == current_selection_index:
                new_selection_row = self.entry_list_widget.count() - 1

        # Clear search bar and apply filter (which will show all items)
        self.search_input.clear() # Clear search text
        # self.filter_entries("") # Filter will be implicitly applied by textChanged signal if search was cleared
        
        # Try to restore selection
        if new_selection_row != -1:
            self.entry_list_widget.setCurrentRow(new_selection_row)
        else: 
            # Clear details pane if list is empty or no selection is restored/possible
            if not self.vault_data or self.entry_list_widget.currentRow() < 0:
                self.clear_details()
            # Update buttons regardless, as selection might have changed implicitly
            self.update_button_states()

    def filter_entries(self):
        """Filters the list widget items based on the search input text."""
        search_text = self.search_input.text().lower().strip()
        
        for i in range(self.entry_list_widget.count()):
            item = self.entry_list_widget.item(i)
            entry_index = item.data(Qt.ItemDataRole.UserRole)
            
            if 0 <= entry_index < len(self.vault_data):
                entry = self.vault_data[entry_index]
                service = entry.get('service', '').lower()
                username = entry.get('username', '').lower()
                
                # Check if search text is in service or username
                if search_text in service or search_text in username:
                    item.setHidden(False) # Show item
                else:
                    item.setHidden(True) # Hide item
            else:
                # Should not happen, but hide item if data is out of sync
                item.setHidden(True)
                
        # If the current selection gets hidden, clear the details pane
        selected_items = self.entry_list_widget.selectedItems()
        if selected_items and selected_items[0].isHidden():
            self.entry_list_widget.clearSelection() # Deselect the hidden item
            self.clear_details()
        # Update button state based on current visible selection state
        self.update_button_states()

    def display_entry_details(self):
        """Updates the detail labels when an item is selected."""
        selected_items = self.entry_list_widget.selectedItems()
        if not selected_items:
            self.clear_details()
            # update_button_states called by clear_details
            return
            
        selected_item = selected_items[0]
        entry_index = selected_item.data(Qt.ItemDataRole.UserRole)
        
        entry = self._get_selected_entry_data() # Use helper
        if entry:
            self.service_label.setText(f"Service: {entry.get('service', 'N/A')}")
            self.username_label.setText(f"Username: {entry.get('username', 'N/A')}")
            # Reset password view state
            self.show_hide_button.setChecked(False) # Ensure button is in "Show" state
            self.password_label.setText("Password: [Hidden]") 
        else:
            # Handle potential index out of bounds or error from helper
            self.clear_details()
            
        self.update_button_states()

    def clear_details(self):
        """Clears the details labels."""
        self.service_label.setText("Service: ")
        self.username_label.setText("Username: ")
        self.password_label.setText("Password: ")
        self.show_hide_button.setChecked(False) # Reset button state
        # Visibility toggled by update_button_states
        self.update_button_states()
        
    def update_button_states(self):
        """Enable/disable buttons based on whether an item is selected."""
        has_selection = len(self.entry_list_widget.selectedItems()) > 0
        self.delete_button.setEnabled(has_selection)
        self.copy_user_button.setEnabled(has_selection)
        self.copy_pass_button.setEnabled(has_selection)
        self.show_hide_button.setEnabled(has_selection) # Enable/disable show/hide button
        # Add button is always enabled
        self.add_button.setEnabled(True)
        
    def toggle_password_details_visibility(self, checked):
        """Toggles the visibility of the password in the details view."""
        entry = self._get_selected_entry_data()
        if not entry:
             # Should not happen if button is enabled only with selection, but check anyway
             self.password_label.setText("Password: ")
             self.show_hide_button.setText("Show")
             return
             
        if checked: # Button is checked -> Show password
            password = entry.get('password', '')
            self.password_label.setText(f"Password: {password}")
            self.show_hide_button.setText("Hide")
        else: # Button is unchecked -> Hide password
            self.password_label.setText("Password: [Hidden]")
            self.show_hide_button.setText("Show")
            
    # --- Button Action Methods --- 
    def add_entry(self):
        dialog = AddEditDialog(parent=self)
        # Execute the dialog modally
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_entry = dialog.get_data()
            if new_entry: # Ensure data was retrieved
                # Check for duplicates (optional, based on service name?)
                # service_exists = any(e.get('service', '').lower() == new_entry['service'].lower() for e in self.vault_data)
                # if service_exists:
                #     QMessageBox.warning(self, "Duplicate", f"An entry for '{new_entry['service']}' already exists.")
                #     return 
                    
                self.vault_data.append(new_entry)
                try:
                    # Save the updated data using the stored master password
                    data_manager.save_data(self.vault_data, self.master_password)
                    # Refresh the list widget
                    self.load_entries_into_list()
                    # Optionally select the newly added item
                    self.entry_list_widget.setCurrentRow(len(self.vault_data) - 1)
                    print("New entry added and saved.")
                except Exception as e:
                    QMessageBox.critical(self, "Save Error", f"Failed to save the new entry: {e}")
                    # Consider reverting the change to self.vault_data if save fails
                    self.vault_data.pop()
        else:
            print("Add entry cancelled.")

    def delete_entry(self):
        selected_items = self.entry_list_widget.selectedItems()
        if not selected_items:
            # Should not happen if button state is managed correctly, but good practice
            QMessageBox.warning(self, "Selection Error", "Please select an entry to delete.")
            return

        selected_item = selected_items[0]
        entry_index = selected_item.data(Qt.ItemDataRole.UserRole)
        
        # Double check index validity before proceeding
        if not (0 <= entry_index < len(self.vault_data)):
             QMessageBox.critical(self, "Error", "Data sync error. Cannot delete item.")
             return
             
        entry_service = self.vault_data[entry_index].get('service', 'this entry')

        # Confirmation dialog
        reply = QMessageBox.question(self, 
                                     "Confirm Delete", 
                                     f"Are you sure you want to delete the entry for '{entry_service}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No) # Default button is No

        if reply == QMessageBox.StandardButton.Yes:
            # Store the item to potentially re-insert if save fails
            item_to_restore = None
            try:
                item_to_restore = self.vault_data[entry_index]
                # Remove the entry from the list
                del self.vault_data[entry_index]
                
                # Save the updated data
                data_manager.save_data(self.vault_data, self.master_password)
                
                # Refresh the UI list only AFTER successful save
                self.load_entries_into_list()
                
                print(f"Entry '{entry_service}' deleted and vault saved.")
                
            except IndexError:
                 # This might happen if index was somehow wrong despite initial check
                 QMessageBox.critical(self, "Error", "Failed to delete entry: Index out of bounds during operation.")
                 # If item was fetched but deletion failed index-wise, try to ensure consistency (though less likely)
                 if item_to_restore is not None and item_to_restore not in self.vault_data:
                      # Potentially reload or force consistency check
                      print("Warning: Potential data inconsistency after failed delete indexing.") 
            except Exception as e:
                 QMessageBox.critical(self, "Save Error", f"Failed to save vault after deletion: {e}")
                 # *** Revert in-memory change if save failed ***
                 if item_to_restore is not None:
                     try:
                         self.vault_data.insert(entry_index, item_to_restore)
                         print("In-memory deletion reverted due to save failure.")
                     except Exception as insert_e:
                          print(f"Critical: Failed to revert in-memory deletion: {insert_e}")
                          QMessageBox.critical(self, "Consistency Error", 
                                               "Failed to save deletion AND failed to revert in-memory change. "
                                               "Restarting the application is recommended.")
                 # Do NOT refresh the list if save failed
        else:
            print("Deletion cancelled.")

    def _get_selected_entry_data(self):
        """Helper method to get the data dictionary of the selected entry."""
        selected_items = self.entry_list_widget.selectedItems()
        if not selected_items:
            return None
            
        selected_item = selected_items[0]
        entry_index = selected_item.data(Qt.ItemDataRole.UserRole)
        
        if 0 <= entry_index < len(self.vault_data):
            return self.vault_data[entry_index]
        else:
            QMessageBox.warning(self, "Error", "Selected item index out of sync with data. Please refresh.")
            return None

    def copy_username(self):
        entry = self._get_selected_entry_data()
        if entry:
            username = entry.get('username', '')
            if username:
                clipboard = QApplication.clipboard()
                clipboard.setText(username)
                print(f"Copied username for {entry.get('service', 'N/A')}")
                # Optional: Add visual feedback (e.g., status bar message)
            else:
                print("No username to copy for this entry.")

    def copy_password(self):
        entry = self._get_selected_entry_data()
        if entry:
            password = entry.get('password', '')
            if password:
                clipboard = QApplication.clipboard()
                # Use ClipboardMode.Clipboard for standard copy,
                # Use ClipboardMode.Selection for X11 primary selection (less common for passwords)
                clipboard.setText(password, mode=QClipboard.Mode.Clipboard)
                print(f"Copied password for {entry.get('service', 'N/A')} (Clipboard will be cleared shortly)")
                
                # Optional: Add visual feedback (e.g., status bar)
                # Security Enhancement: Clear clipboard after a delay
                # Use 15000 milliseconds (15 seconds)
                QTimer.singleShot(15000, lambda: self.clear_clipboard_if_matches(password))
            else:
                print("No password to copy for this entry.")
                
    def clear_clipboard_if_matches(self, expected_text):
        """Clears the clipboard only if it still contains the copied password."""
        clipboard = QApplication.clipboard()
        try:
            # Important: Accessing clipboard can sometimes fail (e.g., on VM disconnects)
            current_text = clipboard.text(mode=QClipboard.Mode.Clipboard)
            if current_text == expected_text:
                clipboard.clear(mode=QClipboard.Mode.Clipboard)
                print("Clipboard cleared automatically.")
            else:
                print("Clipboard content changed before auto-clear timer expired.")
        except Exception as e:
            # Log or print error if clearing fails for some reason
            print(f"Could not verify or clear clipboard: {e}")
            
    # Override closeEvent to handle locking state if needed, then quit
    def closeEvent(self, event):
        # Maybe add a confirmation if locked? For now, just quit.
        QApplication.quit()


# --- Add/Edit Entry Dialog ---
class AddEditDialog(QDialog):
    """Dialog for adding or editing a password entry."""
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.entry = entry # Store entry data if we are editing

        self.setWindowTitle("Add New Entry" if entry is None else "Edit Entry")
        self.setMinimumWidth(450) # Increased width slightly

        layout = QVBoxLayout(self)

        # Form Layout for labels and fields
        form_layout = QVBoxLayout()
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("e.g., Google, Company VPN, Database Server")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Your username or email")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter or generate password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password) # Hide password by default

        form_layout.addWidget(QLabel("Service/Website:"))
        form_layout.addWidget(self.service_input)
        form_layout.addWidget(QLabel("Username:"))
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(QLabel("Password:"))
        
        # Password row with Show/Hide toggle
        password_row_layout = QHBoxLayout()
        password_row_layout.addWidget(self.password_input)
        self.show_pass_button = QPushButton("Show") # Renamed variable
        self.show_pass_button.setCheckable(True)
        self.show_pass_button.toggled.connect(self.toggle_password_visibility)
        password_row_layout.addWidget(self.show_pass_button) # Use renamed variable
        form_layout.addLayout(password_row_layout)

        # Password Generation Section
        gen_group_layout = QHBoxLayout()
        gen_options_layout = QVBoxLayout() 
        
        # Length SpinBox
        len_layout = QHBoxLayout()
        len_layout.addWidget(QLabel("Length:"))
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(8, 128) # Sensible range
        self.length_spinbox.setValue(16) # Default length
        len_layout.addWidget(self.length_spinbox)
        len_layout.addStretch()
        gen_options_layout.addLayout(len_layout)

        # Character Type Checkboxes
        self.lower_check = QCheckBox("Lowercase (abc)")
        self.lower_check.setChecked(True)
        self.upper_check = QCheckBox("Uppercase (ABC)")
        self.upper_check.setChecked(True)
        self.digit_check = QCheckBox("Digits (123)")
        self.digit_check.setChecked(True)
        self.symbol_check = QCheckBox("Symbols (!@#)")
        self.symbol_check.setChecked(True)
        gen_options_layout.addWidget(self.lower_check)
        gen_options_layout.addWidget(self.upper_check)
        gen_options_layout.addWidget(self.digit_check)
        gen_options_layout.addWidget(self.symbol_check)
        
        gen_group_layout.addLayout(gen_options_layout)
        
        # Generate Button (aligned vertically)
        gen_button_layout = QVBoxLayout()
        gen_button_layout.addStretch() # Push button down
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_password)
        gen_button_layout.addWidget(self.generate_button)
        gen_button_layout.addStretch() # Center vertically
        gen_group_layout.addLayout(gen_button_layout)
        
        form_layout.addLayout(gen_group_layout)
        
        layout.addLayout(form_layout)

        # Standard OK/Cancel buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        # Pre-fill fields if editing an existing entry
        if self.entry:
            self.service_input.setText(self.entry.get('service', ''))
            self.username_input.setText(self.entry.get('username', ''))
            self.password_input.setText(self.entry.get('password', ''))
            
    def toggle_password_visibility(self, checked):
        """Toggle the password field echo mode."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_pass_button.setText("Hide") # Use renamed variable
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_pass_button.setText("Show") # Use renamed variable
            
    def generate_password(self):
        """Generates a password based on selected criteria and length."""
        char_pool = ""
        if self.lower_check.isChecked():
            char_pool += string.ascii_lowercase
        if self.upper_check.isChecked():
            char_pool += string.ascii_uppercase
        if self.digit_check.isChecked():
            char_pool += string.digits
        if self.symbol_check.isChecked():
            # Define symbols - avoid ambiguous chars like O, 0, l, 1 if desired
            char_pool += string.punctuation 
            
        if not char_pool:
            QMessageBox.warning(self, "Input Error", "Please select at least one character type.")
            return
            
        length = self.length_spinbox.value()
        
        # Use secrets.choice for cryptographically secure random selection
        generated_password = ''.join(secrets.choice(char_pool) for _ in range(length))
        
        self.password_input.setText(generated_password)
        # Ensure password visibility is reset if it was shown
        self.show_pass_button.setChecked(False) # Use renamed variable
        # self.toggle_password_visibility(False) # Called implicitly by setChecked(False) signal
            
    def get_data(self) -> dict | None:
        """Returns the entered data as a dictionary, performs basic validation."""
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text() # Don't strip password

        if not service:
            QMessageBox.warning(self, "Input Error", "Service name cannot be empty.")
            return None
        # Allow empty username/password, but service is mandatory
            
        return {
            "service": service,
            "username": username,
            "password": password
        }

    # Override accept to perform validation before closing
    def accept(self):
        if self.get_data() is not None: # Validation happens in get_data
            super().accept()
        # Else: stay open because get_data showed a warning


# Remove the initial placeholder print if it exists
# print("Password Manager Initial Setup - GUI Module") 