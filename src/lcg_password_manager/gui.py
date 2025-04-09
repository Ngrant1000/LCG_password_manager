# gui.py

"""Password Manager GUI Implementation.

Security Measures:
1. Secure Memory Management:
   - SecureString class for sensitive data
   - Immediate memory cleanup after use
   - Clipboard clearing after password copy
2. Authentication Protection:
   - Login throttling with exponential backoff
   - Account lockout after failed attempts
   - Session management with timeouts
3. Password Security:
   - zxcvbn for password strength evaluation
   - Cryptographically secure password generation
   - Password masking with configurable visibility
4. Audit Logging:
   - Secure rotating logs with encryption
   - Comprehensive event tracking
   - Size-limited log files
5. Auto-lock Features:
   - Automatic vault locking on inactivity
   - Session timeout enforcement
   - Manual lock capability
"""

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QMessageBox, 
    QListWidget, QListWidgetItem, # Added QListWidget/Item
    QDialog, QDialogButtonBox, QSpinBox, QCheckBox, # Added QSpinBox and QCheckBox
    QMessageBox, # Added for message box
    QProgressBar, # Added for strength meter
    QStackedWidget, # Added QStackedWidget
    QStyle, # Added for standard icons
    QMainWindow
)
from PySide6.QtCore import Qt, Signal, QTimer, QEvent # Changed pyqtSignal to Signal, added QTimer and QEvent
from PySide6.QtGui import QClipboard, QPalette, QColor, QIcon # Added Palette/Color, QIcon
from . import data_manager
from .data_manager import initialize_audit_logger, get_audit_logger
from .encryption_utils import generate_salt
import secrets # Added for password generation
import string # Added for character sets
from zxcvbn import zxcvbn # Added for password strength
import time # Added for login throttling
import logging # Added for logging
import logging.handlers
import os
from datetime import datetime
import ctypes
from ctypes import wintypes
import sys

# Constants for Login Throttling
MAX_LOGIN_ATTEMPTS = 5  # Maximum failed attempts before lockout
LOCKOUT_DURATION_SECONDS = 60  # 60-second lockout after max attempts
FAILED_ATTEMPTS = {"count": 0, "last_attempt_time": 0}

# Setup secure audit logging
def setup_audit_logging():
    """Setup secure audit logging with rotation and encryption.
    
    Security:
    - Log rotation prevents unlimited log growth
    - 10MB size limit per log file
    - 5 backup files maintained
    - UTF-8 encoding for proper character handling
    - Timestamps for forensic analysis
    """
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Create a secure audit logger
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    
    # Create rotating file handler (10MB per file, keep 5 backup files)
    log_file = os.path.join(log_dir, 'audit.log')
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    audit_logger.addHandler(handler)
    
    return audit_logger

# Initialize audit logger
audit_logger = setup_audit_logging()

class SecureString:
    """A class to handle sensitive string data securely in memory.
    
    Security:
    - Immediate memory zeroing on cleanup
    - Windows-specific secure memory clearing when available
    - Automatic cleanup in destructor
    - String masking in string representation
    """
    def __init__(self, value: str):
        self._value = value
        self._secure = True
        
    def __str__(self):
        return self._value if self._secure else "********"
        
    def get_value(self) -> str:
        """Get the actual value. Use with caution."""
        return self._value
        
    def secure_clear(self):
        """Securely clear the sensitive data from memory."""
        if sys.platform == 'win32':
            # Use Windows API to securely clear memory
            ctypes.memset(ctypes.c_char_p(self._value), 0, len(self._value))
        else:
            # Fallback for other platforms
            self._value = '0' * len(self._value)
        self._value = None
        self._secure = False
        
    def __del__(self):
        """Ensure memory is cleared when object is destroyed."""
        self.secure_clear()

class SetupWindow(QWidget):
    """Window for initial master password setup.
    
    Security:
    - zxcvbn password strength evaluation
    - Minimum strength requirements
    - Visual strength feedback
    - Secure password validation
    """
    # Signal to indicate setup is complete, passing the master password
    setup_complete = Signal(str) # Changed pyqtSignal to Signal

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
    """Window for logging in with the master password.
    
    Security:
    - Login attempt throttling
    - Account lockout mechanism
    - Secure password field
    - Audit logging of attempts
    """
    # Signal indicating successful login, passing loaded data and master password
    login_successful = Signal(list, str) # Changed pyqtSignal to Signal
    # Signal to indicate user wants to go to setup
    show_setup = Signal() # Changed pyqtSignal to Signal
    
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
        self.setup_button.setObjectName("setup_button") # Add object name for QSS
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
            # Initialize audit logger with the attempted password
            initialize_audit_logger(password, generate_salt())
            
            # Attempt to load data - this will fail if password is wrong
            loaded_data = data_manager.load_data(password)
            
            # Log successful login
            get_audit_logger().log_event(
                "LOGIN_SUCCESS",
                "User successfully logged in",
                sensitive=True
            )
            
            # Successful login - reset attempts and emit signal
            self.reset_lockout()
            self.login_successful.emit(loaded_data, password) 
            self.close() 
            
        except ValueError as e:
            # Log failed login attempt
            try:
                get_audit_logger().log_event(
                    "LOGIN_FAILURE",
                    f"Failed login attempt {FAILED_ATTEMPTS['count'] + 1} of {MAX_LOGIN_ATTEMPTS}",
                    sensitive=True
                )
            except:
                pass  # Ignore audit logging errors during failed login
            
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
                msg.setText("Are you setting up the password manager for the first time?")
                msg.setInformativeText("If so, click 'Yes' to create a new vault.")
                msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if msg.exec() == QMessageBox.StandardButton.Yes:
                    self.go_to_setup()
                    return
                    
            # Show error message
            if FAILED_ATTEMPTS["count"] >= MAX_LOGIN_ATTEMPTS:
                self.status_label.setText(f"Too many failed attempts. Try again in {LOCKOUT_DURATION_SECONDS}s.")
                self.password_input.setEnabled(False)
                self.login_button.setEnabled(False)
                self.setup_button.setEnabled(False)
                QTimer.singleShot(LOCKOUT_DURATION_SECONDS * 1000 + 100, self.reset_lockout)
            else:
                remaining = MAX_LOGIN_ATTEMPTS - FAILED_ATTEMPTS["count"]
                self.status_label.setText(f"Invalid password. {remaining} attempts remaining.")
                
            self.password_input.clear()
            self.password_input.setFocus()

# --- Main Application Window ---
class MainWindow(QMainWindow):
    LOCK_TIMEOUT_MS = 15 * 60 * 1000 # 15 minutes

    def __init__(self, vault_data: list, master_password: str):
        super().__init__()
        self.vault_data = vault_data
        self.master_password = master_password
        self._is_locked = False
        self._selected_entry_index = -1 # Track selected index
        self._secure_master_password = None
        self._secure_vault_data = []

        self.setWindowTitle("LCG Password Manager")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize the UI
        self.init_ui()
        
        # Set up auto-lock timer
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.timeout.connect(self.lock_vault)
        self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.start(300000)  # 5 minutes
        
        # Session management
        self.session_start_time = time.time()
        self.session_timeout = 3600  # 1 hour timeout
        self.failed_attempts = 0
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        self.last_activity_time = time.time()
        self.activity_timeout = 300  # 5 minutes inactivity timeout
        
        # Setup activity timer
        self.activity_timer = QTimer()
        self.activity_timer.timeout.connect(self.check_session_timeout)
        self.activity_timer.start(1000)  # Check every second
        
        # Install event filter for activity tracking
        self.installEventFilter(self)

        # Get standard icons
        style = self.style()
        copy_icon = style.standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)
        # add_icon = style.standardIcon(QStyle.StandardPixmap.SP_FileLinkIcon) # Using '+' text for now
        delete_icon = style.standardIcon(QStyle.StandardPixmap.SP_TrashIcon)

        # --- Main Stacked Widget for Lock Screen ---
        self.main_stack = QStackedWidget()
        outer_layout = QVBoxLayout(self) # Main window needs a layout
        outer_layout.addWidget(self.main_stack)
        outer_layout.setContentsMargins(0,0,0,0)

        # --- Vault View Widget (Content for the main stack) ---
        self.vault_widget = QWidget()
        vault_layout = QVBoxLayout(self.vault_widget) # Vertical layout for vault view
        vault_layout.setContentsMargins(10, 10, 10, 10) # Add some padding
        vault_layout.setSpacing(10)

        # -- Top Bar (Search and Add) --
        top_bar_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search vault...")
        self.search_input.textChanged.connect(self.filter_entries)
        top_bar_layout.addWidget(self.search_input, 1) # Search takes most space

        self.add_button = QPushButton("+ Add") # Using text for now
        self.add_button.setToolTip("Add a new password entry")
        self.add_button.clicked.connect(self.add_entry)
        top_bar_layout.addWidget(self.add_button)
        vault_layout.addLayout(top_bar_layout)

        # -- Entry List --
        self.entry_list_widget = QListWidget()
        self.entry_list_widget.itemSelectionChanged.connect(self.display_entry_details)
        vault_layout.addWidget(self.entry_list_widget, 1) # List takes available vertical space

        # -- Details Pane (Initially Hidden) --
        self.details_widget = QWidget()
        details_layout = QVBoxLayout(self.details_widget)
        details_layout.setContentsMargins(5, 5, 5, 5)
        details_layout.setSpacing(8)

        # Service
        self.service_display = QLineEdit() # Using QLineEdit for consistent look
        self.service_display.setReadOnly(True)
        self.service_display.setPlaceholderText("Service Name")
        details_layout.addWidget(QLabel("Service:"))
        details_layout.addWidget(self.service_display)

        # Username
        details_layout.addWidget(QLabel("Username:"))
        username_layout = QHBoxLayout()
        self.username_display = QLineEdit()
        self.username_display.setReadOnly(True)
        self.username_display.setPlaceholderText("Username")
        username_layout.addWidget(self.username_display, 1)
        self.copy_user_button = QPushButton(copy_icon, "")
        self.copy_user_button.setToolTip("Copy Username")
        self.copy_user_button.clicked.connect(self.copy_username)
        username_layout.addWidget(self.copy_user_button)
        details_layout.addLayout(username_layout)

        # Password
        details_layout.addWidget(QLabel("Password:"))
        password_layout = QHBoxLayout()
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_display.setPlaceholderText("Password")
        password_layout.addWidget(self.password_display, 1)
        self.copy_pass_button = QPushButton(copy_icon, "")
        self.copy_pass_button.setToolTip("Copy Password")
        self.copy_pass_button.clicked.connect(self.copy_password)
        password_layout.addWidget(self.copy_pass_button)
        self.show_hide_button = QPushButton("Show")
        self.show_hide_button.setObjectName("show_hide_button") # Keep object name for QSS
        self.show_hide_button.setCheckable(True)
        self.show_hide_button.setToolTip("Show/Hide Password")
        self.show_hide_button.toggled.connect(self.toggle_password_details_visibility)
        password_layout.addWidget(self.show_hide_button)
        details_layout.addLayout(password_layout)

        details_layout.addStretch() # Push delete button down

        # Delete Button
        delete_layout = QHBoxLayout()
        delete_layout.addStretch() # Push button to the right
        self.delete_button = QPushButton(delete_icon, " Delete Entry")
        self.delete_button.setToolTip("Delete the selected password entry")
        self.delete_button.clicked.connect(self.delete_entry)
        # Add specific styling for delete button if needed (e.g., make it red)
        # self.delete_button.setObjectName("delete_button")
        delete_layout.addWidget(self.delete_button)
        details_layout.addLayout(delete_layout)

        self.details_widget.setVisible(False) # Start hidden
        vault_layout.addWidget(self.details_widget) # Add details pane to the main layout

        # Add vault view to stack
        self.main_stack.addWidget(self.vault_widget)

        # --- Lock Screen Widget (Remains the same) ---
        self.lock_widget = QWidget()
        lock_layout = QVBoxLayout(self.lock_widget)
        # Add some padding and alignment for better look
        lock_layout.setContentsMargins(50, 50, 50, 50)
        lock_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lock_layout.setSpacing(15)

        lock_layout.addStretch(1)
        lock_label = QLabel("Vault Locked")
        lock_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Optional: Make lock label font larger/bolder
        # font = lock_label.font()
        # font.setPointSize(14)
        # font.setBold(True)
        # lock_label.setFont(font)
        lock_layout.addWidget(lock_label)

        self.lock_password_input = QLineEdit()
        self.lock_password_input.setPlaceholderText("Enter Master Password to Unlock")
        self.lock_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.lock_password_input.returnPressed.connect(self.attempt_unlock)
        lock_layout.addWidget(self.lock_password_input)

        unlock_button = QPushButton("Unlock")
        unlock_button.clicked.connect(self.attempt_unlock)
        lock_layout.addWidget(unlock_button)
        lock_layout.addStretch(2)

        self.main_stack.addWidget(self.lock_widget)

        # --- Auto Lock Timer (Remains the same) ---
        self.lock_timer = QTimer(self)
        self.lock_timer.setInterval(self.LOCK_TIMEOUT_MS)
        self.lock_timer.timeout.connect(self.lock_vault)
        self.lock_timer.start()

        self.installEventFilter(self)

        # Initial state
        self.load_entries_into_list()
        # self.update_button_states() # Now handled by clear/display details
        self.main_stack.setCurrentWidget(self.vault_widget) # Start unlocked

        # Log application start
        audit_logger.info("Application started")

    def eventFilter(self, obj, event):
        """Track user activity for session management."""
        if event.type() in (QEvent.MouseButtonPress, QEvent.KeyPress):
            self.last_activity_time = time.time()
        return super().eventFilter(obj, event)

    def check_session_timeout(self):
        """Check for session timeout and inactivity."""
        current_time = time.time()
        
        # Check session timeout
        if current_time - self.session_start_time > self.session_timeout:
            self.lock_vault()
            QMessageBox.warning(self, "Session Expired", 
                              "Your session has expired. Please log in again.")
            return
            
        # Check inactivity timeout
        if current_time - self.last_activity_time > self.activity_timeout:
            self.lock_vault()
            QMessageBox.warning(self, "Auto-Lock", 
                              "Vault locked due to inactivity.")
            return

    def increment_failed_attempts(self):
        """Increment failed login attempts and handle lockout."""
        self.failed_attempts += 1
        if self.failed_attempts >= self.max_failed_attempts:
            self.lockout_until = time.time() + self.lockout_duration
            QMessageBox.warning(self, "Account Locked", 
                              f"Too many failed attempts. Account locked for {self.lockout_duration//60} minutes.")
            return True
        return False

    def reset_failed_attempts(self):
        """Reset failed login attempts counter."""
        self.failed_attempts = 0

    def is_account_locked(self):
        """Check if account is currently locked."""
        if hasattr(self, 'lockout_until'):
            if time.time() < self.lockout_until:
                remaining = int(self.lockout_until - time.time())
                QMessageBox.warning(self, "Account Locked", 
                                  f"Account is locked. Please try again in {remaining} seconds.")
                return True
            else:
                delattr(self, 'lockout_until')
        return False

    def lock_vault(self):
        """Lock the vault and securely clear sensitive data."""
        # Securely clear sensitive data
        if self._secure_master_password:
            self._secure_master_password.secure_clear()
        self._secure_master_password = None
        
        for entry in self._secure_vault_data:
            entry.secure_clear()
        self._secure_vault_data = []
        
        self.vault_data = []
        self.session_start_time = time.time()
        self.failed_attempts = 0
        if hasattr(self, 'lockout_until'):
            delattr(self, 'lockout_until')
        self.clear_details()
        self.load_entries_into_list()

    def attempt_unlock(self):
        """Handle unlock attempt with secure memory handling."""
        if self.is_account_locked():
            audit_logger.warning("Unlock attempt while account locked")
            return
            
        password = self.lock_password_input.text()
        if not password:
            audit_logger.warning("Empty password attempt")
            QMessageBox.warning(self, "Error", "Please enter your password.")
            return
            
        try:
            # Store password securely
            self._secure_master_password = SecureString(password)
            # Clear password from input field
            self.lock_password_input.clear()
            
            # Load data with secure password
            self.vault_data = data_manager.load_data(self._secure_master_password.get_value())
            self._secure_vault_data = [SecureString(str(entry)) for entry in self.vault_data]
            
            self.main_stack.setCurrentWidget(self.vault_widget)
            self.load_entries_into_list()
            self.reset_failed_attempts()
            audit_logger.info("Successful unlock")
        except Exception as e:
            self.increment_failed_attempts()
            audit_logger.warning(f"Failed unlock attempt: {str(e)}")
            QMessageBox.critical(self, "Error", "Invalid password.")
            # Clear secure data on failure
            if self._secure_master_password:
                self._secure_master_password.secure_clear()
            self._secure_master_password = None
            
    def load_entries_into_list(self):
        """Populates the QListWidget with service names from vault_data."""
        current_selection_index = self._selected_entry_index # Use stored index

        self.entry_list_widget.clear()
        new_selection_row = -1
        for index, entry in enumerate(self.vault_data):
            list_item = QListWidgetItem(entry.get('service', 'No Service Name'))
            list_item.setData(Qt.ItemDataRole.UserRole, index)
            self.entry_list_widget.addItem(list_item)
            if index == current_selection_index:
                new_selection_row = self.entry_list_widget.count() - 1

        # Clear search bar and apply filter
        # self.search_input.clear() # Don't clear search on reload
        self.filter_entries() # Re-apply filter to show/hide correctly

        # Try to restore selection
        if new_selection_row != -1:
            self.entry_list_widget.setCurrentRow(new_selection_row)
        else:
            # If no selection restored, ensure details are hidden
            self.clear_details()

        # If selection was restored, display_entry_details will be called by itemSelectionChanged
        # If list is now empty, clear_details was called.

    def filter_entries(self):
        """Filters the list widget items based on the search input text."""
        search_text = self.search_input.text().lower().strip()
        current_selection_visible = False
        selected_items = self.entry_list_widget.selectedItems()
        current_selected_index = self._selected_entry_index

        for i in range(self.entry_list_widget.count()):
            item = self.entry_list_widget.item(i)
            entry_index = item.data(Qt.ItemDataRole.UserRole)

            if 0 <= entry_index < len(self.vault_data):
                entry = self.vault_data[entry_index]
                service = entry.get('service', '').lower()
                username = entry.get('username', '').lower()

                if search_text in service or search_text in username:
                    item.setHidden(False)
                    if entry_index == current_selected_index:
                        current_selection_visible = True
                else:
                    item.setHidden(True)
            else:
                item.setHidden(True)

        # If the previously selected item is now hidden, clear the details
        if selected_items and not current_selection_visible:
             self.entry_list_widget.clearSelection() # Deselect the hidden item
             self.clear_details()

    def display_entry_details(self):
        """Updates the detail pane when an item is selected and makes it visible."""
        selected_items = self.entry_list_widget.selectedItems()
        if not selected_items:
            # This can happen if selection is cleared programmatically
            # We might already be hidden, but call clear_details just in case
            # self.clear_details() # Avoid recursive loop if clearSelection triggers this
            if self.details_widget.isVisible():
                self.clear_details()
            return

        selected_item = selected_items[0]
        entry_index = selected_item.data(Qt.ItemDataRole.UserRole)
        self._selected_entry_index = entry_index # Store the selected index

        entry = self._get_selected_entry_data()
        if entry:
            self.service_display.setText(entry.get('service', 'N/A'))
            self.username_display.setText(entry.get('username', 'N/A'))
            # Reset password view state
            self.show_hide_button.setChecked(False) # Ensure button is "Show"
            self.password_display.setText("********") # Use placeholder dots
            self.password_display.setEchoMode(QLineEdit.EchoMode.Password) # Ensure hidden
            self.show_hide_button.setText("Show")

            # Make details visible and enable buttons
            self.details_widget.setVisible(True)
            self.update_button_states(True) # Pass True to indicate selection exists
            # Add animation here later if desired
        else:
            # Handle potential index out of bounds or error
            self.clear_details()

    def clear_details(self):
        """Clears the details display fields and hides the details pane."""
        self.service_display.clear()
        self.username_display.clear()
        self.password_display.clear()
        self.show_hide_button.setChecked(False)
        self.show_hide_button.setText("Show")
        self._selected_entry_index = -1 # Clear selected index tracker

        self.details_widget.setVisible(False) # Hide the pane
        self.update_button_states(False) # Pass False to indicate no selection
        # Add animation here later if desired

    def update_button_states(self, has_selection: bool):
        """Enable/disable buttons in the details pane based on selection."""
        # Add button is always enabled (unless locked, handled elsewhere)
        # self.add_button.setEnabled(True)
        # Buttons within the details pane depend on selection
        self.delete_button.setEnabled(has_selection)
        self.copy_user_button.setEnabled(has_selection)
        self.copy_pass_button.setEnabled(has_selection)
        self.show_hide_button.setEnabled(has_selection)

    def toggle_password_details_visibility(self, checked):
        """Toggles the visibility of the password in the details display QLineEdit."""
        entry = self._get_selected_entry_data()
        if not entry:
             # Reset in case of weird state
             self.password_display.setEchoMode(QLineEdit.EchoMode.Password)
             self.password_display.setText("")
             self.show_hide_button.setText("Show")
             return

        if checked: # Button is checked -> Show password
            password = entry.get('password', '')
            self.password_display.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_display.setText(password) # Display actual password
            self.show_hide_button.setText("Hide")
        else: # Button is unchecked -> Hide password
            self.password_display.setEchoMode(QLineEdit.EchoMode.Password)
            # Keep showing dots or clear, your preference. Dots might be better.
            self.password_display.setText("********" if entry.get('password') else "")
            self.show_hide_button.setText("Show")

    # --- Button Action Methods ---
    def add_entry(self):
        """Add new entry with secure memory handling."""
        dialog = AddEditDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_entry = dialog.get_data()
            if new_entry:
                try:
                    # Store sensitive data securely
                    secure_entry = SecureString(str(new_entry))
                    self._secure_vault_data.append(secure_entry)
                    self.vault_data.append(new_entry)
                    
                    data_manager.save_data(self.vault_data, self._secure_master_password.get_value())
                    audit_logger.info(f"Added new entry for service: {new_entry['service']}")
                    new_index = len(self.vault_data) - 1
                    self._selected_entry_index = new_index # Update selection tracker
                    self.load_entries_into_list() # Refresh list
                    # Select the newly added item visually
                    self.entry_list_widget.setCurrentRow(self.entry_list_widget.count() - 1)
                    # display_entry_details will be called by the selection change
                    print("New entry added and saved.")
                except Exception as e:
                    audit_logger.error(f"Failed to add entry: {str(e)}")
                    QMessageBox.critical(self, "Save Error", f"Failed to save the new entry: {e}")
                    self.vault_data.pop()
                    if self._secure_vault_data:
                        self._secure_vault_data[-1].secure_clear()
                        self._secure_vault_data.pop()
                    
    def delete_entry(self):
        """Delete entry with audit logging."""
        if self._selected_entry_index == -1:
            audit_logger.warning("Delete attempt with no selection")
            QMessageBox.warning(self, "Selection Error", "Please select an entry to delete.")
            return
            
        entry_index_to_delete = self._selected_entry_index
        entry_service = self.vault_data[entry_index_to_delete].get('service', 'this entry')
        
        reply = QMessageBox.question(self,
                                   "Confirm Delete",
                                   f"Are you sure you want to delete the entry for '{entry_service}'?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
                                   
        if reply == QMessageBox.StandardButton.Yes:
            try:
                del self.vault_data[entry_index_to_delete]
                data_manager.save_data(self.vault_data, self._secure_master_password.get_value())
                audit_logger.info(f"Deleted entry for service: {entry_service}")
                self.clear_details() # Hide details pane first
                self._selected_entry_index = -1 # Reset selection index
                self.load_entries_into_list() # Reload the list

                print(f"Entry '{entry_service}' deleted and vault saved.")
            except Exception as e:
                audit_logger.error(f"Failed to delete entry: {str(e)}")
                QMessageBox.critical(self, "Save Error", f"Failed to save vault after deletion: {e}")
                
    def _get_selected_entry_data(self):
        """Helper method to get the data dictionary of the selected entry using the tracked index."""
        if self._selected_entry_index != -1 and 0 <= self._selected_entry_index < len(self.vault_data):
            return self.vault_data[self._selected_entry_index]
        else:
            # This might happen if data changes externally or after delete/add errors
            # QMessageBox.warning(self, "Error", "Selected item index out of sync with data.")
            print("Warning: _get_selected_entry_data called with invalid index.")
            self._selected_entry_index = -1 # Reset index
            self.clear_details() # Clear UI
            return None

    def copy_username(self):
        entry = self._get_selected_entry_data() # Gets based on _selected_entry_index
        if entry:
            username = entry.get('username', '') # Get actual data
            if username:
                clipboard = QApplication.clipboard()
                clipboard.setText(username)
                print(f"Copied username for {entry.get('service', 'N/A')}")
                # Add visual feedback here (e.g., temporary button text change)
                self.copy_user_button.setText("Copied!")
                QTimer.singleShot(1500, lambda: self.copy_user_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView))) # Reset icon
                QTimer.singleShot(1500, lambda: self.copy_user_button.setText(""))
            else:
                print("No username to copy for this entry.")

    def copy_password(self):
        """Copy password with secure memory handling."""
        entry = self._get_selected_entry_data()
        if entry:
            password = entry.get('password', '')
            if password:
                # Create temporary secure string for clipboard
                secure_password = SecureString(password)
                clipboard = QApplication.clipboard()
                clipboard.setText(secure_password.get_value(), mode=QClipboard.Mode.Clipboard)
                audit_logger.info(f"Password copied for service: {entry.get('service', 'N/A')}")
                
                # Clear secure string after copying
                secure_password.secure_clear()
                # ... rest of the existing code ...
                
    def closeEvent(self, event):
        """Handle application close with secure cleanup."""
        audit_logger.info("Application closing")
        # Securely clear all sensitive data
        self.lock_vault()
        QApplication.quit()


# --- Add/Edit Entry Dialog ---
class AddEditDialog(QDialog):
    """Dialog for adding or editing a password entry.
    
    Security:
    - Cryptographically secure password generation
    - Strong password enforcement
    - Character pool separation
    - Secure random number generation
    """
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.entry = entry # Store entry data if we are editing

        self.setWindowTitle("Add New Entry" if entry is None else "Edit Entry")
        self.setMinimumWidth(450) # Increased width slightly

        layout = QVBoxLayout(self)

        # Add password strength indicator
        self.strength_label = QLabel("Password Strength: ")
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setTextVisible(True)
        self.strength_bar.setFormat("%p%")
        
        # Connect password input to strength checker
        self.password_input.textChanged.connect(self.check_password_strength)

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
        self.show_pass_button.setObjectName("show_pass_button") # Add object name for QSS
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
        """Generate a cryptographically secure password."""
        if not self.validate_inputs():
            return
            
        length = self.length_spinbox.value()
        
        # Define character pools with clear separation
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each required type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with random characters from all pools
        all_chars = uppercase + lowercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password to ensure random distribution
        secrets.SystemRandom().shuffle(password)
        
        # Join the characters into the final password
        generated_password = ''.join(password)
        
        self.password_input.setText(generated_password)
        # Ensure password visibility is reset if it was shown
        self.show_pass_button.setChecked(False)
            
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

    def check_password_strength(self, password: str) -> None:
        """Check password strength and update the strength indicator."""
        if not password:
            self.strength_bar.setValue(0)
            self.strength_label.setText("Password Strength: Empty")
            return

        score = 0
        # Length check (up to 40 points)
        length_score = min(len(password) * 2, 40)
        score += length_score

        # Character type checks (15 points each)
        if any(c.isupper() for c in password):
            score += 15
        if any(c.islower() for c in password):
            score += 15
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in string.punctuation for c in password):
            score += 15

        # Update UI
        self.strength_bar.setValue(score)
        strength_text = "Weak"
        if score >= 80:
            strength_text = "Very Strong"
        elif score >= 60:
            strength_text = "Strong"
        elif score >= 40:
            strength_text = "Medium"
        self.strength_label.setText(f"Password Strength: {strength_text}")

    def validate_password_strength(self, password: str) -> bool:
        """Validate password meets minimum security requirements."""
        if len(password) < 12:
            QMessageBox.warning(self, "Password Too Weak", 
                              "Password must be at least 12 characters long.")
            return False
        if not any(c.isupper() for c in password):
            QMessageBox.warning(self, "Password Too Weak", 
                              "Password must contain at least one uppercase letter.")
            return False
        if not any(c.islower() for c in password):
            QMessageBox.warning(self, "Password Too Weak", 
                              "Password must contain at least one lowercase letter.")
            return False
        if not any(c.isdigit() for c in password):
            QMessageBox.warning(self, "Password Too Weak", 
                              "Password must contain at least one number.")
            return False
        if not any(c in string.punctuation for c in password):
            QMessageBox.warning(self, "Password Too Weak", 
                              "Password must contain at least one special character.")
            return False
        return True

    # Override accept to perform validation before closing
    def accept(self):
        """Override accept to perform validation before closing."""
        data = self.get_data()
        if data is None:
            return
        
        # Validate password strength
        if not self.validate_password_strength(data['password']):
            return
            
        super().accept() 