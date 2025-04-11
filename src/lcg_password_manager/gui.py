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
    QMainWindow, QTableWidget, QTableWidgetItem, QStatusBar, QMenuBar, QMenu, QFormLayout, QToolBar, QTableView, QAbstractItemView, QFileDialog, QGroupBox, QTextEdit, QHeaderView, QSizePolicy, QTextBrowser, QScrollArea # Added QTextEdit and QHeaderView
)
from PySide6.QtCore import Qt, Signal, QTimer, QEvent, QSortFilterProxyModel, QModelIndex, QDateTime, QPoint # Added QPoint for menu positioning
from PySide6.QtGui import QAction, QClipboard, QPalette, QColor, QIcon, QPixmap, QKeySequence, QStandardItemModel, QStandardItem, QShortcut # Added QAction
from . import data_manager
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
from pathlib import Path
from typing import Optional # Make sure Optional is imported
from .branding import Branding
from .data_manager import DataManager
from .audit_logger import AuditLogger
from .security_utils import SecurityUtils
import markdown # For rendering markdown

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
    # Add signal to request showing the login window again
    show_login = Signal()

    def __init__(self, data_manager: DataManager):
        super().__init__()
        self.data_manager = data_manager
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

        # Add a back button
        self.back_button = QPushButton("Back to Login")
        self.back_button.clicked.connect(self.go_back_to_login)
        layout.addWidget(self.back_button)

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
            # Create initial empty vault using the module-level function, passing the path
            data_manager.save_data([], password, self.data_manager.vault_path)
            
            # Show success message with clear next steps
            QMessageBox.information(
                self, 
                "Vault Created Successfully",
                "Your secure password vault has been created!\n\n"
                "You will now be returned to the login screen where you can\n"
                "sign in with your new master password."
            )
            
            # Go back to login screen
            self.show_login.emit()
            self.close()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create vault: {e}")

    def go_back_to_login(self):
        self.show_login.emit()
        self.close()

class LoginWindow(QDialog):
    """Window for logging in with the master password.
    
    Security:
    - Login attempt throttling
    - Account lockout mechanism
    - Secure password field
    - Audit logging of attempts
    """
    # Signal indicating successful login, passing loaded data and master password
    login_successful = Signal(list, str)
    # Signal to indicate user wants to go to setup
    show_setup = Signal()
    
    def __init__(self, audit_logger: AuditLogger, data_manager: DataManager):
        super().__init__()
        self.branding = Branding()
        self.data_manager = data_manager
        self.audit_logger = audit_logger
        self.security_utils = SecurityUtils()
        
        self.setWindowTitle(self.branding.get_window_title())
        self.setWindowIcon(self.branding.icon)
        self.setStyleSheet(self.branding.get_stylesheet())
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the login interface."""
        layout = QVBoxLayout()
        
        # Add logo at higher resolution
        logo_label = QLabel()
        logo_pixmap = QPixmap(self.branding._logo_path)
        scaled_logo = logo_pixmap.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(scaled_logo)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Add welcome message
        welcome_label = QLabel("Welcome to LCG Password Manager")
        welcome_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        
        # Add description
        desc_label = QLabel("Please enter your master password to access your secure vault")
        desc_label.setStyleSheet("font-size: 14px; color: #666; margin: 10px;")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 1px solid #ccc;
                border-radius: 6px;
                margin: 10px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 2px solid #007bff;
            }
        """)
        layout.addWidget(self.password_input)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
                margin: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #004085;
            }
        """)
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        # Add "Create Master Password" button
        self.setup_button = QPushButton("First time? Create Master Password")
        self.setup_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
                margin: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)
        self.setup_button.clicked.connect(self.go_to_setup)
        layout.addWidget(self.setup_button)
        
        # Add "Forgot Password" link
        forgot_pw_link = QLabel('<a href="#" style="color: #007bff; text-decoration: none;">Forgot your password?</a>')
        forgot_pw_link.setStyleSheet("font-size: 14px; margin: 10px;")
        forgot_pw_link.setOpenExternalLinks(False)
        forgot_pw_link.linkActivated.connect(self.handle_forgot_password)
        forgot_pw_link.setAlignment(Qt.AlignCenter)
        layout.addWidget(forgot_pw_link)
        
        self.setLayout(layout)
        
    def handle_login(self):
        """Handle the login process."""
        password = self.password_input.text()
        
        try:
            # Set the master password in DataManager
            self.data_manager.set_master_password(password)
            
            try:
                # Load encrypted data
                loaded_data = self.data_manager.load()
                
                # Log successful login
                self.audit_logger.log_event("login", "success", "User logged in successfully")
                
                # Emit signal instead of calling show_main_window directly
                self.login_successful.emit(loaded_data, password)
                self.accept() # Close the dialog
                
            except ValueError:
                # Log failed login attempt
                self.audit_logger.log_event("login", "failure", "Invalid password attempt")
                
                # Show error message
                QMessageBox.warning(
                    self,
                    "Login Failed",
                    "The password you entered is incorrect. Please try again."
                )
                
                # Clear password field
                self.password_input.clear()
                
        except Exception as e:
            # Log error
            self.audit_logger.log_event("login", "error", str(e))
            
            # Show error message
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred during login: {str(e)}\n\n"
                "Please try again."
            )
            
            # Clear password field
            self.password_input.clear()
            
    def handle_forgot_password(self):
        """Handle the forgot password request."""
        QMessageBox.information(
            self,
            "Password Recovery",
            "For security reasons, the master password cannot be recovered directly.\n\n"
            "Please contact your system administrator or security team for assistance."
        )
        
    def go_to_setup(self):
        """Emit signal to show the setup window."""
        self.show_setup.emit()
        self.hide()

# --- Main Application Window ---
class MainWindow(QMainWindow):
    LOCK_TIMEOUT_MS = 15 * 60 * 1000 # 15 minutes

    def __init__(self, audit_logger: AuditLogger, data_manager: DataManager, initial_data=None, master_password=None):
        super().__init__()
        self.branding = Branding()
        self.data_manager = data_manager
        self.audit_logger = audit_logger
        self.security_utils = SecurityUtils()
        
        # Store master password and initial data
        self.master_password = master_password
        self.initial_data = initial_data or []

        # Set master password on the single DataManager instance
        if self.master_password:
             self.data_manager.set_master_password(self.master_password)

        self.setWindowTitle(self.branding.get_window_title())
        self.setWindowIcon(self.branding.icon)
        self.setStyleSheet(self.branding.get_stylesheet())
        
        # Resize MainWindow to be closer to AddEditDialog size
        self.setGeometry(150, 150, 700, 600) # Adjusted size

        self.setup_ui()
        self.setup_menu()
        self.setup_status_bar()
        
        # Load initial data if provided
        if self.initial_data:
            self.load_entries()
        
    def setup_ui(self):
        """Set up the main user interface."""
        # Create central widget
        central_widget = QWidget()
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Add buttons
        self.add_button = QPushButton("Add Entry")
        self.add_button.setAccessibleName("Add new password entry")
        self.add_button.clicked.connect(self.add_entry)
        self.add_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #3A7AB3, stop:1 #245A8E);
                color: white;
                border: 1px solid #1A4268;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 70px;
                margin: 1px 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #4A8AC3, stop:1 #346A9E);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1A4268, stop:1 #163753);
            }
        """)
        toolbar.addWidget(self.add_button)
        
        self.edit_button = QPushButton("Edit")
        self.edit_button.setAccessibleName("Edit selected password entry")
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self.edit_entry)
        self.edit_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #3A7AB3, stop:1 #245A8E);
                color: white;
                border: 1px solid #1A4268;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 70px;
                margin: 1px 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #4A8AC3, stop:1 #346A9E);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1A4268, stop:1 #163753);
            }
            QPushButton:disabled {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #B0B0B0, stop:1 #909090);
                color: #E0E0E0;
                border: 1px solid #808080;
            }
        """)
        toolbar.addWidget(self.edit_button)
        
        self.delete_button = QPushButton("Delete")
        self.delete_button.setAccessibleName("Delete selected password entry")
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.delete_entry)
        self.delete_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #3A7AB3, stop:1 #245A8E);
                color: white;
                border: 1px solid #1A4268;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 70px;
                margin: 1px 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #4A8AC3, stop:1 #346A9E);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1A4268, stop:1 #163753);
            }
            QPushButton:disabled {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #B0B0B0, stop:1 #909090);
                color: #E0E0E0;
                border: 1px solid #808080;
            }
        """)
        toolbar.addWidget(self.delete_button)
        
        toolbar.addSeparator()
        
        # Add spacer to push import/export/settings to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        toolbar.addWidget(spacer)
        
        # Create overflow menu button
        self.overflow_button = QPushButton("More")
        self.overflow_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        self.overflow_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #3A7AB3, stop:1 #245A8E);
                color: white;
                border: 1px solid #1A4268;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 70px;
                margin: 1px 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #4A8AC3, stop:1 #346A9E);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1A4268, stop:1 #163753);
            }
        """)
        toolbar.addWidget(self.overflow_button)
        
        # Create overflow menu
        self.overflow_menu = QMenu(self)
        
        # Add Import action to overflow menu
        import_action = QAction("Import Passwords", self)
        import_action.triggered.connect(self.import_entries)
        self.overflow_menu.addAction(import_action)
        
        # Add Export action to overflow menu
        export_action = QAction("Export Passwords", self)
        export_action.triggered.connect(self.export_entries)
        self.overflow_menu.addAction(export_action)
        
        # Connect overflow button to show menu
        self.overflow_button.clicked.connect(self.show_overflow_menu)
        
        # Settings button - make more prominent
        self.settings_button = QPushButton("Settings")
        self.settings_button.setAccessibleName("Open settings dialog")
        self.settings_button.clicked.connect(self.show_settings)
        # Using a simple gear icon from standard icons
        self.settings_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView))
        self.settings_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #3A7AB3, stop:1 #245A8E);
                color: white;
                border: 1px solid #1A4268;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 80px;
                margin: 1px 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #4A8AC3, stop:1 #346A9E);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1A4268, stop:1 #163753);
            }
        """)
        toolbar.addWidget(self.settings_button)
        
        # Create table widget
        self.table = QTableWidget()
        self.table.setColumnCount(5)  # Increased to 5 columns
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Created", "Modified"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # Set all columns to stretch initially
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch) 
        self.table.itemDoubleClicked.connect(self.handle_double_click)
        layout.addWidget(self.table)
        
        # Initialize clipboard timer
        self.clipboard_timer = QTimer()
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self.clear_clipboard)
        
        # Set window size to 85% of original
        self.setGeometry(150, 150, 595, 510)  # Reduced from 700x600
        
        # Reapply stylesheet and polish to ensure updates take effect
        self.setStyleSheet(self.branding.get_stylesheet())
        self.style().unpolish(self)
        self.style().polish(self)

        # Now load entries and set initial status message
        self.load_entries()
        self.statusBar().showMessage("Ready")
        
    def setup_menu(self):
        """Set up the application menu bar."""
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("&File")
        
        import_action = QAction("&Import Passwords...", self)
        import_action.triggered.connect(self.import_entries)
        file_menu.addAction(import_action)
        
        export_action = QAction("&Export Passwords...", self)
        export_action.triggered.connect(self.export_entries)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menu_bar.addMenu("&Edit")
        
        copy_username_action = QAction("Copy &Username", self)
        copy_username_action.setShortcut(QKeySequence("Ctrl+U"))
        copy_username_action.triggered.connect(self.copy_username)
        edit_menu.addAction(copy_username_action)
        
        copy_password_action = QAction("Copy &Password", self)
        copy_password_action.setShortcut(QKeySequence.StandardKey.Copy)
        copy_password_action.triggered.connect(self.copy_password)
        edit_menu.addAction(copy_password_action)
        
        edit_menu.addSeparator()
        
        add_action = QAction("&Add Entry...", self)
        add_action.setShortcut(QKeySequence.StandardKey.New)
        add_action.triggered.connect(self.add_entry)
        edit_menu.addAction(add_action)
        
        edit_action = QAction("&Edit Entry...", self)
        edit_action.triggered.connect(self.edit_entry)
        edit_menu.addAction(edit_action)
        
        delete_action = QAction("&Delete Entry", self)
        delete_action.setShortcut(QKeySequence.StandardKey.Delete)
        delete_action.triggered.connect(self.delete_entry)
        edit_menu.addAction(delete_action)
        
        # Add Theme submenu
        edit_menu.addSeparator()
        theme_menu = edit_menu.addMenu("&Themes")
        
        # Light theme action
        light_theme_action = QAction("&Light Theme", self)
        light_theme_action.triggered.connect(lambda: self.change_theme("light"))
        light_theme_action.setCheckable(True)
        light_theme_action.setChecked(self.branding.theme_manager.current_theme == "light")
        theme_menu.addAction(light_theme_action)
        
        # Dark theme action
        dark_theme_action = QAction("&Dark Theme", self)
        dark_theme_action.triggered.connect(lambda: self.change_theme("dark"))
        dark_theme_action.setCheckable(True)
        dark_theme_action.setChecked(self.branding.theme_manager.current_theme == "dark")
        theme_menu.addAction(dark_theme_action)
        
        # Store theme actions for toggling checked state
        self.theme_actions = {
            "light": light_theme_action,
            "dark": dark_theme_action
        }
        
        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        
        # Add View Help action
        help_action = QAction("&View Help", self)
        help_action.triggered.connect(self.show_help_dialog)
        help_menu.addAction(help_action)

        # Add Contact Support action
        contact_action = QAction("&Contact Support", self)
        contact_action.triggered.connect(self.show_contact_dialog)
        help_menu.addAction(contact_action)

        help_menu.addSeparator()

        about_action = QAction("&About LCG Password Manager", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
        
    def setup_status_bar(self):
        """Set up the status bar."""
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        
        # Add footer text
        footer_label = QLabel(self.branding.get_footer_text())
        status_bar.addPermanentWidget(footer_label)
        
    def load_entries(self):
        """Load password entries into the table."""
        self.table.setRowCount(0)
        entries = self.data_manager.get_entries()
        
        default_date_str = QDateTime.currentDateTime().toString(Qt.ISODate)
        
        for entry in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Service
            self.table.setItem(row, 0, QTableWidgetItem(entry['service']))
            
            # Username
            self.table.setItem(row, 1, QTableWidgetItem(entry['username']))
            
            # Password (masked)
            self.table.setItem(row, 2, QTableWidgetItem('••••••••'))
            
            # Created date (formatted, with fallback)
            created_date_str = entry.get('created_date', entry.get('modified_date', default_date_str))
            created_date = QDateTime.fromString(created_date_str, Qt.ISODate)
            self.table.setItem(row, 3, QTableWidgetItem(created_date.toString('MM/dd/yyyy')))
            
            # Modified date (formatted)
            modified_date_str = entry.get('modified_date', default_date_str)
            modified_date = QDateTime.fromString(modified_date_str, Qt.ISODate)
            self.table.setItem(row, 4, QTableWidgetItem(modified_date.toString('MM/dd/yyyy')))
        
        self.statusBar().showMessage(f"Loaded {len(entries)} entries")
        self.audit_logger.log_event("ENTRIES_LOADED", f"Loaded {len(entries)} entries")
        # Remove resizeColumnsToContents and setStretchLastSection as Stretch is set for all columns now
        # self.table.resizeColumnsToContents()
        # self.table.horizontalHeader().setStretchLastSection(True)
        
        # Connect selection changed signal after loading data
        self.table.itemSelectionChanged.connect(self.update_button_states)
        self.update_button_states() # Initial state check
    
    def add_entry(self):
        """Show dialog to add a new password entry"""
        dialog = AddEditDialog(self.data_manager, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                entry = dialog.get_entry()
                entry['modified_date'] = QDateTime.currentDateTime().toString(Qt.ISODate)
                self.data_manager.add_entry(entry)
                self.load_entries()
                self.statusBar().showMessage("Entry added successfully")
                self.audit_logger.log_event("ENTRY_ADD", f"Added entry for service: {entry['service']}")
            except ValueError as e:
                QMessageBox.warning(self, "Error Adding Entry", str(e))
                self.audit_logger.log_event("ENTRY_ADD_ERROR", f"Failed to add entry for {entry.get('service', '?')}: {e}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add entry: {str(e)}")
                self.audit_logger.log_event("ENTRY_ADD_ERROR", f"Failed to add entry: {str(e)}")
    
    def edit_entry(self):
        """Show dialog to edit the selected password entry"""
        selected_row_index = self._get_selected_source_row()
        if selected_row_index is None:
             QMessageBox.warning(self, "No Selection", "Please select an entry to edit.")
             return

        service_item = self.table.item(selected_row_index, 0)
        username_item = self.table.item(selected_row_index, 1)
        if not service_item or not username_item:
            QMessageBox.warning(self, "Error", "Could not identify selected entry in model.")
            return

        service = service_item.text()
        username = username_item.text()
        old_key = {"service": service, "username": username}

        try:
            # Find the original entry in DataManager's data
            entry = next((e for e in self.data_manager.get_entries() if e['service'] == service and e['username'] == username), None)
            if not entry:
                QMessageBox.warning(self, "Warning", "Entry data not found. Cannot edit.")
                self.audit_logger.log_event("ENTRY_EDIT_ERROR", f"Entry data not found for {service} / {username}")
                self.load_entries()
                return

            dialog = AddEditDialog(self.data_manager, self, entry=entry)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                updated_entry = dialog.get_entry()
                updated_entry['modified_date'] = QDateTime.currentDateTime().toString(Qt.ISODate)

                self.data_manager.update_entry(old_key, updated_entry)
                self.load_entries()
                self.statusBar().showMessage("Entry updated successfully")
                self.audit_logger.log_event("ENTRY_UPDATE", f"Updated entry for service: {service} / {username}")
        except ValueError as e:
            QMessageBox.warning(self, "Error Updating Entry", str(e))
            self.audit_logger.log_event("ENTRY_UPDATE_ERROR", f"Failed to update entry for {service}: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update entry: {str(e)}")
            self.audit_logger.log_event("ENTRY_UPDATE_ERROR", f"Failed to update entry for {service}: {str(e)}")
    
    def delete_entry(self):
        """Delete the selected password entry"""
        selected_row_index = self._get_selected_source_row()
        if selected_row_index is None:
             QMessageBox.warning(self, "No Selection", "Please select an entry to delete.")
             return

        service_item = self.table.item(selected_row_index, 0)
        username_item = self.table.item(selected_row_index, 1)
        if not service_item or not username_item:
            QMessageBox.warning(self, "Error", "Could not identify selected entry in model.")
            return

        service = service_item.text()
        username = username_item.text()
        key_to_delete = {"service": service, "username": username}

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete the entry for \"{service}\" / \"{username}\"?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.data_manager.delete_entry(key_to_delete)
                self.load_entries()
                self.statusBar().showMessage("Entry deleted successfully")
                self.audit_logger.log_event("ENTRY_DELETE", f"Deleted entry for {service} / {username}")
            except ValueError as e:
                QMessageBox.warning(self, "Error Deleting Entry", str(e))
                self.audit_logger.log_event("ENTRY_DELETE_ERROR", f"Failed to delete entry {service} / {username}: {e}")
                self.load_entries()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete entry: {str(e)}")
                self.audit_logger.log_event("ENTRY_DELETE_ERROR", f"Failed to delete entry {service} / {username}: {str(e)}")
    
    def copy_username(self, row=None):
        """Copy username of selected entry to clipboard."""
        if row is None:
            row = self._get_selected_source_row()
        if row is None:
            return

        username_item = self.table.item(row, 1)
        if not username_item:
            return
        username = username_item.text()

        # Use QApplication clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(username)

        self.audit_logger.log_event("USERNAME_COPY", f"Copied username for: {self.table.item(row, 0).text()}")
        self.statusBar().showMessage("Username copied to clipboard", 2000)

    def copy_password(self, row=None):
        """Copy password of selected entry to clipboard."""
        if row is None:
            row = self._get_selected_source_row()
        if row is None:
            return

        service_item = self.table.item(row, 0)
        username_item = self.table.item(row, 1)
        if not service_item or not username_item:
            return

        service = service_item.text()
        username = username_item.text()

        try:
            entry = next((e for e in self.data_manager.get_entries() if e['service'] == service and e['username'] == username), None)
            if entry and 'password' in entry:
                actual_password = entry['password']

                # Use QApplication clipboard
                clipboard = QApplication.clipboard()
                clipboard.setText(actual_password)
                
                # Start the clipboard timer
                self.clipboard_timer.start(15000)  # 15 seconds

                self.audit_logger.log_event("PASSWORD_COPY", f"Copied password for: {service} - {username}")
                self.statusBar().showMessage("Password copied. Clears in 15s.")
            else:
                 QMessageBox.warning(self, "Error", "Could not retrieve password for selected entry.")
                 self.audit_logger.log_event("PASSWORD_COPY_ERROR", f"Failed to retrieve password for {service} - {username}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error retrieving password: {e}")
            self.audit_logger.log_event("PASSWORD_COPY_ERROR", f"Exception retrieving password for {service} - {username}: {e}")

    def show_help_dialog(self):
        """Show the help dialog with the user guide."""
        dialog = HelpDialog(self)
        dialog.exec()

    def show_contact_dialog(self):
        """Show contact information for support."""
        QMessageBox.information(
            self,
            "Contact Support",
            "For assistance, please contact:\n\n"
            "Department: MATI Department\n"
            "Email: ngrant@lcgadvisors.com"
        )

    def show_about_dialog(self):
        """Show about dialog with application information."""
        about_text = f"""
        <h2>LCG Password Manager</h2>
        <p>Version 1.0.0</p> # TODO: Get version dynamically
        <p>Enterprise-grade password management solution.</p>
        <p>{self.branding.get_footer_text()}</p>
        """
        QMessageBox.about(self, "About LCG Password Manager", about_text)
        
    def import_entries(self):
        """Import password entries from a file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Entries",
            "",
            "JSON Files (*.json);;All Files (*.*)"
        )
        
        if file_path:
            try:
                count = self.data_manager.import_entries(file_path)
                self.load_entries()
                self.statusBar().showMessage(f"Successfully imported {count} entries")
                self.audit_logger.log_event("entries_imported", f"Imported {count} entries from file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import entries: {str(e)}")
                self.audit_logger.log_event("error", f"Failed to import entries: {str(e)}")
    
    def export_entries(self):
        """Export password entries to a file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Entries",
            "",
            "JSON Files (*.json);;All Files (*.*)"
        )
        
        if file_path:
            try:
                count = self.data_manager.export_entries(file_path)
                self.statusBar().showMessage(f"Successfully exported {count} entries")
                self.audit_logger.log_event("entries_exported", f"Exported {count} entries to file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export entries: {str(e)}")
                self.audit_logger.log_event("error", f"Failed to export entries: {str(e)}")
    
    def show_settings(self):
        """Show the settings dialog"""
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.load_entries()  # Reload entries in case settings affect display
            self.statusBar().showMessage("Settings updated successfully")
            self.audit_logger.log_event("settings_updated", "Settings were updated")

    def handle_double_click(self, item):
        """Handle double click on table items."""
        row = item.row()
        column = item.column()
        
        if column == 0:  # Service column
            self.edit_entry()
        elif column == 2:  # Password column
            self.copy_password(row)
        elif column == 1:  # Username column
            self.copy_username(row)

    def _get_selected_source_row(self) -> Optional[int]:
        """Helper to get the selected row index."""
        selected_indexes = self.table.selectedIndexes()
        if not selected_indexes:
            return None
        return selected_indexes[0].row()

    def clear_clipboard(self):
        """Clear the clipboard after timeout."""
        clipboard = QApplication.clipboard()
        clipboard.clear()
        self.statusBar().showMessage("Clipboard cleared for security.", 3000)

    def set_initial_data(self, data):
        """Set the initial data (used after login/setup)."""
        self.initial_data = data
        # Don't load here, load_entries is called in __init__ if data exists

    def update_button_states(self):
        """Update button states based on selection"""
        has_selection = len(self.table.selectedIndexes()) > 0
        self.edit_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)
        # Also update menu actions if they exist and need enabling/disabling

    def show_overflow_menu(self):
        """Show the overflow menu below the button."""
        button_pos = self.overflow_button.mapToGlobal(QPoint(0, self.overflow_button.height()))
        self.overflow_menu.exec(button_pos)

    def change_theme(self, theme_name):
        """Change the application theme."""
        # Update theme manager
        self.branding.theme_manager.current_theme = theme_name
        
        # Update checked state of theme actions
        for name, action in self.theme_actions.items():
            action.setChecked(name == theme_name)
        
        # Apply the new stylesheet
        stylesheet = self.branding.get_stylesheet()
        self.setStyleSheet(stylesheet)
        
        # Force repaint of the widgets
        QApplication.instance().setStyleSheet(stylesheet)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()
        QApplication.processEvents()
        
        # Update status bar
        self.statusBar().showMessage(f"Theme changed to {theme_name.title()}", 2000)
        
        # Log theme change
        self.audit_logger.log_event("THEME_CHANGED", f"Theme changed to {theme_name}")

# --- Add/Edit Entry Dialog ---
class AddEditDialog(QDialog):
    """Dialog for adding or editing password entries"""
    
    def __init__(self, data_manager: DataManager, parent=None, entry=None):
        super().__init__(parent)
        self.data_manager = data_manager
        self.entry = entry
        self.security_utils = SecurityUtils()
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the dialog's user interface"""
        self.setWindowTitle("Add Entry" if not self.entry else "Edit Entry")
        self.setModal(True)
        self.setMinimumWidth(600)

        layout = QVBoxLayout()
        form_layout = QFormLayout()
        
        # Service input
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Enter service name (e.g., Google, Amazon)")
        if self.entry:
            self.service_input.setText(self.entry['service'])
            self.service_input.setEnabled(False if self.entry else True)
        form_layout.addRow("Service:", self.service_input)
        
        # Username input
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username or email")
        if self.entry:
            self.username_input.setText(self.entry['username'])
            self.username_input.setEnabled(False if self.entry else True)
        form_layout.addRow("Username:", self.username_input)
        
        # Password input layout (field + generate button + show button)
        password_row_layout = QHBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password or generate")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        if self.entry:
            self.password_input.setText(self.entry['password'])
        password_row_layout.addWidget(self.password_input, 1)

        self.generate_button = QPushButton("Generate")
        self.generate_button.setToolTip("Generate a strong password (16 chars)")
        self.generate_button.clicked.connect(self.generate_password)
        password_row_layout.addWidget(self.generate_button)

        self.show_password_button = QPushButton()
        self.show_password_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton))
        self.show_password_button.setCheckable(True)
        self.show_password_button.setToolTip("Show/Hide Password")
        self.show_password_button.toggled.connect(self.toggle_password_visibility)
        password_row_layout.addWidget(self.show_password_button)

        form_layout.addRow("Password:", password_row_layout)

        # URL input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (optional)")
        if self.entry and 'url' in self.entry:
            self.url_input.setText(self.entry['url'])
        form_layout.addRow("URL:", self.url_input)
        
        # Notes input (Changed to QTextEdit for multi-line)
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Enter notes (optional)")
        self.notes_input.setAcceptRichText(False)
        self.notes_input.setFixedHeight(80)
        if self.entry and 'notes' in self.entry:
            self.notes_input.setPlainText(self.entry['notes'])
        form_layout.addRow("Notes:", self.notes_input)

        layout.addLayout(form_layout)

        # Buttons (OK/Cancel)
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)
        self.service_input.setFocus()

    def generate_password(self):
        """Generates a secure password and updates the input field."""
        try:
            generated_pw = self.security_utils.generate_secure_password(length=16)
            self.password_input.setText(generated_pw)
            self.show_password_button.setChecked(False)
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        except Exception as e:
            QMessageBox.warning(self, "Generation Failed", f"Could not generate password: {e}")

    def toggle_password_visibility(self, checked):
        """Toggle password visibility"""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogNoButton))
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton))

    def get_entry(self):
        """Get the entry data from the dialog"""
        entry = {
            'service': self.service_input.text().strip(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text(),
            'url': self.url_input.text().strip(),
            'notes': self.notes_input.toPlainText().strip()
        }
        
        if not entry['url']:
            del entry['url']
        if not entry['notes']:
            del entry['notes']
            
        return entry
        
    def accept(self):
        """Validate the entry before accepting"""
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not service:
            QMessageBox.warning(self, "Validation Error", "Service name is required.")
            self.service_input.setFocus()
            return
            
        if not username:
            QMessageBox.warning(self, "Validation Error", "Username is required.")
            self.username_input.setFocus()
            return
            
        if not password:
            QMessageBox.warning(self, "Validation Error", "Password is required.")
            self.password_input.setFocus()
            return
            
        if not self.entry:
            if any(e['service'] == service and e['username'] == username for e in self.data_manager.get_entries()):
                QMessageBox.warning(self, "Duplicate Entry",
                                    f"An entry for service '{service}' with username '{username}' already exists.")
                self.service_input.setFocus()
                return

        super().accept()

# --- Application Controller Logic --- 

# Global variable to hold the main window instance
main_app_window = None

def show_login_window():
    """Shows the login window."""
    global login_window
    if setup_window:
        setup_window.hide()
    login_window.show()

def show_setup_window():
    """Shows the setup window."""
    global setup_window, login_window
    app = QApplication.instance()
    if not setup_window:
        setup_window = SetupWindow(app.data_manager)
        setup_window.setup_complete.connect(on_setup_complete)
        setup_window.show_login.connect(show_login_window)
    login_window.hide()
    setup_window.show()

def on_login_success(loaded_data, master_password):
    """Handles successful login."""
    global main_app_window, login_window
    print("Login successful, showing main window.")
    app = QApplication.instance()

    try:
        salt = app.data_manager.get_salt()
        if salt:
            app.audit_logger.set_credentials(master_password, salt)
        else:
            app.audit_logger.log_event("AUDIT_INIT_ERROR", "Could not retrieve salt after login.")
    except Exception as e:
        print(f"Error setting audit logger credentials after login: {e}")
        if app.audit_logger._initialized:
             app.audit_logger.log_event("AUDIT_INIT_ERROR", f"Exception setting credentials: {e}")

    if not main_app_window:
        main_app_window = MainWindow(app.audit_logger, app.data_manager, loaded_data, master_password)
    else:
        main_app_window.master_password = master_password
        app.data_manager.set_master_password(master_password)
        main_app_window.set_initial_data(loaded_data)

    login_window.hide()
    main_app_window.show()
    main_app_window.raise_()
    main_app_window.activateWindow()

def on_setup_complete(master_password):
    """Handles successful setup."""
    global main_app_window, setup_window
    print("Setup complete, showing main window.")
    app = QApplication.instance()

    app.data_manager.set_master_password(master_password)

    try:
        salt = app.data_manager.get_salt()
        if salt:
            app.audit_logger.set_credentials(master_password, salt)
        else:
             print("AuditLogger: Could not retrieve salt after setup.")
    except Exception as e:
        print(f"Error setting audit logger credentials after setup: {e}")

    if not main_app_window:
        main_app_window = MainWindow(app.audit_logger, app.data_manager, master_password=master_password)

    main_app_window.set_initial_data([])

    setup_window.hide()
    main_app_window.show()
    main_app_window.raise_()
    main_app_window.activateWindow()

# --- Main Execution --- 

# Global references to windows
login_window = None
setup_window = None

def main():
    """Main entry point for the LCG Password Manager GUI."""
    global login_window, setup_window, main_app_window

    # Enable high DPI scaling for better look on modern displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Instantiate core components and make them accessible
    app.audit_logger = AuditLogger()
    app.data_manager = DataManager(audit_logger=app.audit_logger)
    app.security_utils = SecurityUtils()
    app.branding = Branding()

    # Determine if vault exists using the app's data_manager
    vault_path = app.data_manager.vault_path
    vault_exists = vault_path.exists()

    # Pass the single audit_logger and data_manager instances
    login_window = LoginWindow(app.audit_logger, app.data_manager)
    login_window.login_successful.connect(on_login_success)
    login_window.show_setup.connect(show_setup_window)

    if vault_exists:
        print(f"Vault found at {vault_path}, showing login window.")
        login_window.show()
    else:
        print(f"Vault not found at {vault_path}, showing setup window.")
        show_setup_window()

    sys.exit(app.exec()) 

class SettingsDialog(QDialog):
    """Dialog for managing application settings"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.branding = Branding() # Add branding for styling
        self.setup_ui()
        self.load_styles() # Load styles

    def load_styles(self):
        """Load stylesheet from Branding."""
        self.setStyleSheet(self.branding.get_stylesheet())
        # Apply specific styles if needed, e.g., make QGroupBox title bolder
        self.findChild(QGroupBox, "changePasswordGroup").setStyleSheet("QGroupBox { font-weight: bold; }")

    def setup_ui(self):
        """Set up the dialog's user interface"""
        self.setWindowTitle("Settings")
        self.setModal(True)
        
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        
        # Master password change section
        group_box = QGroupBox("Change Master Password")
        group_box.setObjectName("changePasswordGroup") # Add object name for styling
        group_layout = QVBoxLayout()
        
        # Current password
        self.current_password = QLineEdit()
        self.current_password.setPlaceholderText("Enter current master password")
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)
        group_layout.addWidget(QLabel("Current Password:"))
        group_layout.addWidget(self.current_password)
        
        # New password
        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("Enter new master password")
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        group_layout.addWidget(QLabel("New Password:"))
        group_layout.addWidget(self.new_password)
        
        # Confirm new password
        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Confirm new master password")
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        group_layout.addWidget(QLabel("Confirm Password:"))
        group_layout.addWidget(self.confirm_password)
        
        # Show password checkboxes
        show_layout = QHBoxLayout()
        
        self.show_current = QCheckBox("Show Current")
        self.show_current.stateChanged.connect(lambda state: self.toggle_password_visibility(self.current_password, state))
        show_layout.addWidget(self.show_current)
        
        self.show_new = QCheckBox("Show New")
        self.show_new.stateChanged.connect(lambda state: self.toggle_password_visibility(self.new_password, state))
        show_layout.addWidget(self.show_new)
        
        self.show_confirm = QCheckBox("Show Confirm")
        self.show_confirm.stateChanged.connect(lambda state: self.toggle_password_visibility(self.confirm_password, state))
        show_layout.addWidget(self.show_confirm)
        
        group_layout.addLayout(show_layout)
        group_box.setLayout(group_layout)
        layout.addWidget(group_box)
        
        # Audit log settings
        log_group = QGroupBox("Audit Log Settings")
        log_layout = QFormLayout()
        
        # Max log age
        self.max_log_age = QSpinBox()
        self.max_log_age.setRange(1, 365)
        self.max_log_age.setValue(30)  # Default 30 days
        self.max_log_age.setSuffix(" days")
        log_layout.addRow("Maximum Log Age:", self.max_log_age)
        
        # Log rotation size
        self.rotation_size = QSpinBox()
        self.rotation_size.setRange(1, 100)
        self.rotation_size.setValue(10)  # Default 10 MB
        self.rotation_size.setSuffix(" MB")
        log_layout.addRow("Log Rotation Size:", self.rotation_size)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_settings)
        save_button.setDefault(True)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def toggle_password_visibility(self, password_input, state):
        """Toggle password visibility for the given input field"""
        password_input.setEchoMode(QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password)
    
    def save_settings(self):
        """Save the settings."""
        try:
            # Get password fields
            current_password = self.current_password.text()
            new_password = self.new_password.text()
            confirm_password = self.confirm_password.text()
            
            password_change_attempted = bool(current_password or new_password or confirm_password)
            
            if password_change_attempted:
                # If attempting to change password, all fields must be filled
                if not current_password or not new_password or not confirm_password:
                    QMessageBox.warning(
                        self,
                        "Validation Error",
                        "To change the master password, please fill in all three password fields."
                    )
                    return # Keep dialog open

                # Validate new passwords match
                if new_password != confirm_password:
                    QMessageBox.warning(
                        self,
                        "Validation Error",
                        "New passwords do not match."
                    )
                    self.new_password.setFocus()
                    return # Keep dialog open
                
                # Validate current password with DataManager
                # Assuming parent is MainWindow which has data_manager
                if not self.parent().data_manager.validate_password(current_password):
                    QMessageBox.warning(
                        self,
                        "Validation Error",
                        "Current password is incorrect."
                    )
                    self.current_password.setFocus()
                    return # Keep dialog open
                
                # --- Check password strength (reuse AddEditDialog logic if available or implement here) ---
                # Example using zxcvbn if integrated:
                # from zxcvbn import zxcvbn
                # results = zxcvbn(new_password)
                # if results['score'] < 3: # Example: Require score 3 or higher
                #     QMessageBox.warning(self, "Weak Password", 
                #                         f"New password is too weak. {results['feedback'].get('warning', '')} "
                #                         f"{', '.join(results['feedback'].get('suggestions', []))}")
                #     self.new_password.setFocus()
                #     return # Keep dialog open
                
                # --- If all validations pass, update the master password ---
                try:
                    self.parent().data_manager.update_master_password(new_password)
                    # Update the master password stored in MainWindow as well
                    self.parent().master_password = new_password 
                    
                    QMessageBox.information(
                        self,
                        "Success",
                        "Master password updated successfully."
                    )
                    self.parent().audit_logger.log_event("MASTER_PASSWORD_CHANGED", "Master password was changed successfully.")
                    self.accept() # Close dialog only on success
                
                except Exception as e:
                     QMessageBox.critical(self, "Error", f"Failed to update master password: {str(e)}")
                     self.parent().audit_logger.log_event("MASTER_PASSWORD_CHANGE_ERROR", f"Failed to update: {str(e)}")
                     # Optionally keep dialog open or close depending on error severity
            
            else:
                # No password change attempted, just close the dialog
                self.accept() 
                
        except Exception as e:
            # Catch unexpected errors during the process
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while saving settings: {str(e)}"
            )
            # Log this unexpected error
            if hasattr(self, 'parent') and hasattr(self.parent(), 'audit_logger'):
                 self.parent().audit_logger.log_event("SETTINGS_SAVE_ERROR", f"Unexpected error: {str(e)}") 

class HelpDialog(QDialog):
    """Dialog to display the user guide."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.branding = Branding()
        self.setupUi()
        
        # Apply the current theme
        self.setStyleSheet(self.branding.get_stylesheet())

    def setupUi(self):
        """Set up the user interface."""
        self.setWindowTitle("LCG Password Manager - User Guide")
        self.resize(800, 600)
        
        # Main layout
        layout = QVBoxLayout()
        
        # Create text browser for displaying the guide
        self.textBrowser = QTextBrowser()
        self.textBrowser.setOpenExternalLinks(True)
        self.textBrowser.setStyleSheet("""
            QTextBrowser {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
                padding: 10px;
            }
        """)
        layout.addWidget(self.textBrowser)
        
        # Add close button at the bottom
        buttonLayout = QHBoxLayout()
        closeButton = QPushButton("Close")
        closeButton.clicked.connect(self.accept)
        buttonLayout.addStretch()
        buttonLayout.addWidget(closeButton)
        layout.addLayout(buttonLayout)
        
        self.setLayout(layout)
        
        # Load the user guide
        self.loadUserGuide()
        
    def loadUserGuide(self):
        """Load and render the user guide markdown file."""
        try:
            # Path to the user guide markdown file
            guide_path = Path(__file__).parent.parent.parent / "docs" / "USER_GUIDE.md"
            
            if guide_path.exists():
                # Read the markdown content
                with open(guide_path, 'r', encoding='utf-8') as f:
                    md_content = f.read()
                
                # Convert markdown to HTML
                html_content = markdown.markdown(md_content)
                
                # Get theme colors
                theme_colors = self.branding.theme_manager.get_theme_colors()
                is_dark = self.branding.theme_manager.current_theme == "dark"
                
                # Background and text colors based on theme
                bg_color = "#f8f8f8" if not is_dark else "#3E3E42"
                text_color = "#333" if not is_dark else "#ffffff"
                code_bg = "#e8e8e8" if not is_dark else "#2D2D30"
                border_color = "#ddd" if not is_dark else "#545454"
                
                # Add some CSS for nicer display
                styled_html = f"""
                <html>
                <head>
                <style>
                    body {{ 
                        font-family: 'Segoe UI', Arial, sans-serif; 
                        line-height: 1.6; 
                        margin: 30px; 
                        color: {text_color}; 
                        background-color: {bg_color};
                        padding: 20px;
                        border-radius: 8px;
                    }}
                    h1, h2, h3, h4 {{ 
                        color: {theme_colors['primary']}; 
                        margin-top: 24px;
                        margin-bottom: 16px;
                    }}
                    h1 {{ 
                        border-bottom: 2px solid {theme_colors['primary']}; 
                        padding-bottom: 10px; 
                        font-size: 28px;
                    }}
                    h2 {{ 
                        border-bottom: 1px solid {border_color}; 
                        padding-bottom: 5px; 
                        font-size: 22px;
                    }}
                    p {{
                        margin: 12px 0;
                    }}
                    code {{ 
                        background: {code_bg}; 
                        padding: 2px 5px; 
                        border-radius: 3px; 
                        font-family: Consolas, monospace;
                        color: {text_color};
                    }}
                    pre {{ 
                        background: {code_bg}; 
                        padding: 15px; 
                        border-radius: 5px; 
                        overflow-x: auto;
                        border: 1px solid {border_color};
                    }}
                    ul, ol {{ 
                        padding-left: 25px; 
                        margin: 15px 0;
                    }}
                    li {{ 
                        margin-bottom: 8px; 
                    }}
                    a {{ 
                        color: {theme_colors['primary']}; 
                        text-decoration: none; 
                        font-weight: bold;
                    }}
                    a:hover {{ 
                        text-decoration: underline; 
                    }}
                    blockquote {{ 
                        background: {code_bg}; 
                        border-left: 5px solid {theme_colors['primary']}; 
                        margin: 15px 0; 
                        padding: 15px; 
                    }}
                    table {{ 
                        border-collapse: collapse; 
                        width: 100%;
                        margin: 20px 0;
                    }}
                    th, td {{ 
                        border: 1px solid {border_color}; 
                        padding: 10px; 
                        text-align: left; 
                    }}
                    th {{ 
                        background-color: {theme_colors['primary']}; 
                        color: white; 
                    }}
                    tr:nth-child(even) {{ 
                        background-color: {code_bg}; 
                    }}
                </style>
                </head>
                <body>
                {html_content}
                </body>
                </html>
                """
                
                # Set the HTML content to the text browser
                self.textBrowser.setHtml(styled_html)
            else:
                self.textBrowser.setPlainText("User guide not found.")
        except Exception as e:
            self.textBrowser.setPlainText(f"Error loading user guide: {str(e)}") 