# main.py

import sys
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt, QObject, Signal, QTimer
# Import necessary GUI windows and data manager function
from gui import SetupWindow, LoginWindow, MainWindow
from data_manager import vault_exists, DEFAULT_VAULT_PATH, initialize_audit_logger, get_audit_logger
from encryption_utils import generate_salt
import os

# Define the stylesheet
DARK_THEME_STYLESHEET = '''
QWidget {
    background-color: #282c34; /* Dark background */
    color: #abb2bf; /* Light grey text */
    font-family: Segoe UI, Arial, sans-serif; /* Modern font */
    font-size: 10pt;
}

QLabel {
    color: #abb2bf; /* Ensure labels use the default text color */
    background-color: transparent; /* Ensure labels have transparent background */
}

QLineEdit, QTextEdit, QSpinBox {
    background-color: #1e2127; /* Slightly darker background for inputs */
    color: #abb2bf;
    border: 1px solid #3b4048; /* Subtle border */
    border-radius: 4px;
    padding: 5px;
}

QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {
    border: 1px solid #61afef; /* Teal border on focus */
}

QPushButton {
    background-color: #61afef; /* Teal background */
    color: #1e2127; /* Dark text on teal button */
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    min-height: 16px; /* Ensure buttons have some height */
    font-weight: bold;
}

QPushButton:hover {
    background-color: #5295c7; /* Slightly darker teal on hover */
}

QPushButton:pressed {
    background-color: #4682b4; /* Even darker teal when pressed */
}

QPushButton:disabled {
    background-color: #4a505a; /* Greyed out background */
    color: #7f848e; /* Greyed out text */
}

/* Special styling for the 'First time?' link-like button */
/* Use object name selector */
QPushButton#setup_button {
    background-color: transparent;
    color: #61afef; /* Teal color for link */
    border: none;
    text-align: center; /* Or left/right as needed */
    padding: 4px; /* Smaller padding */
    font-weight: normal; /* Normal weight for link */
}
QPushButton#setup_button:hover {
    color: #82c3f9; /* Lighter teal on hover */
    text-decoration: underline;
}
QPushButton#setup_button:pressed {
    color: #5295c7;
}

/* Special styling for Show/Hide buttons */
/* Use object name selectors */
QPushButton#show_hide_button, QPushButton#show_pass_button {
    background-color: #4a505a; /* Grey background */
    color: #abb2bf;
    padding: 5px 8px; /* Smaller padding */
    min-height: 10px;
    font-weight: normal; /* Normal weight */
}
QPushButton#show_hide_button:hover, QPushButton#show_pass_button:hover {
    background-color: #5a606a;
}
QPushButton#show_hide_button:pressed, QPushButton#show_pass_button:pressed {
    background-color: #3b4048;
}
QPushButton#show_hide_button:checked, QPushButton#show_pass_button:checked { /* When 'Hide' is shown */
    background-color: #61afef; /* Teal when active/checked */
    color: #1e2127; /* Dark text */
}
QPushButton#show_hide_button:checked:hover, QPushButton#show_pass_button:checked:hover {
    background-color: #5295c7;
}


QListWidget {
    background-color: #1e2127; /* Darker background for list */
    border: 1px solid #3b4048;
    border-radius: 4px;
    color: #abb2bf; /* Default item text color */
    outline: 0; /* Remove focus outline */
}

QListWidget::item {
    padding: 5px;
    border-radius: 3px; /* Rounding for individual items */
}

QListWidget::item:selected {
    background-color: #61afef; /* Teal selection background */
    color: #1e2127; /* Dark text for selected item */
}

QListWidget::item:hover:!selected { /* Hover only when not selected */
    background-color: #3b4048; /* Subtle hover effect */
}


QProgressBar {
    border: 1px solid #3b4048;
    border-radius: 4px;
    text-align: center;
    background-color: #1e2127;
    color: #abb2bf; /* Show percentage text */
}

QProgressBar::chunk {
    background-color: #61afef; /* Teal progress chunk */
    border-radius: 3px;
    /* Margin creates spacing between chunks if needed */
    /* margin: 1px; */
}

QCheckBox {
    spacing: 8px; /* Space between checkbox and text */
}

QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #61afef;
    border-radius: 3px;
    background-color: #1e2127; /* Background of the box */
}

QCheckBox::indicator:unchecked:hover {
    border: 1px solid #82c3f9;
}

QCheckBox::indicator:checked {
    background-color: #61afef; /* Fill color when checked */
    /* You might need an image for a better check mark */
    /* image: url(path/to/check.svg); */
    /* border: none; */ /* Remove border if using image */
}

QCheckBox::indicator:checked:hover {
     background-color: #5295c7;
     border: 1px solid #5295c7;
}

QDialog {
    background-color: #282c34;
    border: 1px solid #3b4048; /* Add subtle border to dialogs */
}

QMessageBox {
    background-color: #282c34;
}

QMessageBox QLabel {
     color: #abb2bf;
     font-size: 10pt; /* Ensure consistent font size */
}

/* Style buttons inside QMessageBox */
QMessageBox QPushButton {
    background-color: #61afef;
    color: #1e2127; /* Dark text */
    border-radius: 4px;
    padding: 6px 12px; /* Slightly smaller padding for dialog buttons */
    min-width: 60px; /* Minimum width for dialog buttons */
    min-height: 14px;
    font-weight: bold;
}

QMessageBox QPushButton:hover {
    background-color: #5295c7;
}

QMessageBox QPushButton:pressed {
    background-color: #4682b4;
}

QToolTip {
    background-color: #1e2127;
    color: #abb2bf;
    border: 1px solid #3b4048;
    padding: 4px;
    border-radius: 3px;
    opacity: 230; /* Slightly transparent */
}
''' # End of the QSS string

# Need a global or class reference to keep MainWindow alive
main_window = None

# Custom class to handle signals between windows
class WindowManager(QObject):
    show_setup_signal = Signal()
    
    def __init__(self):
        super().__init__()

def show_main_window(vault_data, master_password):
    """Creates and shows the MainWindow."""
    global main_window
    
    # Initialize audit logger
    initialize_audit_logger(master_password, generate_salt())
    
    # Log successful login
    get_audit_logger().log_event(
        "LOGIN_SUCCESS",
        "User successfully logged in",
        sensitive=True
    )
    
    # If an instance already exists (shouldn't happen with current flow, but good practice)
    if main_window and main_window.isVisible(): 
        main_window.raise_()
        main_window.activateWindow()
    else:
        main_window = MainWindow(vault_data, master_password)
        main_window.show()

def main():
    app = QApplication(sys.argv)
    
    # Apply the stylesheet globally
    app.setStyleSheet(DARK_THEME_STYLESHEET)
    
    # Create window manager for signal handling
    window_manager = WindowManager()
    
    # Instantiate windows but don't show yet
    login_win = LoginWindow()
    setup_win = SetupWindow()
    
    # Connect signals
    # When login succeeds, pass data and password to show_main_window
    login_win.login_successful.connect(show_main_window)
    # When setup completes, pass password to show_main_window (data is empty list)
    setup_win.setup_complete.connect(lambda password: show_main_window([], password))
    
    # Connect the show_setup signal from LoginWindow directly to setup_win.show
    login_win.show_setup.connect(setup_win.show)
    
    # Connect window manager signals
    window_manager.show_setup_signal.connect(setup_win.show)
    
    # Variable to track if login was successful
    login_successful = False
    
    # Function to check if we need to show setup after login closes
    def on_login_closed():
        # We want a slight delay to allow the login_successful signal to be processed first
        nonlocal login_successful
        if not login_successful and not setup_win.isVisible():
            print("Login window closed without successful login. Showing setup window.")
            QTimer.singleShot(100, window_manager.show_setup_signal.emit)
    
    # Connect login window destroyed signal
    login_win.destroyed.connect(on_login_closed)
    
    # Update the login_successful flag when login is successful
    def on_login_success(data, password):
        nonlocal login_successful
        login_successful = True
    
    login_win.login_successful.connect(on_login_success)
    
    # Check if the vault file exists and show the appropriate initial window
    vault_path = DEFAULT_VAULT_PATH
    
    # Check if file exists and is a valid vault file
    is_valid_vault = False
    try:
        if vault_exists(vault_path):
            is_valid_vault = True
            print(f"Vault found at {vault_path}. Showing Login Window.")
            login_win.show()
        else:
            # Vault doesn't exist or is invalid
            if os.path.exists(vault_path):
                # File exists but is invalid (might be corrupted or empty)
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setWindowTitle("Invalid Vault File")
                msg.setText("Your vault file appears to be corrupted or invalid.")
                msg.setInformativeText("Would you like to create a new vault?")
                msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                response = msg.exec()
                
                if response == QMessageBox.StandardButton.Yes:
                    # User wants to create a new vault
                    print(f"Invalid vault at {vault_path}. Showing Setup Window.")
                    # Optionally backup or rename the corrupted file here
                    setup_win.show()
                else:
                    # User doesn't want to create a new vault, exit app
                    print("User chose not to create a new vault. Exiting.")
                    return
            else:
                # File doesn't exist, show setup
                print(f"Vault not found at {vault_path}. Showing Setup Window.")
                setup_win.show()
    except Exception as e:
        # Handle any unexpected errors
        print(f"Error checking vault: {e}")
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Error")
        msg.setText(f"An error occurred while checking your vault file: {e}")
        msg.setInformativeText("Would you like to create a new vault?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        response = msg.exec()
        
        if response == QMessageBox.StandardButton.Yes:
            setup_win.show()
        else:
            return

    sys.exit(app.exec())

if __name__ == "__main__":
    main() 