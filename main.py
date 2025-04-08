# main.py

import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QTimer
# Import necessary GUI windows and data manager function
from gui import SetupWindow, LoginWindow, MainWindow
from data_manager import vault_exists, DEFAULT_VAULT_PATH
import os

# Need a global or class reference to keep MainWindow alive
main_window = None

# Custom class to handle signals between windows
class WindowManager(QObject):
    show_setup_signal = pyqtSignal()
    
    def __init__(self):
        super().__init__()

def show_main_window(vault_data, master_password):
    """Creates and shows the MainWindow."""
    global main_window
    # If an instance already exists (shouldn't happen with current flow, but good practice)
    if main_window and main_window.isVisible(): 
        main_window.raise_()
        main_window.activateWindow()
    else:
        main_window = MainWindow(vault_data, master_password)
        main_window.show()

def main():
    app = QApplication(sys.argv)
    
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