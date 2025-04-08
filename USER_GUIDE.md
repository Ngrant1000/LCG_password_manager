# LCG Password Manager - User Guide

## 1. Introduction

Welcome to the LCG Password Manager! This secure desktop application helps you store and manage your work-related usernames and passwords safely on your computer. It replaces the need to save sensitive credentials in plain text files.

Your passwords are encrypted using a single **Master Password** that only you should know.

**Important Security Note:** The security of all your stored passwords depends entirely on the strength and secrecy of your Master Password. Choose a strong, unique Master Password and **never forget it**. There is no way to recover your passwords if you lose your Master Password.

## 2. First Time Setup

If this is the first time you are running the application, you will be prompted to create your Master Password:

1.  **Enter Master Password:** Type a strong, memorable password into the first field. The strength meter below will help you assess its quality (aim for "Good" or "Strong").
2.  **Confirm Master Password:** Re-type the exact same password in the second field.
3.  **Create Vault:** Once the passwords match and the strength is acceptable (score 2 or higher), the "Create Vault" button will become enabled. Click it.
4.  You will see a confirmation that the vault was created. The application will then open the main window.

Your encrypted password vault file (`user_vault.dat`) is stored securely within your user profile's application data directory (e.g., `C:\\Users\\YourUsername\\AppData\\Roaming\\LCGPasswordManager` on Windows).

## 3. Logging In

After the first setup, whenever you start the LCG Password Manager, you will see the Login screen:

1.  **Enter Master Password:** Type your Master Password into the field.
2.  **Unlock:** Click the "Unlock" button or press Enter.

**Login Lockout:** If you enter the incorrect password 5 times in a row, the login fields will be disabled for 60 seconds to prevent brute-force guessing. Wait for the timer to expire before trying again.

## 4. Main Window Overview

Once unlocked, the main window displays:

*   **Search Bar (Top Left):** Type here to filter the entry list.
*   **Entry List (Left):** Shows the "Service" names of your saved entries. Click an entry to view its details.
*   **Details Pane (Right):** Displays the Service, Username, and Password (initially hidden) for the selected entry.
*   **Action Buttons (Bottom Right):**
    *   `Add Entry`: Opens a dialog to save a new password.
    *   `Delete Entry`: Deletes the currently selected entry (requires confirmation).
    *   `Copy Username`: Copies the selected entry's username to the clipboard.
    *   `Copy Password`: Copies the selected entry's password to the clipboard (clipboard clears automatically after 15 seconds).
    *   `Show`/`Hide`: Toggles the visibility of the password in the details pane.

## 5. Adding a New Entry

1.  Click the "Add Entry" button.
2.  The "Add New Entry" dialog appears.
3.  **Service/Website:** Enter a descriptive name (e.g., "LCG Internal Portal", "Client X Database"). This field is mandatory.
4.  **Username:** Enter the username or email associated with the service.
5.  **Password:**
    *   Type the password directly. Click "Show" to temporarily view it.
    *   *Or*, use the **Password Generator**:
        *   Adjust the desired `Length` (default 16).
        *   Select the character types to include (Lowercase, Uppercase, Digits, Symbols - all default to on).
        *   Click the "Generate" button. A strong, random password will be placed in the password field.
6.  Click "OK" to save the new entry. Click "Cancel" to discard it.

## 6. Viewing and Selecting Entries

*   Click on any service name in the list on the left.
*   The details (Service, Username, Password \[Hidden]) will appear on the right.
*   To see the password for the selected entry, click the "Show" button next to the password label. Click "Hide" to conceal it again.

## 7. Copying Username or Password

1.  Select the desired entry from the list on the left.
2.  Click the "Copy Username" button to copy the username to your clipboard.
3.  Click the "Copy Password" button to copy the password to your clipboard.
    *   **Note:** For security, the password will be automatically removed from the clipboard after 15 seconds. Paste it where needed shortly after copying.

## 8. Deleting an Entry

1.  Select the entry you wish to delete from the list on the left.
2.  Click the "Delete Entry" button.
3.  A confirmation dialog will appear. Click "Yes" to permanently delete the entry, or "No" to cancel.

## 9. Searching Entries

*   Type keywords into the "Search Entries" bar at the top left.
*   The list will automatically filter to show only entries where the Service name or Username contains your search text (case-insensitive).
*   Clear the search bar to see all entries again.

## 10. Auto-Lock Feature

If you leave the LCG Password Manager open and inactive (no mouse movement or key presses within the window) for 15 minutes, it will automatically lock itself. You will need to re-enter your Master Password to unlock it and continue using it. This helps protect your vault if you step away from your computer.

---
Remember to keep your Master Password safe and secure! 