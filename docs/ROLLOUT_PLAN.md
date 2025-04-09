# LCG Advisors - Secure Password Manager: Agile Rollout Plan

## 1. Project Goal

To develop and deploy a secure, user-friendly desktop application for LCG Advisors employees to manage their work-related usernames and passwords, replacing the insecure practice of storing them in plain text.

## 2. Approach: Agile (Scrum-like)

We will use an iterative and incremental approach, breaking the project into manageable sprints (typically 1-2 weeks, adjustable). Each sprint will deliver a potentially usable piece of functionality, allowing for feedback and adaptation.

**Key Principles:**
*   **Iterative Development:** Build the application in small, functional increments.
*   **Frequent Feedback:** Regularly review progress and gather input from stakeholders/testers.
*   **Adaptability:** Be prepared to adjust the plan based on feedback and changing requirements.
*   **Focus on Value:** Prioritize features that deliver the most security and usability benefit early on.

## 3. Roles (Assumed)

*   **Development Team:** AI Assistant & User (acting as developer).
*   **Product Owner (Recommended):** A designated person from LCG Advisors to prioritize features, provide feedback, and represent end-user needs.
*   **Stakeholders:** LCG Advisors management, IT department.
*   **Pilot Users:** A small group of employees for User Acceptance Testing (UAT).

## 4. Tools & Technology

*   **Language:** Python 3
*   **GUI Library:** PyQt6
*   **Encryption Library:** `cryptography`
*   **Data Format:** JSON (internally, before encryption)
*   **Packaging:** PyInstaller (or similar) for creating executables.
*   **Version Control:** Git (Highly Recommended - Set up a repository)

## 5. Feature Backlog (Initial)

*   Secure Master Password Setup & Login
*   Encrypted Local Data Storage (Salt + Encrypted Blob)
*   Add New Password Entries (Service, Username, Password)
*   View/List Existing Entries
*   Search/Filter Entries
*   Copy Username/Password to Clipboard (Securely)
*   Delete Existing Entries
*   Generate Strong Random Passwords
*   Basic Application Packaging
*   User Documentation

*(Future potential features: Import/Export, Folders/Categories, Secure Notes, Auto-lock, Cloud Sync - not in initial scope)*

## 6. Sprint Plan (Initial Estimate)

**Sprint 0: Foundation & Setup (Completed)**
*   Goal: Establish project structure and core security components.
*   Tasks:
    *   - [x] Initialize project directory.
    *   - [x] Create `main.py`, `gui.py`, `encryption_utils.py`, `requirements.txt`.
    *   - [x] Implement encryption/decryption functions (`encryption_utils.py`).
    *   - [x] Setup Python virtual environment.
    *   - [x] Install dependencies (`PyQt6`, `cryptography`).
    *   - [x] Initialize Git repository (Recommended).
*   Outcome: Basic project files, functional encryption utilities.

**Sprint 1: Core Data Management & Login UI (Completed)**
*   Goal: Implement secure data loading/saving and the initial login/setup screen.
*   Tasks:
    *   - [x] Create `data_manager.py` with functions to load/save the encrypted data file (handling salt, user-specific dir).
    *   - [x] Define data structure for entries (Implicitly JSON list of dicts via `data_manager`).
    *   - [x] Implement logic in `main.py` to check for data file existence.
    *   - [x] Develop `LoginWindow` UI (`gui.py`) for entering the master password.
    *   - [x] Develop initial Master Password setup UI (`SetupWindow` in `gui.py`).
    *   - [x] Connect UI actions to `data_manager` and `encryption_utils` for setup/login.
*   Outcome: Users can create a master password and data file, or log in if one exists. Data is stored encrypted in the user's app data directory. Application directs to the correct window on startup.

**Sprint 2: Basic CRUD Functionality & Main UI (Completed)**
*   Goal: Allow users to add, view, copy, and delete password entries.
*   Tasks:
    *   - [x] Develop basic `MainWindow` UI (`gui.py`) showing a list of entries (initially just service names).
    *   - [x] Implement "Add Entry" dialog (`AddEditDialog` in `gui.py`).
    *   - [x] Implement logic to save new/updated entries via `data_manager` from `MainWindow`.
    *   - [x] Display entries in the `MainWindow` list.
    *   - [x] Implement "Delete Entry" functionality (with confirmation).
    *   - [x] Implement "Copy Username" and "Copy Password" buttons.
    *   - [x] Connect `SetupWindow`/`LoginWindow` signals to open `MainWindow` upon success.
    *   - [x] Pass loaded data and master password to `MainWindow`.
*   Outcome: A functional core password manager where users can manage basic entries.

**Sprint 3: Password Generation & Search (Completed)**
*   Goal: Add password generation and entry searching capabilities.
*   Tasks:
    *   - [x] Implement password generation logic (configurable length, character types).
    *   - [x] Integrate password generator into the "Add/Edit Entry" dialog.
    *   - [x] Add a search bar to `MainWindow`.
    *   - [x] Implement filtering logic for the entry list based on search input (service/username).
    *   - [x] Refine UI elements based on initial usability (Tooltips, Show/Hide Password Detail).
*   Outcome: Enhanced usability with password generation, easy entry lookup, and minor UI polish.

**Sprint 4: Security Enhancements & Testing Prep (Completed)**
*   Goal: Implement additional security features and prepare for testing.
*   Tasks:
    *   - [x] Implement Clipboard Auto-Clear for passwords.
    *   - [x] Implement Master Password Strength Meter in `SetupWindow`.
    *   - [x] Implement Auto-Lock on Inactivity in `MainWindow`.
    *   - [x] Implement Login Throttling in `LoginWindow`.
    *   - [x] Create `tests` directory structure.
    *   - [x] Write initial unit tests (e.g., for encryption_utils, data_manager).
    *   - [x] Write initial integration tests (e.g., for login flow, add/delete flow).
    *   - [x] Conduct thorough internal testing (edge cases, error handling) - *Implicitly started, ongoing*
    *   - [x] Code Review/Refinement (Robust delete save, GUI naming)
*   Outcome: Application with enhanced security measures, a basic test suite, and minor code improvements.

**Sprint 5: Packaging, Documentation & UAT Prep (Completed)**
*   Goal: Package the application, write documentation, and prepare for UAT.
*   Tasks:
    *   - [x] Write basic user guide/instructions (`USER_GUIDE.md`).
    *   - [x] Use PyInstaller (or similar) to package the application into a distributable format (`dist/LCGPasswordManager.exe`).
    *   - [x] Prepare for User Acceptance Testing (UAT) - *Organizational steps assumed complete/next*.
*   Outcome: A distributable application package, basic documentation, ready for UAT.

**Sprint 6: Pilot Rollout (UAT) & Feedback**
*   Goal: Gather real-world feedback from a small group of users.
*   Tasks:
    *   - [ ] Deploy the packaged application to the pilot group.
    *   - [ ] Provide user guide and support channel for testers.
    *   - [ ] Collect feedback on usability, bugs, security perceptions, and installation.
    *   - [ ] Prioritize feedback and identify necessary fixes/improvements.
*   Outcome: UAT feedback, identified bugs, validation of core functionality.

**Sprint 7: Bug Fixing & Refinement**
*   Goal: Address critical issues found during UAT.
*   Tasks:
    *   - [ ] Fix bugs reported by pilot users.
    *   - [ ] Implement high-priority usability improvements.
    *   - [ ] Re-package and potentially re-test with the pilot group if changes are significant.
*   Outcome: A more robust and user-friendly application ready for wider deployment.

## 7. Rollout Strategy

1.  **Pilot Phase (Sprint 6):** Distribute to a small, tech-savvy group (5-10 users) from different departments if possible. Provide clear instructions and a feedback mechanism.
2.  **Wider Rollout (Post-Sprint 7):**
    *   **Communication:** Announce the new tool, its benefits (security), and the rollout schedule. Emphasize the importance of migrating away from plain text files.
    *   **Training:** Provide the user guide. Consider short optional demo sessions (virtual or in-person).
    *   **Distribution:** Make the packaged application easily accessible (e.g., shared network drive, software deployment tool).
    *   **Support:** Designate a point of contact or channel for questions and issues.
    *   **Migration:** Encourage users to manually migrate their existing passwords into the new tool. *Strongly advise deleting the old plain text files afterwards.*
3.  **Ongoing:** Collect further feedback, plan for future updates (Sprint 8+ based on backlog).

## 8. Risks & Considerations

*   **Master Password Security:** Users *must* choose strong master passwords and *must not* forget them. **There is no recovery mechanism** for the locally encrypted file if the password is lost. This needs clear communication.
*   **Data Backup:** The encrypted data file is stored locally. Users are responsible for backing up this file as part of their standard computer backup routine. The application itself won't handle backups.
*   **Phishing/Malware:** Standard endpoint security is still crucial. Malware on the user's machine could potentially compromise the application or capture the master password.
*   **Adoption Rate:** Encourage adoption through clear communication of security benefits and ease of use.
*   **Updates:** Plan how application updates will be distributed and installed.
*   **Platform Compatibility:** Initial focus is likely Windows. If macOS or Linux support is needed, testing and potential adjustments are required. 