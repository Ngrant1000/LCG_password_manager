# LCG Password Manager

Enterprise-grade password management solution with military-grade encryption and comprehensive audit logging. Built on PySide6 with a focus on security, performance, and maintainability.

## Security Architecture

### Encryption & Key Management
- AES-256 encryption with PBKDF2-HMAC-SHA256 key derivation
- Unique salt per vault (32 bytes) with secure random generation
- Memory-safe operations with secure wiping of sensitive data
- No password recovery mechanism - zero-knowledge design

### Access Control
- Master password protection with configurable complexity requirements
- Login attempt throttling (5 attempts) with 60-second lockout
- Auto-lock on configurable inactivity timeout
- Secure clipboard management with auto-clearing

### Audit Logging
- Tamper-evident encrypted audit logs
- Event tracking for:
  - Authentication attempts (success/failure)
  - Vault operations (lock/unlock)
  - Entry modifications (add/edit/delete)
  - Sensitive data access (username/password copies)
- Log rotation and automatic cleanup
- Integrity verification on each log access

## Technical Features

### Core Components
- **Data Manager**: Secure vault operations with integrity checks
- **Encryption Utils**: Cryptographic operations and key management
- **Audit Logger**: Secure event logging with tamper detection
- **GUI Layer**: PySide6-based interface with security-first design

### Security Measures
- Secure file permissions (600 on Unix, owner-only on Windows)
- Memory-safe operations with secure wiping
- Input validation and sanitization
- Rate limiting and brute force protection
- Clipboard security with auto-clearing

## Installation

### Dependencies
```bash
pip install -r requirements.txt
```

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/lcg-password-manager.git

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"

# Run tests
python scripts/run_tests.py

# Start application
python main.py
```

### Testing
```bash
# Run all tests
python scripts/run_tests.py

# Run unit tests only
python scripts/run_tests.py --unit

# Run integration tests only
python scripts/run_tests.py --integration

# Run tests with coverage
python scripts/run_tests.py --coverage

# Run tests in parallel
python scripts/run_tests.py --parallel
```

### Packaging
```bash
# Package all formats (wheel, sdist, executable)
python scripts/package.py

# Package specific format
python scripts/package.py --format wheel
python scripts/package.py --format sdist
python scripts/package.py --format pyinstaller

# Clean build artifacts and package
python scripts/package.py --clean

# Run tests before packaging
python scripts/package.py --test
```

### Production Build
```bash
# Build executable
python scripts/package.py --format pyinstaller
```

## Security Considerations

### Data Storage
- Vault location: `%APPDATA%/LCGPasswordManager/user_vault.dat`
- Audit logs: `%APPDATA%/LCGPasswordManager/audit.log`
- All files encrypted with AES-256
- Secure file permissions enforced

### Memory Safety
- Sensitive data wiped from memory after use
- Secure string handling with zero-copy where possible
- Clipboard contents cleared after 15 seconds
- No password recovery mechanism

### Audit Logging
- Logs encrypted with master password
- Tamper-evident design with integrity checks
- Automatic rotation at 10,000 entries
- 30-day retention policy
- Event types tracked:
  - `LOGIN_SUCCESS`: Successful authentication
  - `LOGIN_FAILURE`: Failed login attempts
  - `VAULT_LOCK`: Vault auto-lock events
  - `VAULT_UNLOCK`: Manual unlock events
  - `ENTRY_ADD`: New entry creation
  - `ENTRY_DELETE`: Entry deletion
  - `USERNAME_COPY`: Username clipboard operations
  - `PASSWORD_COPY`: Password clipboard operations

## Documentation

- [User Guide](USER_GUIDE.md) - Operational procedures
- [Rollout Plan](ROLLOUT_PLAN.md) - Deployment strategy
- [Security Protocol](SECURITY_PROTOCOL.md) - Security implementation details

## License

LGPL v3.0 - See [LICENSE](LICENSE) for details.

## Security Reporting

For security vulnerabilities, please email security@yourdomain.com
Do not create public issues for security-related concerns. 