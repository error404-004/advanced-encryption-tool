ADVANCED ENCRYPTION TOOL

*COMPANY* - CODTECH IT SOLUTIONS

*NAME* - DEEPAYAN DEY

*INTERN ID* - CT04DL977

*DOMAIN* - CYBER SECURITY AND ETHICAL HACKING

*DURATION* - 4 WEEKS

*MENTOR* - NEELA SANTOSH
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Advanced Encryption Tool

## OUTPUT
![Image](https://github.com/user-attachments/assets/48bfb500-153b-4b7d-b2bd-8da67061f3cb)

![Image](https://github.com/user-attachments/assets/6b2eac9f-5120-473c-9206-969aa807ee13)

![Image](https://github.com/user-attachments/assets/b4bf8c55-ebbc-4370-899d-35b560506087) 

---

## Overview

**Advanced Encryption Tool** is a robust Python-based AES-256-GCM encryption utility designed for modern security needs. It supports:

- **Password-based encryption** with strong PBKDF2 key derivation.
- **Cloud KMS integration** (currently AWS KMS) for centralized key management.
- **Hardware token support** via PKCS#11 (HSMs, TPMs).
- **Secure large-file encryption** with streaming chunk processing.
- **Cross-platform GUI** built with PyQt6 for ease of use.
- Extensible architecture for integrating additional KMS providers or hardware tokens.

This project is ideal for security-conscious users and organizations requiring encrypted file storage with enterprise-grade key management.

---

## Features

- AES-256 encryption in Galois/Counter Mode (GCM) for confidentiality and integrity.
- Flexible key management: password, cloud KMS, or direct keys.
- Secure file format with versioning and metadata.
- Audit logging for encryption/decryption operations.
- Support for hardware security modules via PyKCS11.
- Unit tested with pytest for reliability.

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Recommended: Virtual environment for isolation

### Using `pip`

bash
pip install -r requirements.txt



Or install directly from GitHub:

pip install git+https://github.com/error404-004/advanced_encryption_tool.git

Usage
Command Line Interface (CLI)
Basic usage example:

python -m src.main --help

Encrypt a file with password:
python -m src.main encrypt --input secret.txt --output secret.enc --password "StrongPass123!"

Decrypt a file:
python -m src.main decrypt --input secret.enc --output secret_decrypted.txt --password "StrongPass123!"

Graphical User Interface (GUI)
Launch the GUI:
python -m src.main

Project Structure:
📁 AET/
├── __init__.py
├── __init__1.py
├── __init__2.py
├── aes_gcm.py              # AES-GCM encryption engine
├── aws_kms.py              # AWS KMS integration
├── fips_validator.py       # FIPS compliance checks
├── hsm_support.py          # HSM (Hardware Security Module) support
├── interface.py            # Common interface for encryption engines
├── main.py                 # Main CLI or entry point

📄 .gitignore
📄 pyproject.toml           # Project metadata and dependencies (if using Poetry)
📄 README.md
📄 requirements.txt         # List of Python dependencies
📄 setup.py                 # Setup script for pip installation

🧪 Tests
├── test_aes_gcm.py         # Tests for AES-GCM functionality
├── test_aws_kms.py         # Tests for AWS KMS module
├── test_fips_validator.py  # Tests for FIPS validator
├── test_hsm_support.py     # Tests for HSM support
├── test_utils.py           # Tests for utilities

🛠️ utils.py                 # Utility functions
---

Development & Testing
Run all unit tests with:
pytest tests/


Security Considerations:

Always use strong, unique passwords for password-based encryption.
Protect access to KMS credentials and hardware tokens.
The tool securely wipes sensitive keys from memory where possible.
This software is not a substitute for a full security audit.

Contributing:
Contributions, issues, and feature requests are welcome! Please open a GitHub issue or submit a pull request.


Acknowledgments
PyCryptodome for cryptographic primitives.

boto3 for AWS KMS integration.

PyKCS11 for HSM support.

PyQt6 for GUI.



Contact
Created by Deepayan Dey – feel free to reach out!
