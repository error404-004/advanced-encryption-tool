ADVANCED ENCRYPTION TOOL

*COMPANY* - CODTECH IT SOLUTIONS

*NAME* - DEEPAYAN DEY

*INTERN ID* - CT04DL977

*DOMAIN* - CYBER SECURITY AND ETHICAL HACKING

*DURATION* - 4 WEEKS

*MENTOR* - NEELA SANTOSH
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Advanced Encryption Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/advanced_encryption_tool/python-package.yml?branch=main)](https://github.com/yourusername/advanced_encryption_tool/actions)

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

```bash
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

advanced_encryption_tool/
│
├── src/
│   ├── main.py                # Entry point (CLI & GUI)
│   └── encryption/            # Core encryption modules
│       ├── aes_gcm.py
│       ├── cloud_kms.py
│       ├── hsm_support.py
│       └── utils.py
│   └── gui/                   # GUI interface components
│       └── interface.py
│
├── tests/                     # Unit tests
│
├── requirements.txt
├── setup.py
└── README.md

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
