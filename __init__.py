# src/encryption/__init__.py

"""
Encryption submodule initializer for the Advanced Encryption Tool.

Includes AES-GCM encryption, cloud KMS integration, hardware security module (HSM)
support, utility functions, and FIPS compliance checks.
"""

from aes_gcm import AESGCMCipher
from aws_kms import CloudKMSClient
from hsm_support import HSMCipher
from utils import secure_wipe, bytes_to_hex, hex_to_bytes
from fips_validator import is_fips_mode_enabled, validate_library_fips_support, get_platform_fips_info