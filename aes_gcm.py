import os, logging
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoError(Exception):
    """Custom exception for encryption errors."""
    pass

class EncryptionEngine:
    """
    AES-GCM encryption engine with support for different key sources.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def derive_key(self, password: bytes, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """
        Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
        A new random 16-byte salt is generated if not provided.
        """
        if salt is None:
            salt = os.urandom(16)  # cryptographically secure random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key, salt

    def encrypt_file(self, in_filename: str, out_filename: str,
                     key: bytes, salt: Optional[bytes] = None,
                     associated_data: Optional[bytes] = None):
        """
        Encrypts the file at in_filename with AES-256-GCM and writes to out_filename.
        If a salt is given (from derive_key), it is prepended to the output.
        Associated data (AAD) can be included for authentication.
        """
        try:
            if isinstance(key, str):
                key = key.strip().lower()
                if len(key) != 64 or not all(c in '0123456789abcdef' for c in key):
                    raise CryptoError("Key must be a valid 64-character hex string (32 bytes)")
                key = bytes.fromhex(key)

            if len(key) != 32:
                raise CryptoError("Key must be 32 bytes (256 bits) long")

            iv = os.urandom(12)  # 96-bit nonce
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            with open(in_filename, 'rb') as fin, open(out_filename, 'wb') as fout:
                if salt:
                    fout.write(salt)
                fout.write(iv)

                while True:
                    chunk = fin.read(64 * 1024)
                    if not chunk:
                        break
                    fout.write(encryptor.update(chunk))

                fout.write(encryptor.finalize())
                fout.write(encryptor.tag)
        except Exception as e:
            self.logger.exception("Encryption failed")
            raise CryptoError(f"Encryption failed: {e}") from e
        finally:
            if isinstance(key, bytearray):
                for i in range(len(key)):
                    key[i] = 0
            key = None

    def decrypt_file(self, in_filename: str, out_filename: str,
                     key: bytes, salt: Optional[bytes] = None,
                     associated_data: Optional[bytes] = None):
        """
        Decrypts the file at in_filename with AES-256-GCM and writes plaintext to out_filename.
        Expects the salt (if used) and IV to be at the start of the file.
        """
        try:
            if isinstance(key, str):
                key = key.strip().lower()
                if len(key) != 64 or not all(c in '0123456789abcdef' for c in key):
                    raise CryptoError("Key must be a valid 64-character hex string (32 bytes)")
                key = bytes.fromhex(key)

            if len(key) != 32:
                raise CryptoError("Key must be 32 bytes (256 bits) long")

            with open(in_filename, 'rb') as fin, open(out_filename, 'wb') as fout:
                if salt:
                    file_salt = fin.read(len(salt))
                    if salt != file_salt:
                        raise CryptoError("Salt mismatch or corruption")

                iv = fin.read(12)

                fin.seek(0, os.SEEK_END)
                file_size = fin.tell()
                ciphertext_len = file_size - (len(salt) if salt else 0) - 12 - 16
                fin.seek((len(salt) if salt else 0) + 12)
                ciphertext = fin.read(ciphertext_len)
                tag = fin.read(16)

                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                ).decryptor()

                if associated_data:
                    decryptor.authenticate_additional_data(associated_data)

                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                fout.write(plaintext)
        except Exception as e:
            self.logger.exception("Decryption failed")
            raise CryptoError(f"Decryption failed: {e}") from e
        finally:
            if isinstance(key, bytearray):
                for i in range(len(key)):
                    key[i] = 0
            key = None
