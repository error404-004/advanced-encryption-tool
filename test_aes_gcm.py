import os
import tempfile
import pytest
from aes_gcm import generate_key, encrypt_file, decrypt_file

def test_generate_key_length():
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32  # 256 bits

def test_encrypt_decrypt_file_roundtrip():
    key = generate_key()

    with tempfile.TemporaryDirectory() as tempdir:
        plaintext_path = os.path.join(tempdir, "plaintext.txt")
        encrypted_path = os.path.join(tempdir, "encrypted.enc")
        decrypted_path = os.path.join(tempdir, "decrypted.txt")

        # Create a test plaintext file
        with open(plaintext_path, "wb") as f:
            f.write(b"This is a test message.")

        # Encrypt the file
        encrypt_file(key, plaintext_path, encrypted_path)
        assert os.path.exists(encrypted_path)

        # Decrypt it back
        decrypt_file(key, encrypted_path, decrypted_path)
        assert os.path.exists(decrypted_path)

        # Compare original and decrypted
        with open(plaintext_path, "rb") as f1, open(decrypted_path, "rb") as f2:
            assert f1.read() == f2.read()

def test_decrypt_with_wrong_key_fails():
    key = generate_key()
    wrong_key = generate_key()

    with tempfile.TemporaryDirectory() as tempdir:
        plaintext_path = os.path.join(tempdir, "plain.txt")
        encrypted_path = os.path.join(tempdir, "enc.bin")
        decrypted_path = os.path.join(tempdir, "fail.txt")

        with open(plaintext_path, "wb") as f:
            f.write(b"Secret stuff")

        encrypt_file(key, plaintext_path, encrypted_path)

        with pytest.raises(Exception):
            decrypt_file(wrong_key, encrypted_path, decrypted_path)