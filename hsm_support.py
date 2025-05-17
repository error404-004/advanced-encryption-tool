import PyKCS11
import logging
from PyKCS11 import PyKCS11Lib, PyKCS11Error, Mechanism

class HsmError(Exception):
    """Custom exception for HSM operations."""
    pass

class HsmClient:
    """
    HSM client using PKCS#11 (PyKCS11) for AES key operations.
    """
    def __init__(self, library_path: str, slot_index: int = 0, user_pin: str = None):
        self.logger = logging.getLogger(__name__)
        try:
            self.lib = PyKCS11Lib()
            self.lib.load(library_path)
            slots = self.lib.getSlotList(tokenPresent=True)
            if not slots:
                raise HsmError("No PKCS#11 slots available or token not present")
            slot = slots[slot_index]
            self.session = self.lib.openSession(slot, PyKCS11.CKF_RW_SESSION)
            if user_pin:
                self.session.login(user_pin)
        except PyKCS11Error as e:
            self.logger.exception("Failed to initialize HSM session")
            raise HsmError(f"HSM initialization error: {e}") from e

    def generate_aes_key(self, label: str, key_length: int = 32, persistent: bool = True):
        """
        Generate a new AES key on the HSM with given label.
        """
        try:
            template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
                (PyKCS11.CKA_VALUE_LEN, key_length),
                (PyKCS11.CKA_LABEL, label),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE if persistent else PyKCS11.CK_FALSE),
                (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            ]
            mech = Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
            key_handle = self.session.generateKey(template, mech)
            return key_handle
        except PyKCS11Error as e:
            self.logger.error("HSM key generation failed: %s", e)
            raise HsmError(f"HSM key generation failed: {e}") from e

    def find_key(self, label: str):
        """
        Find an AES key by label on the HSM.
        """
        try:
            keys = self.session.findObjects([
                (PyKCS11.CKA_LABEL, label),
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY)
            ])
            if not keys:
                raise HsmError(f"No key found with label {label}")
            return keys[0]
        except PyKCS11Error as e:
            self.logger.error("HSM find_key failed: %s", e)
            raise HsmError(f"HSM find_key failed: {e}") from e

    def encrypt(self, key_handle, plaintext: bytes, associated_data: bytes = b'') -> tuple[bytes, bytes]:
        """
        Encrypt data with AES-GCM on the HSM. Returns (iv, ciphertext_with_tag).
        """
        try:
            iv = bytes(self.session.generateRandom(12))
            mech = PyKCS11.AES_GCM_Mechanism(iv=iv, aad=associated_data, tagBits=128)
            ciphertext = self.session.encrypt(key_handle, plaintext, mech)
            return iv, bytes(ciphertext)
        except PyKCS11Error as e:
            self.logger.error("HSM encryption failed: %s", e)
            raise HsmError(f"HSM encryption failed: {e}") from e

    def decrypt(self, key_handle, iv: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
        """
        Decrypt data with AES-GCM on the HSM. Returns plaintext.
        """
        try:
            mech = PyKCS11.AES_GCM_Mechanism(iv=iv, aad=associated_data, tagBits=128)
            plaintext = self.session.decrypt(key_handle, ciphertext, mech)
            return bytes(plaintext)
        except PyKCS11Error as e:
            self.logger.error("HSM decryption failed: %s", e)
            raise HsmError(f"HSM decryption failed: {e}") from e

    def logout(self):
        """
        Logout and close the HSM session.
        """
        try:
            self.session.logout()
            self.session.closeSession()
        except PyKCS11Error as e:
            self.logger.warning("Error during HSM logout: %s", e)