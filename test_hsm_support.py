import unittest
from hsm_support import HardwareTokenClient, PKCS11Client, TPMClient

class TestHardwareTokenClientBase(unittest.TestCase):
    def setUp(self):
        self.client = HardwareTokenClient()

    def test_generate_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.generate_data_key('token1')

    def test_decrypt_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.decrypt_data_key(b'wrapped_key', 'token1')

    def test_list_tokens_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.list_tokens()

class TestPKCS11Client(unittest.TestCase):
    def setUp(self):
        self.client = PKCS11Client()

    def test_generate_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.generate_data_key('token1')

    def test_decrypt_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.decrypt_data_key(b'wrapped_key', 'token1')

    def test_list_tokens_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.list_tokens()

class TestTPMClient(unittest.TestCase):
    def setUp(self):
        self.client = TPMClient()

    def test_generate_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.generate_data_key('token1')

    def test_decrypt_data_key_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.decrypt_data_key(b'wrapped_key', 'token1')

    def test_list_tokens_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.client.list_tokens()

if __name__ == '__main__':
    unittest.main()