import unittest
import os
import utils

class TestUtils(unittest.TestCase):

    def test_secure_wipe(self):
        # Create a temporary file with data
        filename = 'temp_test_file.txt'
        data = b'sensitive data to be wiped'
        with open(filename, 'wb') as f:
            f.write(data)

        # Wipe file content securely
        utils.secure_wipe(filename)

        # Check file exists and size is zero or file is removed
        self.assertTrue(os.path.exists(filename))
        self.assertEqual(os.path.getsize(filename), 0)

        # Clean up
        os.remove(filename)

    def test_pkcs7_pad_and_unpad(self):
        # Test padding to block size
        block_size = 16
        data = b'YELLOW SUBMARINE'
        padded = utils.pkcs7_pad(data, block_size)
        self.assertEqual(len(padded) % block_size, 0)

        # Unpad should return original data
        unpadded = utils.pkcs7_unpad(padded)
        self.assertEqual(unpadded, data)

        # Unpad should raise ValueError on invalid padding
        with self.assertRaises(ValueError):
            utils.pkcs7_unpad(b'wrongpadding\x05\x05\x05')

    def test_bytes_to_hex_and_back(self):
        data = b'\x00\x01\x02\x03\x04'
        hex_str = utils.bytes_to_hex(data)
        self.assertIsInstance(hex_str, str)
        data_back = utils.hex_to_bytes(hex_str)
        self.assertEqual(data_back, data)

if __name__ == '__main__':
    unittest.main()