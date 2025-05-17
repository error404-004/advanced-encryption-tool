import unittest
from utils import FIPSValidator

class TestFIPSValidator(unittest.TestCase):
    def setUp(self):
        self.validator = FIPSValidator()

    def test_fips_mode_enabled(self):
        # Assuming is_fips_mode_enabled() returns True/False depending on system
        # For test purposes, mock or simulate as needed
        result = self.validator.is_fips_mode_enabled()
        self.assertIsInstance(result, bool)

    def test_validate_algorithm(self):
        # Assuming validate_algorithm() checks if an algorithm is FIPS compliant
        self.assertTrue(self.validator.validate_algorithm('AES'))
        self.assertFalse(self.validator.validate_algorithm('MD5'))
        self.assertFalse(self.validator.validate_algorithm('NonExistentAlgo'))

    def test_validate_key_length(self):
        # Test key length validation (e.g., AES-256 allowed, AES-128 allowed, others not)
        self.assertTrue(self.validator.validate_key_length('AES', 256))
        self.assertTrue(self.validator.validate_key_length('AES', 128))
        self.assertFalse(self.validator.validate_key_length('AES', 192))  # Depending on policy

if __name__ == "__main__":
    unittest.main()