import unittest
from unittest.mock import patch, MagicMock
from aws_kms import AWSKMSClient
from botocore.exceptions import ClientError

class TestAWSKMSClient(unittest.TestCase):
    def setUp(self):
        self.kms_client = AWSKMSClient(region_name="us-east-1")
        self.test_key_id = "alias/test-key"

    @patch("boto3.client")
    def test_generate_data_key_success(self, mock_boto_client):
        mock_kms = MagicMock()
        mock_boto_client.return_value = mock_kms
        mock_kms.generate_data_key.return_value = {
            'Plaintext': b'plaintextkeybytes'*2,
            'CiphertextBlob': b'encryptedkeybytes'
        }

        plaintext, ciphertext = self.kms_client.generate_data_key(self.test_key_id)
        self.assertIsInstance(plaintext, bytes)
        self.assertIsInstance(ciphertext, bytes)
        self.assertEqual(len(plaintext), 32)  # AES-256 key length

    @patch("boto3.client")
    def test_generate_data_key_failure(self, mock_boto_client):
        mock_kms = MagicMock()
        mock_boto_client.return_value = mock_kms
        mock_kms.generate_data_key.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}}, "GenerateDataKey"
        )

        with self.assertRaises(RuntimeError) as context:
            self.kms_client.generate_data_key(self.test_key_id)
        self.assertIn("Failed to generate data key", str(context.exception))

    @patch("boto3.client")
    def test_decrypt_data_key_success(self, mock_boto_client):
        mock_kms = MagicMock()
        mock_boto_client.return_value = mock_kms
        mock_kms.decrypt.return_value = {
            'Plaintext': b'plaintextkeybytes'*2
        }

        plaintext = self.kms_client.decrypt_data_key(b'encryptedkeybytes')
        self.assertIsInstance(plaintext, bytes)
        self.assertEqual(len(plaintext), 32)

    @patch("boto3.client")
    def test_decrypt_data_key_failure(self, mock_boto_client):
        mock_kms = MagicMock()
        mock_boto_client.return_value = mock_kms
        mock_kms.decrypt.side_effect = ClientError(
            {"Error": {"Code": "InvalidCiphertextException", "Message": "Invalid ciphertext"}}, "Decrypt"
        )

        with self.assertRaises(RuntimeError) as context:
            self.kms_client.decrypt_data_key(b'encryptedkeybytes')
        self.assertIn("Failed to decrypt data key", str(context.exception))

if __name__ == "__main__":
    unittest.main()