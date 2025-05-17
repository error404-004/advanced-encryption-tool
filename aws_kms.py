import boto3
from botocore.exceptions import ClientError
import logging

class KmsError(Exception):
    """Custom exception for AWS KMS errors."""
    pass

class AwsKmsClient:
    """
    AWS KMS client for generating and decrypting data keys (AES-256) using boto3.
    """
    def __init__(self, key_id: str, region_name: str = None, profile_name: str = None):
        self.logger = logging.getLogger(__name__)
        self.key_id = key_id
        try:
            session_params = {}
            if profile_name:
                session_params['profile_name'] = profile_name
            session = boto3.Session(**session_params)
            self.client = session.client('kms', region_name=region_name)
        except Exception as e:
            self.logger.exception("Failed to initialize AWS KMS client")
            raise KmsError(f"Failed to initialize AWS KMS client: {e}")

    def generate_data_key(self, context: dict = None) -> tuple[bytes, bytes]:
        """
        Generate a 256-bit data key. Returns (plaintext_key, encrypted_key_blob).
        """
        try:
            params = {
                'KeyId': self.key_id,
                'KeySpec': 'AES_256'
            }
            if context:
                params['EncryptionContext'] = context
            response = self.client.generate_data_key(**params)
            plaintext_key = response['Plaintext']
            encrypted_blob = response['CiphertextBlob']
            return plaintext_key, encrypted_blob
        except ClientError as e:
            self.logger.error("KMS generate_data_key failed: %s", e)
            raise KmsError(f"KMS generate_data_key failed: {e}") from e

    def decrypt_data_key(self, encrypted_blob: bytes, context: dict = None) -> bytes:
        """
        Decrypts the data key. Returns plaintext key bytes.
        """
        try:
            params = { 'CiphertextBlob': encrypted_blob }
            if context:
                params['EncryptionContext'] = context
            response = self.client.decrypt(**params)
            plaintext_key = response['Plaintext']
            return plaintext_key
        except ClientError as e:
            self.logger.error("KMS decrypt_data_key failed: %s", e)
            raise KmsError(f"KMS decrypt_data_key failed: {e}") from e