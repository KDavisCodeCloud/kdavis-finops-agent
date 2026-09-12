"""
tests/test_encryption.py
Tests for security/encryption.py -- the shared Fernet encrypt/decrypt
helper used by core/azure_onboarding.py to store a tenant's Azure
Service Principal client_secret at rest. Mirrors kdavis-agentic-
platform's tests/test_encryption.py, the file this module was copied
from.
"""

from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet, InvalidToken

from security import encryption


@pytest.fixture(autouse=True)
def _encryption_key():
    key = Fernet.generate_key().decode()
    with patch.dict("os.environ", {"ENCRYPTION_KEY": key}):
        yield key


class TestEncryptDecrypt:
    def test_round_trip(self):
        ciphertext = encryption.encrypt("azure-client-secret-value")
        assert encryption.decrypt(ciphertext) == "azure-client-secret-value"

    def test_ciphertext_is_not_plaintext(self):
        ciphertext = encryption.encrypt("azure-client-secret-value")
        assert ciphertext != "azure-client-secret-value"
        assert "azure-client-secret-value" not in ciphertext

    def test_decrypt_garbage_raises(self):
        with pytest.raises(InvalidToken):
            encryption.decrypt("not-a-real-fernet-token")


class TestMissingKey:
    def test_encrypt_without_key_raises(self):
        with patch.dict("os.environ", {"ENCRYPTION_KEY": ""}):
            with pytest.raises(EnvironmentError):
                encryption.encrypt("value")

    def test_decrypt_without_key_raises(self):
        with patch.dict("os.environ", {"ENCRYPTION_KEY": ""}):
            with pytest.raises(EnvironmentError):
                encryption.decrypt("value")
