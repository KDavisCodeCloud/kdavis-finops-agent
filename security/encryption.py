"""Shared Fernet encrypt/decrypt helper, keyed by the ENCRYPTION_KEY env var.

Same mechanism as kdavis-agentic-platform's security/encryption.py (copied
here rather than shared as a cross-repo dependency -- that's a separate,
proprietary repo). Used by core/azure_onboarding.py to store a tenant's
Azure Service Principal client_secret at rest -- the one credential in
this service's onboarding flow that's a real secret (AWS's external_id
is not, by design).
"""

import os

from cryptography.fernet import Fernet


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY", "")
    if not key:
        raise EnvironmentError("ENCRYPTION_KEY not set — cannot encrypt/decrypt")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()
