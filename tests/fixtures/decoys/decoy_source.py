"""Adversarial decoy fixture.

A labeled benchmark with adversarial decoys: measured, not asserted.

A crypto scanner's two failure modes are opposite, and a corpus that only contains true positives
measures neither. Every line here is designed to LOOK like a finding to a naive regex, and must
produce NO finding. The scanner's precision is only meaningful if this file yields nothing.

Decoy classes covered:
  1. algorithm names in PROSE and DOCSTRINGS
  2. algorithm names in a large base64/hex blob (the "secret" that is really a hash)
  3. security-themed identifiers that are not primitives (crypto_helper, SecureRandom naming)
  4. non-security uses of hash-like identifiers (etag, content-address, git blob)
  5. a filename that merely contains an algorithm name
"""

# 1. Prose. An algorithm named in a sentence is a mention, not a use.
#    NOTE: `import`/`from` are absent, so there is nothing for the AST pass to bind.
RSA_THE_ALGORITHM = "RSA"
DESCRIPTION = """
This service used RSA for key transport before the migration.
Historical notes: AES-256-GCM at rest, ECDSA for signatures, SHA-1 was retired in 2019.
The old config listed TLS_RSA_WITH_AES_128_GCM_SHA256 in its cipher list.
"""
DOCSTRING = '''
def legacy_note():
    """Originally wrapped RSA, ECDSA and SHA-1. Retained for the migration audit only."""
    return "ML-KEM-768, ML-DSA-44"
'''

# 2. A blob that is really a digest. A long hex run has the shape of key material to a regex.
FAKE_BLOB = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

# 3. Security-themed identifiers that are not primitives. `SecureRandom` is a CSPRNG name, not a
#    primitive in our registry; `crypto` is a domain word.
class CryptoHelper:
    def __init__(self, seed: int = 0):
        self.state = seed

    def secure_random_bytes(self, n: int) -> bytes:
        return bytes(n)


def make_crypto_helper():
    return CryptoHelper(1234)


# ===========================================================================================
# NON-DECOY -- the functions below DO call real cryptographic primitives.
#
# They sit here deliberately so the distinction is visible. `hashlib.sha256(...)` and
# `hashlib.md5(...)` are genuine invocations, and the decoy suite is ALLOWED to flag them. They are
# content-addressing and cache-key uses rather than security uses, but a static scanner cannot
# prove that from the call alone -- claiming it could would be a precision claim we cannot back.
# Flagging them is correct; judging their purpose is a review step, not a detection step.
# ===========================================================================================
import hashlib
import base64


def build_etag(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def cache_key(path: str) -> str:
    return hashlib.md5(path.encode()).hexdigest()


GIT_BLOB = "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
