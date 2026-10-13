"""Signed scan attestation for IndraMesh reports.

Produces a small JSON sidecar (``indramesh_attestation.json``) next to the
report artefacts so CI can prove *which* scanner produced a report and that
the payload was not modified afterwards.

Design:
  * The payload (coverage manifest + report digest + subject) is canonicalised
    with ``json.dumps(sort_keys=True, separators=(",", ":"))`` so the digest
    is stable across runs.
  * ``digest`` is sha256 over the canonical payload bytes.
  * ``signature`` is HMAC-SHA256 over the digest using the attestation key.
  * Verification recomputes both and compares with ``hmac.compare_digest``.
  * Missing-field inputs are rejected with ``ValueError`` (never ``KeyError``
    leaking internals, never a silent ``False`` for a malformed envelope).
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone

SCANNER_NAME = "IndraMesh"
SCANNER_VERSION = "0.2.0"
ATTESTATION_VERSION = 1

_REQUIRED_ENVELOPE_FIELDS = ("payload", "digest", "signature",
                             "scanner", "scanner_version", "timestamp")
_REQUIRED_PAYLOAD_FIELDS = ("subject", "format", "coverage", "report_digest")


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def payload_digest(payload: dict) -> str:
    """sha256 hex digest of the canonicalised payload."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    return hashlib.sha256(_canonical(payload)).hexdigest()


def sign_attestation(payload: dict, key) -> dict:
    """Sign ``payload`` and return the attestation envelope.

    ``key`` may be ``str`` or ``bytes``; empty keys are rejected.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        raise ValueError("key must be str or bytes")
    if not key_bytes:
        raise ValueError("key must not be empty")
    digest = payload_digest(payload)
    sig = hmac.new(key_bytes, digest.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return {
        "attestation_version": ATTESTATION_VERSION,
        "payload": payload,
        "digest": digest,
        "signature": sig,
        "scanner": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "timestamp": _utc_now(),
    }


def verify_attestation(attestation: dict, key) -> bool:
    """Return True iff the envelope is well-formed and the signature matches.

    Raises ``ValueError`` when required fields are missing or malformed so
    callers can distinguish "tampered" (False) from "malformed" (error).
    """
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be a dict")
    missing = [f for f in _REQUIRED_ENVELOPE_FIELDS if f not in attestation]
    if missing:
        raise ValueError(f"attestation missing fields: {', '.join(missing)}")
    payload = attestation["payload"]
    if not isinstance(payload, dict):
        raise ValueError("attestation payload must be a dict")
    missing_p = [f for f in _REQUIRED_PAYLOAD_FIELDS if f not in payload]
    if missing_p:
        raise ValueError(f"payload missing fields: {', '.join(missing_p)}")
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        raise ValueError("key must be str or bytes")
    if not key_bytes:
        raise ValueError("key must not be empty")
    expected_digest = payload_digest(payload)
    if not hmac.compare_digest(str(attestation["digest"]), expected_digest):
        return False
    expected_sig = hmac.new(key_bytes, expected_digest.encode("utf-8"),
                            hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(attestation["signature"]), expected_sig)


def build_payload(*, subject: str, output_format: str,
                  coverage: dict, report_digest: str) -> dict:
    """Build the standard attestation payload from scan outputs."""
    if not isinstance(coverage, dict):
        raise ValueError("coverage must be a dict")
    return {
        "subject": subject,
        "format": output_format,
        "coverage": coverage,
        "report_digest": report_digest,
    }
