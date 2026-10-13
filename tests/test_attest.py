"""Attestation roundtrip, tamper detection and malformed-input rejection."""

import copy

import pytest

from engine.attest import (
    build_payload,
    sign_attestation,
    verify_attestation,
)

_KEY = "test-key-123"
_COVERAGE = {
    "files_scanned": 3,
    "files_skipped": 0,
    "findings_total": 1,
    "ml_reason": "disabled",
}


def _payload():
    return build_payload(subject="dummy", output_format="cbom",
                         coverage=dict(_COVERAGE), report_digest="abc123")


def test_roundtrip_verifies():
    att = sign_attestation(_payload(), _KEY)
    assert att["digest"] and att["signature"]
    assert att["scanner_version"]
    assert att["timestamp"]
    assert verify_attestation(att, _KEY) is True


def test_tampered_payload_fails():
    att = sign_attestation(_payload(), _KEY)
    bad = copy.deepcopy(att)
    bad["payload"]["report_digest"] = "tampered"
    assert verify_attestation(bad, _KEY) is False


def test_tampered_signature_fails():
    att = sign_attestation(_payload(), _KEY)
    bad = copy.deepcopy(att)
    bad["signature"] = "0" * 64
    assert verify_attestation(bad, _KEY) is False


def test_wrong_key_fails():
    att = sign_attestation(_payload(), _KEY)
    assert verify_attestation(att, "other-key") is False


def test_missing_envelope_field_rejected():
    att = sign_attestation(_payload(), _KEY)
    for field in ("payload", "digest", "signature",
                  "scanner", "scanner_version", "timestamp"):
        bad = {k: v for k, v in att.items() if k != field}
        with pytest.raises(ValueError):
            verify_attestation(bad, _KEY)


def test_missing_payload_field_rejected():
    att = sign_attestation(_payload(), _KEY)
    for field in ("subject", "format", "coverage", "report_digest"):
        bad = copy.deepcopy(att)
        del bad["payload"][field]
        with pytest.raises(ValueError):
            verify_attestation(bad, _KEY)


def test_empty_key_rejected():
    with pytest.raises(ValueError):
        sign_attestation(_payload(), "")
    att = sign_attestation(_payload(), _KEY)
    with pytest.raises(ValueError):
        verify_attestation(att, "")


def test_cli_attestation_signed_via_env_key(tmp_path, monkeypatch):
    """A scan with INDRAMESH_ATTEST_KEY set writes a sidecar that verifies."""
    import hashlib
    import json

    from cli import _write_attestation

    report = tmp_path / "indramesh_report.json"
    report.write_text("{\"ok\": true}", encoding="utf-8")
    monkeypatch.setenv("INDRAMESH_ATTEST_KEY", _KEY)

    path = _write_attestation(str(tmp_path), "dummy", "cbom", dict(_COVERAGE),
                              str(report), None)
    assert path is not None
    att = json.loads((tmp_path / "indramesh_attestation.json").read_text(encoding="utf-8"))
    assert verify_attestation(att, _KEY) is True
    expected = hashlib.sha256(report.read_bytes()).hexdigest()
    assert att["payload"]["report_digest"] == expected


def test_cli_attestation_skips_visibly_without_key(tmp_path, monkeypatch, capsys):
    """No key -> no sidecar and a visible skip; never an unsigned 'attestation'."""
    from cli import _write_attestation

    report = tmp_path / "indramesh_report.json"
    report.write_text("{\"ok\": true}", encoding="utf-8")
    monkeypatch.delenv("INDRAMESH_ATTEST_KEY", raising=False)

    path = _write_attestation(str(tmp_path), "dummy", "cbom", dict(_COVERAGE),
                              str(report), None)
    assert path is None
    assert not (tmp_path / "indramesh_attestation.json").exists()
    assert "skipped" in capsys.readouterr().out
