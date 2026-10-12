"""Tests for the X.509 certificate sensor (engine/certificates.py).

What is being defended here, and why each test can fail:

  * A certificate produces findings in the SAME schema as `engine/scanner.py`, with
    `evidence_class="observed"` -- a parsed artefact, not a capability.
  * The KeyUsage extension flows into `engine.purpose.resolve_purpose` and actually decides the
    primitive. Before this sensor existed, that branch of the resolver was unreachable from any
    real input; these tests are the proof that it now has one.
  * A dual-use KeyUsage resolves to `unresolved` and NO PQC target is named. A certificate that
    does not say what its key is for has not settled it, and a confident ML-KEM answer for an RSA
    signing certificate is the exact failure this tool criticises competitors for.
  * A corrupt certificate is recorded in `errors` and never raises. A scan that dies on one bad
    `.pem` is indistinguishable from a scan that found nothing.
  * A private key is never read, never stored and never reaches a finding; a certificate in the
    same file still is.
  * Scanning is idempotent, and the stdlib DER reader agrees with `cryptography` field for field.

NO BINARY FIXTURES ARE COMMITTED. Every certificate here is generated at test time, and the one
certificate `cryptography` refuses to produce (SHA-1 signed: version 46 rejects the hash) is
assembled byte by byte in `sha1_certificate()` and verified in pure Python -- the RSA
PKCS#1 v1.5 signature is checked against the public exponent before the fixture is used, and
`cryptography` is asserted to load it. An unverified blob in a test is a test that can pass for
the wrong reason.
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys
import textwrap

import pytest

from engine.cbom import generate_cbom
from engine.certificates import (RULE_CERT_EXPIRY, RULE_CERT_PUBKEY, RULE_CERT_PURPOSE_UNKNOWN,
                                 RULE_CERT_SIGALG, SCANNER_NAME, CertificateParseError,
                                 CertificateScanner, parse_certificate, resolve_key_purpose,
                                 scan_certificates)
from engine.mosca import calculate_risk, quantum_break_model
from engine.purpose import (ASSURANCE_OBSERVED, PURPOSE_KEY_ESTABLISHMENT, PURPOSE_SIGNATURE,
                            PURPOSE_UNRESOLVED, proven_use_count, resolve_assurance,
                            resolve_purpose, unresolved_purpose_count)
from engine.recommender import get_pqc_recommendation
from engine.scanner import IndraMeshScanner

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAVE_CRYPTOGRAPHY = True
except ImportError:                                       # pragma: no cover - env dependent
    HAVE_CRYPTOGRAPHY = False

needs_cryptography = pytest.mark.skipif(not HAVE_CRYPTOGRAPHY,
                                        reason="cryptography is not installed")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_FIELDS = ("file", "line", "type", "name", "primitive", "rule_id", "scanner",
                 "evidence_class", "artefact_class", "uses", "match")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture(scope="session")
def rsa_key():
    if not HAVE_CRYPTOGRAPHY:
        pytest.skip("cryptography is not installed")
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_key():
    if not HAVE_CRYPTOGRAPHY:
        pytest.skip("cryptography is not installed")
    return ec.generate_private_key(ec.SECP256R1())


# x509.KeyUsage takes NINE POSITIONAL arguments in this order (RFC 5280 bit order):
# digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign,
# cRLSign, encipherOnly, decipherOnly. A helper, so a test says which bits it means.
KU_BIT_ORDER = ("digital_signature", "content_commitment", "key_encipherment",
                "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                "encipher_only", "decipher_only")


def ku(**flags):
    unknown = set(flags) - set(KU_BIT_ORDER)
    assert not unknown, f"not KeyUsage bits: {unknown}"
    return [bool(flags.get(bit)) for bit in KU_BIT_ORDER]


KU_SIGNING = ku(digital_signature=True, key_cert_sign=True)
KU_ENCIPHER = ku(key_encipherment=True)
KU_DUAL = ku(digital_signature=True, key_encipherment=True)
KU_AGREEMENT = ku(key_agreement=True, encipher_only=True)


def build_certificate(key, common_name="indramesh.test", serial=0x1000, key_usage=None,
                      eku=None, ca=False, not_before=None, not_after=None, digest=None):
    """A self-signed certificate with exactly the extensions a test asks for."""
    now = _now()
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(not_before or (now - datetime.timedelta(days=1)))
               .not_valid_after(not_after or (now + datetime.timedelta(days=365))))
    if key_usage is not None:
        builder = builder.add_extension(x509.KeyUsage(*key_usage), critical=True)
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    return builder.sign(key, digest or hashes.SHA256())


def write_pem(path, certificate):
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(path)


def write_der(path, certificate):
    path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    return str(path)


def write_text(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def pubkey_findings(findings):
    return [f for f in findings if f["rule_id"] == RULE_CERT_PUBKEY]


def only_pubkey(findings):
    keys = pubkey_findings(findings)
    assert len(keys) == 1, f"expected exactly one public-key finding, got {len(keys)}"
    return keys[0]

# ------------------------------------------------------------------------------------------
# The SHA-1 fixture, built byte by byte.
#
# `cryptography` 46 refuses to sign with SHA-1 ("hash algorithm sha1 not supported for
# signatures"), and OpenSSL 3 will not produce one either, so the classically broken case -- the
# one this sensor most needs to catch -- cannot be generated with a library. It is assembled here
# instead: a minimal DER encoder, a real RSA key, and PKCS#1 v1.5 signing done with `pow()`. The
# result is a genuine certificate, and the test asserts that before using it: the signature is
# verified against the public exponent, and `cryptography` is asked to load it. An unverified
# blob in a test suite is a test that can pass for entirely the wrong reason.
# ------------------------------------------------------------------------------------------


def _der(tag, body):
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    encoded = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + body


def _seq(*parts):
    return _der(0x30, b"".join(parts))


def _set(*parts):
    return _der(0x31, b"".join(parts))


def _integer(value):
    return _der(0x02, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big"))


def _oid(dotted):
    arcs = [int(part) for part in dotted.split(".")]
    chunks = [arcs[0] * 40 + arcs[1]]
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        chunks.extend(reversed(chunk))
    return _der(0x06, bytes(chunks))


def _bit_string(data, unused_bits=0):
    return _der(0x03, bytes([unused_bits]) + data)


def _octet_string(data):
    return _der(0x04, data)


def _utc_time(moment):
    return _der(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _context(number, body):
    return _der(0xA0 + number, body)


def _null():
    return _der(0x05, b"")


def _utf8(text):
    return _der(0x0C, text.encode("utf-8"))


# DigestInfo prefix for id-sha1 with NULL parameters (RFC 8017 A.2.4): SEQUENCE { SEQUENCE {
# OID id-sha1, NULL }, OCTET STRING (20) }.
SHA1_DIGEST_INFO = bytes.fromhex("300906052b0e03021a05000414")
SHA1_RSA_OID = "1.2.840.113549.1.1.5"
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"


def sha1_certificate(key, common_name="indramesh sha1 fixture", serial=0x0BADF00D,
                     not_before=None, not_after=None):
    """Build a SHA-1-signed, self-signed RSA certificate. Returns (der, signature_int, n, e)."""
    private = key.private_numbers()
    public = key.public_key().public_numbers()
    name = _seq(_set(_seq(_oid("2.5.4.3"), _utf8(common_name))))
    spki = _seq(_seq(_oid(RSA_ENCRYPTION_OID), _null()),
                _bit_string(_seq(_integer(public.n), _integer(public.e))))
    sig_alg = _seq(_oid(SHA1_RSA_OID), _null())
    # KeyUsage with digitalSignature set: the first bit of the first content octet, 7 unused.
    key_usage = _seq(_oid("2.5.29.15"), _der(0x01, b"\xff"),
                     _octet_string(_bit_string(b"\x80", 7)))
    _now()
    tbs = _seq(
        _context(0, _integer(2)),                     # version v3
        _integer(serial),
        sig_alg,
        name,
        _seq(_utc_time(not_before or datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)),
             _utc_time(not_after or datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc))),
        name,
        spki,
        _context(3, _seq(key_usage)),
    )
    size = (public.n.bit_length() + 7) // 8
    digest_info = SHA1_DIGEST_INFO + hashlib.sha1(tbs).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - 3 - len(digest_info)) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private.d, public.n)
    signature_bytes = signature.to_bytes(size, "big")
    certificate = _seq(tbs, sig_alg, _bit_string(signature_bytes))
    return certificate, signature, public.n, public.e, encoded


def assert_genuine_sha1_certificate(key):
    """The fixture is a real certificate with a real signature, or the test is worthless."""
    certificate, signature, modulus, exponent, encoded = sha1_certificate(key)
    # 1. The signature verifies against the public exponent: a correct PKCS#1 v1.5 block.
    assert pow(signature, exponent, modulus) == int.from_bytes(encoded, "big")
    # 2. It is a certificate, not merely bytes that our own parser is willing to read.
    loaded = x509.load_der_x509_certificate(certificate)
    assert loaded.signature_hash_algorithm.name == "sha1"
    return certificate

# ==========================================================================================
# 1. A valid certificate produces findings, in the source scanner's schema.
# ==========================================================================================


@needs_cryptography
def test_valid_certificate_produces_findings(tmp_path, rsa_key):
    """A self-signed RSA certificate yields a public-key finding and a signature finding."""
    path = write_pem(tmp_path / "server.crt",
                     build_certificate(rsa_key, "indramesh.example", key_usage=KU_SIGNING))
    findings, scanner = scan_certificates(str(tmp_path))

    assert scanner.errors == [], f"a valid certificate must not produce errors: {scanner.errors}"
    key = only_pubkey(findings)
    assert key["name"] == "RSA"
    assert key["key_length"] == 2048
    assert key["file"] == path
    assert [f["rule_id"] for f in findings if f["rule_id"] == RULE_CERT_SIGALG], \
        "the algorithm that signed the certificate must be reported too"
    assert len(findings) == 2, f"unexpected findings: {[f['rule_id'] for f in findings]}"


@needs_cryptography
def test_findings_carry_the_source_scanner_schema(tmp_path, rsa_key):
    """Every schema field engine/scanner.py sets is present and non-empty here.

    The certificate findings are concatenated with source findings by the CLI and the CBOM, so a
    missing field is a KeyError in someone else's pipeline, not a cosmetic difference.
    """
    write_pem(tmp_path / "server.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    findings, _ = scan_certificates(str(tmp_path))

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("import rsa\nkey = rsa.newkeys(2048)\n", encoding="utf-8")
    source_findings, _ = scan_certificates(str(source_dir))  # no certificates: must be empty
    assert source_findings == []
    reference = IndraMeshScanner(enable_ml=False).scan_directory(str(source_dir))
    assert reference, "the reference source scan produced nothing, so the comparison is void"
    reference_keys = set(reference[0])

    for finding in findings:
        for field in SCHEMA_FIELDS:
            assert field in finding, f"{finding['rule_id']} is missing the schema field {field!r}"
            if field == "line":
                # A certificate has no source line, exactly as a binary finding has none. The field
                # is present and None; inventing a line number would be a worse lie.
                assert finding[field] is None
                continue
            assert finding[field] not in (None, ""), \
                f"{finding['rule_id']} left {field!r} empty"
        assert finding["scanner"] == SCANNER_NAME
        assert finding["scanner"] != reference[0]["scanner"], \
            "the certificate sensor must be identifiable as its own scanner"
        for field in reference_keys - {"key_usage", "dl_confidence", "ast_depth",
                                       "ml_model_label", "key_length"}:
            assert field in finding, f"source findings carry {field!r}; certificate findings must too"


@needs_cryptography
def test_certificate_evidence_class_is_observed(tmp_path, rsa_key):
    """A parsed certificate is ASSURANCE_OBSERVED, the strongest tier, and counts as proven use."""
    write_pem(tmp_path / "server.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    findings, _ = scan_certificates(str(tmp_path))

    for finding in findings:
        assert finding["evidence_class"] == "observed"
        assert resolve_assurance(finding)[0] == ASSURANCE_OBSERVED
    assert proven_use_count(findings) == len(findings)
    # A dependency finding is a capability and is NOT observed. The two must not be conflated.
    capability = {"evidence_class": "dependency"}
    assert resolve_assurance(capability)[0] != ASSURANCE_OBSERVED


@needs_cryptography
def test_ec_certificate_reports_curve_and_key_size(tmp_path, ec_key):
    """Curve and size are read from the key, not guessed from the file name."""
    write_pem(tmp_path / "ec.crt", build_certificate(ec_key, key_usage=KU_SIGNING))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["name"] == "ECDSA"
    assert key["curve"] == "secp256r1"
    assert key["key_length"] == 256


@needs_cryptography
def test_rsa_key_size_is_measured_not_assumed(tmp_path):
    """A hardcoded 2048 would pass every other RSA test in this file, so measure a second size.

    The size is what tells Mosca and the CBOM how much classical security a key has, and a sensor
    that always says 2048 is a sensor that is confidently wrong about every other RSA key.
    """
    big = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    write_pem(tmp_path / "big.crt", build_certificate(big, key_usage=KU_SIGNING))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["key_length"] == 3072
    assert "3072-bit" in key["match"]


# ==========================================================================================
# 2. KeyUsage -> engine/purpose.py. The wiring this whole sensor exists for.
# ==========================================================================================


@needs_cryptography
def test_digital_signature_key_usage_resolves_to_signature(tmp_path, rsa_key):
    """digitalSignature alone: purpose signature, and the primitive agrees with it."""
    write_pem(tmp_path / "signing.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["key_usage"] == ["digitalsignature", "keycertsign"]
    purpose, signals, reason = resolve_purpose(key)
    assert purpose == PURPOSE_SIGNATURE, f"got {purpose}: {signals} ({reason})"
    assert any("KeyUsage" in signal for signal in signals), \
        "the resolver must say the CERTIFICATE settled it, not a call-site string"
    assert key["primitive"] == "signature"
    assert unresolved_purpose_count([key]) == 0, \
        "a settled purpose must not be counted as needing a human"


@needs_cryptography
def test_key_encipherment_key_usage_resolves_to_key_establishment(tmp_path, rsa_key):
    """keyEncipherment alone: key establishment, and a TLS key-usage cert gets the hybrid KEM."""
    write_pem(tmp_path / "server.crt", build_certificate(rsa_key, key_usage=KU_ENCIPHER, eku=True))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    purpose, signals, _ = resolve_purpose(key)
    assert purpose == PURPOSE_KEY_ESTABLISHMENT
    assert any("keyencipherment" in signal for signal in signals)
    assert key["primitive"] == "key-agreement"
    assert key["uses"] == "tls", "a serverAuth EKU is what makes this a TLS claim"
    recommendation = get_pqc_recommendation(key)
    assert "X25519MLKEM768" in recommendation["algorithm"], \
        f"a TLS key-establishment certificate should get the hybrid, got {recommendation}"


@needs_cryptography
def test_key_agreement_ec_certificate_is_named_ecdh(tmp_path, ec_key):
    """An EC key is named by its purpose: ECDH for key agreement, not a bare 'ECC'."""
    write_pem(tmp_path / "dh.crt", build_certificate(ec_key, key_usage=KU_AGREEMENT))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["name"] == "ECDH"
    assert key["primitive"] == "key-agreement"
    assert resolve_purpose(key)[0] == PURPOSE_KEY_ESTABLISHMENT


@needs_cryptography
def test_dual_use_key_usage_is_unresolved_and_names_no_target(tmp_path, rsa_key):
    """Both purposes asserted: unresolved, and the recommender must refuse to pick a family.

    This is the case that separates a tool that reasons from one that guesses. ML-KEM for an RSA
    certificate that may well be a signing key is a confidently wrong answer.
    """
    write_pem(tmp_path / "dual.crt", build_certificate(rsa_key, key_usage=KU_DUAL))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert set(key["key_usage"]) == {"digitalsignature", "keyencipherment"}
    purpose, signals, reason = resolve_purpose(key)
    assert purpose == PURPOSE_UNRESOLVED
    assert "both" in reason.lower()
    assert key["primitive"] == "unknown", \
        "a certificate that asserts two purposes must not be typed as one of them"
    recommendation = get_pqc_recommendation(key)
    assert recommendation["algorithm"].startswith("Unresolved"), \
        f"a target was named for a dual-use certificate: {recommendation['algorithm']}"
    assert "ML-KEM" not in recommendation["algorithm"] and "ML-DSA" not in recommendation["algorithm"]
    assert unresolved_purpose_count([key]) == 1, \
        "an unresolved purpose on a Shor-vulnerable primitive must be counted for a human"


@needs_cryptography
def test_absent_key_usage_produces_an_explicit_unresolved_record(tmp_path, rsa_key):
    """No KeyUsage: the sensor says so, instead of letting a name-based fallback choose."""
    write_pem(tmp_path / "bare.crt", build_certificate(rsa_key))
    findings, _ = scan_certificates(str(tmp_path))

    key = only_pubkey(findings)
    assert key["key_usage"] == []
    assert key["primitive"] == "unknown"
    gaps = [f for f in findings if f["rule_id"] == RULE_CERT_PURPOSE_UNKNOWN]
    assert len(gaps) == 1, "the missing extension must be reported, not silently absorbed"
    assert gaps[0]["name"] == "X509-CERTIFICATE-PURPOSE-UNRESOLVED"
    assert gaps[0]["would_resolve"], "an unresolved finding must name what would resolve it"
    assert get_pqc_recommendation(gaps[0])["algorithm"] == "Manual review required"


@needs_cryptography
def test_present_key_usage_does_not_emit_the_gap_record(tmp_path, rsa_key):
    """The extra record exists for the ABSENT extension only, or it becomes noise."""
    write_pem(tmp_path / "signing.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    findings, _ = scan_certificates(str(tmp_path))
    assert [f for f in findings if f["rule_id"] == RULE_CERT_PURPOSE_UNKNOWN] == []


def test_resolve_key_purpose_matches_the_resolver_rules():
    """The sensor's own purpose rule and engine/purpose.py agree, bit for bit."""
    cases = {
        "digitalsignature": PURPOSE_SIGNATURE,
        "keycertsign": PURPOSE_SIGNATURE,
        "crlsign": PURPOSE_SIGNATURE,
        "nonrepudiation": PURPOSE_SIGNATURE,
        "keyencipherment": PURPOSE_KEY_ESTABLISHMENT,
        "keyagreement": PURPOSE_KEY_ESTABLISHMENT,
        "dataencipherment": PURPOSE_KEY_ESTABLISHMENT,
    }
    for bit, expected in cases.items():
        assert resolve_key_purpose([bit])[0] == expected
        assert resolve_purpose({"key_usage": [bit]})[0] == expected, \
            f"the sensor and engine/purpose.py disagree about {bit}"
    assert resolve_key_purpose(["digitalsignature", "keyencipherment"])[0] == PURPOSE_UNRESOLVED
    assert resolve_purpose({"key_usage": ["digitalsignature", "keyencipherment"]})[0] == \
        PURPOSE_UNRESOLVED
    assert resolve_key_purpose([])[0] == PURPOSE_UNRESOLVED
    # A member of the ambiguous pair on its own is not dual-use.
    assert resolve_purpose({"key_usage": ["digitalsignature"]})[0] == PURPOSE_SIGNATURE

# ==========================================================================================
# 3. The signature algorithm, and the classical/quantum distinction.
# ==========================================================================================


@needs_cryptography
def test_sha1_signed_certificate_is_reported_as_classically_broken(tmp_path, rsa_key):
    """A SHA-1 certificate signature is a real finding, and it is reported as CLASSICAL.

    This is the case `cryptography` refuses to generate, which is why `sha1_certificate()` exists.
    """
    der = assert_genuine_sha1_certificate(rsa_key)
    (tmp_path / "legacy.crt").write_bytes(der)
    findings, scanner = scan_certificates(str(tmp_path))

    assert scanner.errors == [], scanner.errors
    sig = [f for f in findings if f["rule_id"] == RULE_CERT_SIGALG]
    assert len(sig) == 1
    assert sig[0]["name"] == "SHA-1"
    assert sig[0]["primitive"] == "hash"
    assert sig[0]["key_length"] == 160
    recommendation = get_pqc_recommendation(sig[0])
    assert "classical" in recommendation["justification"].lower(), \
        f"SHA-1 must be reported as a classical failure: {recommendation['justification']}"
    # And the quantum claim is made where it belongs: on the RSA KEY, not on the digest.
    assert quantum_break_model(sig[0]["name"], sig[0]["primitive"]) == "weakened-by-Grover"
    assert quantum_break_model("RSA", "signature") == "broken-by-Shor"


@needs_cryptography
def test_sha256_signed_certificate_is_not_reported_as_broken(tmp_path, rsa_key):
    """A SHA-256 signature is inventory, not a defect. A sensor that cries wolf is ignored."""
    write_pem(tmp_path / "modern.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    findings, _ = scan_certificates(str(tmp_path))

    sig = only_pubkey(findings) and [f for f in findings if f["rule_id"] == RULE_CERT_SIGALG][0]
    assert sig["name"] == "SHA-256"
    assert get_pqc_recommendation(sig)["algorithm"] == "No migration required"


@needs_cryptography
def test_sha1_fixture_agrees_with_the_cryptography_backend(tmp_path, rsa_key):
    """The hand-built fixture is a real certificate, not something only our parser accepts."""
    der = assert_genuine_sha1_certificate(rsa_key)
    from engine.certificates import _parse_der

    stdlib = _parse_der(der)
    library = parse_certificate(der, prefer="cryptography")
    assert stdlib["sig_algorithm"] == "sha1WithRSAEncryption" == library["sig_algorithm"]
    assert stdlib["sig_hash"] == "SHA-1" == library["sig_hash"]
    assert stdlib["key_size"] == library["key_size"] == 2048
    assert stdlib["key_usage"] == library["key_usage"] == ["digitalsignature"]


# ==========================================================================================
# 4. Expiry.
# ==========================================================================================


@needs_cryptography
def test_expired_certificate_is_reported(tmp_path, rsa_key):
    """notAfter in the past is a genuinely reportable condition."""
    write_pem(tmp_path / "expired.crt", build_certificate(
        rsa_key, key_usage=KU_SIGNING,
        not_before=_now() - datetime.timedelta(days=400),
        not_after=_now() - datetime.timedelta(days=30)))
    findings, _ = scan_certificates(str(tmp_path))

    expired = [f for f in findings if f["rule_id"] == RULE_CERT_EXPIRY]
    assert len(expired) == 1, f"an expired certificate must be reported: {findings}"
    assert expired[0]["name"] == "X509-CERTIFICATE-EXPIRED"
    assert expired[0]["days_past_or_until"] >= 30
    assert expired[0]["type"] == "certificate", \
        "a validity date is not an algorithm and must not enter the crypto inventory as one"
    assert calculate_risk(expired[0])["break_model"] == "not-affected", \
        "an expired certificate is not a quantum exposure and must not be scored as one"


@needs_cryptography
def test_valid_certificate_is_not_reported_as_expired(tmp_path, rsa_key):
    write_pem(tmp_path / "valid.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    findings, _ = scan_certificates(str(tmp_path))
    assert [f for f in findings if f["rule_id"] == RULE_CERT_EXPIRY] == []
    key = only_pubkey(findings)
    assert 360 < key["days_until_expiry"] <= 366
    assert key["not_after"].endswith("Z"), "dates are reported as unambiguous UTC"


@needs_cryptography
def test_not_yet_valid_certificate_is_reported(tmp_path, rsa_key):
    """A certificate whose notBefore is in the future is equally unusable, and equally reportable."""
    write_pem(tmp_path / "future.crt", build_certificate(
        rsa_key, key_usage=KU_SIGNING,
        not_before=_now() + datetime.timedelta(days=10),
        not_after=_now() + datetime.timedelta(days=400)))
    findings, _ = scan_certificates(str(tmp_path))

    names = {f["name"] for f in findings}
    assert "X509-CERTIFICATE-NOT-YET-VALID" in names


# ==========================================================================================
# 5. Corrupt input is recorded, never raised.
# ==========================================================================================


def test_corrupt_pem_is_recorded_and_does_not_stop_the_scan(tmp_path):
    """One bad file must not cost the operator every other finding in the tree."""
    write_text(tmp_path / "broken.pem",
               "-----BEGIN CERTIFICATE-----\nZm9vYmFyYmF6\n-----END CERTIFICATE-----\n")
    write_text(tmp_path / "truncated.pem",
               "-----BEGIN CERTIFICATE-----\nMIIB\n")
    (tmp_path / "garbage.der").write_bytes(b"\x30\x82\xff\xff not a certificate at all")
    (tmp_path / "empty.crt").write_bytes(b"")
    (tmp_path / "notes.txt").write_text("just a note", encoding="utf-8")

    findings, scanner = scan_certificates(str(tmp_path))

    assert findings == [], "no readable certificate, so no findings"
    assert len(scanner.errors) == 4, f"every unreadable file must be named: {scanner.errors}"
    for error in scanner.errors:
        assert error["reason"], "an error entry with no reason is worse than no entry"
    assert scanner.coverage["certificates_failed"] >= 1
    # A file that was never a certificate is not an error, and is not silently counted as one.
    assert all("notes.txt" not in error["file"] for error in scanner.errors)


@needs_cryptography
def test_one_corrupt_file_does_not_hide_a_valid_certificate(tmp_path, rsa_key):
    """The regression that matters: a corrupt neighbour must not cost a real finding."""
    write_pem(tmp_path / "good.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    write_text(tmp_path / "bad.pem", "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")

    findings, scanner = scan_certificates(str(tmp_path))

    assert only_pubkey(findings)["name"] == "RSA"
    assert scanner.coverage["certificates_parsed"] == 1
    assert scanner.coverage["certificates_failed"] == 1
    assert any("bad.pem" in error["file"] for error in scanner.errors)


@needs_cryptography
def test_truncated_der_is_an_error_not_an_exception(tmp_path, rsa_key):
    """Byte-level corruption of a real certificate: cut it in half, and flip a length byte."""
    certificate = build_certificate(rsa_key, key_usage=KU_SIGNING).public_bytes(
        serialization.Encoding.DER)
    (tmp_path / "half.der").write_bytes(certificate[:len(certificate) // 2])
    flipped = bytearray(certificate)
    flipped[1] = 0x7F                                     # a length that overruns the buffer
    (tmp_path / "badlen.der").write_bytes(bytes(flipped))

    findings, scanner = scan_certificates(str(tmp_path))
    assert findings == []
    assert len(scanner.errors) == 2, scanner.errors


def test_malformed_der_never_raises(tmp_path):
    """Every one of these is attacker-controlled input. None of them may escape as an exception."""
    payloads = [b"", b"\x30", b"\x30\x80", b"\x30\x84\xff\xff\xff\xff", b"\x00" * 64,
                b"\x30\x03\x02\x01", bytes(range(256))]
    for index, payload in enumerate(payloads):
        path = tmp_path / f"fuzz{index}.der"
        path.write_bytes(payload)
        try:
            findings, scanner = scan_certificates(str(tmp_path))
        except Exception as exc:                           # noqa: BLE001 -- the thing being tested
            raise AssertionError(f"payload {index} ({payload[:8]!r}) raised {exc!r}") from exc
        assert findings == [] or all(f["file"] for f in findings)
    assert scanner.errors, "unreadable inputs must be recorded"


def test_parse_certificate_reports_both_backends_on_failure():
    """A parse failure names every backend tried, so 'it did not work' is diagnosable."""
    with pytest.raises(CertificateParseError) as caught:
        parse_certificate(b"\x30\x03\x02\x01\x01", prefer="auto")
    message = str(caught.value)
    assert "der" in message and "cryptography" in message
    with pytest.raises(ValueError):
        parse_certificate(b"", prefer="nonsense-backend")

# ==========================================================================================
# 6. Containment: a private key is never read, a certificate always is.
# ==========================================================================================


def test_private_key_file_is_refused(tmp_path):
    """A key-only file yields no findings and a NAMED refusal, never a silent success.

    The body below is not a usable key and does not need to be: the sensor must decide on the
    PEM LABEL, before any parsing, so the test is about the policy and not about key material.
    """
    secret = "cHJpdmF0ZSBrZXkgbWF0ZXJpYWw"          # base64 of a sentence, not a key
    write_text(tmp_path / "server.key",
               f"-----BEGIN EC PRIVATE KEY-----\n{secret}\n-----END EC PRIVATE KEY-----\n")

    findings, scanner = scan_certificates(str(tmp_path))

    assert findings == [], "a private key is not a certificate and must produce no findings"
    assert scanner.errors, "the refusal must be recorded, not silent"
    reason = scanner.errors[0]["reason"]
    assert "private key" in reason.lower(), reason
    assert scanner.coverage["private_key_files"] == 1


@needs_cryptography
def test_no_finding_ever_contains_private_key_material(tmp_path, rsa_key):
    """The strongest form of the claim: the key bytes appear nowhere in the output."""
    key_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    body = key_pem.decode("ascii").splitlines()[1]
    (tmp_path / "server.key").write_bytes(key_pem)

    findings, _ = scan_certificates(str(tmp_path))
    serialised = json.dumps(findings)
    assert body not in serialised
    assert "PRIVATE KEY" not in serialised


def test_private_key_blocks_are_redacted_before_anything_is_parsed():
    """Redaction is observable, not just implied by the absence of a leak downstream.

    Without this the redaction could be deleted and the suite would still pass, because a private
    key block is not a certificate block and so never reaches a finding anyway. What redaction
    buys is that the key bytes are not even PRESENT in the text handed to the parser, so they
    cannot be logged, cached or serialised by anything downstream of this line.
    """
    from engine.certificates import _redact_private_keys, pem_certificate_blocks

    secret = "cHJpdmF0ZSBrZXkgbWF0ZXJpYWw"          # base64 of a sentence, not a key
    text = (f"-----BEGIN EC PRIVATE KEY-----\n{secret}\n-----END EC PRIVATE KEY-----\n"
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")

    clean, labels = _redact_private_keys(text)

    assert secret not in clean, "the key body survived redaction and is still in memory"
    assert "EC PRIVATE KEY" in clean, "the label is kept, so the file can still be named"
    assert labels == ["EC PRIVATE KEY"]
    blocks = pem_certificate_blocks(clean)
    assert len(blocks) == 1, "redaction must not damage the certificate beside the key"


@needs_cryptography
def test_certificate_bundled_with_a_key_is_still_reported(tmp_path, rsa_key):
    """`fullchain-with-key.pem` is a real thing. Refusing to inventory it would lose a real key.

    The certificate is public and is reported; the key is named as present and never read.
    """
    key_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    certificate = build_certificate(rsa_key, key_usage=KU_SIGNING).public_bytes(
        serialization.Encoding.PEM)
    (tmp_path / "bundle.pem").write_bytes(key_pem + certificate)

    findings, scanner = scan_certificates(str(tmp_path))

    assert only_pubkey(findings)["name"] == "RSA", "the certificate must still be inventoried"
    assert scanner.warnings, "the key material must be named, not passed over in silence"
    assert "private key" in scanner.warnings[0]["reason"].lower()
    assert scanner.coverage["private_key_files"] == 1


def test_public_key_pem_is_not_mistaken_for_a_private_key(tmp_path):
    """`server.pub` sits next to `server.key` in most deployments. Neither is a certificate.

    The distinction matters because the coverage manifest counts files where private key material
    was passed over: a public key is redacted too, but calling it a private key would inflate a
    number an operator is meant to act on.
    """
    write_text(tmp_path / "server.pub",
               "-----BEGIN PUBLIC KEY-----\nQUJDREVG\n-----END PUBLIC KEY-----\n")

    findings, scanner = scan_certificates(str(tmp_path))

    assert findings == []
    assert scanner.coverage["private_key_files"] == 0, \
        "a public key must not be counted as private key material"
    assert scanner.errors and "PUBLIC KEY" in scanner.errors[0]["reason"], \
        "the file must be named for what it actually is"
    assert not scanner.warnings or "public key" in scanner.warnings[0]["reason"].lower()


@needs_cryptography
def test_credential_store_names_are_refused_before_any_read(tmp_path, rsa_key):
    """`id_rsa.pem` is a credential store by NAME, even when its bytes are a certificate.

    engine/fspolicy.py decides this on the file name alone, before a byte is read, and the sensor
    must not be a way around it.
    """
    write_pem(tmp_path / "id_rsa.pem", build_certificate(rsa_key, key_usage=KU_SIGNING))

    findings, scanner = scan_certificates(str(tmp_path))

    assert findings == [], "a credential store is not read even if it parses as a certificate"
    assert any("credential store" in error["reason"] for error in scanner.errors)


@needs_cryptography
def test_symlink_escaping_the_scan_root_is_not_followed(tmp_path, rsa_key):
    """Containment, inherited from engine/fspolicy.py: a link out of the root is not read."""
    outside = tmp_path.parent / "outside-cert.pem"
    outside.write_bytes(build_certificate(rsa_key, key_usage=KU_SIGNING).public_bytes(
        serialization.Encoding.PEM))
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(outside, root / "link.pem")
    except (OSError, NotImplementedError):                # pragma: no cover - Windows without rights
        pytest.skip("symlink creation is not permitted here")
    try:
        findings, scanner = scan_certificates(str(root))
        assert findings == [], "a symlink out of the scan root must not be followed"
        assert any("symlink" in error["reason"] for error in scanner.errors)
    finally:
        outside.unlink(missing_ok=True)


# ==========================================================================================
# 7. Idempotence, containment of the walk, and the coverage manifest.
# ==========================================================================================


@needs_cryptography
def test_scanning_is_idempotent(tmp_path, rsa_key, ec_key):
    """The same bytes must give the same answer twice, and one scanner must not double-count."""
    write_pem(tmp_path / "a.crt", build_certificate(rsa_key, "a", key_usage=KU_SIGNING))
    write_pem(tmp_path / "b.crt", build_certificate(ec_key, "b", key_usage=KU_AGREEMENT))

    first, scanner_a = scan_certificates(str(tmp_path))
    second, scanner_b = scan_certificates(str(tmp_path))
    assert first == second, "two scans of one tree must agree exactly"
    assert scanner_a.coverage["certificates_parsed"] == scanner_b.coverage["certificates_parsed"]

    # The same scanner instance, pointed at the same file twice, must not duplicate findings.
    single = CertificateScanner()
    once = single.scan_file(str(tmp_path / "a.crt"))
    twice = single.scan_file(str(tmp_path / "a.crt"))
    assert len(once) == 2
    assert twice == [], "a repeated file must yield nothing the second time"


@needs_cryptography
def test_a_chain_in_one_file_yields_every_certificate(tmp_path, rsa_key):
    """A fullchain.pem holds several certificates; each is a separate artefact with its own key."""
    leaf = build_certificate(rsa_key, "leaf", serial=1, key_usage=KU_SIGNING)
    intermediate = build_certificate(rsa_key, "intermediate", serial=2, key_usage=KU_SIGNING,
                                     ca=True)
    (tmp_path / "chain.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                         intermediate.public_bytes(serialization.Encoding.PEM))

    findings, scanner = scan_certificates(str(tmp_path))

    serials = {f["cert_serial"] for f in findings}
    assert serials == {"1", "2"}, f"both certificates must be reported, got {serials}"
    ca_findings = [f for f in findings if f["is_ca"]]
    assert ca_findings and ca_findings[0]["artefact_class"] == "ca-root", \
        "a CA certificate is a different migration from a leaf one"
    assert scanner.coverage["certificates_parsed"] == 2


@needs_cryptography
def test_der_and_pem_are_both_detected(tmp_path, rsa_key):
    """Detection is by content, not by extension: the same certificate in either envelope."""
    certificate = build_certificate(rsa_key, key_usage=KU_SIGNING)
    write_pem(tmp_path / "a.pem", certificate)
    write_der(tmp_path / "a.der", certificate)
    write_pem(tmp_path / "no_extension_at_all", certificate)

    findings, scanner = scan_certificates(str(tmp_path))

    assert len(pubkey_findings(findings)) == 3, "all three spellings must be found"
    assert scanner.coverage["certificates_parsed"] == 3


@needs_cryptography
def test_certificate_inside_a_pkcs7_style_container_is_found(tmp_path, rsa_key):
    """A .p7b holds certificates inside a SET; the walk must descend into it, not stop at it."""
    from engine.certificates import embedded_certificates

    certificate = build_certificate(rsa_key, key_usage=KU_SIGNING).public_bytes(
        serialization.Encoding.DER)
    signed_data = _seq(_oid("1.2.840.113549.1.7.2"),            # id-signedData
                       _context(0, _set(certificate)))
    container = _seq(signed_data)
    (tmp_path / "bundle.p7b").write_bytes(container)

    embedded = embedded_certificates(container)
    assert len(embedded) == 1, "the certificate inside the SET must be found"
    assert embedded[0][0]["key_usage"] == ["digitalsignature", "keycertsign"]

    findings, _ = scan_certificates(str(tmp_path))
    assert only_pubkey(findings)["name"] == "RSA"


@needs_cryptography
def test_coverage_manifest_accounts_for_everything_it_walked(tmp_path, rsa_key):
    """A manifest that does not add up is the one artefact whose whole job is to be believed."""
    write_pem(tmp_path / "a.crt", build_certificate(rsa_key, key_usage=KU_SIGNING))
    write_text(tmp_path / "broken.pem", "-----BEGIN CERTIFICATE-----\nQUJD\n"
                                        "-----END CERTIFICATE-----\n")
    (tmp_path / "readme.txt").write_text("nothing to see", encoding="utf-8")
    findings, scanner = scan_certificates(str(tmp_path))

    manifest = scanner.coverage_manifest(findings)
    assert manifest["scanners_run"] == [SCANNER_NAME]
    assert manifest["files_seen"] == 3
    assert manifest["certificate_files_seen"] == 2, "a .txt was walked but never in scope"
    assert manifest["certificates_parsed"] == 1
    assert manifest["certificates_failed"] == 1
    assert manifest["findings_total"] == len(findings)
    assert manifest["purpose_resolved"] == 1 and manifest["purpose_unresolved"] == 0
    assert "observed" in manifest["assurance"]
    assert manifest["never_in_scope"], "what was never examined must be stated"
    assert manifest["errors"] and all(error["reason"] for error in manifest["errors"])
    json.dumps(manifest), "the manifest must be JSON-serialisable for the report"


@needs_cryptography
def test_findings_survive_the_whole_pipeline(tmp_path, rsa_key):
    """Mosca, the recommender and the CBOM must all accept a certificate finding unchanged."""
    write_pem(tmp_path / "a.crt", build_certificate(rsa_key, key_usage=KU_SIGNING, eku=True))
    write_pem(tmp_path / "b.crt", build_certificate(rsa_key, "b", key_usage=KU_DUAL))
    write_pem(tmp_path / "c.crt", build_certificate(rsa_key, "c", key_usage=KU_ENCIPHER))
    findings, _ = scan_certificates(str(tmp_path))
    for finding in findings:
        finding["risk"] = calculate_risk(finding)
        finding["recommendation"] = get_pqc_recommendation(finding)

    document = json.loads(generate_cbom(findings, enriched=True))
    assert document["components"], "the CBOM must contain the certificate assets"
    components = {component["name"]: component for component in document["components"]}
    assert "RSA" in components and "SHA-256" in components, sorted(components)
    # The purpose the resolver reached is exported, so a reader can audit the decision.
    properties = [prop for component in document["components"]
                  for prop in component.get("properties", [])]
    exported = {prop["value"] for prop in properties if prop["name"] == "im:purpose"}
    assert PURPOSE_SIGNATURE in exported and PURPOSE_KEY_ESTABLISHMENT in exported, \
        f"the CBOM must export the purpose the KeyUsage settled: {exported}"

# ==========================================================================================
# 8. The stdlib path. `cryptography` is optional, and that claim is tested, not asserted.
# ==========================================================================================

# Run in a subprocess with `cryptography` blocked at import time. In-process monkeypatching cannot
# prove the module IMPORTS without the package -- the import already happened by then, which is
# exactly the thing that has to work on a machine that has never heard of pyca.
NO_CRYPTOGRAPHY_PROGRAM = textwrap.dedent("""
    import json, sys

    class _BlockCryptography:
        def find_spec(self, name, path=None, target=None):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("cryptography is blocked for this test")
            return None

    for module in [m for m in sys.modules if m.split(".")[0] == "cryptography"]:
        del sys.modules[module]
    sys.meta_path.insert(0, _BlockCryptography())

    import engine.certificates as sensor
    assert sensor._x509 is None, "cryptography should be unavailable in this interpreter"

    record = sensor.parse_certificate(open(sys.argv[1], "rb").read(), prefer="auto")
    findings = sensor.findings_for_certificate("blocked.crt", record, 0)
    print(json.dumps({
        "backend": record["backend"],
        "family": record["key_family"],
        "key_size": record["key_size"],
        "key_usage": record["key_usage"],
        "subject": record["subject"],
        "not_after": record["not_after"].isoformat(),
        "sig_hash": record["sig_hash"],
        "purposes": sorted({f["purpose"] for f in findings if f.get("purpose")}),
        "backend_status": sensor.parser_backend_status(),
    }))
""")


@needs_cryptography
def test_module_imports_and_parses_without_cryptography(tmp_path, rsa_key):
    """A fresh interpreter, `cryptography` blocked: the sensor still works and says so."""
    certificate = build_certificate(rsa_key, "indramesh.nodeps", key_usage=KU_SIGNING)
    path = tmp_path / "server.crt"
    write_der(path, certificate)

    environment = dict(os.environ, PYTHONPATH=REPO_ROOT)
    completed = subprocess.run([sys.executable, "-c", NO_CRYPTOGRAPHY_PROGRAM, str(path)],
                               capture_output=True, text=True, cwd=REPO_ROOT,
                               env=environment, timeout=180)
    assert completed.returncode == 0, \
        f"the sensor failed without cryptography:\n{completed.stderr}"
    report = json.loads(completed.stdout.strip().splitlines()[-1])

    assert report["backend"] == "der", "the stdlib reader must be the one that ran"
    assert report["family"] == "RSA" and report["key_size"] == 2048
    assert report["key_usage"] == ["digitalsignature", "keycertsign"], \
        "KeyUsage is the whole point of the sensor; it must survive the missing dependency"
    assert report["subject"] == "CN=indramesh.nodeps"
    assert report["sig_hash"] == "SHA-256"
    assert PURPOSE_SIGNATURE in report["purposes"]
    assert report["backend_status"][0] is False, "the manifest must admit the backend is missing"
    assert "stdlib DER reader only" in report["backend_status"][1]


@needs_cryptography
@pytest.mark.parametrize("size,family", [(2048, "rsa"), (3072, "rsa"), (256, "ec")])
def test_both_backends_agree_field_for_field(tmp_path, rsa_key, ec_key, size, family):
    """The two parsers are not allowed to disagree.

    This is the regression test for a real defect: the DER reader unpacked four values from a
    three-value element, raised ValueError on every certificate, and `parse_certificate` silently
    fell back to the other backend. Both backends "agreed" because only one of them ever ran. The
    stdlib parser is therefore called DIRECTLY here, so it cannot be quietly skipped.

    The RSA cases cover two key sizes on purpose. A hardcoded key size in either backend agrees
    with the other for 2048 and disagrees for everything else, so a single size would let that bug
    through in both directions.
    """
    from engine.certificates import _parse_der

    if family == "rsa":
        key = rsa_key if size == 2048 else rsa.generate_private_key(public_exponent=65537,
                                                                   key_size=size)
    else:
        key = ec_key
    certificate = build_certificate(
        key, f"indramesh.{family}{size}",
        key_usage=KU_SIGNING if family == "rsa" else KU_AGREEMENT, eku=True, ca=True)
    der = certificate.public_bytes(serialization.Encoding.DER)

    stdlib = _parse_der(der)
    library = parse_certificate(der, prefer="cryptography")
    assert stdlib["backend"] == "der" and library["backend"] == "cryptography"
    differences = {field: (stdlib.get(field), library.get(field))
                   for field in set(stdlib) | set(library)
                   if field != "backend" and stdlib.get(field) != library.get(field)}
    assert not differences, f"the two backends disagree: {differences}"
    assert stdlib["key_size"] == size
    assert stdlib["key_usage"] and stdlib["is_ca"] is True
    assert stdlib["extended_key_usage"] == ["serverAuth"]


@needs_cryptography
def test_stdlib_backend_is_used_when_asked_explicitly(tmp_path, rsa_key, monkeypatch):
    """`prefer="der"` must not quietly fall back to the library when the library is present."""
    from engine.certificates import _parse_der

    certificate = build_certificate(rsa_key, key_usage=KU_SIGNING)
    write_pem(tmp_path / "a.crt", certificate)
    write_pem(tmp_path / "b.crt", certificate)
    findings, scanner = scan_certificates(str(tmp_path), prefer="der")

    assert findings, "the stdlib path must produce findings on its own"
    assert {f["parser_backend"] for f in findings} == {"der"}
    assert scanner.coverage["backend"] == "cryptography", \
        "the manifest reports which backend is AVAILABLE, not which was used per finding"
    # And a certificate the stdlib reader genuinely cannot read is an error, not a silent fallback.
    with pytest.raises(CertificateParseError):
        _parse_der(b"\x30\x03\x02\x01\x01")


# ==========================================================================================
# 9. Precision: what the sensor refuses to claim.
# ==========================================================================================


@needs_cryptography
def test_certificate_subject_cannot_steer_the_purpose(tmp_path, rsa_key):
    """A CN is attacker-chosen text and must not reach the purpose resolver.

    engine/purpose.py reads `match` for call-site signals. If the subject were quoted there, a
    certificate with CN "keyagreement" would silently resolve an RSA key to key establishment and
    earn a confident ML-KEM recommendation. The identity lives in `cert_subject` instead.
    """
    write_pem(tmp_path / "decoy.crt",
              build_certificate(rsa_key, "keyagreement sign( pkcs1v15", key_usage=KU_SIGNING))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["cert_common_name"] == "keyagreement sign( pkcs1v15", \
        "the identity must still be reported"
    for planted in ("keyagreement", "sign(", "pkcs1v15"):
        assert planted not in key["match"], \
            f"{planted!r} leaked into `match`, where the purpose resolver would read it"
    # The purpose came from the KeyUsage, and says so.
    purpose, signals, _ = resolve_purpose(key)
    assert purpose == PURPOSE_SIGNATURE
    assert not any(planted in signal for signal in signals for planted in
                   ("keyagreement", "sign(", "pkcs1v15"))


@needs_cryptography
def test_tls_is_not_inferred_for_a_certificate_that_names_no_protocol(tmp_path, ec_key):
    """A key-agreement certificate with no EKU and no SAN is not evidence of TLS.

    Claiming `uses=tls` here would select the hybrid KEM recommendation on the strength of a file
    extension. The honest answer is a key-establishment key used for an unnamed purpose.
    """
    write_pem(tmp_path / "bare-dh.crt", build_certificate(ec_key, key_usage=KU_AGREEMENT))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["uses"] == "key-establishment", key["uses"]
    assert key["uses_reason"]
    recommendation = get_pqc_recommendation(key)
    assert "hybrid" not in recommendation["algorithm"].lower(), \
        f"a hybrid KEM was recommended with no evidence of TLS: {recommendation['algorithm']}"


@needs_cryptography
def test_self_issued_is_not_claimed_as_self_signed(tmp_path, rsa_key):
    """subject == issuer is a NAME match. No signature is verified, so it is not called verified."""
    write_pem(tmp_path / "self.crt", build_certificate(rsa_key, "indramesh.self", key_usage=KU_SIGNING))
    key = only_pubkey(scan_certificates(str(tmp_path))[0])

    assert key["self_issued"] is True
    assert "self_signed" not in key and "signature_verified" not in key, \
        "nothing here verified a signature, so nothing may claim to"