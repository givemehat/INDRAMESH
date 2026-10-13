"""X.509 certificate sensor: PEM, DER and PKCS#7, with NO hard dependency on `cryptography`.

THE GAP THIS CLOSES
-------------------
`engine/purpose.py` already knows how to resolve a certificate's cryptographic purpose from its
KeyUsage extension (digitalSignature -> signature, keyEncipherment/keyAgreement -> key
establishment, both -> unresolved). Nothing in the codebase ever PRODUCED a finding carrying
`key_usage`, so that branch was dead code reachable only from hand-built test dicts. This module
is the missing input. It parses real certificates and emits findings in the `engine/scanner.py`
schema, so the purpose resolver runs against parsed evidence instead of a fixture.

This closes the sensor parity gap with enterprise PKI analyzers.

WHY A CERTIFICATE IS WORTH A SENSOR
-----------------------------------
A certificate is the one place where a deployed system states, in a signed artefact, what a key
is FOR. The source scanner sees `rsa.newkeys(2048)` and cannot say whether the key signs or
wraps; the KeyUsage extension says so. That turns a purpose guess into a parsed fact, and
purpose is what decides whether the replacement is ML-KEM or ML-DSA.

PARSING WITHOUT `cryptography`
------------------------------
`cryptography` is used when importable, because it is the better parser, but it is NOT required.
The stdlib path is `ssl.PEM_cert_to_DER_cert` for the envelope plus the small DER reader below for
the TBSCertificate fields we need. Both backends produce the same normalised certificate record,
and every finding records which one ran (`parser_backend`), so a degraded report is never
presented as a complete one.

WHAT IS AND IS NOT READ
-----------------------
A certificate is PUBLIC. Its KeyUsage is the strongest purpose evidence available to static
analysis, and refusing to read it would leave this tool blind to the thing it exists to report. A
private key is the opposite: `engine/fspolicy.py` refuses credential stores by name before any
byte is read, and a PEM bundle that carries key material has those blocks REDACTED before
anything is parsed, so key material is never handed to a parser, never stored and never placed
in a finding. A key-only file yields no findings and a named error, never a silent success.

HOW A CERTIFICATE'S PURPOSE IS DECIDED
--------------------------------------
The primitive is a claim about CRYPTOGRAPHY and `uses` is a claim about DEPLOYMENT; they are
decided separately and neither is guessed.

  * An algorithm that can only do one thing is typed by that fact: Ed25519 is a signature, X25519
    is key agreement. A KeyUsage contradicting the algorithm is a certificate defect, not a
    different purpose.
  * A multi-purpose algorithm (RSA, EC) is typed by the certificate's KeyUsage and by nothing
    else. `digitalSignature` -> signature. `keyEncipherment`/`keyAgreement`/`dataEncipherment` ->
    key agreement. Both at once, or the extension absent -> `unknown`, because a certificate that
    does not say what its key is for has not settled it.
  * `uses` says "tls" only when the certificate names TLS (a serverAuth/clientAuth EKU, or a
    subjectAltName), and "signing" when it names a signing EKU or the key is a signing key. It can
    return a value outside the usual tls/signing/at-rest vocabulary, because `key-establishment`
    and `unknown` are the honest answers when no protocol is named.
  * When the KeyUsage extension is ABSENT the sensor also emits an explicit
    X509-CERTIFICATE-PURPOSE-UNRESOLVED finding. engine/recommender.py falls back to the algorithm
    name when a primitive is vague, which would offer ML-KEM for an RSA certificate whose key is,
    in the common TLS case, a signing key; the explicit record says so next to the finding.

NOTHING HERE RAISES AT THE CALLER
---------------------------------
A truncated `.pem`, a `-----BEGIN CERTIFICATE-----` whose base64 decodes to noise, a `.p7b` whose
container we cannot open: all are recorded in `errors` with a reason and the scan continues.
A corrupt certificate is a result, not an exception.
"""
import base64
import binascii
import datetime
import os
import re
import ssl

from engine.fspolicy import check_root, is_credential_store, resolve_within

try:                                                        # pragma: no cover - env dependent
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa, ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed448 as _ed448
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.asymmetric import x448 as _x448
    from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519
    _CRYPTOGRAPHY_ERROR = None
except Exception as exc:                                   # noqa: BLE001 -- absence is a mode
    _x509 = None
    _dsa = _ec = _ed448 = _ed25519 = _rsa = _x448 = _x25519 = None
    _CRYPTOGRAPHY_ERROR = f"{type(exc).__name__}: {exc}"

# The stdlib envelope parser: PEM -> DER with no third-party package. Used by BOTH backends, so
# the PEM/DER split behaves identically whether or not `cryptography` is installed.
_PEM_TO_DER = getattr(ssl, "PEM_cert_to_DER_cert", None)

SCANNER_NAME = "certificate-scanner"

# Rule ids. The ECD- prefix matches engine/scanner.py and engine/dependencies.py, so a report
# reads as one system.
RULE_CERT_PUBKEY = "IM-CERT-PUBKEY-001"
RULE_CERT_SIGALG = "IM-CERT-SIGALG-001"
RULE_CERT_EXPIRY = "IM-CERT-EXPIRY-001"
RULE_CERT_NOT_YET_VALID = "IM-CERT-EXPIRY-002"
RULE_CERT_PURPOSE_UNKNOWN = "IM-CERT-PURPOSE-001"

# Files are routed by CONTENT, not by extension: a .pem fullchain and a .cer are the same object,
# and a file with no extension at all is still found when its bytes say CERTIFICATE.
CERT_EXTENSIONS = (".pem", ".crt", ".cer", ".der", ".p7b", ".p7c")
PEM_CERT_MARKER = b"-----BEGIN CERTIFICATE-----"
# Sniffed for as well, so that a private key lying in the scan root is OPENED, recognised and
# reported rather than skipped in silence. It is opened to be refused, not to be read: the blocks
# are redacted before anything is parsed.
PEM_KEY_MARKER = b"-----BEGIN "

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----(.*?)-----END \1-----", re.DOTALL)
_PEM_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----")

PRIVATE_KEY_LABELS = {
    "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
}
CERTIFICATE_LABELS = {"CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"}

# A certificate is small. The cap is a DoS guard against a hostile or accidental "certificate".
MAX_CERT_BYTES = 1024 * 1024
# Only this much of a non-candidate file is read while looking for a PEM marker.
SNIFF_BYTES = 4096
# Depth cap for the PKCS#7 / embedded-certificate walk.
MAX_WALK_DEPTH = 8


class CertificateParseError(Exception):
    """Raised by the parsers; always caught at the sensor boundary and turned into an `errors` entry."""
# ------------------------------------------------------------------------------------------
# KeyUsage bit names, in RFC 5280 bit order. Lower-cased, so they match the sets in
# engine/purpose.py exactly; that equality is the whole reason these strings are spelled so.
# ------------------------------------------------------------------------------------------
KEY_USAGE_BITS = [
    "digitalsignature", "nonrepudiation", "keyencipherment", "dataencipherment",
    "keyagreement", "keycertsign", "crlsign", "encipheronly", "decipheronly",
]
# The two purpose buckets, mirrored from engine/purpose.py rather than re-derived, so the
# primitive this sensor writes and the purpose the resolver returns cannot drift apart.
KU_SIGNATURE = {"digitalsignature", "nonrepudiation", "keycertsign", "crlsign"}
KU_KEY_ESTABLISHMENT = {"keyencipherment", "keyagreement", "dataencipherment"}

EKU_NAMES = {
    "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}
# EKU values that assert what the certificate is FOR. Used for `uses`, never for the primitive.
EKU_SIGNING = {"codeSigning", "emailProtection", "timeStamping"}
EKU_TLS = {"serverAuth", "clientAuth"}

# Key families. `fixed_primitive` is the purpose the ALGORITHM itself can serve; a family without
# one (RSA, EC) is multi-purpose, and only the certificate KeyUsage can settle its purpose.
KEY_FAMILIES = {
    "1.2.840.113549.1.1.1": {"family": "RSA", "display": "RSA", "fixed_primitive": None},
    "1.2.840.10045.2.1": {"family": "EC", "display": None, "fixed_primitive": None},
    "1.2.840.10040.4.1": {"family": "DSA", "display": "DSA", "fixed_primitive": "signature"},
    "1.2.840.10046.2.1": {"family": "DH", "display": "DH", "fixed_primitive": "key-agreement"},
    "1.3.101.112": {"family": "Ed25519", "display": "Ed25519", "fixed_primitive": "signature",
                    "key_size": 256, "curve": "Ed25519"},
    "1.3.101.113": {"family": "Ed448", "display": "Ed448", "fixed_primitive": "signature",
                    "key_size": 456, "curve": "Ed448"},
    "1.3.101.110": {"family": "X25519", "display": "X25519", "fixed_primitive": "key-agreement",
                    "key_size": 256, "curve": "X25519"},
    "1.3.101.111": {"family": "X448", "display": "X448", "fixed_primitive": "key-agreement",
                    "key_size": 448, "curve": "X448"},
}
# Display name per family, once the purpose is known. An EC key cannot be NAMED before its purpose
# is resolved: ECDSA and ECDH are different algorithms with different PQC replacements.
EC_DISPLAY = {"signature": "ECDSA", "key-establishment": "ECDH"}

CURVE_SIZES = {
    "1.2.840.10045.3.1.7": 256, "1.3.132.0.34": 384, "1.3.132.0.35": 521,
    "1.3.132.0.33": 224, "1.3.132.0.10": 256, "1.3.132.0.9": 283,
    "1.3.36.3.3.2.8.1.1.7": 256, "1.3.36.3.3.2.8.1.1.11": 384,
    "1.3.36.3.3.2.8.1.1.13": 512, "1.3.36.3.3.2.8.1.1.1": 192,
}
CURVE_NAMES = {
    "1.2.840.10045.3.1.7": "secp256r1", "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1", "1.3.132.0.33": "secp224r1",
    "1.3.132.0.10": "secp256k1", "1.3.132.0.9": "secp283k1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.1": "brainpoolP192r1",
}
# SignatureAlgorithmIdentifier -> (display, digest name, digest bits). A None digest means the
# scheme has none (Ed25519 signs the message directly), which is reported as a signature
# primitive rather than a hash: calling Ed25519 a "hash" would be a category error.
SIG_ALGORITHMS = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "MD5", 128),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "SHA-1", 160),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", None, None),          # digest lives in the params
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "SHA-256", 256),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "SHA-384", 384),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "SHA-512", 512),
    "1.2.840.10040.4.3": ("dsaWithSHA1", "SHA-1", 160),
    "1.2.840.10045.4.1": ("ecdsaWithSHA1", "SHA-1", 160),
    "1.2.840.10045.4.3.1": ("ecdsaWithSHA224", "SHA-224", 224),
    "1.2.840.10045.4.3.2": ("ecdsaWithSHA256", "SHA-256", 256),
    "1.2.840.10045.4.3.3": ("ecdsaWithSHA384", "SHA-384", 384),
    "1.2.840.10045.4.3.4": ("ecdsaWithSHA512", "SHA-512", 512),
    "2.16.840.1.101.3.4.3.1": ("dsaWithSHA224", "SHA-224", 224),
    "2.16.840.1.101.3.4.3.2": ("dsaWithSHA256", "SHA-256", 256),
    "1.3.101.112": ("ed25519", None, None),
    "1.3.101.113": ("ed448", None, None),
}
# NIST hash OIDs, for an RSASSA-PSS parameter block.
HASH_OIDS = {
    "1.3.14.3.2.26": ("SHA-1", 160), "2.16.840.1.101.3.4.2.1": ("SHA-256", 256),
    "2.16.840.1.101.3.4.2.2": ("SHA-384", 384), "2.16.840.1.101.3.4.2.3": ("SHA-512", 512),
    "1.2.840.113549.2.5": ("MD5", 128),
}

EXT_KEY_USAGE = "2.5.29.15"
EXT_EXT_KEY_USAGE = "2.5.29.37"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_SAN = "2.5.29.17"

NAME_OIDS = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C",
    "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O",
    "2.5.4.11": "OU", "2.5.4.12": "title", "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
}

# DER tags used by the reader below.
T_BOOLEAN, T_INTEGER, T_BIT_STRING, T_OCTET_STRING, T_OID = 0x01, 0x02, 0x03, 0x04, 0x06
T_UTCTIME, T_GENTIME, T_BMPSTRING, T_UNIVERSALSTRING = 0x17, 0x18, 0x1E, 0x1C
T_SEQUENCE = 0x30
CTX_0, CTX_3 = 0xA0, 0xA3

# ------------------------------------------------------------------------------------------
# A minimal DER reader.
#
# It exists so the sensor works with no third-party package installed. It is deliberately small
# and strict: malformed input raises CertificateParseError rather than yielding a half-parsed
# record, because a quietly wrong certificate record is worse than one reported as unreadable.
# ------------------------------------------------------------------------------------------


def _read_tlv(data, offset, limit=None):
    """Read one DER element. Returns (tag, content_start, content_end, next_offset)."""
    limit = len(data) if limit is None else limit
    if offset >= limit:
        raise CertificateParseError(f"truncated DER: expected a tag at offset {offset}")
    tag = data[offset]
    idx = offset + 1
    if idx >= limit:
        raise CertificateParseError(f"truncated DER: tag 0x{tag:02x} has no length")
    first = data[idx]
    idx += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise CertificateParseError("indefinite-length encoding is BER, not DER")
    else:
        count = first & 0x7F
        if count > 4:
            raise CertificateParseError(f"length field of {count} bytes is out of range")
        if idx + count > limit:
            raise CertificateParseError("truncated DER: length field")
        length = int.from_bytes(data[idx:idx + count], "big")
        idx += count
    end = idx + length
    if end > limit:
        raise CertificateParseError("truncated DER: content runs past the end of the buffer")
    return tag, idx, end, end


def _iter_tlv(data, start, end):
    """Yield (tag, content_start, content_end) for each element of a constructed body."""
    offset = start
    while offset < end:
        tag, c_start, c_end, nxt = _read_tlv(data, offset, end)
        yield tag, c_start, c_end
        if nxt <= offset:
            raise CertificateParseError("DER element does not advance: the parser would not stop")
        offset = nxt


def _decode_oid(data, start, end):
    """Decode an OBJECT IDENTIFIER body to dotted form."""
    if start >= end:
        raise CertificateParseError("empty OBJECT IDENTIFIER")
    first = data[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    if value:
        parts.append(str(value))          # truncated final arc: record it rather than drop it
    return ".".join(parts)


def _decode_integer(data, start, end):
    if start >= end:
        raise CertificateParseError("empty INTEGER")
    return int.from_bytes(data[start:end], "big", signed=True)


def _sanitise(value, limit=200):
    """Make an issuer-chosen string safe to print and safe to put in a report.

    A certificate subject is arbitrary data chosen by whoever issued it, and it ends up in JSON,
    a terminal and a CBOM, so control characters are folded to spaces and the length is capped.
    """
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _decode_string(tag, data, start, end):
    raw = bytes(data[start:end])
    if tag in (T_BMPSTRING, T_UNIVERSALSTRING):
        text = raw.decode("utf-16-be" if tag == T_BMPSTRING else "utf-32-be", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    return _sanitise(text)


def _decode_time(tag, raw):
    """UTCTime / GeneralizedTime -> an aware UTC datetime, or None when unreadable."""
    text = raw.decode("ascii", "replace").strip()
    try:
        if tag == T_UTCTIME:
            if len(text) < 11 or not text[:6].isdigit():
                return None
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900        # RFC 5280 sliding window
            rest = text[2:]
        else:
            if len(text) < 13 or not text[:8].isdigit():
                return None
            year, rest = int(text[0:4]), text[4:]
        month, day = int(rest[0:2]), int(rest[2:4])
        hour, minute = int(rest[4:6]), int(rest[6:8])
        second = int(rest[8:10]) if len(rest) >= 10 and rest[8:10].isdigit() else 0
        return datetime.datetime(year, month, day, hour, minute, second,
                                 tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


def _bit_indices(data, start, end):
    """DER BIT STRING body -> the set of set bit positions (bit 0 is the MSB of byte 0)."""
    if start >= end:
        raise CertificateParseError("empty BIT STRING")
    unused = data[start]
    if unused > 7:
        raise CertificateParseError(f"BIT STRING declares {unused} unused bits")
    body = bytes(data[start + 1:end])
    total = len(body) * 8 - unused if unused else len(body) * 8
    out = set()
    for bit in range(max(0, total)):
        if body[bit // 8] & (0x80 >> (bit % 8)):
            out.add(bit)
    return out


def _algorithm_oid(data, element):
    """The algorithm OID of an AlgorithmIdentifier ::= SEQUENCE { OID, parameters OPTIONAL }."""
    tag, start, end = element
    if tag != T_SEQUENCE:
        raise CertificateParseError("AlgorithmIdentifier is not a SEQUENCE")
    parts = list(_iter_tlv(data, start, end))
    if not parts or parts[0][0] != T_OID:
        raise CertificateParseError("AlgorithmIdentifier does not start with an OBJECT IDENTIFIER")
    return _decode_oid(data, parts[0][1], parts[0][2])


def _algorithm_parameters(data, element):
    """The parameters elements of an AlgorithmIdentifier: everything after the OID."""
    tag, start, end = element
    if tag != T_SEQUENCE:
        return []
    return list(_iter_tlv(data, start, end))[1:]

def _decode_name(data, element):
    """Name (RDNSequence) -> ('CN=example,O=Acme', 'example')."""
    _, start, end = element
    parts, common_name = [], None
    for _, rdn_start, rdn_end in _iter_tlv(data, start, end):
        for _, atv_start, atv_end in _iter_tlv(data, rdn_start, rdn_end):
            fields = list(_iter_tlv(data, atv_start, atv_end))
            if len(fields) < 2:
                continue
            try:
                oid = _decode_oid(data, fields[0][1], fields[0][2])
            except CertificateParseError:
                continue
            label = NAME_OIDS.get(oid, oid)
            value = _decode_string(fields[1][0], data, fields[1][1], fields[1][2])
            parts.append(f"{label}={value}")
            if oid == "2.5.4.3" and common_name is None:
                common_name = value
    return ", ".join(parts), common_name


def _parse_extensions(data, start, end):
    """Extensions SEQUENCE -> { oid: (value_start, value_end) } of the extnValue OCTET STRINGs."""
    out = {}
    for _, ext_start, ext_end in _iter_tlv(data, start, end):
        fields = list(_iter_tlv(data, ext_start, ext_end))
        if not fields or fields[0][0] != T_OID:
            continue
        oid = _decode_oid(data, fields[0][1], fields[0][2])
        for tag, value_start, value_end in fields[1:]:
            if tag == T_OCTET_STRING:
                out[oid] = (value_start, value_end)
    return out


def _inner_element(data, span):
    """Read the single DER element that an extnValue OCTET STRING contains."""
    tag, start, end, _ = _read_tlv(data, span[0])
    if end > span[1]:
        raise CertificateParseError("extension value runs past its OCTET STRING")
    return tag, start, end


def _decode_key_usage(data, span):
    tag, start, end = _inner_element(data, span)
    if tag != T_BIT_STRING:
        raise CertificateParseError("KeyUsage is not a BIT STRING")
    return [KEY_USAGE_BITS[i] for i in sorted(_bit_indices(data, start, end))
            if i < len(KEY_USAGE_BITS)]


def _decode_extended_key_usage(data, span):
    tag, start, end = _inner_element(data, span)
    if tag != T_SEQUENCE:
        raise CertificateParseError("ExtendedKeyUsage is not a SEQUENCE")
    names = []
    for oid_tag, oid_start, oid_end in _iter_tlv(data, start, end):
        if oid_tag != T_OID:
            continue
        names.append(EKU_NAMES.get(_decode_oid(data, oid_start, oid_end),
                                   _decode_oid(data, oid_start, oid_end)))
    return names


def _decode_basic_constraints(data, span):
    tag, start, end = _inner_element(data, span)
    if tag != T_SEQUENCE:
        raise CertificateParseError("BasicConstraints is not a SEQUENCE")
    is_ca, path_length = False, None
    for field_tag, f_start, f_end in _iter_tlv(data, start, end):
        if field_tag == T_BOOLEAN and f_end > f_start:
            is_ca = bytes(data[f_start:f_end]) != b"\x00"
        elif field_tag == T_INTEGER:
            path_length = _decode_integer(data, f_start, f_end)
    return is_ca, path_length


def _decode_san(data, span):
    """subjectAltName -> the DNS names only. Other GeneralName types are not parsed."""
    tag, start, end = _inner_element(data, span)
    if tag != T_SEQUENCE:
        return []
    names = []
    for name_tag, n_start, n_end in _iter_tlv(data, start, end):
        if name_tag == 0x82:                     # [2] IMPLICIT dNSName
            names.append(_sanitise(bytes(data[n_start:n_end]).decode("utf-8", "replace"), 120))
    return names[:16]

def _rsa_modulus_bits(der_key):
    tag, start, end, _ = _read_tlv(der_key, 0)
    if tag != T_SEQUENCE:
        raise CertificateParseError("RSA public key is not a SEQUENCE")
    parts = list(_iter_tlv(der_key, start, end))
    if not parts or parts[0][0] != T_INTEGER:
        raise CertificateParseError("RSA public key has no modulus")
    return _decode_integer(der_key, parts[0][1], parts[0][2]).bit_length()


def _ec_point_bits(point):
    """Uncompressed point 0x04 || X || Y -> the field size in bits."""
    if not point or point[0] != 0x04:
        return None
    return ((len(point) - 1) // 2) * 8


def _decode_public_key(data, spki):
    """SubjectPublicKeyInfo -> { key_algorithm_oid, key_family, key_size, curve }."""
    tag, start, end = spki
    if tag != T_SEQUENCE:
        raise CertificateParseError("subjectPublicKeyInfo is not a SEQUENCE")
    fields = list(_iter_tlv(data, start, end))
    if len(fields) < 2 or fields[1][0] != T_BIT_STRING:
        raise CertificateParseError("malformed subjectPublicKeyInfo")
    key_oid = _algorithm_oid(data, fields[0])
    params = _algorithm_parameters(data, fields[0])
    known = KEY_FAMILIES.get(key_oid, {"family": "UNKNOWN", "display": None,
                                        "fixed_primitive": None})
    info = {
        "key_algorithm_oid": key_oid,
        "key_family": known["family"],
        "key_size": known.get("key_size"),
        "curve": known.get("curve"),
    }
    body = bytes(data[fields[1][1] + 1:fields[1][2]])       # drop the unused-bits octet
    try:
        if known["family"] == "RSA":
            info["key_size"] = _rsa_modulus_bits(body)
        elif known["family"] == "EC":
            curve_oid = _decode_oid(data, params[0][1], params[0][2]) if params else None
            if curve_oid:
                info["curve"] = CURVE_NAMES.get(curve_oid, curve_oid)
                info["key_size"] = CURVE_SIZES.get(curve_oid)
            if info["key_size"] is None:
                info["key_size"] = _ec_point_bits(body)      # unnamed / custom curve
        elif known["family"] == "DSA":
            if params:
                parts = list(_iter_tlv(data, params[0][1], params[0][2]))
                if parts:
                    info["key_size"] = _decode_integer(data, parts[0][1], parts[0][2]).bit_length()
    except (CertificateParseError, IndexError):
        # A key we can name but not measure is still worth reporting; the size is what is lost.
        pass
    return info


def _pss_digest(data, params):
    for tag, start, end in params:
        if tag != T_SEQUENCE:
            continue
        fields = list(_iter_tlv(data, start, end))
        if not fields or fields[0][0] != T_OID:
            continue
        oid = _decode_oid(data, fields[0][1], fields[0][2])
        if oid in HASH_OIDS:
            return HASH_OIDS[oid]
    return None, None


def _signature_details(data, sig_alg_element):
    """AlgorithmIdentifier -> display name, digest name, digest bits, oid."""
    oid = _algorithm_oid(data, sig_alg_element)
    display, digest, bits = SIG_ALGORITHMS.get(oid, (f"unknownSigAlg({oid})", None, None))
    if oid == "1.2.840.113549.1.1.10" and digest is None:
        # RSASSA-PSS names its digest in the parameters, so read it there rather than guess.
        digest, bits = _pss_digest(data, _algorithm_parameters(data, sig_alg_element))
    return {
        "sig_algorithm_oid": oid,
        "sig_algorithm": display,
        "sig_hash": digest,
        "sig_hash_bits": bits,
    }

def _parse_der(der):
    """Parse a DER-encoded X.509 certificate into the normalised record.

    This is the no-dependency path. It reads what the findings need and raises
    CertificateParseError for anything it cannot read, rather than returning a half-record.
    """
    tag, start, end, _ = _read_tlv(der, 0)
    if tag != T_SEQUENCE:
        raise CertificateParseError(
            f"not a certificate: top-level tag is 0x{tag:02x}, expected SEQUENCE (0x30)")
    top = list(_iter_tlv(der, start, end))
    if len(top) != 3:
        raise CertificateParseError(
            f"a Certificate holds exactly 3 elements, found {len(top)}")
    if top[1][0] != T_SEQUENCE:
        raise CertificateParseError("signatureAlgorithm is not a SEQUENCE")
    if top[2][0] != T_BIT_STRING:
        raise CertificateParseError("signatureValue is not a BIT STRING")

    tbs = _parse_tbs_certificate(der, top[0])
    tbs.update(_signature_details(der, top[1]))
    # RFC 5280 4.1.1.2: the outer and the inner algorithm identifier must be the same. When they
    # are not the certificate is internally inconsistent: recorded, never silently reconciled.
    inner_oid = tbs.get("inner_sig_algorithm_oid")
    tbs["sig_algorithm_mismatch"] = bool(inner_oid and inner_oid != tbs["sig_algorithm_oid"])
    tbs["backend"] = "der"
    return tbs


def _parse_tbs_certificate(der, element):
    tag, start, end = element
    if tag != T_SEQUENCE:
        raise CertificateParseError("tbsCertificate is not a SEQUENCE")
    fields = list(_iter_tlv(der, start, end))
    index = 0
    version = 1
    if fields and fields[0][0] == CTX_0:                 # [0] EXPLICIT Version, DEFAULT v1
        inner = list(_iter_tlv(der, fields[0][1], fields[0][2]))
        if inner:
            version = _decode_integer(der, inner[0][1], inner[0][2]) + 1
        index = 1
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < index + 6:
        raise CertificateParseError(
            f"tbsCertificate has {len(fields) - index} fields; at least 6 are required")
    serial = _decode_integer(der, fields[index][1], fields[index][2])
    inner_sig_oid = _algorithm_oid(der, fields[index + 1])
    issuer, issuer_cn = _decode_name(der, fields[index + 2])
    subject, subject_cn = _decode_name(der, fields[index + 4])
    key = _decode_public_key(der, fields[index + 5])

    not_before = not_after = None
    validity = fields[index + 3]
    for v_tag, v_start, v_end in _iter_tlv(der, validity[1], validity[2]):
        if v_tag in (T_UTCTIME, T_GENTIME):
            value = _decode_time(v_tag, bytes(der[v_start:v_end]))
            if not_before is None:
                not_before = value
            elif not_after is None:
                not_after = value

    extensions = {}
    for e_tag, e_start, e_end in fields[index + 6:]:
        if e_tag == CTX_3:                                # [3] EXPLICIT Extensions
            wrapped = list(_iter_tlv(der, e_start, e_end))
            if wrapped and wrapped[0][0] == T_SEQUENCE:
                extensions = _parse_extensions(der, wrapped[0][1], wrapped[0][2])

    key_usage = (_decode_key_usage(der, extensions[EXT_KEY_USAGE])
                 if EXT_KEY_USAGE in extensions else [])
    eku = (_decode_extended_key_usage(der, extensions[EXT_EXT_KEY_USAGE])
           if EXT_EXT_KEY_USAGE in extensions else [])
    if EXT_BASIC_CONSTRAINTS in extensions:
        is_ca, path_length = _decode_basic_constraints(der, extensions[EXT_BASIC_CONSTRAINTS])
    else:
        is_ca, path_length = False, None
    san = _decode_san(der, extensions[EXT_SAN]) if EXT_SAN in extensions else []

    return {
        "version": version,
        "serial": serial,
        "serial_hex": f"{serial:x}" if serial >= 0 else "-",
        "inner_sig_algorithm_oid": inner_sig_oid,
        "issuer": issuer,
        "issuer_cn": issuer_cn,
        "subject": subject,
        "subject_cn": subject_cn,
        "not_before": not_before,
        "not_after": not_after,
        "key_usage": key_usage,
        "extended_key_usage": eku,
        "is_ca": is_ca,
        "path_length": path_length,
        "subject_alt_names": san,
        **key,
    }

# ------------------------------------------------------------------------------------------
# The `cryptography` backend. Same output record as the DER reader above, so the findings are
# identical either way; only `backend` differs and the sensor reports which one ran.
# ------------------------------------------------------------------------------------------

# cryptography's KeyUsage attribute -> the RFC 5280 bit name used throughout this module.
_CRYPT_KU_ATTRS = (
    ("digital_signature", "digitalsignature"),
    ("content_commitment", "nonrepudiation"),
    ("key_encipherment", "keyencipherment"),
    ("data_encipherment", "dataencipherment"),
    ("key_agreement", "keyagreement"),
    ("key_cert_sign", "keycertsign"),
    ("crl_sign", "crlsign"),
    ("encipher_only", "encipheronly"),
    ("decipher_only", "decipheronly"),
)
_CRYPT_VERSIONS = {"v1": 1, "v3": 3}
# cryptography's digest names -> the spelling the rest of the engine uses.
_CRYPT_HASH_NAMES = {"sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
                     "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}


def _crypt_name(attribute):
    """A stable display string for a `cryptography` object.

    `.name` first (a curve is `secp256r1`), then `._name` (an OID is `serverAuth`). Never
    `str(obj)`: that yields `<...SECP256R1 object at 0x7f...>`, which differs per run and would make
    two scans of the same bytes produce two different reports.
    """
    for attribute_name in ("name", "_name"):
        value = getattr(attribute, attribute_name, None)
        if isinstance(value, str) and value:
            return _sanitise(value, 120)
    return _sanitise(type(attribute).__name__, 120)


def _crypt_key_usage(extension):
    """Read the KeyUsage bits, skipping the pairs cryptography refuses to report inconsistently.

    `encipher_only` is only meaningful with `key_agreement`, and cryptography raises rather than
    returning a value. A bit we cannot read is dropped; the rest of the extension still counts.
    """
    names = []
    for attribute, bit_name in _CRYPT_KU_ATTRS:
        try:
            if getattr(extension.value, attribute):
                names.append(bit_name)
        except Exception:                                   # noqa: BLE001 -- skip, do not fail
            continue
    return names


def _crypt_public_key(public_key):
    """Public key object -> { key_algorithm_oid, key_family, key_size, curve }.

    Matched with isinstance, not by class name: the Rust-backed classes are spelled
    `ECPublicKey`, not `EllipticCurvePublicKey`, and a name comparison silently reported every
    elliptic-curve certificate as an unknown key family until this was caught.
    """
    if isinstance(public_key, _rsa.RSAPublicKey):
        family, size, curve, oid = "RSA", getattr(public_key, "key_size", None), None, \
            "1.2.840.113549.1.1.1"
    elif isinstance(public_key, _ec.EllipticCurvePublicKey):
        family = "EC"
        size = getattr(public_key, "key_size", None)
        curve = _crypt_name(getattr(public_key, "curve", "") or "")
        oid = "1.2.840.10045.2.1"
    elif isinstance(public_key, _dsa.DSAPublicKey):
        family, size, curve, oid = "DSA", getattr(public_key, "key_size", None), None, \
            "1.2.840.10040.4.1"
    elif isinstance(public_key, (_ed25519.Ed25519PublicKey, _ed448.Ed448PublicKey,
                                _x25519.X25519PublicKey, _x448.X448PublicKey)):
        family = type(public_key).__name__.replace("PublicKey", "")
        oid = "1.3.101." + {"Ed25519": "112", "Ed448": "113",
                            "X25519": "110", "X448": "111"}[family]
        size, curve = KEY_FAMILIES[oid]["key_size"], family
    else:
        family, size, curve, oid = "UNKNOWN", None, None, None
    return {"key_algorithm_oid": oid, "key_family": family, "key_size": size, "curve": curve}


def _crypt_signature_details(cert):
    oid = getattr(cert.signature_algorithm_oid, "dotted_string", None)
    display, digest, bits = SIG_ALGORITHMS.get(oid, (f"unknownSigAlg({oid})", None, None))
    try:
        hash_alg = cert.signature_hash_algorithm
    except Exception:                                       # noqa: BLE001 -- unknown/absent digest
        hash_alg = None
    if hash_alg is not None and digest is None:
        # cryptography names digests "sha256"; the rest of the engine says "SHA-256".
        digest = _CRYPT_HASH_NAMES.get(str(getattr(hash_alg, "name", "")).lower(),
                                       str(getattr(hash_alg, "name", "")).upper() or None)
        bits = int(getattr(hash_alg, "digest_size", 0)) * 8 or None
    return {
        "sig_algorithm_oid": oid,
        "sig_algorithm": display,
        "sig_hash": digest,
        "sig_hash_bits": bits,
    }


def _parse_with_cryptography(der):
    """Parse via the `cryptography` package, normalising to the same record as _parse_der."""
    cert = _x509.load_der_x509_certificate(der)
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:                                  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    key_usage, eku, is_ca, path_length, san = [], [], False, None, []
    for extension in cert.extensions:
        value = extension.value
        if isinstance(value, _x509.KeyUsage):
            key_usage = _crypt_key_usage(extension)
        elif isinstance(value, _x509.ExtendedKeyUsage):
            eku = [_crypt_name(oid) for oid in value]
        elif isinstance(value, _x509.BasicConstraints):
            is_ca = bool(value.ca)
            path_length = value.path_length
        elif isinstance(value, _x509.SubjectAlternativeName):
            san = [_sanitise(str(name), 120) for name in value.get_values_for_type(_x509.DNSName)][:16]

    inner_oid = None
    try:
        inner_oid = cert.signature_algorithm_oid.dotted_string
    except Exception:                                       # noqa: BLE001
        pass
    outer_oid = getattr(cert.signature_algorithm_oid, "dotted_string", None)
    return {
        "version": _CRYPT_VERSIONS.get(getattr(cert.version, "name", ""), None),
        "serial": int(cert.serial_number),
        "serial_hex": f"{int(cert.serial_number):x}",
        "inner_sig_algorithm_oid": inner_oid,
        "sig_algorithm_oid": outer_oid,
        "sig_algorithm_mismatch": False,
        "issuer": _sanitise(cert.issuer.rfc4514_string()),
        "issuer_cn": _first_cn(cert.issuer),
        "subject": _sanitise(cert.subject.rfc4514_string()),
        "subject_cn": _first_cn(cert.subject),
        "not_before": not_before,
        "not_after": not_after,
        "key_usage": key_usage,
        "extended_key_usage": eku,
        "is_ca": is_ca,
        "path_length": path_length,
        "subject_alt_names": san,
        **_crypt_public_key(cert.public_key()),
        **_crypt_signature_details(cert),
        "backend": "cryptography",
    }


def _first_cn(name):
    for attribute in name:
        if attribute.oid.dotted_string == "2.5.4.3":
            return _sanitise(attribute.value, 120)
    return None


def parser_backend_status():
    """(available, description) for the coverage manifest. Never raises."""
    if _x509 is not None:
        return True, f"cryptography {_cryptography_version()}"
    return False, f"stdlib DER reader only ({_CRYPTOGRAPHY_ERROR})"


def _cryptography_version():
    try:
        import cryptography
        return getattr(cryptography, "__version__", "unknown")
    except Exception:                                       # noqa: BLE001
        return "unknown"

# ------------------------------------------------------------------------------------------
# Backend selection and the embedded-certificate walk (PKCS#7 and friends).
# ------------------------------------------------------------------------------------------


def parse_certificate(der, prefer="auto"):
    """Parse DER bytes into the normalised certificate record.

    `prefer` is 'auto' | 'cryptography' | 'der'. Both backends produce the same record, so the
    choice is a fidelity decision, never a semantic one -- but a report must say which ran, and
    `backend` says so on every finding. When one backend fails the other is tried, and if both
    fail the raised error names both. A partial record is never returned.
    """
    if prefer not in ("auto", "cryptography", "der"):
        raise ValueError(f"unknown parser backend {prefer!r}")
    if prefer == "der":
        order = ("der", "cryptography")
    elif prefer == "cryptography":
        order = ("cryptography", "der")
    else:
        order = ("cryptography", "der") if _x509 is not None else ("der", "cryptography")

    attempts = []
    for backend in order:
        if backend == "cryptography" and _x509 is None:
            attempts.append(f"cryptography: not importable ({_CRYPTOGRAPHY_ERROR})")
            continue
        try:
            if backend == "cryptography":
                return _parse_with_cryptography(der)
            return _parse_der(der)
        except CertificateParseError as exc:
            attempts.append(f"{backend}: {exc}")
        except Exception as exc:                           # noqa: BLE001 -- a parser bug is a result
            attempts.append(f"{backend}: {type(exc).__name__}: {exc}")
    raise CertificateParseError("not a parsable X.509 certificate [" + "; ".join(attempts) + "]")


def embedded_certificates(der, prefer="auto"):
    """Every certificate inside a DER buffer. Returns [(certificate record, der slice)].

    A PKCS#7 bundle or a concatenated blob is not one certificate, and guessing where the
    certificates sit inside it is exactly the kind of guess this tool refuses to make. So every
    SEQUENCE is offered to the certificate parser and the ones that parse ARE the certificates.

    Two properties matter and are tested. The walk descends into every CONSTRUCTED element, not
    just SEQUENCEs, because PKCS#7 keeps its certificates inside a `[0] IMPLICIT SET OF
    Certificate` -- a walk that stopped at the SET would never reach them. And it does NOT descend
    into a sequence that already parsed as a certificate, so the SEQUENCEs nested inside one
    certificate cannot be reported a second time as certificates of their own. Depth and file size
    are capped, so a hostile bundle cannot make this run away.
    """
    found, seen = [], set()

    def walk(start, end, depth):
        offset = start
        while offset < end:
            try:
                tag, c_start, c_end, nxt = _read_tlv(der, offset, end)
            except CertificateParseError:
                return                              # not a DER structure from here on: stop
            if tag & 0x20:                          # constructed
                if tag == T_SEQUENCE and (offset, nxt) not in seen:
                    seen.add((offset, nxt))
                    # The candidate is the WHOLE element, header included: a certificate is a
                    # SEQUENCE, so handing the parser only its content would never parse.
                    element = der[offset:nxt]
                    try:
                        record = parse_certificate(element, prefer=prefer)
                    except (CertificateParseError, ValueError):
                        record = None
                    if record is not None:
                        found.append((record, element))
                        offset = nxt if nxt > offset else offset + 1
                        continue                   # a certificate: do not descend into it
                if depth < MAX_WALK_DEPTH:
                    walk(c_start, c_end, depth + 1)
            offset = nxt if nxt > offset else offset + 1

    walk(0, len(der), 0)
    return found


# ------------------------------------------------------------------------------------------
# Purpose, primitive and `uses` -- the bridge to engine/purpose.py.
# ------------------------------------------------------------------------------------------

# The purpose vocabulary is engine/purpose.py's, verbatim: a finding's `purpose` field and
# `resolve_purpose(finding)[0]` must be the same string, or the sensor contradicts the resolver it
# exists to feed. Note that a PURPOSE ("key-establishment") and a PRIMITIVE ("key-agreement") are
# different vocabularies, and a finding carries both.
PURPOSE_SIGNATURE = "signature"
PURPOSE_KEY_ESTABLISHMENT = "key-establishment"
PURPOSE_UNRESOLVED = "unresolved"
PRIMITIVE_SIGNATURE = "signature"
PRIMITIVE_KEY_AGREEMENT = "key-agreement"
PRIMITIVE_UNKNOWN = "unknown"


def resolve_key_purpose(key_usage):
    """(purpose, reason) from a certificate KeyUsage list.

    Deliberately the same rule engine/purpose.py applies, so the primitive this sensor writes and
    the purpose the resolver returns agree. When the extension is absent or asserts both purposes
    the answer is `unresolved`: a certificate that does not say what its key is for has not
    settled it, and a human reviewer is cheaper than a confidently wrong ML-KEM/ML-DSA answer.
    """
    usage = {str(bit).lower() for bit in (key_usage or [])}
    signature_bits = usage & KU_SIGNATURE
    establishment_bits = usage & KU_KEY_ESTABLISHMENT
    if signature_bits and establishment_bits:
        return PURPOSE_UNRESOLVED, ("KeyUsage asserts both signing and key establishment "
                                    "(" + ",".join(sorted(signature_bits | establishment_bits)) + ")")
    if signature_bits:
        return PURPOSE_SIGNATURE, "KeyUsage asserts " + ",".join(sorted(signature_bits))
    if establishment_bits:
        return PURPOSE_KEY_ESTABLISHMENT, "KeyUsage asserts " + ",".join(sorted(establishment_bits))
    if usage:
        return PURPOSE_UNRESOLVED, "KeyUsage carries no purpose bit"
    return PURPOSE_UNRESOLVED, "no KeyUsage extension: the certificate asserts no purpose"


def _key_primitive(family_entry, purpose):
    """(primitive, reason) for a public key.

    An algorithm that can only do one thing (Ed25519 signs; X25519 agrees) is typed by that fact
    rather than by its KeyUsage, because a KeyUsage contradicting the algorithm is a certificate
    defect, not a different purpose. A multi-purpose family (RSA, EC) is typed by the KeyUsage,
    and by nothing else.
    """
    fixed = family_entry.get("fixed_primitive")
    if fixed:
        return fixed, f"{family_entry['family']} can only be used for {fixed}"
    if purpose == PURPOSE_SIGNATURE:
        return PRIMITIVE_SIGNATURE, "typed from the certificate KeyUsage"
    if purpose == PURPOSE_KEY_ESTABLISHMENT:
        return PRIMITIVE_KEY_AGREEMENT, "typed from the certificate KeyUsage"
    return PRIMITIVE_UNKNOWN, "the certificate does not say what this key is for"


def _key_display(family_entry, purpose):
    family = family_entry["family"]
    if family == "EC":
        return EC_DISPLAY.get(purpose, "ECC")
    return family_entry.get("display") or family


def _uses_for(info, purpose):
    """(uses, reason).

    `uses` is a claim about DEPLOYMENT and is kept strictly separate from the primitive, which is a
    claim about CRYPTOGRAPHY. A certificate is used for TLS only when it says so (an EKU, or a
    subjectAltName) -- never merely because it happens to hold a key-agreement key. That is why
    this can return a value outside the usual tls/signing/at-rest vocabulary: `key-establishment`
    and `unknown` are the honest answers when the certificate names no protocol, and a made-up
    "tls" would push the recommender towards a hybrid KEM on no evidence.
    """
    eku = set(info.get("extended_key_usage") or [])
    if eku & EKU_TLS:
        return "tls", "ExtendedKeyUsage asserts " + ",".join(sorted(eku & EKU_TLS))
    if eku & EKU_SIGNING:
        return "signing", "ExtendedKeyUsage asserts " + ",".join(sorted(eku & EKU_SIGNING))
    if info.get("subject_alt_names") and purpose == PURPOSE_KEY_ESTABLISHMENT:
        return "tls", "subjectAltName names a host and the key establishes keys"
    if purpose == PURPOSE_SIGNATURE:
        return "signing", "the key is asserted for signing and no protocol is named"
    if purpose == PURPOSE_KEY_ESTABLISHMENT:
        return "key-establishment", "the key establishes keys; no protocol is named by the certificate"
    return "unknown", "the certificate names neither a protocol nor a purpose"

# ------------------------------------------------------------------------------------------
# Findings. Schema copied from engine/scanner.py so these concatenate with source findings and
# feed engine/mosca.py, engine/recommender.py and engine/cbom.py with no translation.
# ------------------------------------------------------------------------------------------

# `evidence_class` is "observed" for every finding here, and that is the load-bearing choice: a
# parsed certificate is a real artefact, so engine/purpose.py maps it to ASSURANCE_OBSERVED, the
# strongest tier. It is not a capability (a name in a manifest) and not a discovered call site
# (a regex over source). The certificate says the key exists AND what it is for.
EVIDENCE_CLASS = "observed"
# A CA certificate is a different migration from an end-entity one: rotating a root means
# redistributing trust, which is the slowest thing in the whole programme.
ARTEFACT_CLASS_CA = "ca-root"
ARTEFACT_CLASS_LEAF = "config"


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _cert_metadata(info, index, now):
    """The certificate facts every finding about that certificate repeats."""
    not_after = info.get("not_after")
    days = None
    if isinstance(not_after, datetime.datetime) and not_after.tzinfo is not None:
        days = int((not_after - now).total_seconds() // 86400)
    subject = info.get("subject") or ""
    issuer = info.get("issuer") or ""
    meta = {
        "cert_index": index,
        "cert_serial": info.get("serial_hex"),
        "cert_subject": subject or None,
        "cert_common_name": info.get("subject_cn"),
        "cert_issuer": issuer or None,
        "cert_version": info.get("version"),
        "not_before": _iso(info.get("not_before")),
        "not_after": _iso(not_after),
        "days_until_expiry": days,
        "is_ca": bool(info.get("is_ca")),
        "extended_key_usage": list(info.get("extended_key_usage") or []),
        "parser_backend": info.get("backend"),
        # "self_issued" and not "self_signed": the subject and issuer NAMES match. The signature
        # is not verified, so calling this self-signed would assert something we did not check.
        "self_issued": bool(subject) and subject == issuer,
    }
    if info.get("subject_alt_names"):
        meta["subject_alt_names"] = list(info["subject_alt_names"])
    if info.get("sig_algorithm_mismatch"):
        meta["sig_algorithm_mismatch"] = True
    return meta


def _finding(file_path, name, primitive, rule_id, match, uses, artefact_class, info, **extra):
    finding = {
        "file": file_path,
        "line": None,
        "type": "algorithm",
        "name": name,
        "primitive": primitive,
        "rule_id": rule_id,
        "scanner": SCANNER_NAME,
        "evidence_class": EVIDENCE_CLASS,
        "artefact_class": artefact_class,
        "uses": uses,
        # `match` is built ONLY from values this sensor derived. A certificate's subject is
        # attacker-chosen text, and engine/purpose.py reads `match` for purpose signals, so
        # putting a CN here would let anyone who ships a certificate choose the purpose the tool
        # reports. The identity lives in cert_subject / cert_common_name instead.
        "match": match[:160],
    }
    finding.update(extra)
    return finding


def public_key_finding(file_path, info, index, now):
    """The certificate's public key: the algorithm, typed by what the certificate says it is for."""
    family_entry = KEY_FAMILIES.get(info.get("key_algorithm_oid"),
                                   {"family": "UNKNOWN", "display": None, "fixed_primitive": None})
    purpose, purpose_reason = resolve_key_purpose(info.get("key_usage"))
    primitive, primitive_reason = _key_primitive(family_entry, purpose)
    display = _key_display(family_entry, purpose)
    uses, uses_reason = _uses_for(info, purpose)
    artefact_class = ARTEFACT_CLASS_CA if info.get("is_ca") else ARTEFACT_CLASS_LEAF
    key_size = info.get("key_size")
    bits = f"{key_size}-bit" if key_size else "key size unknown"

    extra = {
        "key_usage": list(info.get("key_usage") or []),
        "purpose": purpose,
        "purpose_reason": purpose_reason,
        "primitive_reason": primitive_reason,
        "uses_reason": uses_reason,
        "key_algorithm_oid": info.get("key_algorithm_oid"),
        "sig_algorithm": info.get("sig_algorithm"),
    }
    if key_size:
        extra["key_length"] = key_size
    if info.get("curve"):
        extra["curve"] = info["curve"]
    # X for the Mosca inequality. A TLS certificate's key protects session keys, which the
    # house table already prices at 2 years; a code-signing certificate is verifiable for the
    # life of the software. Left unset otherwise, so the default data class applies rather than
    # a guess.
    if uses == "tls":
        extra["data_class"] = "session"
    elif "codeSigning" in (info.get("extended_key_usage") or []):
        extra["data_class"] = "code-signing"

    match = (f"{display} {bits} public key; KeyUsage="
             f"{','.join(info.get('key_usage') or []) or 'absent'}; serial {info.get('serial_hex')}")
    finding = _finding(file_path, display, primitive, RULE_CERT_PUBKEY, match, uses,
                       artefact_class, info, **extra)
    finding.update(_cert_metadata(info, index, now))
    return finding


def signature_algorithm_finding(file_path, info, index, now):
    """The algorithm that signed the certificate.

    A SHA-1 or MD5 certificate signature is a real, classically broken artefact and is reported as
    one -- while being explicit that this is a classical failure, not a quantum one, which is what
    engine/recommender.py's RULE-HASH-LEGACY says when it sees a hash finding.
    """
    digest = info.get("sig_hash")
    digest_bits = info.get("sig_hash_bits")
    if digest:
        name, primitive = str(digest).upper(), "hash"
    else:
        display = info.get("sig_algorithm") or "unknown"
        name = "Ed25519" if "ed25519" in str(display).lower() else str(display)
        primitive = "signature" if primitive_is_signature_oid(info.get("sig_algorithm_oid")) \
            else "unknown"
    uses = "signing"
    # `match` is derived-only, for the same reason as on the public-key finding: the digest name
    # of an RSA signature is "sha256WithRSAEncryption", and engine/purpose.py matches the needle
    # "rsaencrypt" against a lowercased blob -- so quoting the OID name here reported a SHA-256
    # certificate signature as key establishment. The real name is in `sig_algorithm`.
    match = (f"certificate signature digest {name}"
             f"{f' ({digest_bits}-bit)' if digest_bits else ''}"
             f"; serial {info.get('serial_hex')}")
    extra = {
        "sig_algorithm": info.get("sig_algorithm"),
        "sig_algorithm_oid": info.get("sig_algorithm_oid"),
        "uses_reason": "a certificate signature exists to be verified",
        "signature_note": "a digest that signs a certificate is a classical integrity control; "
                          "Grover weakens its pre-image resistance but does not forge signatures, "
                          "so this finding is not a quantum exposure",
    }
    if primitive == "hash" and digest_bits:
        extra["key_length"] = digest_bits
    finding = _finding(file_path, name, primitive, RULE_CERT_SIGALG, match, uses,
                       ARTEFACT_CLASS_CA if info.get("is_ca") else ARTEFACT_CLASS_LEAF,
                       info, **extra)
    finding.update(_cert_metadata(info, index, now))
    return finding


def primitive_is_signature_oid(oid):
    """True for a signature scheme with no separate digest (Ed25519, Ed448)."""
    return SIG_ALGORITHMS.get(oid, (None, None, None))[1] is None and oid in (
        "1.3.101.112", "1.3.101.113")


def validity_findings(file_path, info, index, now):
    """Expiry and not-yet-valid conditions. Classical hygiene, so no Shor claim is attached."""
    not_before, not_after = info.get("not_before"), info.get("not_after")
    out = []
    for when, expired, name, rule_id, reason in (
            (not_after, True, "X509-CERTIFICATE-EXPIRED", RULE_CERT_EXPIRY,
             "notAfter is in the past: the certificate is no longer valid for any peer"),
            (not_before, False, "X509-CERTIFICATE-NOT-YET-VALID", RULE_CERT_NOT_YET_VALID,
             "notBefore is in the future: the certificate is not valid yet")):
        if not isinstance(when, datetime.datetime) or when.tzinfo is None:
            continue
        delta = (now - when).total_seconds()
        if expired and delta <= 0:
            continue
        if not expired and delta >= 0:
            continue
        days = int(delta // 86400)
        finding = _finding(file_path, name, "unknown", rule_id,
                           f"{name.split('-')[-1].lower()} {_iso(when)}", "unknown",
                           ARTEFACT_CLASS_CA if info.get("is_ca") else ARTEFACT_CLASS_LEAF,
                           info,
                           validity_note=reason,
                           days_past_or_until=days)
        # `type` is deliberately not "algorithm": an expired certificate is not an algorithm, and
        # labelling it one would put a certificate lifecycle fact into the crypto inventory.
        finding["type"] = "certificate"
        finding["purpose"] = PURPOSE_UNRESOLVED
        finding["purpose_reason"] = "a certificate validity date is not a cryptographic purpose"
        finding["uses_reason"] = "validity is a deployment condition, not a use of a primitive"
        finding.update(_cert_metadata(info, index, now))
        out.append(finding)
    return out


def purpose_unknown_finding(file_path, info, index, now):
    """The evidence gap, as a finding of its own, for a certificate that names no purpose.

    Emitted only when the KeyUsage extension is ABSENT. When the extension is present but
    dual-use, engine/purpose.py reports the conflict in its signals and engine/recommender.py
    refuses to name a target (RULE-PURPOSE-UNRESOLVED). With no extension there is no signal at
    all, so the recommender falls back to the ALGORITHM NAME -- which would offer ML-KEM for an RSA
    certificate whose key is, in the overwhelmingly common TLS case, a signing key. The gap in the
    evidence is therefore reported explicitly, together with what would close it.
    """
    family = KEY_FAMILIES.get(info.get("key_algorithm_oid"), {"family": "UNKNOWN"})
    key_size = info.get("key_size")
    match = (f"{family['family']} {key_size or '?'}-bit key carries no KeyUsage extension; "
             f"the certificate does not state whether the key signs or establishes keys")
    finding = _finding(file_path, "X509-CERTIFICATE-PURPOSE-UNRESOLVED", "unknown",
                       RULE_CERT_PURPOSE_UNKNOWN, match, "unknown",
                       ARTEFACT_CLASS_CA if info.get("is_ca") else ARTEFACT_CLASS_LEAF, info,
                       purpose=PURPOSE_UNRESOLVED,
                       purpose_reason="no KeyUsage extension: the certificate asserts no purpose",
                       uses_reason="no protocol and no purpose are named by the certificate",
                       would_resolve=[
                           "a KeyUsage extension on the certificate (the issuer states the purpose)",
                           "the TLS handshake or server log naming the negotiated suite",
                           "the call site that consumes this key",
                       ])
    finding["type"] = "certificate"
    finding.update(_cert_metadata(info, index, now))
    return finding


def findings_for_certificate(file_path, info, index, now=None):
    """All findings for one parsed certificate. A certificate always yields at least the key."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    findings = [public_key_finding(file_path, info, index, now),
                signature_algorithm_finding(file_path, info, index, now)]
    findings.extend(validity_findings(file_path, info, index, now))
    if not info.get("key_usage"):
        findings.append(purpose_unknown_finding(file_path, info, index, now))
    return findings

# ------------------------------------------------------------------------------------------
# Reading certificate files.
# ------------------------------------------------------------------------------------------


def _redact_private_keys(text):
    """Replace every private-key PEM body with a marker. Returns (clean text, labels found).

    This runs BEFORE any parsing, so key material is never handed to a parser, never stored on an
    object and never reachable from a finding. A `.pem` that bundles a key with a chain is common
    (`fullchain-with-key.pem`), and refusing to inventory the certificates in it would lose a
    Shor-broken key over material the sensor is not allowed to look at anyway.
    """
    labels = []

    def replace(match):
        label = match.group(1)
        if label in CERTIFICATE_LABELS:
            return match.group(0)
        labels.append(label)
        return f"-----BEGIN {label}----- [REDACTED: private key material is never read] -----"

    return _PEM_BLOCK_RE.sub(replace, text), labels


def pem_certificate_blocks(text):
    """The base64 body of every certificate block, decoded to DER."""
    out = []
    for match in _PEM_BLOCK_RE.finditer(text):
        if match.group(1) not in CERTIFICATE_LABELS:
            continue
        body = "".join(match.group(2).split())
        try:
            if _PEM_TO_DER is not None:
                out.append((match.group(1), _PEM_TO_DER(match.group(0))))
                continue
        except (ValueError, ssl.SSLError):
            pass
        try:
            out.append((match.group(1), base64.b64decode(body, validate=True)))
        except (binascii.Error, ValueError) as exc:
            raise CertificateParseError(
                f"PEM block {match.group(1)!r} does not decode to DER ({exc})") from exc
    return out


def _candidate(path, data=None):
    """Is this path worth opening? Extension first, then a bounded sniff of the first bytes.

    A bare `-----BEGIN ` is enough to be worth opening, because a private key in the scan root is
    a fact the operator needs stated and it is only visible by looking. Opening it costs a read;
    the blocks are redacted immediately afterwards, so nothing sensitive is retained.
    """
    if str(path).lower().endswith(CERT_EXTENSIONS):
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(SNIFF_BYTES)
    except OSError:
        return False
    return PEM_KEY_MARKER in head

class CertificateScanner:
    """Scan a tree, a file or a PEM/DER bundle for X.509 certificates.

    Findings use the `engine/scanner.py` schema, so they concatenate with source findings and feed
    engine/mosca.py, engine/recommender.py and engine/cbom.py unchanged. `errors` is the honesty
    channel: every certificate-shaped file that could not be parsed, and every private key that was
    passed over, appears there with a reason, so an empty finding list never means "could not look".
    """

    def __init__(self, prefer="auto", now=None):
        if prefer not in ("auto", "cryptography", "der"):
            raise ValueError(f"unknown parser backend {prefer!r}")
        self.prefer = prefer
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.errors = []
        self.warnings = []
        self.certificates = []          # every certificate parsed, for the coverage manifest
        self._seen = set()               # (path, serial) -- makes a scan idempotent
        self.coverage = {
            "files_seen": 0,
            "certificate_files_seen": 0,
            "certificates_seen": 0,
            "certificates_parsed": 0,
            "certificates_failed": 0,
            "key_usage_present": 0,
            "purpose_resolved": 0,
            "purpose_unresolved": 0,
            "expired": 0,
            "private_key_files": 0,
            "backend": "cryptography" if _x509 is not None else "der",
        }

    # ------------------------------------------------------------------ bookkeeping

    def _note_error(self, path, reason):
        self.errors.append({"file": path, "reason": reason})

    def _note_warning(self, path, reason):
        self.warnings.append({"file": path, "reason": reason})

    def _record(self, path, info, findings):
        """Register one parsed certificate. Repeated parses of the same certificate are dropped."""
        key = (os.path.abspath(path), str(info.get("serial_hex")), str(info.get("key_algorithm_oid")))
        if key in self._seen:
            return []
        self._seen.add(key)
        self.coverage["certificates_parsed"] += 1
        if info.get("key_usage"):
            self.coverage["key_usage_present"] += 1
        purpose = resolve_key_purpose(info.get("key_usage"))[0]
        if purpose == PURPOSE_UNRESOLVED:
            self.coverage["purpose_unresolved"] += 1
        else:
            self.coverage["purpose_resolved"] += 1
        not_after = info.get("not_after")
        if isinstance(not_after, datetime.datetime) and not_after.tzinfo is not None \
                and not_after < self.now:
            self.coverage["expired"] += 1
        self.certificates.append({
            "file": path,
            "serial": info.get("serial_hex"),
            "subject": info.get("subject"),
            "issuer": info.get("issuer"),
            "not_after": _iso(not_after),
            "key_family": info.get("key_family"),
            "key_usage": list(info.get("key_usage") or []),
            "purpose": purpose,
        })
        return findings

    # ------------------------------------------------------------------ one file

    def scan_file(self, path, data=None):
        """Findings for one file. Any failure is recorded, never raised at the caller."""
        if data is None:
            try:
                size = os.path.getsize(path)
            except OSError as exc:
                self._note_error(path, f"unreadable ({exc.strerror or exc})")
                return []
            if size > MAX_CERT_BYTES:
                self._note_error(path, f"{size} bytes, over the {MAX_CERT_BYTES}-byte cap; not read")
                return []
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError as exc:
                self._note_error(path, f"unreadable ({exc.strerror or exc})")
                return []

        self.coverage["certificate_files_seen"] += 1
        if not data:
            self._note_error(path, "empty file: no certificate")
            return []

        blocks = []
        if PEM_KEY_MARKER in data:
            # `errors="replace"` cannot raise, so there is no exception to catch here.
            text = data.decode("utf-8", "replace")
            text, key_labels = _redact_private_keys(text)
            secret_labels = sorted(set(key_labels) & PRIVATE_KEY_LABELS)
            if key_labels:
                # Named, not silently dropped: an operator should know what is lying next to the
                # certificate, and that none of it was read. A block we do not recognise as a key is
                # still redacted, and is reported under its own label rather than called a key.
                if secret_labels:
                    self.coverage["private_key_files"] += 1
                self._note_warning(path, (
                    f"private key material present ({', '.join(secret_labels)})"
                    if secret_labels else
                    f"non-certificate PEM block(s) redacted ({', '.join(sorted(set(key_labels)))})")
                    + ": never read, never stored, never reported")
            try:
                blocks = pem_certificate_blocks(text)
            except CertificateParseError as exc:
                self._note_error(path, str(exc))
                return []
            if not blocks:
                if secret_labels:
                    reason = ("private key only: nothing to inventory, and the key is never read")
                elif key_labels:
                    reason = (f"PEM file with no CERTIFICATE block (found "
                              f"{', '.join(sorted(set(key_labels)))}: not a certificate)")
                else:
                    reason = "PEM file with no CERTIFICATE block: not a certificate"
                self._note_error(path, reason)
                return []

        findings = []
        for label, der in blocks:
            findings.extend(self._parse_one(path, der, f"PEM {label} block"))
        if not blocks and not findings:
            findings.extend(self._scan_der_container(path, data))
        return findings

    def _parse_one(self, path, der, where):
        self.coverage["certificates_seen"] += 1
        try:
            info = parse_certificate(der, prefer=self.prefer)
        except CertificateParseError as exc:
            self.coverage["certificates_failed"] += 1
            self._note_error(path, f"{where}: {exc}")
            return []
        except Exception as exc:                           # noqa: BLE001 -- a parser bug is a result
            self.coverage["certificates_failed"] += 1
            self._note_error(path, f"{where}: unexpected {type(exc).__name__}: {exc}")
            return []
        index = self.coverage["certificates_parsed"]
        return self._record(path, info, findings_for_certificate(path, info, index, self.now))

    def _scan_der_container(self, path, data):
        """A DER file: one certificate, or a bundle (PKCS#7) holding several."""
        self.coverage["certificates_seen"] += 1
        try:
            info = parse_certificate(data, prefer=self.prefer)
        except CertificateParseError:
            found = embedded_certificates(data, prefer=self.prefer)
            if not found:
                self.coverage["certificates_failed"] += 1
                self._note_error(path, "DER file is not a parsable X.509 certificate, and no "
                                       "certificate was found embedded in it")
                return []
            findings = []
            for index, (inner_info, _der) in enumerate(found):
                findings.extend(self._record(path, inner_info,
                                             findings_for_certificate(path, inner_info, index, self.now)))
            return findings
        index = self.coverage["certificates_parsed"]
        return self._record(path, info, findings_for_certificate(path, info, index, self.now))
    # ------------------------------------------------------------------ targets

    def scan(self, target):
        """Scan a directory tree or a single file. Returns findings, de-duplicated.

        Files that are not certificates are ignored SILENTLY -- they were never in scope, and
        reporting them as errors would drown the real ones. The coverage counters make the
        distinction explicit instead: `files_seen` against `certificate_files_seen`.
        """
        findings = []
        if os.path.isfile(target):
            self.coverage["files_seen"] = 1
            base = os.path.basename(target)
            if is_credential_store(base):
                # Refused by name, before a single byte is read (engine/fspolicy.py). Named in
                # errors so the operator knows the file was passed over deliberately.
                self._note_error(target, "credential store: contents never read")
                return findings
            if not _candidate(target):
                return findings
            return self.scan_file(target)

        if not os.path.isdir(target):
            self._note_error(target, "path does not exist or is not a directory")
            return findings
        try:
            real_root = check_root(target)
        except Exception as exc:                            # noqa: BLE001 -- a refusal is a result
            self._note_error(target, f"refused by filesystem policy: {exc}")
            return findings

        for root, dirs, files in os.walk(real_root):
            dirs[:] = [d for d in dirs
                       if resolve_within(real_root, os.path.join(root, d))]
            for basename in files:
                self.coverage["files_seen"] += 1
                path = os.path.join(root, basename)
                if is_credential_store(basename):
                    self._note_error(path, "credential store: contents never read")
                    continue
                if resolve_within(real_root, path) is None:
                    self._note_error(path, "symlink escapes the scan root: not followed")
                    continue
                if not _candidate(path):
                    continue                                # out of scope, silently
                findings.extend(self.scan_file(path))
        return self._dedupe(findings)

    def _dedupe(self, findings):
        """One finding per (file, rule, name, certificate). The same bytes must give one answer."""
        unique, seen = [], set()
        for finding in findings:
            key = (finding.get("file"), finding.get("rule_id"), finding.get("name"),
                   finding.get("cert_serial"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    # ------------------------------------------------------------------ coverage

    def coverage_manifest(self, findings=None):
        """What was read, what failed, what was deliberately not read, and what is never in scope.

        Same contract as `IndraMeshScanner.coverage_manifest` and `DependencyScanner.coverage_manifest`,
        so one panel can render every sensor.
        """
        available, description = parser_backend_status()
        manifest = {
            "scanners_run": [SCANNER_NAME] if self.certificates else [],
            "files_seen": self.coverage["files_seen"],
            "certificate_files_seen": self.coverage["certificate_files_seen"],
            "certificates_seen": self.coverage["certificates_seen"],
            "certificates_parsed": self.coverage["certificates_parsed"],
            "certificates_failed": self.coverage["certificates_failed"],
            "key_usage_present": self.coverage["key_usage_present"],
            "purpose_resolved": self.coverage["purpose_resolved"],
            "purpose_unresolved": self.coverage["purpose_unresolved"],
            "expired": self.coverage["expired"],
            "private_key_files_passed_over": self.coverage["private_key_files"],
            "parser_backend": self.coverage["backend"],
            "parser_backend_available": available,
            "parser_backend_reason": description,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "never_in_scope": [
                "private key material (redacted before parsing, never read into a finding)",
                "certificate REVALIDATION: a chain is not validated and a signature is not "
                "verified, so 'expired' is a date comparison and 'self_issued' is a name match",
                "certificates inside a live TLS session (requires a capture sensor)",
                "certificates held only by a remote peer, a CA or a managed PKI",
                "encrypted or password-protected key stores, and PKCS#12 containers",
            ],
        }
        if findings is not None:
            manifest["findings_total"] = len(findings)
            # Every finding here is ASSURANCE_OBSERVED by construction. Stated rather than left
            # implicit, because "N findings" without it reads as N breaches.
            manifest["assurance"] = (
                "observed -- each finding is a parsed certificate, so the algorithm, its key size "
                "and its KeyUsage were read from the artefact rather than inferred")
        return manifest


def scan_certificates(target, prefer="auto", now=None):
    """Convenience wrapper: `(findings, scanner)` for a target path."""
    scanner = CertificateScanner(prefer=prefer, now=now)
    return scanner.scan(target), scanner