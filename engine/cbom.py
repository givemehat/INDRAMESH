"""
CycloneDX CBOM generation.

DESIGN NOTE -- what changed on 2026-09-25 and why
------------------------------------------------------------------------------------------------
The previous revision emitted `specVersion: "1.6"` with:

  * non-standard `primitive` values ("public-key-encryption", "symmetric-encryption",
    "cryptographic-library", "neural-detected") -- CycloneDX defines a fixed primitive vocabulary
    (pke, signature, key-agreement, kem, ae, block-cipher, hash, mac, protocol, ...), so a
    consumer's schema validation would reject these;
  * `nistQuantumSecurityLevel` omitted entirely, even though that is the standard's own field for
    expressing whether an algorithm survives a quantum attack (0 = broken);
  * key length, curve and mode dumped into `properties[]` as `keyLength` / `curve` / `mode`
    instead of the standard's `algorithmProperties` fields;
  * no `oid`, no `cryptoFunctions`, no `classicalSecurityLevel`;
  * no `dependencies[]`, so there is no machine-readable "which app uses which algorithm"
    and no way to express CycloneDX's `implements` vs `uses` distinction;
  * un-namespaced property names (`moscaRiskTier`, `pqcRecommendation`) that could collide with
    another tool's properties;
  * no `metadata.timestamp`, `serialNumber` or `tools`, which CycloneDX 1.5+ expects.

validate_real_world.py even printed "Skipping schema validation due to 404 on schema URL", i.e.
the document was never checked against the schema. This revision emits a schema-shaped v1.7
document, keeps all IndraMesh-specific values in a documented `im:` property namespace so the base
document stays valid, and `validate_real_world.py` now performs local schema validation.
"""
import json
import re
import uuid
from datetime import datetime, timezone

from engine.purpose import PURPOSE_UNRESOLVED, resolve_assurance, resolve_purpose

SPEC_VERSION = "1.7"
PROPERTY_NS = "im"          # IndraMesh-namespaced extension properties

# CycloneDX primitive vocabulary, taken from the published 1.7 JSON Schema enum
# (schemas/bom-1.7.schema.json -> definitions.cryptoProperties.properties.algorithmProperties).
# Note the exact spelling `key-agree`, and note that `protocol` is NOT a primitive: a protocol is
# modelled as assetType "protocol" with protocolProperties, which is what we emit below.
PRIMITIVE_ENUM = {
    "pke": "pke",
    "key-agreement": "key-agree",
    "key-agree": "key-agree",
    "key-exchange": "key-agree",
    "kem": "kem",
    "signature": "signature",
    "ae": "ae",
    "block-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    "hash": "hash",
    "mac": "mac",
    "kdf": "kdf",
    "key-derive": "kdf",
    "key-wrap": "key-wrap",
    "combiner": "combiner",
    "xof": "xof",
    "drbg": "drbg",
    "other": "other",
    "public-key-encryption": "pke",
    "digital-signature": "signature",
    "symmetric-encryption": "ae",
    "cryptographic-library": "unknown",
    "neural-detected": "unknown",
    "protocol": "unknown",      # handled via assetType=protocol, not as an algorithm
    "unknown": "unknown",
}

# Protocol asset types allowed by the schema.
PROTOCOL_TYPE_ENUM = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "dtls", "quic",
                      "eap-aka", "eap-aka-prime", "prins", "5g-aka", "other", "unknown"}

# NIST quantum security levels: 0 = broken by a CRQC (Shor), 1-5 = NIST categories.
QUANTUM_BROKEN = 0
QUANTUM_CATEGORY = {"AES-128": 1, "AES-192": 3, "AES-256": 5,
                    "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}

# NIST SP 800-57 security strength in bits, for `classicalSecurityLevel`. That field means
# "equivalent security in BITS", not key length: RSA-2048 is 2048-bit key but ~112-bit
# security. Reporting the key length there overstates every asymmetric algorithm by an order
# of magnitude, and it is the number a consumer reads to judge adequacy.
CLASSICAL_STRENGTH_BITS = {
    "RSA-1024": 80, "RSA-2048": 112, "RSA-3072": 128, "RSA-4096": 152,
    "EC-P-192": 96, "EC-P-224": 112, "EC-P-256": 128, "EC-P-384": 192, "EC-P-521": 256,
    "X25519": 128, "X448": 224, "Ed25519": 128, "Ed448": 224,
    "DSA-2048": 112,
    "ML-KEM-512": 128, "ML-KEM-768": 192, "ML-KEM-1024": 256,
    # ML-DSA-44 is NIST category 2, not 1. The level-1 slot belonged to ML-KEM-512, and giving
    # 44 the same level understated it -- the same error shape as this file's other NIST bugs,
    # where the number that is easy to remember is the number that is wrong.
    "ML-DSA-44": 128, "ML-DSA-65": 192, "ML-DSA-87": 256,
    "SLH-DSA-SHA2-128s": 128, "SLH-DSA-SHA2-192s": 192, "SLH-DSA-SHA2-256s": 256,
    # The `f` (fast) SLH-DSA variants trade signature size for signing time at the SAME security
    # category as the `s` variant. Reporting 0 here said "no security at all", which is false and
    # is the same class of error as calling RSA-1024 quantum-safe.
    "SLH-DSA-SHA2-128f": 128, "SLH-DSA-SHA2-192f": 192, "SLH-DSA-SHA2-256f": 256,
    # HQC (FIPS 206, selected 2025) parameter sets, per the round-3 submission.
    "HQC-128": 128, "HQC-192": 192, "HQC-256": 256,
    # Deployed hybrid KEM groups. Strength is that of the STRONGER component: a hybrid is only
    # as strong as its weakest part, and here the PQ half (ML-KEM-768 = 192) dominates the
    # classical half (X25519 = 128). Reporting 128 understated it; reporting 0 was worse -- it
    # claimed SecP256r1MLKEM768 has NO security, when it is the 128-bit-class PQC group that
    # Cloudflare and AWS actually deploy.
    "X25519MLKEM768": 192, "SecP256r1MLKEM768": 128, "SecP384r1MLKEM1024": 256,
    "X25519Kyber768Draft00": 192, "X25519MLKEM1024": 256, "X25519MLKEM512": 128,
    "MLKEM512": 128, "MLKEM768": 192, "MLKEM1024": 256,
    "AES-128": 128, "AES-192": 192, "AES-256": 256,
    "SHA-256": 128, "SHA-384": 192, "SHA-512": 256,
    # MD5 is not "128-bit". It is a 128-bit OUTPUT, broken by collision in seconds and with no
    # security value whatsoever. 0 is the honest number.
    "SHA-1": 87, "MD5": 0, "3DES": 112,
    # Stream ciphers and the wide-block/legacy block ciphers. These were MISSING entirely, and a
    # missing entry is not neutral: `_classical_strength` returns 0 for an unknown name, so every
    # ChaCha20 and Blowfish finding was published as `classicalSecurityLevel: 0` -- "no security".
    # ChaCha20 is a NIST SP 800-38E standard with a 256-bit key and no practical attack, and it
    # is the default in TLS cipher suites that AES dominates on low-end hardware. Reporting it as
    # worthless is the same class of error as publishing Ed25519 at 0, which was itself a bug we
    # fixed earlier (the mixed-case keys in this table were once unreachable).
    #
    # 3DES is 168-bit raw but ~112-bit effective (Sweet32 birthday bounds on the 64-bit block),
    # so 112 is the honest figure rather than 168.
    "ChaCha20": 256, "XChaCha20": 256, "ChaCha8": 128, "Salsa20": 256,
    "Blowfish": 56, "CAST5": 128, "IDEA": 128, "SEED": 128, "Camellia-128": 128,
    "Camellia-192": 192, "Camellia-256": 256, "Twofish": 256, "RC4": 0,
    # RC4 and MD5 are both here deliberately, with 0. A 1990s stream cipher with practical
    # keystream biases has no security value, and saying so is more useful than omitting it.
    #
    # The ELLIPTIC-CURVE and DH families. These are NOT stored here. They were, and that was a
    # bug: `CLASSICAL_STRENGTH_BITS` is consulted on an EXACT name match BEFORE the key length
    # is considered, so "ECDH" -> 128 shadowed every parameter set, and `{"name": "ECDH",
    # "key_length": 384}` reported 128 instead of 192. The family defaults now live only in
    # `_KEY_LENGTH_STRENGTH` and are reached through `_strength_for_key_length`, which runs
    # first -- so a known parameter set always wins and an unknown curve still gets the
    # conservative P-256-class figure rather than falling through to 0.
    #
    # DH and DHE are the exception to the rule above: they have no NIST-named parameter sets, so
    # the 2048-bit MODP figure is recorded as their name-level value. 112 rather than 2048 is
    # deliberate -- this field means security STRENGTH, and writing the key length here is
    # precisely the error the table's own docstring warns about.
    #
    # THE BARE "DH" KEY IS THE TRAP, and it is why the substring fallback must be length-sorted.
    # A naive `for key in table` reached "DH" while scanning the name "ECDH" and answered 112, so
    # every curve-based key exchange was reported as a 2048-bit MODP group. That turned an
    # UNRATED unknown into a confident "deprecated" verdict in mosca.py -- a sentinel becoming a
    # verdict, which is the one failure mode this module's whole design exists to prevent. The
    # substring fallback now iterates longest-key-first, and a bare name with no size resolves to
    # unknown instead.
    "DH": 112, "DHE": 112, "MODP": 112,
}

# Post-quantum algorithm families, matched on the name BEFORE any primitive-based rule. ML-KEM,
# ML-DSA, SLH-DSA and FN-DSA are the standardised replacements: a CRQC does not break them, so
# they must never inherit the "broken by Shor" verdict that applies to the primitives they
# replace. Getting this backwards is the most damaging possible error in this file -- the tool
# would label its own migration recommendation as quantum-vulnerable.
#
# Spelling variants are NORMALISED before matching rather than listed one by one. Real
# deployments use every spelling at once: IANA/TLS codepoints write `X25519MLKEM768`, the
# `cryptography` library writes `MLKEM1024`, the SSH draft writes `mlkem768x25519-sha256`, and
# the NIST names are hyphenated (`ML-KEM-768`). Matching only the hyphenated forms meant the
# single most important name in the file -- our own recommended hybrid `X25519MLKEM768` -- was
# classified as NOT post-quantum. A tuple of literal strings could never stay current, so the
# families are the regexes that survive the spelling variation instead.
PQC_FAMILIES = (r"ML[-_]?KEM", r"ML[-_]?KSA", r"ML[-_]?DSA", r"SLH[-_]?DSA", r"FN[-_]?DSA",
                r"FALCON", r"XMSS", r"LMS", r"SPHINCS", r"HQC", r"DILITHIUM", r"FIPS.?204",
                r"SPHINCS\+", r"RAINBOW", r"CLASSIC\.MCELIECE", r"MCELIECE", r"NTRU",
                # The pre-standard PQ schemes still present in deployed TLS stacks and IANA
                # registries. These are NOT ML-KEM and must not be reported as if they were, but
                # they ARE post-quantum -- omitting them made `X25519Kyber768Draft00` fall
                # through to the Shor table on the "X25519" it contains, so a hybrid that is
                # half post-quantum was reported as fully quantum-broken.
                r"KYBER", r"BIKE", r"FRODO", r"CRYSTALS", r"SIKE", r"GEMS", r"CECPQ",
                r"MQDSS", r"OQS", r"PICNIC", r"XMSS", r"MSR", r"RAINBOW")

_PQC_RE = re.compile("|".join(PQC_FAMILIES), re.IGNORECASE)


def is_pqc(name):
    """True if `name` denotes a post-quantum (or hybrid) algorithm.

    Deliberately a substring test on a normalised haystack rather than a word-boundary match:
    hybrid names concatenate a classical and a PQ component (`X25519MLKEM768`,
    `SecP384r1MLKEM1024`, `p256_mlkem768`) with no separator, and a `\b` boundary would split
    `MLKEM768` off from its prefix and miss it.
    """
    return bool(_PQC_RE.search(str(name or "")))

# Cryptographic function, inferred from purpose. CycloneDX types `cryptoFunctions` as a list
# from a closed vocabulary, and hardcoding "keygen" for a signing-only artefact is simply wrong.
_CRYPTO_FUNCTIONS = {
    "signature": ["sign", "verify", "keygen"],
    "key-establishment": ["keygen", "encapsulate", "decapsulate", "keyderive"],
    "confidentiality": ["keygen", "encrypt", "decrypt", "keyderive"],
    "hash": ["digest", "tag"],
    "mac": ["tag", "generate", "verify"],
    "ae": ["encrypt", "decrypt", "tag", "keygen"],
    "block-cipher": ["encrypt", "decrypt", "keygen"],
    "stream-cipher": ["encrypt", "decrypt", "keygen"],
    "kdf": ["keyderive"],
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "drbg": ["generate"],
    "unknown": ["keygen"],
}

OID_BY_NAME = {
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "RSA-2048": "1.2.840.113549.1.1.1",
    "RSA-PKCS1-1.5-SHA-256-2048": "1.2.840.113549.1.1.11",
}


def _canonical_primitive(primitive):
    return PRIMITIVE_ENUM.get(str(primitive or "").lower(), "unknown")


def _is_pqc(name):
    """True when the name is a standardised post-quantum algorithm family.

    Checked BEFORE any primitive rule, because ML-KEM has primitive `kem` and ML-DSA has
    primitive `signature` -- the same primitive values as RSA and ECDSA. Ordering the primitive
    check first made every PQC algorithm inherit the "broken by Shor" verdict, so the tool
    labelled its own migration recommendation `nistQuantumSecurityLevel: 0`.

    Delegates to `is_pqc`, which normalises spelling variants rather than matching only the
    hyphenated NIST forms.
    """
    return is_pqc(name)


def _nist_quantum_level(finding, primitive):
    """NIST category 0..5, where 0 means "a CRQC breaks this".

    CycloneDX types `nistQuantumSecurityLevel` as an integer 0-5 and documents 0 as
    "the algorithm is vulnerable to attack by a quantum computer". That makes 0 a STRONG and
    load-bearing claim, not a default.

    The previous version returned 0 as its catch-all, which meant every symmetric cipher, MAC,
    KDF, stream cipher and UNRECOGNISED primitive was published as "a CRQC breaks this". That
    is both wrong and self-contradicting: AES-256, SHA3-256, HMAC-SHA256 and ChaCha20 are the
    algorithms a CRQC does NOT break, and returning 0 for them while also returning 0 for RSA
    destroyed the meaning of the field.

    So a primitive whose category is genuinely unknown is no longer silently 0. The schema has
    no "unknown" member for this field, so the honest answer is to OMIT the property (see
    `_crypto_properties`) rather than assert a number the tool cannot justify. The cases that
    really are Shor-broken are decided by `mosca.quantum_break_model`, which is called first.
    """
    name = str(finding.get("name", "")).upper()
    key_length = finding.get("key_length")

    # A standardised post-quantum algorithm is NOT broken by Shor. This must be tested first.
    if _is_pqc(name):
        if name in QUANTUM_CATEGORY:
            return QUANTUM_CATEGORY[name]
        # Parameter-set families, per FIPS 203 (ML-KEM), 204 (ML-DSA) and 205 (SLH-DSA).
        #
        # `name` is upper-cased above, so every token here MUST be upper-case too. These tokens
        # were once written "128s"/"192s"/"256s", which can never match an upper-cased name, so
        # all six SLH-DSA parameter sets fell through to the default and every one of them
        # claimed NIST level 3. That is wrong for 128 (level 1) and 256 (level 5): the tool
        # overstated a level-1 signature as level 3 and understated a level-5 one as level 3.
        #
        # Both the slow ("S") and fast ("F") SLH-DSA variants are listed. FIPS 205 defines six
        # parameter sets, and recognising only three of them is silently wrong on the rest.
        #
        # The two-digit ML-DSA tokens ("44", "65", "87") are checked against a name that also
        # carries a hash family, so they are matched on a dash boundary rather than as bare
        # substrings: "44" must not be found inside an unrelated token.
        for token, level in (("ML-KEM-512", 1), ("ML-DSA-44", 1), ("128S", 1), ("128F", 1),
                             ("ML-KEM-768", 3), ("ML-DSA-65", 3), ("192S", 3), ("192F", 3),
                             ("ML-KEM-1024", 5), ("ML-DSA-87", 5), ("256S", 5), ("256F", 5),
                             ("HQC-128", 1), ("HQC-192", 3), ("HQC-256", 5)):
            if token in name:
                return level
        # A PQC family we have no level for is not "broken", and 3 is the honest floor: these
        # algorithms are not Shor-broken and the tool does not yet have the table to say better.
        return 3

    # Asymmetric primitives really are broken by a CRQC. 0 is correct HERE and only here.
    #
    # The list must include the CANONICAL CycloneDX spellings, not just the scanner's own
    # vocabulary: `generate_cbom` normalises `key-agreement` to `key-agree` before this runs, so
    # a list containing only the internal name silently returned None for every key-agreement
    # asset -- the same value an unrecognised primitive gets. An ECDH finding therefore lost its
    # "broken by a CRQC" marking entirely.
    #
    # `kdf` and `key-derive` are DELIBERATELY ABSENT. They were here once, and it was wrong:
    # PBKDF2, Argon2id, scrypt and bcrypt are not Shor targets, so listing them published
    # `nistQuantumSecurityLevel: 0` -- CycloneDX's own definition of "vulnerable to attack by a
    # quantum computer" -- for algorithms a CRQC does not break. It also contradicted
    # `mosca.py`, which scopes KDFs out of the public-key analysis and returns `not-in-scope` for
    # them. A KDF's quantum story is Grover on its underlying hash, which is a preimage effect
    # already reflected by the hash's own level; asserting 0 here overstated it by five levels.
    if primitive in ("pke", "signature", "key-agreement", "key-agree", "kem",
                     "pke-encapsulation"):
        return QUANTUM_BROKEN

    if "AES" in name:
        if key_length:
            # An AES size we do not have a level for is unknown, not 0.
            return QUANTUM_CATEGORY.get(f"AES-{key_length}")
        return None
    if primitive == "hash":
        if "SHA256" in name or "SHA-256" in name:
            return 1
        if "SHA-384" in name or "SHA384" in name:
            return 3
        if "SHA-512" in name or "SHA512" in name:
            return 5
        # SHA-3, SHAKE, BLAKE2 and MD5/SHA-1 have no NIST category in this table. Returning 0
        # would claim a CRQC breaks them, which is false -- Grover only halves the exponent.
        return None

    # Symmetric, MAC, KDF, stream cipher, or an unrecognised primitive. UNKNOWN.
    # The caller omits the property rather than publishing a false 0.
    return None


def _coerce_int(value):
    """Best-effort int, or None. A CBOM generator must never crash on a malformed finding.

    `key_length` arrives from regex capture groups and from third-party inputs, so it can be any
    string. `int('unknown')` raises ValueError and would abort the whole report -- turning one
    bad field into a total scan failure. An unknown key size is a reportable condition, not a
    fatal one: it is simply omitted and the artefact stays in the CBOM.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# CycloneDX 1.7 types `algorithmProperties.mode` as a CLOSED enum with nine values. Modes such as
# XTS, GCM-SIV, EAX, OCB and SIV are real, widely deployed AEAD/cipher modes but are NOT in it.
# The schema provides `other` and `unknown` precisely so an unrecognised mode can be
# represented; emitting a raw lowercase mode name would produce a document that fails validation,
# so a mode outside the enum degrades to `other` and the verbatim value is preserved in the
# namespaced `im:` properties where it costs the document nothing.
CYCLONEDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}


def _canonical_mode(raw):
    """Map a free-text cipher mode onto the CycloneDX closed enum, or None if unrecognised."""
    m = str(raw or "").strip().lower().replace("_", "-")
    if not m:
        return None
    if m in CYCLONEDX_MODES:
        return m
    # A compound name such as "GCM-SIV" or "AES-256-GCM" resolves to its base mode when the
    # base is a member of the enum; otherwise it is genuinely `other`.
    for part in re.split(r"[-/ ]+", m):
        if part in CYCLONEDX_MODES:
            return part
    return "other"


def _classical_strength(finding, primitive):
    """Equivalent security in BITS (NIST SP 800-57), for `classicalSecurityLevel`.

    That field means security strength, NOT key length. RSA-2048 has a 2048-bit key but ~112-bit
    security; reporting 2048 overstated every asymmetric algorithm by more than an order of
    magnitude, and this is the number a downstream consumer reads to judge adequacy. The raw key
    length is still emitted, correctly, as `parameterSetIdentifier`.
    """
    name = str(finding.get("name", "") or "")
    upper = name.upper()
    # The table is keyed in SP 800-57 canonical casing ("Ed25519", "SLH-DSA-SHA2-128f"), but
    # `upper` is uppercase, so every mixed-case key was UNREACHABLE and the substring fallback
    # was case-sensitive too. Measured before the fix: 8 of 47 entries dead, including Ed25519
    # and Ed448 -- both Shor-broken, both NIST-registered -- which were therefore published as
    # `classicalSecurityLevel: 0` ("no security"). A table that silently cannot be read is
    # worse than no table.
    if name in CLASSICAL_STRENGTH_BITS:
        return CLASSICAL_STRENGTH_BITS[name]

    # A KNOWN KEY LENGTH OUTRANKS A FAMILY DEFAULT, and this check therefore sits ABOVE the
    # upper-cased table lookup -- not after it. The table carries family entries ("ECDH": 128) so
    # that a finding with no curve at all stops falling through to `return 0`, and an earlier
    # ordering let those family keys shadow the parameter sets: `{"name": "ECDH",
    # "key_length": 384}` reported 128 instead of 192, making a P-384 finding look like P-256
    # purely because the table had just been made more generous. Being imprecise must never be
    # rewarded with a better-looking number.
    key_bits = _coerce_int(finding.get("key_length"))
    if key_bits is not None:
        sized = _strength_for_key_length(upper, key_bits)
        if sized is not None:
            return sized

    if upper in CLASSICAL_STRENGTH_BITS_UPPER:
        return CLASSICAL_STRENGTH_BITS_UPPER[upper]

    # Substring fallback, and it must be WORD-BOUNDED with the longest key first.
    #
    # "ECDH" contains "DH" and "ECDSA" contains "DS". Two independent bugs lived here, and both
    # turned an UNRATED unknown into a confident verdict:
    #   1. plain substring matching reached "DH" while scanning the name "ECDH" and answered 112,
    #      so every curve-based key exchange was reported as a 2048-bit MODP group;
    #   2. without length ordering, a family containing another family shadows it.
    # Word boundaries fix (1) -- `\bDH\b` does not match inside "ECDH" -- and longest-first
    # ordering fixes (2). mosca.py then read 112, selected the `lt_128` tier, and published
    # "deprecated" for an algorithm whose curve it had never seen.
    for key in sorted(CLASSICAL_STRENGTH_BITS_UPPER, key=len, reverse=True):
        if re.search(rf"\b{re.escape(key)}\b", upper):
            return CLASSICAL_STRENGTH_BITS_UPPER[key]

    # Nothing in the table and no usable key length. Return None, NOT 0: an unknown algorithm is
    # unknown, and in this field 0 means "no security whatsoever". The schema has no "unknown"
    # member, so the honest move is to omit the property, which `_crypto_properties` does.
    return None


# NIST SP 800-57 Part 1 Rev 5 strength by PARAMETER SET, for the case where the algorithm name
# is a bare family and the parameter is the key length. Extracted from the inline table that used
# to live at the bottom of `_classical_strength`, because the function now has to consult it
# BEFORE the family fallbacks, and duplicating the numbers in two places is how a table drifts.
# The SECP224R1 entry is 112, not 96: 224-bit curves were removed from SP 800-57's second
# edition after a 2013 transition, and the historical 96-bit figure is not what a current tool
# should publish.
_KEY_LENGTH_STRENGTH = {
    "RSA": {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256},
    "DSA": {1024: 80, 2048: 112, 3072: 128},
    "EC":   {192: 96, 224: 112, 256: 128, 384: 192, 521: 256},
    # ELLIPTIC-CURVE and DIFFIE-HELLMAN are checked by substring, so "EC" must not preempt them.
    # The loop below therefore tests the longer family names first.
    "ECDSA": {192: 96, 224: 112, 256: 128, 384: 192, 521: 256},
    "ECDH":  {192: 96, 224: 112, 256: 128, 384: 192, 521: 256},
    "DH":    {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256},
    "DHE":   {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256},
    "MODP":  {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256},
    # SYMMETRIC and HASH: for these the key/digest size IS the strength, so the length alone is
    # enough. AES-256 is 256 because a 256-bit key is a 256-bit claim, not because "AES" appears.
    "AES":   {128: 128, 192: 192, 256: 256},
    "SHA":   {1: 87, 224: 112, 256: 128, 384: 192, 512: 256},
    "CHACHA": {256: 256},
}

# Longest first, so "ECDSA" is tested before "EC" and "ECDH" before "EC".
_STRENGTH_FAMILY_ORDER = ("ECDSA", "ECDH", "SHA", "CHACHA", "AES", "RSA", "DSA", "DHE", "MODP",
                          "DH", "EC")


def _strength_for_key_length(upper_name, key_bits):
    """Security strength implied by a bare family name plus a key length, or None.

    Extracted so `_classical_strength` can consult the parameter set BEFORE the family defaults.
    The ordering inside is the subtle part: "EC" is a substring of both "ECDSA" and "ECDH", so
    the longer families are tested first. Getting that backwards reports every ECDSA-P-256 as a
    192-bit curve, which is a security OVERSTATEMENT rather than an error of precision.
    """
    if not upper_name or not key_bits:
        return None
    for family in _STRENGTH_FAMILY_ORDER:
        table = _KEY_LENGTH_STRENGTH[family]
        if family in upper_name and key_bits in table:
            return table[key_bits]
    return None


def _crypto_functions(finding, primitive):
    """The cryptographic functions this asset provides, per CycloneDX's closed vocabulary.

    Hardcoding ["keygen"] for every artefact was simply wrong: a signing key does not encrypt and
    a digest is not a key generator. The purpose model already resolves what a finding is FOR, so
    the function list follows the purpose when known and the primitive otherwise.
    """
    try:
        purpose = resolve_purpose(finding)[0]
    except Exception:                                    # noqa: BLE001 - never fail a report
        purpose = PURPOSE_UNRESOLVED
    fns = _CRYPTO_FUNCTIONS.get(purpose)
    if fns is None:
        fns = _CRYPTO_FUNCTIONS.get(primitive, _CRYPTO_FUNCTIONS["unknown"])
    return list(fns)


# Case-folded view of the table above, built once at import. Without it the mixed-case canonical
# spellings ("Ed25519", "Ed448", "SLH-DSA-SHA2-128f") could never be matched, because the lookup
# upper-cases the NAME before probing a table keyed in canonical casing.
CLASSICAL_STRENGTH_BITS_UPPER = {k.upper(): v for k, v in CLASSICAL_STRENGTH_BITS.items()}


# CycloneDX 1.7 `relatedCryptoMaterialProperties.type` enum members we can justify from a
# source-level match. A private key found in a repository is `private-key`; we do NOT claim
# `credential` or `token`, because finding the string does not prove the credential is live.
RELATED_MATERIAL_TYPES = {
    "IM-KEY-PEM-001": "private-key",
    "IM-KEY-PGP-001": "private-key",
}


def _related_material_type(finding):
    """The `relatedCryptoMaterialProperties.type` for this finding, or None if it is not one.

    Keyed on the RULE, not the name. A finding whose `name` merely contains the word "key" is
    not thereby key material -- an algorithm called "key-agreement" is an algorithm, and typing
    it as `related-crypto-material` would be a new category error in the opposite direction.
    """
    return RELATED_MATERIAL_TYPES.get(str(finding.get("rule_id", "")))


def _algorithm_properties(finding, primitive):
    props = {
        "primitive": primitive,
        "executionEnvironment": "software-plain-ram",
        "cryptoFunctions": _crypto_functions(finding, primitive),
    }
    key_length = finding.get("key_length")
    if key_length:
        # The raw value is still worth recording (e.g. "unknown"), but only a real integer can
        # be a CycloneDX parameterSetIdentifier consumer would recognise.
        props["parameterSetIdentifier"] = str(key_length)
    if finding.get("mode"):
        mode = _canonical_mode(finding["mode"])
        if mode:
            props["mode"] = mode
    if finding.get("curve"):
        props["curve"] = str(finding["curve"])
    # `uses` (at-rest / tls / signing) has no CycloneDX field; it is emitted as an `im:uses`
    # property instead, so it never invalidates the base document.
    #
    # classicalSecurityLevel is EQUIVALENT SECURITY IN BITS (NIST SP 800-57), not key length.
    #
    # A None result is OMITTED, not emitted as JSON null. CycloneDX types this field as a
    # non-nullable integer, so `"classicalSecurityLevel": null` fails schema validation and takes
    # the whole CBOM with it -- the property has to be absent from the dict, not present-and-empty.
    # This is the same discipline the comment below describes for the quantum level, and it is
    # what makes an unknown curve (an ECDSA finding whose curve the scanner could not see) leave
    # no trace rather than an invalid one.
    strength = _classical_strength(finding, primitive)
    if strength is not None:
        props["classicalSecurityLevel"] = strength
    # REMOVED, TWICE, AND NOW FOR THE THIRD REASON: the old fallback read
    #     if not props["classicalSecurityLevel"] and primitive == "hash":
    #         props["classicalSecurityLevel"] = 0
    # which published an unmeasured hash as 0, and then (after a partial fix) an ECDSA with an
    # unknown curve as 0. Both are worse than saying nothing. MD5 genuinely IS 0 and is in the
    # table, so the special case is no longer needed for it either.
    # 0 is a load-bearing claim in this field -- "a CRQC breaks this" -- so it is emitted only
    # when the tool can justify it. `_nist_quantum_level` returns None for a category it does
    # not know, and an unknown category is OMITTED rather than published as 0. Emitting 0 for
    # every symmetric cipher, MAC, KDF and unrecognised primitive was how AES-256 and RSA came
    # to share a value that means opposite things.
    nist_level = _nist_quantum_level(finding, primitive)
    if nist_level is None:
        # The primitive alone is not always enough. `engine/mosca.quantum_break_model` decides
        # Shor vs Grover vs unaffected from the ALGORITHM NAME, and it knows about named curves
        # (secp256k1, P-384, brainpool, SM2) that the primitive enum cannot express. An ECC
        # finding that arrives with primitive="unknown" was therefore emitted with no
        # nistQuantumSecurityLevel at all, while the SAME record's risk block said
        # `break_model=broken-by-Shor`. The document denied the quantum marking the engine had
        # just established. Where mosca says Shor-broken, 0 is the correct value regardless of
        # how the primitive was labelled.
        try:
            from engine.mosca import quantum_break_model
            if quantum_break_model(finding.get("name", ""), primitive) == "broken-by-Shor":
                nist_level = QUANTUM_BROKEN
        except Exception:      # never let a cross-module import break CBOM generation
            pass
    if nist_level is not None:
        props["nistQuantumSecurityLevel"] = nist_level
    return props


def nist_level_gap(finding, primitive):
    """Why `nistQuantumSecurityLevel` is absent, or '' when it is present.

    CycloneDX 1.7 sets `additionalProperties: false` on `algorithmProperties`, so the reason
    cannot live beside the value it explains -- an invented sibling field would fail schema
    validation. It is emitted as an `im:`-namespaced property instead, which is this project's
    existing convention for data the standard has no slot for.
    """
    if _nist_quantum_level(finding, primitive) is not None:
        return ""
    return ("no NIST category is derivable for this primitive by static analysis; the value is "
            "omitted rather than reported as 0, which would claim a CRQC breaks it")


def _ecd_properties(finding, risk, recommendation):
    """All IndraMesh-specific values, namespaced so the base document stays schema-valid."""
    out = []
    name = str(finding.get("name", "unknown"))
    for key, value in (
        ("algorithm", name),
        ("evidence_class", finding.get("evidence_class", "discovered")),
        ("artefact_class", finding.get("artefact_class", "source")),
        ("uses", finding.get("uses", "")),
        ("scanner", finding.get("scanner", "")),
        ("rule_id", finding.get("rule_id", "")),
    ):
        if value:
            out.append({"name": f"{PROPERTY_NS}:{key}", "value": str(value)})

    # Assurance answers "what does the evidence PROVE?", which is a different question from
    # confidence ("is this identification correct?"). A dependency on a crypto library can be a
    # CERTAIN identification of something that proves very little, so the two must both be
    # exported or a reader cannot tell which they are looking at.
    assurance, assurance_reason = resolve_assurance(finding)
    out.append({"name": f"{PROPERTY_NS}:assurance", "value": assurance})
    out.append({"name": f"{PROPERTY_NS}:assurance_meaning", "value": assurance_reason})

    # runtime-resolved: name the resolver file ON the component. A consumer that sees an
    # algorithm name without this property reads it as "this is what runs"; with it, as
    # "this is what was asked for -- the file below decides what runs". Absence of the
    # property means the scanner pinned the identity from the scanned bytes.
    if finding.get("resolver"):
        out.append({"name": f"{PROPERTY_NS}:resolver", "value": str(finding["resolver"])[:500]})

    # Say WHY nistQuantumSecurityLevel is missing. A consumer that sees the field absent cannot
    # distinguish "this asset was assessed and has no category" from "IndraMesh never looked", and
    # the first reading of an absent field is usually the optimistic one.
    # The gap reason must be computed from the SAME primitive the LEVEL was computed from.
    # `_algorithm_properties` normalises through PRIMITIVE_ENUM, but this was called with the raw
    # `finding["primitive"]`. So a "digital-signature" finding emitted
    # nistQuantumSecurityLevel=0 (because it normalises to "signature", a known member) AND the
    # text "no NIST category is derivable" (because the raw string is not a member). One
    # component, two opposite claims about the same field; 4 of 22 components carried both.
    # Normalising here makes the two answers agree by construction.
    gap = nist_level_gap(finding, _canonical_primitive(finding.get("primitive", "")))
    if gap:
        out.append({"name": f"{PROPERTY_NS}:nist_level_gap", "value": gap})

    # Purpose decides which PQC family replaces the primitive, and is itself sometimes
    # unresolvable from static evidence. Exporting it makes the recommendation auditable.
    purpose, purpose_signals, purpose_reason = resolve_purpose(finding)
    out.append({"name": f"{PROPERTY_NS}:purpose", "value": purpose})
    if purpose_signals:
        out.append({"name": f"{PROPERTY_NS}:purpose_signals", "value": "; ".join(purpose_signals)})
    if purpose == PURPOSE_UNRESOLVED:
        out.append({"name": f"{PROPERTY_NS}:purpose_note", "value": purpose_reason})

    if finding.get("line"):
        out.append({"name": f"{PROPERTY_NS}:line", "value": str(finding["line"])})
    if finding.get("mode"):
        # The verbatim mode, alongside the schema-constrained `algorithmProperties.mode`. A mode
        # like "GCM-SIV" or "XTS" is not in the CycloneDX closed enum and is emitted there as
        # `other`; recording what it actually was prevents that from being a silent loss.
        out.append({"name": f"{PROPERTY_NS}:mode_verbatim", "value": str(finding["mode"])})
    if finding.get("dl_confidence") is not None:
        out.append({"name": f"{PROPERTY_NS}:detector_confidence",
                    "value": str(finding.get("dl_confidence"))})
    if risk:
        for key in ("tier", "x", "y", "z", "x_y", "margin", "is_vulnerable",
                    "hndl_exposed", "horizon_type", "break_model", "x_reason", "y_reason",
                    "latest_safe_migration_start", "policy", "z_stable"):
            if key in risk:
                value = risk[key]
                out.append({"name": f"{PROPERTY_NS}:mosca.{key}", "value": str(value)})
        if risk.get("policy_deadline", {}).get("year"):
            out.append({"name": f"{PROPERTY_NS}:mosca.policy_deadline",
                        "value": str(risk["policy_deadline"]["year"])})
        # The YEAR alone is not the verdict. A downstream consumer reading only
        # `policy_deadline = 2030` cannot tell a 112-bit algorithm that is merely deprecated
        # (and stays usable while migrating) from a >= 128-bit one that is disallowed. The
        # status and the source document's draft state travel with it, or the export is the
        # place where the nuance is lost.
        pd = risk.get("policy_deadline") or {}
        if pd.get("status"):
            out.append({"name": f"{PROPERTY_NS}:mosca.policy_status",
                        "value": str(pd["status"])})
        if pd.get("note"):
            out.append({"name": f"{PROPERTY_NS}:mosca.policy_note",
                        "value": str(pd["note"])[:240]})
        if pd.get("draft"):
            out.append({"name": f"{PROPERTY_NS}:mosca.policy_source_is_draft",
                        "value": "true"})
        if risk.get("z_band"):
            out.append({"name": f"{PROPERTY_NS}:mosca.z_band", "value": json.dumps(risk["z_band"])})
    if recommendation:
        for key in ("algorithm", "action", "hybrid_semantics", "cost_band",
                    "ossification_risk", "rule_trace", "standard_basis", "tradeoff_size",
                    "tradeoff_latency"):
            value = recommendation.get(key)
            if value:
                out.append({"name": f"{PROPERTY_NS}:rec.{key}",
                            "value": value if isinstance(value, str) else json.dumps(value)})
    return out


def generate_cbom(findings, enriched=False, subject_name="IndraMesh-Scanned-Artefact",
                  subject_version=None, coverage=None):
    """Build a CycloneDX v1.7 CBOM from scanner findings.

    When `enriched=True` and a finding carries `risk` / `recommendation`, the Mosca verdict and
    the PQC recommendation are attached as `im:`-namespaced properties so the base document
    remains schema-valid and portable to other tools.
    """
    components = []
    dependencies = []
    uses_targets = []

    for idx, f in enumerate(findings):
        ref = f"crypto-asset-{idx}"
        primitive = _canonical_primitive(f.get("primitive"))
        is_library = f.get("type") == "library"
        risk = f.get("risk") if enriched else None
        recommendation = f.get("recommendation") if enriched else None

        if is_library:
            # A library is a software component that *implements* algorithms, not an algorithm
            # itself. Emitting it as cryptographic-asset with a fake primitive misrepresents it.
            components.append({
                "type": "library",
                "bom-ref": ref,
                "name": f.get("name", "unknown"),
                "scope": "required",
                "properties": _ecd_properties(f, risk, recommendation),
            })
            continue

        # A protocol (TLS, a configured cipher suite) is modelled by CycloneDX as
        # assetType "protocol" with protocolProperties -- `protocol` is NOT a valid primitive.
        if f.get("primitive") == "protocol" or f.get("type") == "protocol":
            proto_type = "tls" if "TLS" in str(f.get("name", "")).upper() else "other"
            if proto_type not in PROTOCOL_TYPE_ENUM:
                proto_type = "other"
            protocol = {"type": proto_type}
            if f.get("match"):
                protocol["version"] = str(f["match"])[:120]
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f.get("name", "unknown"),
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": protocol,
                },
                "properties": _ecd_properties(f, risk, recommendation),
            })
            if f.get("line"):
                components[-1]["evidence"] = {
                    "occurrences": [{"bom-ref": f"occ-{idx}",
                                     "location": f.get("file", ""), "line": f.get("line")}]
                }
            continue

        algo = _algorithm_properties(f, primitive)
        # A PRIVATE KEY is not an algorithm, and `related-crypto-material` is the asset type
        # CycloneDX 1.7 defines for exactly this: "other cryptographic assets related to
        # algorithms, certificates, and protocols such as keys and tokens". Its properties object
        # has NO `primitive` field, so the whole question of which enum member describes a PEM
        # header simply does not arise -- the previous shape forced a hardcoded "key" primitive
        # that canonicalised to `unknown`.
        if _related_material_type(f) is not None:
            material = _related_material_type(f)
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f.get("name") or "unknown",
                "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": {
                        "type": material,
                        "state": "pre-activation",
                    },
                },
                "properties": _ecd_properties(f, risk, recommendation),
            })
            if f.get("line"):
                components[-1]["evidence"] = {
                    "occurrences": [{"bom-ref": f"occ-{idx}",
                                     "location": f.get("file", ""), "line": f.get("line")}]
                }
            continue
        # `dict.get(k, default)` returns None when the key EXISTS with a None value, so a
        # finding from an external source carrying `"name": null` produced `"name": null` and an
        # invalid document. Falling back only on falsy covers both the missing key and the null.
        # The value is also coerced to a hashable string: a JSON inventory can legitimately carry
        # a list or dict for `name`, and an unhashable key raises TypeError deep inside a dict
        # lookup -- taking the whole report down over one malformed field.
        algo_name = f.get("name")
        if not isinstance(algo_name, str) or not algo_name:
            algo_name = "unknown"
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": algo_name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
            "properties": _ecd_properties(f, risk, recommendation),
        }
        oid = OID_BY_NAME.get(algo_name)
        if oid:
            component["cryptoProperties"]["oid"] = oid
        if f.get("line"):
            component["evidence"] = {
                "occurrences": [{
                    "bom-ref": f"occ-{idx}",
                    "location": f.get("file", ""),
                    "line": f.get("line"),
                }]
            }
        components.append(component)
        if not f.get("file"):
            uses_targets.append(ref)

    if uses_targets:
        # NO `dependencyType` field here. The vendored CycloneDX 1.7 `definitions.dependency`
        # allows only `ref`, `dependsOn` and `provides`, and sets additionalProperties:false --
        # emitting `dependencyType` makes the document invalid for every consumer that validates
        # it, which defeats the purpose of publishing a CBOM at all. The `implements` vs `uses`
        # distinction the design intends is expressed through `compositions` and component
        # `type`, not through a field on a dependency edge. Findings with no `file` are ambient
        # or global, so the subject genuinely does use them; that is what `dependsOn` says.
        dependencies.append({
            "ref": subject_name,
            "dependsOn": uses_targets,
        })

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata_component = {"type": "application", "name": str(subject_name)}
    if subject_version is not None and str(subject_version).strip():
        # CycloneDX types `component.version` as a string. A caller passing `1` (an int) would
        # otherwise produce a document that fails schema validation, so coerce rather than
        # reject: the value is still meaningful as text and refusing it would be unhelpful.
        metadata_component["version"] = str(subject_version)

    metadata = {
        "timestamp": timestamp,
        "tools": {"components": [
            {"type": "application", "name": "indramesh", "version": "0.2.0"},
        ]},
        "component": metadata_component,
    }
    if coverage:
        metadata["properties"] = [
            {"name": f"{PROPERTY_NS}:coverage.files_scanned", "value": str(coverage.get("files_scanned", 0))},
            {"name": f"{PROPERTY_NS}:coverage.files_skipped", "value": str(coverage.get("files_skipped", 0))},
            {"name": f"{PROPERTY_NS}:coverage.ml_reason", "value": str(coverage.get("ml_reason", ""))},
            {"name": f"{PROPERTY_NS}:coverage.never_in_scope", "value": json.dumps(coverage.get("never_in_scope", []))},
        ]
        # Report the PROVEN-use count next to the raw total. Reporting "412 quantum-vulnerable
        # assets" when 300 are capabilities nothing calls is the easiest way for a discovery tool
        # to mislead, so the two numbers are published together or the raw one is meaningless.
        if "assurance_histogram" in coverage:
            hist = coverage["assurance_histogram"]
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:assurance_histogram", "value": json.dumps(hist)})
        if "proven_use" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:proven_use", "value": str(coverage["proven_use"])})
        if "findings_total" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:findings_total", "value": str(coverage["findings_total"])})
        if "unresolved_purpose" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:unresolved_purpose", "value": str(coverage["unresolved_purpose"])})

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if dependencies:
        cbom["dependencies"] = dependencies

    return json.dumps(cbom, indent=2)

