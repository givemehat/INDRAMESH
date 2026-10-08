"""Cryptographic purpose model.

Adopted from the competitive analysis (research/competitive/ANALYSIS.md, item C2 / rank 3).
Sibling `cryptodrishti` makes the sharpest observation in the whole scrape:

    "Nothing in the string `RSA` tells you which, so purpose is a property of the *finding*,
     resolved from the call site."
    "Where the evidence does not settle it, no target is named and the recommendation says what
     would resolve it. An unresolved finding a human reviews is worth more than a resolved one
     that is wrong."

Our previous recommender always named a target, so an RSA finding we could not classify was
silently pushed to ML-KEM or ML-DSA. This module makes the uncertainty a first-class carried value
instead of a guess.

Two distinct questions are answered here, and they must not be conflated:

  * PURPOSE    -- what is the primitive FOR? (signature / key-establishment / confidentiality)
  * ASSURANCE  -- what does the evidence actually PROVE? (a library that merely CAN do RSA is a
                  capability; a resolved call site is a use)
"""

PURPOSE_SIGNATURE = "signature"
PURPOSE_KEY_ESTABLISHMENT = "key-establishment"
PURPOSE_CONFIDENTIALITY = "confidentiality"
PURPOSE_UNRESOLVED = "unresolved"        # deliberately not a default

PURPOSE_TO_PRIMITIVE = {
    PURPOSE_SIGNATURE: "signature",
    PURPOSE_KEY_ESTABLISHMENT: "key-agreement",
    PURPOSE_CONFIDENTIALITY: "pke",
}

# Signal -> purpose. Ordered most-specific first. The resolver returns UNRESOLVED when no signal
# settles it, and reports the signals it saw so the operator knows what to go look at.
PURPOSE_SIGNALS = [
    (PURPOSE_SIGNATURE, ("padding.pss", "rsassa-pss", "rsa_sign", "rsasapss", "ecdsa_sign",
                         "rsa_sign_pss", "signpss", "ecdsa_sign_prehash")),
    (PURPOSE_SIGNATURE, ("signature.getinstance", "digital_signature", "key_cert_sign",
                         "keycertsign", "codesigning", "sign(")),
    (PURPOSE_KEY_ESTABLISHMENT, ("padding.oaep", "rsa_encrypt_oaep", "rsaes_oaep",
                                  "key_encipherment", "keyencipherment", "key_agreement",
                                  "keyagreement", "keyexchange", "rsa/ecb", "rsaencrypt")),
    (PURPOSE_KEY_ESTABLISHMENT, ("ecdh", "x25519", "diffie", "key_wrap", "wrap_key")),
    # Ambiguous on purpose: these prove the primitive is reachable and nothing more.
    (PURPOSE_UNRESOLVED, ("pkcs1v15", "pkcs1_v1_5", "generatekey", "keypairgenerator",
                          "newkeys", "generate_private_key", "evp_pkey_rsa", "evp_pkey_ec",
                          "rsa_new", "rsa_sign(0)")),
]

# Certificate KeyUsage extensions (RFC 5280). The strongest purpose evidence a certificate
# carries, and free once a certificate sensor exists.
KEY_USAGE_SIGNATURE = {"digitalsignature", "nonrepudiation", "keycertsign", "crlsign"}
KEY_USAGE_KEY_ESTABLISHMENT = {"keyencipherment", "keyagreement", "dataencipherment"}
KEY_USAGE_DUAL = {"digitalsignature", "keyencipherment"}     # present in both -> unresolved


def resolve_purpose(finding):
    """Return (purpose, evidence_signals, reason).

    Never guesses. If nothing settles the purpose, returns PURPOSE_UNRESOLVED plus the signals
    that were seen, so the caller can name what would resolve it.
    """
    signals = []
    blob = " ".join([
        str(finding.get("name", "")),
        str(finding.get("primitive", "")),
        str(finding.get("mode", "")),
        str(finding.get("uses", "")),
        str(finding.get("match") or ""),
        str(finding.get("rule_id") or ""),
    ]).lower()

    key_usage = {str(k).lower() for k in (finding.get("key_usage") or [])}
    if key_usage:
        signals.append("cert KeyUsage=" + ",".join(sorted(key_usage)))
        sig_bits = key_usage & KEY_USAGE_SIGNATURE
        ke_bits = key_usage & KEY_USAGE_KEY_ESTABLISHMENT
        # Dual-use means the extension asserts BOTH, not that it merely contains a member of the
        # ambiguous pair -- `digitalSignature` on its own is not dual-use.
        if sig_bits and ke_bits:
            return PURPOSE_UNRESOLVED, signals, "certificate KeyUsage spans both purposes"
        if sig_bits:
            return PURPOSE_SIGNATURE, signals, "certificate KeyUsage asserts signing"
        if ke_bits:
            return PURPOSE_KEY_ESTABLISHMENT, signals, "certificate KeyUsage asserts key establishment"

    ambiguous = False
    for purpose, needles in PURPOSE_SIGNALS:
        hit = next((n for n in needles if n in blob), None)
        if hit:
            signals.append(hit)
            if purpose != PURPOSE_UNRESOLVED:
                return purpose, signals, f"call-site signal '{hit}'"
            ambiguous = True
    if ambiguous:
        return PURPOSE_UNRESOLVED, signals, (
            "the artefact is reachable but its purpose is not settled by the evidence")
    return PURPOSE_UNRESOLVED, [], "no purpose signal found"


# ---------------------------------------------------------------------------------------
# Assurance -- what does the evidence PROVE? Deliberately separate from `confidence`, which
# answers a different question: is the identification of the algorithm itself correct?
# ---------------------------------------------------------------------------------------
ASSURANCE_CAPABILITY = "capability"   # reachable; nothing shows it is called
ASSURANCE_DECLARED = "declared"       # configuration permits it
# Late-binding runtime resolution: the code INVOKES a crypto factory at this line, but which
# concrete algorithm, provider or protocol version actually runs is decided by a resolver that
# lives in ANOTHER FILE -- `java.security` (provider preference order, jdk.tls.disabledAlgorithms,
# jdk.tls.client.protocols), an OpenSSL `openssl.cnf` CipherString, the Windows SCHANNEL registry
# key, or the Go toolchain version that compiled the binary. `SSLContext.getInstance("TLS")` is
# the archetype: the string names a family, not an algorithm, and everything that makes it
# concrete is outside the file we scanned.
#
# This is deliberately NOT `used`. `used` asserts "this algorithm runs"; runtime-resolved asserts
# "something runs here and the file that decides what is X". Silence is the failure mode being
# fixed -- reporting nothing because we could not pin the identity from source throws away a real
# call site; reporting `used` would overstate what the evidence proves.
ASSURANCE_RUNTIME_RESOLVED = "runtime-resolved"
ASSURANCE_USED = "used"               # code invokes THIS algorithm -- the strongest static claim
ASSURANCE_OBSERVED = "observed"       # seen in a real artefact (parsed cert, completed handshake)

ASSURANCE_RANK = {
    ASSURANCE_OBSERVED: 4,
    ASSURANCE_USED: 3,
    # Between `used` and `declared`: a real invocation happened (stronger than a config line
    # permitting one) but the algorithm identity is not pinned at this line (weaker than `used`).
    ASSURANCE_RUNTIME_RESOLVED: 2,
    ASSURANCE_DECLARED: 1,
    ASSURANCE_CAPABILITY: 0,
}

ASSURANCE_MEANING = {
    ASSURANCE_CAPABILITY: "The algorithm is reachable. Nothing shows it is called.",
    ASSURANCE_DECLARED: "Configuration permits it. Stated policy, not an execution.",
    ASSURANCE_RUNTIME_RESOLVED: (
        "Code invokes a cryptographic factory here, but which algorithm, provider or protocol "
        "version actually runs is decided outside this file. The resolver is named on the "
        "finding -- go read it before trusting the algorithm name."),
    ASSURANCE_USED: "Code invokes it. The strongest claim static analysis can make.",
    ASSURANCE_OBSERVED: "Seen in a real artefact.",
}

# Evidence classes map to an assurance level. A dependency manifest is a capability: listing
# `pycryptodome` shows the algorithm is available, not that anything runs.
EVIDENCE_TO_ASSURANCE = {
    "discovered": ASSURANCE_USED,
    "configured": ASSURANCE_DECLARED,
    "declared": ASSURANCE_CAPABILITY,
    "negotiated": ASSURANCE_OBSERVED,
    "observed": ASSURANCE_OBSERVED,
    "capability": ASSURANCE_CAPABILITY,
    "dependency": ASSURANCE_CAPABILITY,
    # A JCA/JCE factory call (`SSLContext.getInstance("TLS")`, a bare `Cipher.getInstance("AES")`,
    # a transformation passed by variable) IS an invocation, but the concrete algorithm is decided
    # by a resolver outside this file. That must never be flattened to `used` (which asserts the
    # identity) or dropped to silence. The resolver is carried on the finding's `resolver` field.
    "runtime-resolved": ASSURANCE_RUNTIME_RESOLVED,
}


def resolve_assurance(finding):
    """Return (assurance, reason)."""
    evidence = str(finding.get("evidence_class", "discovered")).lower()
    level = EVIDENCE_TO_ASSURANCE.get(evidence, ASSURANCE_CAPABILITY)
    return level, ASSURANCE_MEANING[level]


def proven_use_count(findings):
    """Count findings whose assurance is `used` or `observed`.

    A raw total that mixes 300 capabilities nobody calls with 5 real call sites is the easiest way
    for a discovery tool to mislead a reader. Report this alongside the raw count.
    """
    return sum(1 for f in findings
               if resolve_assurance(f)[0] in (ASSURANCE_USED, ASSURANCE_OBSERVED))


def assurance_histogram(findings):
    hist = {a: 0 for a in ASSURANCE_RANK}
    for f in findings:
        hist[resolve_assurance(f)[0]] += 1
    return hist


# Primitives for which a post-quantum target must be named, and therefore for which an unresolved
# purpose is a real problem. A hash or a symmetric cipher has no meaningful purpose ambiguity:
# there is nothing to choose between ML-KEM and ML-DSA, so counting it as "unresolved" would
# inflate a number whose whole purpose is to say "a human must look at this".
PRIMITIVES_REQUIRING_PQC_TARGET = {"pke", "signature", "key-agreement", "kem", "unknown"}


def needs_pqc_target(finding):
    """True when a PQC replacement must be named for this finding, so purpose matters."""
    primitive = str(finding.get("primitive", "") or "").strip().lower()
    # Fall back to the name for findings that carry a legacy descriptive primitive string.
    if not primitive:
        name = str(finding.get("name", "")).upper()
        if name in ("RSA", "DSA", "DH", "ECDH", "X25519", "X448"):
            return True
        return False
    return primitive in PRIMITIVES_REQUIRING_PQC_TARGET


def unresolved_purpose_count(findings):
    """How many findings a human must resolve before a target can be named."""
    return sum(1 for f in findings
               if needs_pqc_target(f) and resolve_purpose(f)[0] == PURPOSE_UNRESOLVED)

