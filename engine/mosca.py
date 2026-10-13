from datetime import date

"""
Mosca's inequality:  X + Y > Z  =>  migration should already have started.

    X = years the data (or the signed artefact) must remain protected
    Y = years required to migrate this artefact
    Z = years until a Cryptographically Relevant Quantum Computer (CRQC) exists

Source: M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?",
IACR ePrint 2015/1075; IEEE Security & Privacy 16(5), 2018.

------------------------------------------------------------------------------------------------
DESIGN NOTE -- why X and Y are NOT derived from model confidence (fixed 2026-09-25)
------------------------------------------------------------------------------------------------
An earlier revision of this module computed:

    X = 3.0 + (dl_confidence * 5.0)      # <- NOT DEFENSIBLE
    Y = 1.0 + (ast_depth / 10.0) * 0.5

X is a *business/compliance* property of the DATA (how long must this remain secret, or how long
must this signature remain trustworthy?). It is not a property of how confident the detector is
that it found an algorithm. Deriving X from `dl_confidence` had three consequences:

  1. No evidential basis. No published correlation exists between detector confidence and
     data-retention obligations, so the tool could not answer "where does X come from?".
  2. The risk tier depended on the neural network's confidence, so every model retrain silently
     re-rated the estate. Risk verdicts must be reproducible.
  3. It bypassed the brief's requirement to classify artefacts by "type, lifetime and business
     criticality" -- the lifetime input was replaced by a proxy.

X and Y now come from explicit, documented, overridable tables below. The ML complexity signal is
retained, but only as a BOUNDED, clearly-labelled adjustment to Y -- never as X.
------------------------------------------------------------------------------------------------
"""

# ---------------------------------------------------------------------------------------------
# Horizon semantics: which clock does X measure for a given primitive?
# ---------------------------------------------------------------------------------------------
HORIZON_CONFIDENTIALITY = "confidentiality"   # data must stay secret -> HNDL applies
HORIZON_VERIFIABILITY = "verifiability"       # signature must stay trustworthy -> no HNDL
HORIZON_NONE = "none"                          # symmetric/hash -> inequality does not apply

PRIMITIVE_HORIZON = {
    "public-key-encryption": HORIZON_CONFIDENTIALITY,
    "pke": HORIZON_CONFIDENTIALITY,
    "key-agreement": HORIZON_CONFIDENTIALITY,
    "kem": HORIZON_CONFIDENTIALITY,
    "key-transport": HORIZON_CONFIDENTIALITY,
    "digital-signature": HORIZON_VERIFIABILITY,
    "signature": HORIZON_VERIFIABILITY,
    "symmetric-encryption": HORIZON_NONE,
    "ae": HORIZON_NONE,
    "block-cipher": HORIZON_NONE,
    "hash": HORIZON_NONE,
    "mac": HORIZON_NONE,
    "cryptographic-library": HORIZON_NONE,
}

# ---------------------------------------------------------------------------------------------
# Z -- the CRQC planning horizon, in YEARS from "now".
# Deliberately NOT a compliance deadline (India DST CII 2029, NIST IR 8547 deprecate-2030 /
# disallow-2035, CNSA 2.0 2030/2033). Those are procurement dates reported separately.
# Basis: GRI/evolutionQ "Quantum Threat Timeline" (7th ed., Mar 2026) -- expert consensus
# window 10-20 years, with 28-49% probability of a CRQC within 10 years.
# ---------------------------------------------------------------------------------------------
Z_PRESETS = {
    "aggressive":   {"years": 5,  "label": "Z=5y  (plan-as-if-early; ~2031)",
                     "basis": "Lower bound of the expert-consensus window."},
    "gri_midpoint": {"years": 10, "label": "Z=10y (GRI 2026 midpoint; ~2036)",
                     "basis": "Midpoint of the GRI/evolutionQ 10-20 year consensus window."},
    "conservative": {"years": 15, "label": "Z=15y (upper bound; ~2041)",
                     "basis": "Upper bound of the expert-consensus window."},
}
DEFAULT_Z = Z_PRESETS["gri_midpoint"]["years"]
Z_SENSITIVITY_YEARS = (5, 10, 15)   # band reported alongside every verdict

POLICY_DEADLINES = {
    "india_dst_nqm": {"label": "India DST / National Quantum Mission (CII migration)", "year": 2029},
    # STRENGTH-DEPENDENT, per the verified NIST IR 8547 transition tables.
    # Quoting the draft: NIST "intends to instead deprecate rather than fully disallow classical
    # key-establishment schemes at the 112-bit security level. Organizations may continue using
    # these algorithms and parameter sets as they migrate." The 2035 DISALLOWANCE attaches to
    # the >= 128-bit tier; the 112-bit tier is merely DEPRECATED (after 2030).
    #
    # A single flat 2035 "disallowed" for every artefact overstated the 112-bit case -- a
    # compliance tool must not claim an algorithm is banned when the standard says it is
    # usable during migration. `year` is kept as the DISALLOW year (the operative date for the
    # >= 128-bit tier) so existing consumers keep working, and `tiers` carries the nuance.
    "nist_ir_8547":  {"label": "NIST IR 8547 ipd -- quantum-vulnerable PKC (DRAFT)",
                      "year": 2035,
                      "draft": True,
                      "tiers": {
                          # 112-bit: DEPRECATED after 2030. The year is 2030, not 2035, because
                          # the deprecation is the actionable date for this tier and there is no
                          # disallowance attached to it. Reporting 2035 here would tell a 112-bit
                          # operator they have five extra years they do not have.
                          "lt_128": {"year": 2030, "status": "deprecated",
                                     "note": "Deprecated after 2030. NIST intends to allow "
                                             "continued use during migration rather than "
                                             "disallow. Not a hard ban."},
                          # >= 128-bit: disallowed after 2035. This is the hard date.
                          "gte_128": {"year": 2035, "status": "disallowed",
                                      "note": "Disallowed after 2035."},
                      }},
    "cnsa_2_0":      {"label": "CNSA 2.0 -- exclusive use across NSS",                  "year": 2033},
}
DEFAULT_POLICY = "india_dst_nqm"

# The strength (in equivalent security bits) at or above which a policy is a hard disallowance
# rather than a deprecation. NIST SP 800-57 equivalence puts RSA-2048, ECDSA-P-224, 3DES and
# 2-key triple-DES at the 112-bit boundary, so 112 is genuinely a distinct regulatory tier.
DISALLOW_TIER_BITS = 128

# The primitives NIST IR 8547's transition tables actually govern: quantum-vulnerable PUBLIC-KEY
# algorithms. Everything else -- symmetric ciphers, hashes, MACs, KDFs, DRBGs, protocols, and
# bare libraries -- is out of scope, because the tables say nothing about them. Membership here
# is what gates a policy verdict; deriving one from key strength alone is the category error that
# reported AES-256 as "disallowed by NIST".
PUBLIC_KEY_PRIMITIVES = frozenset({
    "pke", "signature", "key-agreement", "key-agree", "kem",
    "key-derive", "keyderive", "key-wrap", "key-establishment", "pke-encapsulation",
})


def _z_band_points(z_years):
    """The Z values the sensitivity band should probe, given the caller's chosen Z.

    The point of a sensitivity band is to show how the verdict MOVES as Z moves. Iterating a
    fixed (5, 10, 15) tuple while the caller had chosen, say, Z=40 answered a question nobody
    asked: the report said "z: 40.0" and then showed a band that never included 40, and
    `z_stable` could report a stable verdict without 40 ever being evaluated.

    So the band is built around the chosen Z. When Z sits at or near the default, the published
    GRI consensus window (5-15) is still preferred, because that range is itself a sourced claim
    and a reader expects to see it.
    """
    lo, hi = Z_SENSITIVITY_YEARS[0], Z_SENSITIVITY_YEARS[-1]
    if lo <= z_years <= hi:
        return sorted({float(v) for v in Z_SENSITIVITY_YEARS})
    step = max(1.0, abs(hi - lo) / 2.0)
    return sorted({max(0.0, z_years - step), float(z_years), z_years + step})


def resolve_policy_deadline(finding, policy):
    """The deadline that actually applies to THIS artefact, and whether it is a ban or a nudge.

    A flat year per policy was wrong for NIST IR 8547, whose transition tables are keyed on
    security strength: the >= 128-bit tier is *disallowed* after 2035, but for the 112-bit tier
    NIST states it "intends to instead deprecate rather than fully disallow [...] Organizations
    may continue using these algorithms and parameter sets as they migrate." Reporting both as
    "disallowed 2035" told an operator their 112-bit RSA was banned when the standard says the
    opposite.

    THE FOUR GATES BELOW ARE THE WHOLE POINT, and each fixes a false compliance claim:

      1. NOT IN SCOPE. IR 8547's tables cover quantum-vulnerable PUBLIC-KEY algorithms. A
         symmetric cipher, hash, MAC or KDF is not in them. Deriving a status from key strength
         alone put AES-256, SHA-512 and ChaCha20 in the "disallowed" bucket -- the tool asserting
         that NIST bans AES-256. A category error like that discredits the whole report.
      2. NOT QUANTUM-VULNERABLE. A post-quantum algorithm is not deprecated by IR 8547 at all;
         it IS the replacement. ML-KEM-768 and X25519MLKEM768 -- our own recommended targets --
         were being reported "disallowed".
      3. UNRATED. A strength of 0 or None means we could not measure it, which is not the same
         as 112-bit. A sentinel must never become a verdict: folding 0 into the "deprecated"
         tier quietly downgraded every unrecognised algorithm.
      4. NO LEAK. `tiers` is popped so the raw table never reaches the CBOM or the console.

    Returns `year`, `status`, `note`, `draft`, `strength_tier` and `security_strength_bits`, so a
    consumer can render "deprecated, still usable while migrating" instead of a bare year.
    """
    entry = dict(POLICY_DEADLINES.get(policy) or {})
    tiers = entry.pop("tiers", None)
    base = {"label": entry.get("label", policy), "draft": bool(entry.get("draft")),
            "security_strength_bits": None, "strength_tier": None}

    def _out(status, note, year=None, bits=None, tier=None):
        result = dict(base)
        result.update({"year": year if year is not None else entry.get("year"),
                       "status": status, "note": note,
                       "security_strength_bits": bits, "strength_tier": tier})
        return result

    if not tiers:
        # No strength-dependent table. India DST and CNSA 2.0 are procurement targets, not
        # algorithm-status tables, so "target" is the honest word -- not "disallowed".
        return _out("target", "", year=entry.get("year"))

    primitive = str(finding.get("primitive", "") or "").lower()

    if primitive not in PUBLIC_KEY_PRIMITIVES:
        return _out("not-in-scope",
                    "NIST IR 8547 governs quantum-vulnerable public-key algorithms. This is a "
                    "%s primitive and is not in the transition table."
                    % (primitive or "unknown"))

    from engine.cbom import is_pqc, _classical_strength   # cbom does not import mosca

    if is_pqc(finding.get("name", "")):
        return _out("not-applicable",
                    "This is a post-quantum algorithm. IR 8547 retires the algorithms it "
                    "replaces, not the replacements themselves.")

    strength = _classical_strength(finding, primitive)
    if not strength:
        return _out("unrated",
                    "No SP 800-57 equivalent security strength could be determined, so no tier "
                    "could be selected. NOT counted as compliant and NOT deprecated.")

    tier_key = "gte_128" if strength >= DISALLOW_TIER_BITS else "lt_128"
    tier = tiers.get(tier_key) or {}
    return _out(tier.get("status", "disallowed"), tier.get("note", ""),
                year=tier.get("year", entry.get("year")), bits=strength, tier=tier_key)

# ---------------------------------------------------------------------------------------------
# X -- required protection lifetime, in years, by data class. Overridable per artefact or scan.
# Brackets derive from the regulatory retention regimes behind the published Mosca worked
# examples (HIPAA, statutory financial retention, classification schedules, device support life).
# ---------------------------------------------------------------------------------------------
DATA_CLASS_LIFETIME = {
    "session":             {"years": 2,  "note": "ephemeral session / traffic keys"},
    "internal-credential": {"years": 5,  "note": "short-lived internal service credential"},
    "operational-record":  {"years": 7,  "note": "typical operational / audit retention"},
    "financial-record":    {"years": 12, "note": "regulatory financial retention + loan lifecycle"},
    "personal-data":       {"years": 12, "note": "regulated personal data retention"},
    "ip-source-code":      {"years": 20, "note": "intellectual property / trade-secret horizon"},
    "code-signing":        {"years": 25, "note": "verifiability across a device support life"},
    "defence-classified":  {"years": 25, "note": "classification schedules"},
    "statutory-archive":   {"years": 30, "note": "long statutory record retention"},
    "health-record":       {"years": 50, "note": "patient lifetime + heirs"},
}
DEFAULT_DATA_CLASS = "operational-record"

# ---------------------------------------------------------------------------------------------
# Y -- migration duration, in years, by artefact class. Documented, editable assumptions.
# ---------------------------------------------------------------------------------------------
MIGRATION_EFFORT = {
    "config":   {"years": 1, "note": "configuration change + regression test"},
    "protocol": {"years": 2, "note": "protocol/stack upgrade, peer coordination"},
    "source":   {"years": 3, "note": "application code change + release cycle"},
    "library":  {"years": 4, "note": "third-party / vendored dependency upgrade"},
    "hsm-tpm":  {"years": 6, "note": "HSM firmware + validation + key ceremony"},
    "firmware": {"years": 7, "note": "firmware / hardware refresh cycle"},
    "ca-root":  {"years": 8, "note": "root/CA rollover: trust distribution lag"},
}
DEFAULT_ARTEFACT_CLASS = "source"

# Bounded complexity adjustment derived from the ML/AST signal. Kept because structural
# complexity genuinely does correlate with migration effort -- but capped, and always reported
# in the output so the number is auditable.
COMPLEXITY_ADJUSTMENT_MAX_YEARS = 1.5
COMPLEXITY_AST_DEPTH_REFERENCE = 30.0

SHOR_VULNERABLE = ("RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE", "ELGAMAL",
                   "X25519", "ED25519", "CURVE25519")

# The token list above is a floor, not a definition, and treating it as the whole vocabulary
# produced FALSE QUANTUM-SAFETY ASSURANCES -- the most damaging class of error this tool can
# make. Measured before this change: X448, Ed448, secp256k1, P-384, prime256v1,
# brainpoolP256r1, EC and SM2 all returned "not-affected" while `cbom.py` simultaneously
# emitted `nistQuantumSecurityLevel: 0` ("a CRQC breaks this") for the very same finding.
# One CBOM component asserted "not vulnerable, tier LOW" and "broken by a CRQC" together.
#
# The cause is naming, not cryptography. `X25519` is a token but `X448` is not; `ED25519` is
# a token but `Ed448` is not; and the standard EC names are `prime256v1`, `secp384r1`,
# `secp256k1`, `brainpoolP256r1`, none of which contain "EC" or "DH" as substrings. Matching
# on a short token list cannot survive the naming diversity of real deployed curves.
#
# So asymmetric key establishment and signature algorithms are identified by STRUCTURE --
# is this thing a public-key primitive? -- with the token list demoted to a fast path. A
# generic EC/curve/KEM name is Shor-broken unless a PQC screen has already exempted it.
SHOR_VULNERABLE_ASYMMETRIC = (
    "RSA", "DSA", "DH", "DIFFIE", "ELGAMAL", "ECDH", "ECDSA", "EDDSA", "EC",
    "X25519", "X448", "ED25519", "ED448", "CURVE25519", "MONTGOMERY",
    # Standard named-curve spellings. These are the ones that broke false assurance.
    "SECP", "PRIME256", "PRIME192", "BRAINPOOL", "SECT", "P-192", "P-224", "P-256",
    "P-384", "P-521", "P256", "P384", "P521", "K-163", "K-233", "K-283", "K-409",
    # Chinese and Korean national standards, deployed in 5G and payment networks.
    "SM2", "SM9", "SM3-SIG",
    # Lattice/ECC-based PQ candidates that are NOT the NIST standard, plus KEM aliases.
    "KYBER", "BIKE", "FRODO", "NTRU", "FALCON", "DILITHIUM",
)

# Symmetric primitives weakened by Grover but NOT broken by Shor, and NOT retroactive.
# Matched as whole words, not substrings: "AES" inside "frodoKEM640-AES" must not make a KEM
# Grover-weakened, and "SHA" inside "SHA3" needs its own entry.
GROVER_WEAKENED = ("AES", "SHA", "SHA2", "SHA3", "SHAKE", "MD5", "3DES", "DES",
                   "BLOWFISH", "CHACHA", "RC4", "SERPENT", "CAMELLIA", "ARIA",
                   "TWOFISH", "CAST", "IDEA", "SALSA", "POLY1305")

# Reused rather than re-declared: the family vocabulary is the thing most likely to drift, and
# two copies is how `X25519MLKEM768` ends up Shor-broken in one module and PQC in another.
from .cbom import is_pqc  # noqa: E402  (circular-import guard; cbom imports nothing from mosca)


def quantum_break_model(name, primitive=""):
    """Return 'broken-by-Shor' | 'weakened-by-Grover' | 'not-affected'.

    Shor  => the primitive is dead, and data captured TODAY is retroactively readable (HNDL).
    Grover => quadratic speedup only, and NOT retroactive: ciphertext recorded today cannot be
              recovered faster later merely because Grover exists. This is exactly why the
              Mosca inequality must not be applied to symmetric primitives -- doing so is a
              category error that would flag every AES-256 user as exposed.
    """
    # A post-quantum algorithm is checked FIRST, and that ordering is load-bearing. `X25519MLKEM768`
    # is a hybrid: it contains "X25519", which is in the Shor table, so a token scan that reaches
    # the table before the PQC screen calls our own top migration recommendation Shor-broken.
    # The same inversion mislabelled `ML-DSA-65`, because "DSA" is a substring of "ML-DSA".
    if is_pqc(name):
        return "not-affected"
    haystack = f"{name} {primitive}".upper()
    for token in SHOR_VULNERABLE_ASYMMETRIC:
        if token in haystack:
            return "broken-by-Shor"
    for token in GROVER_WEAKENED:
        if token in haystack:
            return "weakened-by-Grover"
    return "not-affected"


def _horizon_type(finding, break_model):
    """Which X applies: confidentiality, verifiability, or none."""
    if break_model != "broken-by-Shor":
        return HORIZON_NONE
    primitive = str(finding.get("primitive", "")).lower()
    if primitive in PRIMITIVE_HORIZON:
        return PRIMITIVE_HORIZON[primitive]
    if "sign" in primitive:
        return HORIZON_VERIFIABILITY
    if str(finding.get("mode", "")).lower() == "signing":
        return HORIZON_VERIFIABILITY
    return HORIZON_CONFIDENTIALITY


def _resolve_x(finding, horizon, user_x):
    """X in years, plus the reason. Never derived from detection confidence."""
    if user_x is not None:
        if user_x < 0:
            raise ValueError("Data Shelf Life (X) cannot be negative.")
        return float(user_x), "explicit override"
    if horizon == HORIZON_NONE:
        return 0.0, "not applicable (symmetric/hash primitive)"
    data_class = finding.get("data_class", DEFAULT_DATA_CLASS)
    entry = DATA_CLASS_LIFETIME.get(data_class, DATA_CLASS_LIFETIME[DEFAULT_DATA_CLASS])
    return float(entry["years"]), f"data_class='{data_class}': {entry['note']}"


def _resolve_y(finding, user_y):
    """Y in years from an artefact-class table plus a bounded, reported complexity adjustment.

    `observed_history`, when supplied, takes precedence over the table -- see
    `migration_rate_from_history`. Deriving Y from an organisation's own completed migrations
    replaces a guess with a measurement.
    """
    if user_y is not None:
        if user_y < 0:
            raise ValueError("Migration Time (Y) cannot be negative.")
        return float(user_y), 0.0, "explicit override"

    artefact_class = finding.get("artefact_class", DEFAULT_ARTEFACT_CLASS)
    entry = MIGRATION_EFFORT.get(artefact_class, MIGRATION_EFFORT[DEFAULT_ARTEFACT_CLASS])
    base = float(entry["years"])

    ast_depth = max(0.0, float(finding.get("ast_depth", 0.0) or 0.0))
    if ast_depth <= 0:
        adjustment = 0.0
    else:
        ratio = min(1.0, ast_depth / COMPLEXITY_AST_DEPTH_REFERENCE)
        adjustment = round(ratio * COMPLEXITY_ADJUSTMENT_MAX_YEARS, 2)

    reason = f"artefact_class='{artefact_class}': {entry['note']}"
    if adjustment:
        reason += f"; +{adjustment}y complexity adjustment (AST depth {ast_depth:.0f})"
    return base, adjustment, reason


def migration_rate_from_history(completed_migrations):
    """Derive a migration rate (years per artefact class) from an org's own track record.

    WHY THIS EXISTS. Y -- migration time -- is the term almost nobody measures. Z is
    unknowable, so it gets argued about and must be hardcoded; but Y is entirely knowable,
    because every organisation has already completed crypto migrations and has the dates.
    Deriving Y from that record is the difference between an assumption and a measurement.

    WHAT IT ACCEPTS. A list of completed migrations, each a mapping with:
      * `artefact_class` -- matched against MIGRATION_EFFORT keys (config, protocol, source,
        library, hsm-tpm, firmware, ca-root)
      * `started` / `finished` -- ISO dates, either order-independent

    WHAT IT RETURNS. (rate, n, note). `rate` is the MEDIAN elapsed years for that class, which
    is used in preference to the generic table when the caller supplies history. The median
    rather than the mean because one aborted nine-year attempt should not define the
    organisation's velocity.

    Returns (None, 0, reason) when nothing usable is supplied, and the caller falls back to the
    table. It never invents a number and never raises on malformed input -- a bad history
    silently degrading to the documented table is better than a crash in a risk report.
    """
    if not completed_migrations:
        return None, 0, "no migration history supplied; using the generic effort table"

    per_class = {}
    skipped = []
    for i, m in enumerate(completed_migrations or []):
        if not isinstance(m, dict):
            skipped.append(f"entry {i}: not a mapping")
            continue
        cls = str(m.get("artefact_class") or "").strip().lower()
        if cls not in MIGRATION_EFFORT:
            skipped.append(f"entry {i}: artefact_class {cls!r} not in the effort table")
            continue
        start, end = m.get("started"), m.get("finished")
        if not start or not end:
            skipped.append(f"entry {i}: missing started/finished")
            continue
        try:
            elapsed = (date.fromisoformat(str(end)) - date.fromisoformat(str(start))).days / 365.25
        except (ValueError, TypeError):
            skipped.append(f"entry {i}: unparseable dates ({start!r} -> {end!r})")
            continue
        if elapsed < 0:
            skipped.append(f"entry {i}: finished before started")
            continue
        per_class.setdefault(cls, []).append(elapsed)

    if not per_class:
        return None, 0, ("no usable history (" + "; ".join(skipped[:3]) +
                         "); using the generic effort table")

    # Median of the per-observation medians, so one class with many entries does not dominate.
    rates = {cls: sorted(v)[len(v) // 2] for cls, v in per_class.items()}
    overall = sorted(rates.values())[len(rates) // 2]
    note = (f"derived from {sum(len(v) for v in per_class.values())} completed migration(s) "
            f"of this organisation; per-class median(s): "
            + ", ".join(f"{c}={r:.1f}y" for c, r in sorted(rates.items()))
            + (f"; {len(skipped)} entr(y/ies) skipped" if skipped else ""))
    return overall, sum(len(v) for v in per_class.values()), note



def _grover_effective_bits(name, key_length):
    """Post-Grover effective strength in bits, or None when it cannot be determined."""
    upper = str(name).upper()
    if "AES" in upper:
        return int(key_length) // 2 if key_length else None
    if "3DES" in upper:
        return 56   # 112-bit classical -> ~56 after Grover
    if "DES" in upper:
        return 28
    if "MD5" in upper:
        return 32
    if "SHA-1" in upper or upper.endswith("SHA1") or "-SHA1" in upper:
        return 40
    if "SHA" in upper:
        # NO hardcoded 128 fallback. `key_length` absent means the digest is unmeasured, and
        # returning 128 invented a confident number that then crossed the >= 128 threshold in
        # `_tier` and produced a LOW verdict -- the SAFE side of the boundary. An unmeasured
        # hash was therefore rated LOW by default. `None` propagates instead, and the tier
        # logic treats an unknown strength as unknown rather than as adequate.
        #
        # The digest family is still inferable from the NAME for the standard families, so a
        # finding that says "SHA-384" without a key_length is rated rather than abandoned.
        for bits, tokens in ((512, ("SHA512", "SHA-512")), (384, ("SHA384", "SHA-384")),
                             (256, ("SHA256", "SHA-256")), (224, ("SHA224", "SHA-224"))):
            if any(t in upper for t in tokens):
                return bits // 2
        if "SHA3" in upper or "SHAKE" in upper or "BLAKE2" in upper:
            return 128      # these families are defined at 256 and above
        return int(key_length) // 2 if key_length else None
    return None


def _tier(break_model, subject, is_vulnerable, hndl, margin, effective_bits,
          margin_at_boundary=False):
    """Tier from the inequality outcome and exposure type -- not from the algorithm family."""
    if break_model == "broken-by-Shor":
        if not subject:
            return "LOW"
        if hndl or (is_vulnerable and margin >= 10):
            return "CRITICAL"
        # ZERO SLACK. Mosca's inequality is not satisfied yet, but X + Y == Z means there is no
        # headroom at all: the migration has to be finished today, and any slip exposes the
        # artefact. Reporting MEDIUM here made a boundary indistinguishable from an artefact
        # with two years of margin -- the two produced the SAME tier, so "0.0 years of headroom"
        # and "comfortably inside" looked identical on the panel. HIGH says: act now.
        if margin_at_boundary:
            return "HIGH"
        if is_vulnerable:
            return "HIGH"
        return "MEDIUM"           # not yet exposed per the inequality
    if break_model == "weakened-by-Grover":
        if effective_bits is None:
            return "MEDIUM"       # unknown key size -> needs confirmation, not a blind upgrade
        return "LOW" if effective_bits >= 128 else "MEDIUM"
    return "LOW"


def calculate_risk(finding, user_x=None, user_y=None, z_collapse_time=None,
                   policy=None, current_year=None, include_z_band=True,
                   migration_history=None):
    """Apply Mosca's inequality (X + Y > Z) to one finding.

    Returns a dict with the verdict plus every input and reason used to reach it, so the GUI
    and the CBOM can explain the number instead of asserting it.

    `migration_history` -- a list of the organisation's COMPLETED migrations, in the form
    `migration_rate_from_history` documents. When supplied and usable, Y is derived from that
    record rather than from the generic effort table, so the output MEASURES the organisation
    instead of restating an assumption about it. See that function for why Y is the term worth
    measuring rather than Z, which cannot be.
    """
    import datetime

    if current_year is None:
        current_year = datetime.date.today().year
    z_years = float(DEFAULT_Z if z_collapse_time is None else z_collapse_time)
    if z_years < 0:
        raise ValueError("Z (years to CRQC) cannot be negative.")
    if not policy:
        policy = DEFAULT_POLICY
    elif policy not in POLICY_DEADLINES:
        # An unrecognised policy used to fall through to an EMPTY deadline: year=None,
        # status="target". A null year is silently dangerous, because every comparison against
        # it is False -- so an artefact already past its deadline could never be reported late,
        # and the report looked entirely normal. Refuse instead.
        raise ValueError(
            "Unknown policy %r. Known policies: %s. Pass one of these, or None for the default."
            % (policy, ", ".join(sorted(POLICY_DEADLINES))))


    name = str(finding.get("name", ""))
    primitive = str(finding.get("primitive", ""))
    key_length = finding.get("key_length")

    break_model = quantum_break_model(name, primitive)
    horizon = _horizon_type(finding, break_model)
    subject = break_model == "broken-by-Shor" and horizon != HORIZON_NONE

    x_years, x_reason = _resolve_x(finding, horizon, user_x)
    y_base, y_adjust, y_reason = _resolve_y(finding, user_y)
    y_source = "effort-table"
    if migration_history and user_y is None:
        rate, n, hist_note = migration_rate_from_history(migration_history)
        if rate is not None:
            y_base = rate
            y_adjust = 0.0        # the measured rate supersedes the generic complexity bump
            y_reason = hist_note
            y_source = "observed-migration-history"
    y_years = y_base + y_adjust

    # Round to a precision far finer than any real input BEFORE comparing, because the verdict
    # and the displayed numbers must not disagree. In binary floating point 0.1 + 21.1 is
    # 21.200000000000003, which is > 21.2, so the tool would print "x_y: 21.2" next to "z: 21.2"
    # and still claim RISK. A reader who checks the arithmetic loses trust in every other number
    # in the report -- the most damaging way this tool could fail, and precisely the
    # self-contradiction we criticise competitors for.
    #
    # 1e-9 years is ~30 microseconds. No meaningful input differs at that scale, so quantising
    # cannot change a real verdict; it only removes representation noise.
    PRECISION = 9
    total = round(x_years + y_years, PRECISION)
    z_cmp = round(float(z_years), PRECISION)
    x_cmp = round(float(x_years), PRECISION)
    raw_margin = total - z_cmp
    # The margin is rounded for DISPLAY but the boundary test must use the raw value.
    #
    # Rounding first produced a verdict that was wrong in the dangerous direction. With
    # X=10, Y=3, Z=13 the true margin is +0.0 to within float representation -- sometimes
    # 1.8e-15 above, sometimes below. `round(raw, 2)` printed "0.00" for both, and the
    # strict `total > z_cmp` test then read FALSE, dropping a Shor-vulnerable artefact from
    # HIGH to MEDIUM. Margin -2.00 and margin 0.00 produced the SAME tier, so an artefact
    # sitting exactly ON the inequality was reported as though it were comfortably inside it.
    #
    # Mosca's inequality is X + Y > Z: at X + Y == Z you have not yet lost, but you have also
    # not yet started, and the clock runs the instant you do. A boundary is not a pass. So the
    # test is `raw_margin > 0`, computed before any rounding, and an exact boundary counts as
    # exposed.
    margin = round(raw_margin, 2)
    boundary_tolerance = 1e-6
    margin_at_boundary = bool(subject and abs(raw_margin) <= boundary_tolerance)
    # `is_vulnerable` is kept FAITHFUL to Mosca's published inequality, which is strict:
    # X + Y > Z. At X + Y == Z the inequality is false, and reporting True would mean the tool
    # no longer implements the framework it claims to implement -- which is the more serious
    # error of the two, because a reviewer checking the mathematics would find it immediately.
    #
    # The reviewer's objection to the boundary is nonetheless correct, and it is answered in
    # `_tier` rather than here: zero slack means the migration must begin NOW, so a boundary
    # artefact is tiered HIGH despite `is_vulnerable` being False. The two fields answer
    # different questions -- "is the inequality satisfied?" and "how much time is left?" -- and
    # a single boolean cannot carry both.
    is_vulnerable = bool(subject and raw_margin > 0.0)
    hndl_exposed = bool(subject and horizon == HORIZON_CONFIDENTIALITY and x_cmp > z_cmp)
    effective_bits = _grover_effective_bits(name, key_length)

    tier = _tier(break_model, subject, is_vulnerable, hndl_exposed, margin,
                 effective_bits, margin_at_boundary)

    # Z-sensitivity: the verdict must be shown as a band, not a single number, because Z is
    # an estimate. If the tier flips inside the band, say so rather than asserting one answer.
    #
    # The band is CENTRED ON THE CHOSEN Z, not the fixed tuple (5,10,15). Iterating the constant
    # meant `--z 40` printed "z: 40.0" beside a band labelled 5/10/15, and reported a verdict as
    # "stable" without 40 ever being probed -- the single most misleading thing a sensitivity
    # analysis can do. The published consensus window is retained as the band whenever the
    # caller's Z is near it, so the default still shows the documented 5-15 range.
    z_band = {}
    if include_z_band:
        band_points = _z_band_points(z_years)
        for z in band_points:
            m = round(total - z, 2)
            vuln = bool(subject and total > z)
            hndl = bool(horizon == HORIZON_CONFIDENTIALITY and x_cmp > z)
            z_band["Z=%g" % z] = _tier(break_model, subject, vuln, hndl, m, effective_bits)
    stable = len(set(z_band.values())) <= 1 if z_band else True

    if break_model == "broken-by-Shor":
        threat = "Shor's algorithm (full break)"
    elif break_model == "weakened-by-Grover":
        threat = "Grover's algorithm (quadratic speed-up only; not retroactive)"
    else:
        threat = "No quantum break model applies"

    # Resolved BEFORE the return so the audit trail records the deadline that actually applies
    # to this artefact, including whether it is a hard disallowance or a deprecation.
    resolved_deadline = resolve_policy_deadline(finding, policy)

    return {
        # --- Mosca inputs, each with the reason it holds that value ---
        "x": round(x_years, 2),
        "y": round(y_years, 2),
        "y_base": round(y_base, 2),
        "y_complexity_adjustment": round(y_adjust, 2),
        "z": z_years,
        "x_y": round(total, 2),
        "margin": margin,
        "latest_safe_migration_start": int(current_year + z_years - y_years),
        # --- verdict ---
        "is_vulnerable": is_vulnerable,
        "subject_to_inequality": subject,
        "hndl_exposed": hndl_exposed,
        "horizon_type": horizon,
        "break_model": break_model,
        "grover_effective_bits": effective_bits,
        "tier": tier,
        "threat": threat,
        "z_band": z_band,
        "z_stable": stable,
        # --- audit trail ---
        "policy": policy,
        # Resolved per-artefact, not a flat per-policy year. For NIST IR 8547 the transition
        # tables are keyed on security strength, so a 112-bit RSA and a 256-bit RSA do NOT share
        # a verdict: the first is only deprecated, the second is disallowed. See
        # resolve_policy_deadline and NIST IR 8547 specification.
        "policy_deadline": resolved_deadline,
        "x_reason": x_reason,
        "y_reason": y_reason,
    "y_source": y_source,
    "margin_at_boundary": margin_at_boundary,
        "assumptions": [
            f"X={round(x_years, 2)}y from {x_reason}",
            f"Y={round(y_years, 2)}y from {y_reason}",
            f"Z={z_years}y is a CRQC estimate, not a compliance deadline "
            f"(policy deadline: {resolved_deadline.get('year', 'n/a')}"
            + (f", {resolved_deadline['status']} for the "
               f"{resolved_deadline.get('security_strength_bits') or 'unrated'}-bit tier"
               if resolved_deadline.get("strength_tier") else "") + ")",
        ],
        # --- retained ML diagnostics (reported, never used to derive X) ---
        "dl_confidence": round(max(0.0, min(1.0, float(finding.get("dl_confidence", 0.5) or 0.5))), 4),
        "ast_depth": round(max(0.0, float(finding.get("ast_depth", 0.0) or 0.0)), 2),
    }

