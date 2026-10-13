"""
Post-migration verification: did the PQC migration actually LAND?

Closes Phase-1 gap **G13** ("no surveyed product verifies migration from the artefact").

THE INVERSE PROBLEM
------------------------------------------------------------------------------------------------
`engine/scanner.py` proves that quantum-VULNERABLE crypto is present. This module proves the
opposite: that a POST-QUANTUM algorithm is present, in a shipped artefact, after a team says
they migrated. As Kestrel (docs/phase-1-literature-review.md, A6) puts it, NTT-constant
fingerprinting identifies the algorithm from the parameter tables its arithmetic depends on,
and is directly reusable as a post-migration verification module. We do NOT implement NTT
fingerprinting -- that is a research method requiring per-implementation constant tables, and
claiming it without them would be exactly the over-claim this project exists to avoid. What
this module does is marker-based presence verification, and `NOT_PROVEN` says so in its own
output.

THE DISTINCTION THAT MATTERS MOST (H6)
------------------------------------------------------------------------------------------------
**Kyber-768 is NOT ML-KEM-768.** FIPS 203 standardised ML-KEM. Kyber round-3 / 90s is the
pre-standardisation draft: a different algorithm with different security claims. Reporting
"Kyber768" as "ML-KEM-768 landed" is precisely the error `docs/CODE_REVIEW.md` H6 records and
`tests/test_recommender.py::test_no_pre_standardisation_algorithm_names` guards against.

So a Kyber marker is NEVER counted as ML-KEM. It produces its own status,
`STATUS_DEPRECATED_VARIANT`, with the reason spelled out. PQC protocol standards treat
"classical + hybrid + pure ML-KEM + deprecated Kyber" as SEPARATE codepoints, and
describe PQC maturity as a `final` or `draft` state. We do the same, statically.

The same rule applies to the other two pre-standardisation names: Dilithium is the old name
for ML-DSA (FIPS 204) and SPHINCS+ the old name for SLH-DSA (FIPS 205). A shipped
`Dilithium3` is a deprecated variant, not ML-DSA-65, however related the parameter sets are.

HYBRID SEMANTICS
------------------------------------------------------------------------------------------------
A hybrid such as X25519MLKEM768 combines X25519 and ML-KEM-768 so the connection holds if
EITHER survives. That is a real hedge, and its honest statement is an AND: **both halves must
be broken** for the exchange to fail. We say exactly that rather than let a reader assume a
hybrid is "half migrated".

WHAT IS AND IS NOT PROVEN
------------------------------------------------------------------------------------------------
A marker proves PRESENCE -- a name, OID or codepoint appears in the artefact. Presence is not
usage: a string in a binary may be dead code, a test fixture, a comment, or a vendored copy
of a library the application never calls. This is the same capability-vs-use distinction
`engine/purpose.py` draws, and the report labels its own evidence class accordingly.

Exit codes (CLI-usable):
    0  MIGRATION VERIFIED -- at least one standardised PQC algorithm is present
    1  NOT VERIFIED       -- readable, but no standardised PQC (possibly only a deprecated
                             Kyber/Dilithium/SPHINCS+ variant, which is reported as such)
    2  INCONCLUSIVE       -- the artefact could not be read, or was empty/undecipherable
"""
import os
import re

from engine.fspolicy import check_root, is_credential_store, resolve_within

# ---------------------------------------------------------------------------------------------
# Statuses
# ---------------------------------------------------------------------------------------------
STATUS_PRESENT = "present"
STATUS_ABSENT = "absent"
STATUS_DEPRECATED_VARIANT = "deprecated-variant"
STATUS_INCONCLUSIVE = "inconclusive"

# Overall verdicts. Distinct from the per-algorithm statuses: the brief asks for a per-algorithm
# status of present / absent / deprecated-variant, and an overall outcome of verified / not
# verified / inconclusive. Collapsing the two vocabularies into one set of strings would make
# "ML-DSA is absent" indistinguishable from "the migration as a whole is absent", which are
# different statements about different things.
VERDICT_VERIFIED = "verified"
VERDICT_NOT_VERIFIED = "not-verified"
VERDICT_INCONCLUSIVE = "inconclusive"

# The four FIPS families we verify. Names are the CANONICAL post-standardisation names.
ALGO_ML_KEM = "ML-KEM"        # FIPS 203
ALGO_ML_DSA = "ML-DSA"        # FIPS 204
ALGO_SLH_DSA = "SLH-DSA"      # FIPS 205
ALGO_FN_DSA = "FN-DSA"        # FIPS 206

PQC_ALGORITHMS = (ALGO_ML_KEM, ALGO_ML_DSA, ALGO_SLH_DSA, ALGO_FN_DSA)

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_INCONCLUSIVE = 2

# ---------------------------------------------------------------------------------------------
# Standardised markers.
#
# Deliberately CONSERVATIVE. Each pattern must name the family AND a parameter set, or be an
# unambiguous family-only spelling. A pattern that could also match a deprecated name is not
# here.
#
# Sources for the codepoints below: the IANA TLS Supported Groups registry, which lists
#   512/513/514  MLKEM512 / MLKEM768 / MLKEM1024  "FIPS 203 version of ..."  [RFC-ietf-tls-mlkem-10]
#   4587 SecP256r1MLKEM768  "Combining secp256r1 ECDH with ML-KEM-768"         [RFC 10024]
#   4588 X25519MLKEM768     "Combining X25519 ECDH with ML-KEM-768"             [RFC 10024]
#   4589 SecP384r1MLKEM1024  "Combining secp384r1 ECDH with ML-KEM-1024"        [RFC 10024]
#   25497 X25519Kyber768Draft00 (OBSOLETE)   25498 SecP256r1Kyber768Draft00 (OBSOLETE)
#     both annotated "Pre-standards version of Kyber768. Obsoleted by RFC 10024."
# The registry's "Recommended" column marks X25519MLKEM768 (4588) as Y and both Kyber draft
# codepoints as D/OBSOLETE. We take that difference as authoritative: RFC 10024 defines the
# hybrid groups, so 4588 is standardised.
# ---------------------------------------------------------------------------------------------
STANDARD_MARKERS = {
    ALGO_ML_KEM: [
        (r"ML[-_ ]?KEM[-_ ]?(?:512|768|1024)\b", "named ML-KEM with a parameter set (FIPS 203)"),
        (r"\bMLKEM(?:512|768|1024)\b", "IANA TLS group name for FIPS 203 ML-KEM"),
        (r"\bML[-_ ]?KEM\b", "named ML-KEM without a parameter set (FIPS 203 family)"),
        (r"id[-_]alg[-_]ml[-_]kem", "ML-KEM algorithm identifier (id-alg-ml-kem-*)"),
        # NIST CSOR arcs: .3.4.4 for ML-KEM, .3.4.3 for ML-DSA.
        (r"2\.16\.840\.1\.101\.3\.4\.4\.[123]\b", "ML-KEM OID (NIST CSOR arc .3.4.4)"),
    ],
    ALGO_ML_DSA: [
        (r"ML[-_ ]?DSA[-_ ]?(?:44|65|87)\b", "named ML-DSA with a parameter set (FIPS 204)"),
        (r"\bMLDSA(?:44|65|87)\b", "compact ML-DSA spelling"),
        (r"\bML[-_ ]?DSA\b", "named ML-DSA without a parameter set (FIPS 204 family)"),
        (r"id[-_]ml[-_]dsa[-_](?:44|65|87)\b", "ML-DSA object identifier (id-ml-dsa-*)"),
        (r"2\.16\.840\.1\.101\.3\.4\.3\.(?:17|18|19)\b", "ML-DSA OID (NIST CSOR arc)"),
    ],
    ALGO_SLH_DSA: [
        (r"SLH[-_ ]?DSA[-_ ]?SHA(?:2|KE)[-_ ]?(?:128|192|256)[sf]\b",
         "named SLH-DSA parameter set (FIPS 205)"),
        (r"\bslh[-_]?dsa[-_]sha(?:2|ke)[-_ ]?(?:128|192|256)[sf]\b",
         "lowercase SLH-DSA parameter-set identifier"),
        (r"\bSLH[-_ ]?DSA\b", "named SLH-DSA without a parameter set (FIPS 205 family)"),
    ],
    ALGO_FN_DSA: [
        (r"FN[-_ ]?DSA[-_ ]?(?:205|666)\b", "named FN-DSA with a parameter set (FIPS 206)"),
        (r"\bFN[-_ ]?DSA\b", "named FN-DSA without a parameter set (FIPS 206 family)"),
    ],
}

# ---------------------------------------------------------------------------------------------
# DEPRECATED markers: pre-standardisation names and OBSOLETE codepoints.
#
# These are matched FIRST, and a hit SUPPRESSES any standard marker overlapping the same span.
# Reason: `X25519Kyber768Draft00` contains the substring `Kyber768`, and a naive scan would
# report that as a Kyber-768 KEM without noticing the codepoint is obsolete. Suppression by
# span is what makes "a Kyber draft marker is NOT ML-KEM" a property of the CODE rather than of
# a careful reading order.
#
# Sources: the IANA registry text quoted above for the codepoints; the liboqs README for
# Kyber/Dilithium still shipping under their draft names; docs/CODE_REVIEW.md H6 for why the
# distinction is a correctness requirement rather than a stylistic preference.
# ---------------------------------------------------------------------------------------------
DEPRECATED_MARKERS = [
    # (regex, the family this is a draft OF, human reason)
    (r"X25519Kyber768Draft00", ALGO_ML_KEM,
     "X25519Kyber768Draft00 (IANA 25497) is marked OBSOLETE and D in the IANA registry, with "
     "the note 'Pre-standards version of Kyber768. Obsoleted by RFC 10024.' It is a Kyber "
     "DRAFT hybrid, not X25519MLKEM768 (IANA 4588, RFC 10024)."),
    (r"SecP256r1Kyber768Draft00", ALGO_ML_KEM,
     "SecP256r1Kyber768Draft00 (IANA 25498) is marked OBSOLETE and D: 'Pre-standards version of "
     "Kyber768. Obsoleted by RFC 10024.' Not SecP256r1MLKEM768 (IANA 4587)."),
    (r"X25519Kyber512Draft00", ALGO_ML_KEM,
     "X25519Kyber512Draft00: a pre-standardisation Kyber-512 draft hybrid, not ML-KEM-512."),
    (r"\bX25519Kyber768\b", ALGO_ML_KEM,
     "X25519Kyber768 is the pre-RFC-10024 spelling of the Kyber draft hybrid. The standardised "
     "group is X25519MLKEM768 (IANA 4588)."),
    (r"\bKyber[-_ ]?(?:512|768|1024)\b", ALGO_ML_KEM,
     "Kyber-<mode> is the pre-FIPS-203 draft name. FIPS 203 standardised ML-KEM, and Kyber-768 "
     "is NOT ML-KEM-768. [docs/CODE_REVIEW.md H6]"),
    (r"\bkyber[-_ ]?r3\b|\bkyber[-_ ]?round[-_ ]?3\b|\bkyber[-_ ]?draft\b", ALGO_ML_KEM,
     "An explicit Kyber round-3 / draft marker: the submission-era algorithm, not FIPS 203."),
    (r"\bDilithium[-_ ]?(?:2|3|5)\b", ALGO_ML_DSA,
     "Dilithium-<mode> is the pre-FIPS-204 name. ML-DSA-65 is not 'Dilithium3' under the "
     "standard: the standard renamed and re-derived the scheme. [docs/CODE_REVIEW.md H6]"),
    (r"\bSPHINCS\+?[-_ ]?SHA(?:256|512)[-_ ]?(?:128|192|256)[fs]\b", ALGO_SLH_DSA,
     "A SPHINCS+ parameter set: the pre-FIPS-205 name. The standard is SLH-DSA. "
     "[docs/CODE_REVIEW.md H6]"),
    (r"\bSPHINCS\+?\b", ALGO_SLH_DSA,
     "SPHINCS+ is the pre-standardisation name for SLH-DSA (FIPS 205)."),
]

# Hybrid constructions: canonical name -> (classical half, PQC half, IANA codepoint, RFC).
# `MLKEM512/768/1024` are PURE post-quantum groups, not hybrids; they are included so a
# deployment that chose pure PQ is still recognised, with the classical half stated as such
# rather than being silently mislabelled a hybrid.
HYBRID_GROUPS = {
    "X25519MLKEM768": ("X25519", "ML-KEM-768", 4588, "RFC 10024"),
    "SecP256r1MLKEM768": ("P-256", "ML-KEM-768", 4587, "RFC 10024"),
    "SecP384r1MLKEM1024": ("P-384", "ML-KEM-1024", 4589, "RFC 10024"),
    "SecP256r1MLKEM512": ("P-256", "ML-KEM-512", 4585,
                          "draft-rosomakho-tls-ecdhe-mlkem512-00"),
    "MLKEM512X25519": ("X25519", "ML-KEM-512", 4586,
                       "draft-rosomakho-tls-ecdhe-mlkem512-00"),
    "MLKEM512": ("(none -- pure post-quantum)", "ML-KEM-512", 512, "RFC-ietf-tls-mlkem-10"),
    "MLKEM768": ("(none -- pure post-quantum)", "ML-KEM-768", 513, "RFC-ietf-tls-mlkem-10"),
    "MLKEM1024": ("(none -- pure post-quantum)", "ML-KEM-1024", 514, "RFC-ietf-tls-mlkem-10"),
    # Underscore spellings used by Go's crypto/tls and by BoringSSL-style internal identifiers.
    # These name a real classical+PQC PAIRING but do NOT correspond to a named IANA codepoint in
    # their own right, so `iana_codepoint` is None rather than a borrowed number. Claiming 4589
    # for `p384_mlkem` would assert that it IS SecP384r1MLKEM1024, which is a different
    # construction with a different PQC parameter set.
    "p256_mlkem768": ("P-256", "ML-KEM-768", None,
                      "Go crypto/tls-style internal name; no separate IANA codepoint"),
    "p384_mlkem": ("P-384", "ML-KEM", None,
                   "underscore P-384 + ML-KEM pairing; no separate IANA codepoint"),
}

HYBRID_SEMANTICS = (
    "Hybrid AND: the exchange holds if EITHER half holds, so BOTH halves must be broken for it "
    "to fail. That is what makes a hybrid a hedge -- it covers a future cryptanalytic break of "
    "the lattice scheme AND an implementation flaw in it (KyberSlash is the worked example of "
    "the latter [Cloudflare 2025]). It is NOT half-migrated: the classical half is still "
    "Shor-broken on its own, so the PAIRING is the migration, not the X25519 alone."
)

NOT_PROVEN = [
    "that a present marker is EXECUTED rather than dead code, a test fixture, or a comment",
    "that a present marker is the one NEGOTIATED at runtime (needs a live handshake capture)",
    "that a present marker is correctly parameterised -- that needs Kestrel-style NTT-constant "
    "fingerprinting, which this module does NOT implement and does not claim",
    "absence in a binary whose symbols were stripped below the printable-string floor",
    "anything about an algorithm provided by a system library resolved only at run time",
]

# SSH KEX algorithm names (OpenSSH 9.x-10.x). The final ML-KEM name is `mlkem768x25519-sha256`
# (OpenSSH 10.0+); `sntrup761x25519-sha512@openssh.com` is an NTRU PRIME draft, which is a
# different scheme again and is deliberately NOT counted as any FIPS algorithm.
SSH_KEX_STANDARDISED = re.compile(r"\bmlkem(\d{3})x25519-sha256\b")
SSH_KEX_DRAFT = re.compile(r"\b(sntrup\d{3}x25519-sha512|mceliece\d{3}falcon\d{3}|"
                           r"kyber-shake|x25519-kyber)\S*")

_COMPILED_STANDARD = {
    algo: [(re.compile(pattern, re.IGNORECASE), reason)
           for pattern, reason in patterns]
    for algo, patterns in STANDARD_MARKERS.items()
}
_COMPILED_DEPRECATED = [(re.compile(pattern, re.IGNORECASE), family, reason)
                        for pattern, family, reason in DEPRECATED_MARKERS]
_COMPILED_HYBRIDS = {name: (re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE),) + spec
                     for name, spec in HYBRID_GROUPS.items()}


def _overlaps(span, other):
    """True when two (start, end) spans intersect. Used for deprecated-marker suppression."""
    return span[0] < other[1] and other[0] < span[1]


# ---------------------------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------------------------

# Bytes to read from a binary. A PQC symbol table lives in the first few MB of any real
# artefact; reading the whole file would turn a scan into a memory incident on a 4 GB image.
BINARY_READ_CAP = 64 * 1024 * 1024


def extract_printable_strings(data, min_len=4):
    """Pure-Python `strings` equivalent (the external binary is absent on Windows)."""
    out, cur = [], bytearray()
    for byte in data:
        if 32 <= byte < 127 or byte in (9, 10, 13):
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="replace"))
    return out


def _line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def _find_deprecated(text, source):
    """Deprecated markers first: they own their span, and anything overlapping is not evidence
    of the standard algorithm. See the SUPPRESSION note above DEPRECATED_MARKERS."""
    hits, suppressed = [], []
    for pattern, family, reason in _COMPILED_DEPRECATED:
        for match in pattern.finditer(text):
            span = match.span()
            suppressed.append(span)
            hits.append({
                "family": family,
                "marker": match.group(0),
                "reason": reason,
                "file": source,
                "line": _line_of(text, span[0]),
                "offset": span[0],
            })
    return hits, suppressed


def analyse_text(text, source="<text>"):
    """Classify every PQC marker in `text`.

    Returns a dict with per-algorithm status, the deprecated variants found, the hybrid
    constructions found, and the evidence spans. Pure function: no filesystem, no I/O, so it is
    directly testable and cannot be affected by containment policy.
    """
    deprecated_hits, suppressed_spans = _find_deprecated(text, source)

    algorithms = {algo: {"status": STATUS_ABSENT, "matches": [], "reasons": []}
                  for algo in PQC_ALGORITHMS}
    for algo, patterns in _COMPILED_STANDARD.items():
        # `claimed` is the single deduplication mechanism, and it subsumes three needs at once:
        #   1. the same text repeated (a binary string table mentions ML-KEM-768 200 times; that
        #      is ONE fact about the artefact, not 200),
        #   2. a LESS specific pattern matching text nested inside a MORE specific match
        #      (`ML-KEM` inside `ML-KEM-768`), and
        #   3. two patterns matching the identical span.
        # Patterns are ordered most-specific first, so a match contained in an already-claimed
        # span adds no information and would inflate every count in the report.
        claimed, markers_seen = [], set()
        for pattern, reason in patterns:
            for match in pattern.finditer(text):
                span = match.span()
                if any(_overlaps(span, blocked) for blocked in suppressed_spans):
                    # A deprecated span owns this text. Counting it as the standard algorithm
                    # is the H6 conflation, so it is dropped and the deprecated hit stands.
                    continue
                marker = match.group(0)
                # Nesting is checked FIRST, and the span is claimed even when the marker is a
                # repeat: a later family-only pattern must still see that this text is already
                # accounted for. Skipping the claim on a repeat leaves `claimed` incomplete and
                # the nesting check silently stops working.
                if any(span[0] >= start and span[1] <= end for start, end in claimed):
                    continue                       # nested inside a more specific match
                claimed.append(span)
                if marker.lower() in markers_seen:
                    continue                       # the same marker, already reported
                markers_seen.add(marker.lower())
                algorithms[algo]["status"] = STATUS_PRESENT
                algorithms[algo]["matches"].append({
                    "marker": marker, "reason": reason,
                    "file": source, "line": _line_of(text, span[0]),
                })
                if reason not in algorithms[algo]["reasons"]:
                    algorithms[algo]["reasons"].append(reason)

    hybrids = []
    for name, (pattern, classical, pqc, codepoint, spec) in _COMPILED_HYBRIDS.items():
        for match in pattern.finditer(text):
            span = match.span()
            if any(_overlaps(span, blocked) for blocked in suppressed_spans):
                continue
            hybrids.append({
                "name": name,
                "classical_half": classical,
                "pqc_half": pqc,
                "iana_codepoint": codepoint,
                "specification": spec,
                "is_hybrid": classical != "(none -- pure post-quantum)",
                "semantics": HYBRID_SEMANTICS,
                "file": source,
                "line": _line_of(text, span[0]),
            })
    # SSH KEX names are a separate naming scheme; a final `mlkem768x25519-sha256` is real
    # evidence, and a `sntrup761...` draft is reported as neither of the four families.
    ssh_hits, ssh_drafts = [], []
    for match in SSH_KEX_STANDARDISED.finditer(text):
        ssh_hits.append({"marker": match.group(0), "file": source,
                         "line": _line_of(text, match.start())})
    for match in SSH_KEX_DRAFT.finditer(text):
        ssh_drafts.append({
            "marker": match.group(0), "file": source,
            "line": _line_of(text, match.start()),
            "reason": "An OpenSSH post-quantum KEX DRAFT name (NTRU Prime or a vendor Kyber "
                      "variant). It is not any of the four FIPS 203/204/205/206 algorithms, so it "
                      "neither satisfies nor is reported as a completed migration."})

    for algo, data in algorithms.items():
        if data["status"] != STATUS_ABSENT:
            continue
        related = [hit for hit in deprecated_hits if hit["family"] == algo]
        if related:
            # A deprecated draft is a REAL, REPORTABLE state -- not `absent`, because the
            # operator has Kyber in their build and must be told it is not ML-KEM.
            data["status"] = STATUS_DEPRECATED_VARIANT
            data["reasons"] = [hit["reason"] for hit in related]
            data["deprecated_markers"] = [hit["marker"] for hit in related]
        elif algo == ALGO_ML_KEM and ssh_hits:
            data["status"] = STATUS_PRESENT
            data["matches"].append({
                "marker": ssh_hits[0]["marker"],
                "reason": "OpenSSH final post-quantum KEX name (mlkem<mode>x25519-sha256)",
                "file": source, "line": ssh_hits[0]["line"]})
            data["reasons"].append("present via an OpenSSH mlkem* KEX name")

    if any(h["is_hybrid"] for h in hybrids) and algorithms[ALGO_ML_KEM]["status"] == STATUS_ABSENT:
        # A hybrid group implies ML-KEM even if the bare family name never appears.
        algorithms[ALGO_ML_KEM]["status"] = STATUS_PRESENT
        algorithms[ALGO_ML_KEM]["reasons"].append(
            "implied by a standardised hybrid construction: "
            + ", ".join(h["name"] for h in hybrids if h["is_hybrid"]))
        algorithms[ALGO_ML_KEM]["matches"].append({
            "marker": "hybrid", "reason": "hybrid construction carrying ML-KEM",
            "file": source, "line": hybrids[0]["line"]})

    return {
        "algorithms": algorithms,
        "deprecated_variants": deprecated_hits,
        "hybrids": hybrids,
        "ssh_kex": ssh_hits,
        "other_pqc_drafts": ssh_drafts,
    }


# ---------------------------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------------------------

# NOTE: there is deliberately NO extension allow-list here. A PQC group name turns up in a `.c`,
# a `.conf`, a lockfile, a Dockerfile and a compiled `.so`, and filtering by extension would
# miss whichever kind we failed to list -- silently, which is the failure mode this module
# exists to avoid. Every readable file in the tree is examined; `errors` names the ones that
# could not be.


class MigrationVerifier:
    """Verify a post-quantum migration against a file, directory or tree.

    `errors` follows the same honesty contract as `DependencyScanner` and `IndraMeshScanner`: a
    file that could not be read is named with a reason, so an empty result is distinguishable
    from an unreadable one. The report carries `not_proven` so a reader cannot mistake
    "verified" for "verified end-to-end on the wire".
    """

    def __init__(self, max_bytes=None):
        self.errors = []
        self.files_examined = 0
        self.max_bytes = max_bytes or BINARY_READ_CAP

    def _note_error(self, path, reason):
        self.errors.append({"file": path, "reason": reason})

    def analyse_file(self, path):
        """Analyse one artefact. Returns the `analyse_text` dict, or None if unreadable."""
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            self._note_error(path, f"unreadable ({exc.strerror or exc})")
            return None
        if size > self.max_bytes:
            self._note_error(path, f"{size} bytes exceeds the {self.max_bytes}-byte read cap; "
                                   f"not examined")
            return None
        try:
            with open(path, "rb") as handle:
                data = handle.read(self.max_bytes)
        except OSError as exc:
            self._note_error(path, f"unreadable ({exc.strerror or exc})")
            return None
        if not data:
            return None
        self.files_examined += 1
        # Text when it decodes cleanly, printable strings otherwise. Both paths are needed: a
        # PQC symbol lives in a source file in one and in a .so's string table in the other.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = "\n".join(extract_printable_strings(data))
        return analyse_text(text, source=path)

    def _merge(self, into, addition):
        for algo, data in addition["algorithms"].items():
            target = into["algorithms"][algo]
            if data["status"] == STATUS_PRESENT:
                if target["status"] != STATUS_PRESENT:
                    target["status"] = STATUS_PRESENT
                    target["reasons"] = []
            if data["status"] == STATUS_DEPRECATED_VARIANT and target["status"] == STATUS_ABSENT:
                target["status"] = STATUS_DEPRECATED_VARIANT
                target["reasons"] = data["reasons"]
                target["deprecated_markers"] = data.get("deprecated_markers", [])
            target["matches"].extend(data["matches"])
            for reason in data["reasons"]:
                if reason not in target["reasons"]:
                    target["reasons"].append(reason)
        for key in ("deprecated_variants", "hybrids", "ssh_kex", "other_pqc_drafts"):
            into[key].extend(addition[key])
        return into

    def _empty_result(self):
        return {
            "algorithms": {algo: {"status": STATUS_ABSENT, "matches": [], "reasons": []}
                           for algo in PQC_ALGORITHMS},
            "deprecated_variants": [], "hybrids": [], "ssh_kex": [], "other_pqc_drafts": [],
        }

    def scan(self, target):
        """Analyse a file or a directory tree and return the raw merged result."""
        result = self._empty_result()
        if os.path.isfile(target):
            addition = self.analyse_file(target)
            return addition if addition else result
        if not os.path.isdir(target):
            self._note_error(target, "path does not exist or is not a directory")
            return result
        try:
            real_root = check_root(target)
        except Exception as exc:                     # noqa: BLE001 -- a policy refusal is a result
            self._note_error(target, f"refused by filesystem policy: {exc}")
            return result
        for root, dirs, files in os.walk(real_root):
            dirs[:] = [d for d in dirs if resolve_within(real_root, os.path.join(root, d))]
            for basename in files:
                path = os.path.join(root, basename)
                if is_credential_store(basename):
                    self._note_error(path, "credential store: contents never read")
                    continue
                if resolve_within(real_root, path) is None:
                    self._note_error(path, "symlink escapes the scan root: not followed")
                    continue
                addition = self.analyse_file(path)
                if addition:
                    self._merge(result, addition)
        return result

    # ------------------------------------------------------------------ the report

    def verdict(self, result):
        """Turn a merged result into the report, including the CLI exit code.

        Decision order, and the reasoning for it:

        * nothing was examined (no such path, or every file unreadable) -> INCONCLUSIVE (2).
          "We could not look" must never be reported as "the migration did not happen".
        * at least one FIPS 203/204/205/206 algorithm is PRESENT -> VERIFIED (0), even if a
          deprecated marker also appears: shipping a deprecated draft alongside the standard is
          a cleanup item, not a failed migration, and the report says so.
        * otherwise -> NOT VERIFIED (1). A deprecated-variant-only result gets its own
          `verdict_reason` naming the draft, because "you have Kyber, not ML-KEM" is the single
          most useful thing this tool can tell such a user.
        """
        statuses = {algo: data["status"] for algo, data in result["algorithms"].items()}
        present = [algo for algo, status in statuses.items() if status == STATUS_PRESENT]
        deprecated = [algo for algo, status in statuses.items()
                      if status == STATUS_DEPRECATED_VARIANT]

        examined = self.files_examined
        if examined == 0:
            verdict = VERDICT_INCONCLUSIVE
            exit_code = EXIT_INCONCLUSIVE
            reason = ("Nothing could be examined: the target does not exist, is empty, or every "
                      "file in it was unreadable. This is NOT a statement about the migration.")
        elif present:
            verdict = VERDICT_VERIFIED
            exit_code = EXIT_VERIFIED
            reason = (f"Post-quantum migration VERIFIED by presence: {', '.join(present)} found "
                      f"in the artefact.")
            # A deprecated marker alongside a present one is cleanup debt, not a failure. It must
            # still be named here, not only in the `deprecated_variants` list a UI may not show.
            if result["deprecated_variants"]:
                markers = sorted({hit["marker"] for hit in result["deprecated_variants"]})
                reason += (f" Note: a DEPRECATED pre-standardisation marker also appears "
                           f"({', '.join(markers)}); it is reported separately and does not "
                           f"count as the standardised algorithm.")
        elif deprecated:
            verdict = VERDICT_NOT_VERIFIED
            exit_code = EXIT_NOT_VERIFIED
            markers = sorted({hit["marker"] for hit in result["deprecated_variants"]})
            reason = (f"NOT verified. No standardised PQC algorithm is present, but a "
                      f"pre-standardisation draft IS ({', '.join(markers) or 'see variants'}). "
                      f"A deprecated draft is not the standard: Kyber-768 is not ML-KEM-768, "
                      f"Dilithium is not ML-DSA, and SPHINCS+ is not SLH-DSA.")
        else:
            verdict = VERDICT_NOT_VERIFIED
            exit_code = EXIT_NOT_VERIFIED
            reason = ("NOT verified. No post-quantum marker of any kind was found in the "
                      "artefacts examined. Absence of a marker is weaker than presence of one: "
                      "see `not_proven`.")

        return {
            "verdict": verdict,
            "verified": verdict == VERDICT_VERIFIED,
            "exit_code": exit_code,
            "verdict_reason": reason,
            "files_examined": examined,
            "algorithms": {
                algo: {
                    "status": data["status"],
                    "matches": data["matches"],
                    "reasons": data["reasons"],
                    "deprecated_markers": data.get("deprecated_markers", []),
                }
                for algo, data in result["algorithms"].items()
            },
            "hybrids": result["hybrids"],
            "deprecated_variants": result["deprecated_variants"],
            "ssh_kex": result["ssh_kex"],
            "other_pqc_drafts": result["other_pqc_drafts"],
            "errors": list(self.errors),
            "not_proven": list(NOT_PROVEN),
            "evidence_class": "observed",
            "evidence_note": ("Marker PRESENCE in the artefact. This is stronger than a "
                              "dependency-manifest capability and weaker than a handshake: the "
                              "algorithm is IN the artefact, not proven to be the one in use."),
            "exit_codes": {"verified": EXIT_VERIFIED, "not_verified": EXIT_NOT_VERIFIED,
                           "inconclusive": EXIT_INCONCLUSIVE},
            "verdicts": [VERDICT_VERIFIED, VERDICT_NOT_VERIFIED, VERDICT_INCONCLUSIVE],
        }

    def verify(self, target):
        """The whole operation: scan a path and return the report, exit code included."""
        return self.verdict(self.scan(target))

    def verify_text(self, text, source="<text>"):
        """Verify an in-memory string. Used by the tests and by callers holding a response body
        or a config blob.

        The text counts as one examined artefact, so the verdict logic treats it as a real read.
        Without that, `verify_text` on a real ML-KEM string would report INCONCLUSIVE -- a
        silent false negative caused by a bookkeeping detail, which is exactly the class of bug
        this project keeps writing regression tests for.
        """
        self.files_examined += 1
        return self.verdict(analyse_text(text, source=source))


def verify_migration(target):
    """Convenience wrapper: the report for a path. `report["exit_code"]` is the CLI code."""
    return MigrationVerifier().verify(target)


def verify_migration_text(text, source="<text>"):
    """Convenience wrapper: the report for a string of text."""
    return MigrationVerifier().verify_text(text, source)
