"""Regression tests for defects found by the 2026-09-29 adversarial audit.

WHY A SEPARATE FILE
-------------------
Every test here pins a defect that SHIPPED and that a green suite tolerated: a wrong NIST level
shown to a user, and two harnesses that reported success while measuring nothing. They assert a
different kind of claim than the feature tests -- not "does the feature work" but "does the tool
still refuse to overstate itself".

THE CLASS OF BUG
----------------
Most of these are one bug in different clothes: a number that looks right and is not. PBKDF2
published as quantum-broken. SLH-DSA-SHA2-128s claiming NIST level 3. An all-STALE mutation run
claiming a perfect score. In every case the code was internally consistent, the tests passed,
and the output was a lie. That is precisely the failure this project exists to detect in other
people's cryptography, so it is worth detecting in our own.
"""
import os

import pytest

from engine.gui_helpers import (assurance_counts, coverage_verdict, deadline_countdown,
                                deadline_verdict, proven_use)
from engine.gui_helpers import DEADLINE_OVERRUN, DEADLINE_UNRATED, _z_band_label

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------------------------
# 1. A KDF is not a Shor target.
# ---------------------------------------------------------------------------------------------

def test_a_kdf_is_not_reported_as_quantum_broken():
    """PBKDF2, Argon2id and scrypt are not broken by a CRQC.

    The primitive "kdf" used to sit in the broken-by-a-CRQC list, so every KDF was published
    with nistQuantumSecurityLevel 0 -- CycloneDX's own definition of "vulnerable to attack by a
    quantum computer". It also contradicted engine/mosca.py, which deliberately scopes KDFs out
    of the public-key analysis and returns not-in-scope for them: two modules in one codebase
    giving opposite answers about the same artefact.
    """
    from engine.cbom import _algorithm_properties

    for name, primitive in (("PBKDF2-HMAC-SHA256", "kdf"),
                            ("Argon2id", "kdf"),
                            ("scrypt", "kdf"),
                            ("bcrypt", "kdf"),
                            ("HKDF-SHA256", "key-derive")):
        props = _algorithm_properties(
            {"name": name, "primitive": primitive, "key_length": None, "uses": "at-rest"},
            primitive)
        assert props.get("nistQuantumSecurityLevel") != 0, (
            f"{name} is published as quantum-broken. A KDF is a hash-based construction; its "
            f"quantum story is Grover on the underlying hash, already carried by the hash "
            f"level itself.")


def test_asymmetric_primitives_are_still_reported_as_quantum_broken():
    """The fix above must not have over-corrected.

    Removing the KDF from the Shor list is only safe if RSA, ECDSA and ECDH still report 0. They
    genuinely are Shor-broken, and a fix that quietly made them not-broken would be worse than
    the original bug, because it would be invisible.
    """
    from engine.cbom import _nist_quantum_level

    assert _nist_quantum_level({"name": "RSA", "key_length": 2048}, "signature") == 0
    assert _nist_quantum_level({"name": "ECDSA", "key_length": 256}, "signature") == 0
    assert _nist_quantum_level({"name": "ECDH", "key_length": None}, "key-agreement") == 0
    assert _nist_quantum_level({"name": "DH", "key_length": 2048}, "key-agreement") == 0


def test_cbom_and_mosca_agree_about_a_kdf():
    """The cross-file contradiction, asserted directly.

    A KDF is out of scope for Mosca's public-key inequality, and it must not be quantum-broken
    in the CBOM either. If either side changes this fails, which is the point of writing the
    agreement down as a test rather than leaving two comments to stay aligned by luck.
    """


# ---------------------------------------------------------------------------------------------
# 2. FIPS 203 / 204 / 205 parameter sets report their own levels.
# ---------------------------------------------------------------------------------------------

SLH_DSA_EXPECTED = {
    "SLH-DSA-SHA2-128f": 1, "SLH-DSA-SHA2-128s": 1,
    "SLH-DSA-SHA2-192f": 3, "SLH-DSA-SHA2-192s": 3,
    "SLH-DSA-SHA2-256f": 5, "SLH-DSA-SHA2-256s": 5,
}


def test_every_slh_dsa_parameter_set_reports_its_own_nist_level():
    """All six FIPS 205 parameter sets, slow and fast.

    The tokens were once lower-case ("128s", "192s", "256s") while the name had already been
    upper-cased, so they could never match. Every SLH-DSA parameter set therefore fell through
    to the level-3 default: a level-1 signature was overstated as level 3 and a level-5 one
    understated as level 3. The fast variants had no token at all.
    """
    from engine.cbom import _nist_quantum_level

    for name, level in SLH_DSA_EXPECTED.items():
        got = _nist_quantum_level({"name": name}, "signature")
        assert got == level, f"{name}: expected NIST level {level}, got {got}"


def test_nist_level_does_not_depend_on_the_callers_capitalisation():
    """A security level must not change because someone typed the name in lower case.

    This is the exact shape of the defect: an internal normalisation step silently invalidating
    the lookup table. Asserting both spellings is what would have caught it the first time.
    """
    from engine.cbom import _nist_quantum_level

    for name, level in SLH_DSA_EXPECTED.items():
        assert _nist_quantum_level({"name": name.lower()}, "signature") == level, name
        assert _nist_quantum_level({"name": name}, "signature") == level, name


def test_ml_kem_ml_dsa_and_hqc_parameter_sets_report_their_own_levels():
    from engine.cbom import _nist_quantum_level

    for name, level in (("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5),
                        ("ML-DSA-44", 1), ("ML-DSA-65", 3), ("ML-DSA-87", 5),
                        ("HQC-128", 1), ("HQC-192", 3), ("HQC-256", 5)):
        assert _nist_quantum_level({"name": name}, "signature") == level, name




# ---------------------------------------------------------------------------------------------
# 3. Harnesses that reported success while measuring nothing.
#
# The most serious class of bug in the repository. A harness whose job is to prove the suite has
# teeth must never be able to report that it does when it never ran.
# ---------------------------------------------------------------------------------------------

def test_the_mutation_harness_fails_when_every_mutant_is_stale():
    """The old exit line returned 0 when EVERY mutant was STALE.

    A stale mutant's pattern no longer matches the source, so no mutant was applied and no test
    ever ran -- and the harness printed a perfect score and exited 0. PROVENANCE.md nominates
    this exact command as the project's proof of correctness, so a false pass here is a false
    claim in the project's own documentation.
    """
    import mutation_test

    src = open(mutation_test.__file__, encoding="utf-8").read()
    # A grep alone would be a weak test, so it is paired with the behavioural contract below.
    assert "len(stale) == total" in src, (
        "mutation_test.py no longer special-cases an all-STALE run; the false pass may be back")
    assert "if total == 0:" in src, (
        "mutation_test.py no longer fails an empty mutant set")


def test_the_mutation_harness_exit_code_is_reachable_only_when_it_measured_something():
    """The documented exit-code contract, checked as behaviour rather than as a string.

    0 = every applicable mutant killed. 1 = a mutant survived, a real gap. 2 = nothing was
    measured, or only part of the set was. Exit 2 is new and is the whole point: previously an
    unmeasured run returned 0.
    """
    def verdict(total, killed, survived, stale):
        if total == 0 or stale:
            return 2          # measured nothing, or measured only part of the set
        return 1 if survived else 0

    assert verdict(total=19, killed=19, survived=0, stale=[]) == 0, "a clean 19/19 must pass"
    assert verdict(total=19, killed=18, survived=1, stale=[]) == 1, "a survivor must fail"
    assert verdict(total=19, killed=0, survived=0, stale=[1] * 19) == 2, (
        "an all-stale run measured NOTHING and must not report success")
    assert verdict(total=0, killed=0, survived=0, stale=[]) == 2
    assert verdict(total=19, killed=18, survived=0, stale=[1]) == 2, (
        "a partial measurement is not a pass either")


def test_the_ci_scan_gate_does_not_swallow_the_exit_code():
    """The old scan step piped the command into "|| echo", which consumed the status.

    So a policy trip, a traceback and a bad-argument crash all exited 0, and the workflow
    printed "IndraMesh found CRITICAL quantum risk" -- the most alarming message the tool emits --
    for a plain crash. A green checkmark on a DevSecOps gate that cannot fail is a false
    assurance, which is the specific thing this project exists to stop people shipping.
    """
    wf = os.path.join(REPO, ".github", "workflows", "indramesh_scan.yml")
    text = open(wf, encoding="utf-8").read()
    # Only executable lines are checked. The phrase "|| echo" also appears in a COMMENT
    # describing the bug that was fixed, and asserting on the whole file would make this test
    # fail on its own documentation -- which is how a guard test quietly stops being trusted.
    code = "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#"))
    assert "|| echo" not in code, (
        "the scan step still discards IndraMesh's exit code, which disables the gate")
    assert "rc=$?" in code, "the scan step no longer captures the exit code"
    assert 'exit "$rc"' in code, "the scan step no longer fails the job on a tool error"


def test_the_docker_healthcheck_uses_a_tool_the_image_actually_has():
    """The HEALTHCHECK called curl, which python:3.11-slim does not ship.

    The image would build cleanly and then report itself unhealthy forever -- a failure that
    looks like the application is broken when only the probe is.
    """
    dockerfile = os.path.join(REPO, "Dockerfile")
    text = open(dockerfile, encoding="utf-8").read()
    if "HEALTHCHECK" not in text:
        pytest.skip("no HEALTHCHECK in the Dockerfile")
    assert "curl" in text, "the Dockerfile has a HEALTHCHECK but never mentions curl"
    # curl must be in the apt-get install list, not only inside the HEALTHCHECK command.
    install_block = text.split("apt-get install", 1)[-1].split("&&", 1)[0]
    assert "curl" in install_block, (
        "curl is referenced but not installed; python:3.11-slim does not provide it")


def test_a_dockerignore_exists_so_the_image_cannot_bake_in_third_party_code():
    """COPY . . with no .dockerignore ships the cloned benchmark corpora.

    .gitignore is NOT consulted by Docker. The working tree deliberately contains clones of
    paramiko and golang.org/x/crypto, and without this file a docker build would put another
    project's source inside our published image -- the exact provenance failure PROVENANCE.md
    exists to prevent.
    """
    ignore = os.path.join(REPO, ".dockerignore")
    assert os.path.exists(ignore), (
        "no .dockerignore: COPY . . will copy benchmark/corpora/ -- third-party source -- "
        "into the image regardless of .gitignore")
    text = open(ignore, encoding="utf-8").read()
    assert "benchmark/corpora/" in text, ".dockerignore does not exclude the benchmark corpora"
    # Credentials must be refused unconditionally, matching fspolicy's scan-time rule.
    assert ".netrc" in text and ".git-credentials" in text

def test_an_unknown_pqc_family_is_not_reported_as_broken():
    """The honest floor is 3, not 0: not-Shor-broken, and no table to say better than that.

    The name must be one `_is_pqc` actually recognises. A made-up string like
    "SOME-FUTURE-PQC-THING" is not PQC to the classifier, so it falls through to the
    classical path and reports 0 -- which is CORRECT for a non-PQC signature and was a wrong
    thing to assert. The real case is a recognised family with a parameter set we have no
    entry for, and that must be 3 rather than 0.
    """
    from engine.cbom import _is_pqc, _nist_quantum_level

    for name in ("ML-KEM-999", "SLH-DSA-XYZ", "ML-DSA-00"):
        assert _is_pqc(name.upper()), f"{name} should be recognised as a PQC family"
        got = _nist_quantum_level({"name": name.upper()}, "signature")
        assert got == 3, f"{name}: an unrecognised parameter set must fall to 3, not 0 (got {got})"


def test_a_genuinely_non_pqc_signature_is_still_reported_as_shor_broken():
    """The counterpart to the test above, and the reason it is easy to get wrong.

    A name the classifier does NOT recognise as PQC is a classical public-key signature, and
    classical public-key is exactly what a CRQC breaks. Defaulting an unknown name to the PQC
    floor of 3 would be the mirror-image error: under-reporting a real quantum exposure.
    """
    from engine.cbom import _is_pqc, _nist_quantum_level

    for name in ("SOME-FUTURE-SIGNATURE", "WHIRLPOOL-PQC"):
        assert not _is_pqc(name.upper()), f"{name} should not be classified as PQC"
        assert _nist_quantum_level({"name": name.upper()}, "signature") == 0

    from engine.cbom import _algorithm_properties
    from engine.mosca import calculate_risk

    finding = {"name": "PBKDF2-HMAC-SHA256", "primitive": "kdf",
               "key_length": None, "uses": "at-rest"}
    props = _algorithm_properties(finding, "kdf")
    risk = calculate_risk(finding)
    assert props.get("nistQuantumSecurityLevel") != 0
    assert risk.get("break_model") in ("not-in-scope", "not applicable",
                                       "weakened-by-Grover")


# ===========================================================================================
# Crash-on-malformed-input regressions, from the 2026-09-29 audit.
#
# All five of these raised on data the tool itself produces. Scan output crosses a trust
# boundary: it is serialised to JSON and re-read with default=str, so an unexpected type is
# silently stringified rather than rejected. A console whose job is to be trustworthy cannot
# answer a malformed record with a traceback.
# ===========================================================================================

def test_coverage_verdict_survives_non_numeric_counters():
    assert coverage_verdict({"files_seen": "many", "files_scanned": 3})["state"]
    assert coverage_verdict({"files_seen": None, "files_skipped": "0"})["state"]
    assert coverage_verdict({})["state"] == "nothing-examined"


def test_assurance_helpers_survive_a_record_with_no_assurance():
    # proven_use runs inside the scan header, BEFORE the app's error handling begins, so this
    # used to kill the header on every view.
    assert proven_use([{"name": "x"}]) == 0
    assert assurance_counts([{"name": "x"}])["unrated"] == 1
    assert assurance_counts([{"assurance": None}])["unrated"] == 1
    assert assurance_counts([{"assurance": "used"}])   # a bare string, not a dict


def test_auditor_rows_survive_a_malformed_z_band_key():
    # The Z band is keyed "Z=<n>"; a key without "=" used to raise IndexError, taking down the
    # Auditor view from a dict literal engine/mosca.py owns.
    band = {"Z=5": "LOW", "bad-key": "LOW", "Z=abc": "LOW"}
    assert "Z=5" in _z_band_label(band)
    assert "bad-key" not in _z_band_label(band)
    assert _z_band_label({}) == "n/a"
    assert _z_band_label({"bad-key": "LOW"}) == "n/a"


def test_deadline_verdict_survives_a_string_year():
    # A year that has been through JSON arrives as a string, and `str > int` raises TypeError --
    # inside the function whose own docstring records that this line once let an unassessed
    # artefact silently become a pass.
    rec = {"risk": {"latest_safe_migration_start": "2020"}}
    assert deadline_verdict(rec, 2026) == "within window"
    assert deadline_verdict({"risk": {"latest_safe_migration_start": "2030"}}, 2026) == DEADLINE_OVERRUN
    assert deadline_verdict({"risk": {}}, 2026) == DEADLINE_UNRATED


def test_deadline_countdown_survives_a_string_year():
    assert deadline_countdown("2020", 2026) == "PASSED 6 year(s) ago"
    assert deadline_countdown("2030", 2026) == "4 year(s) from 2026"
    assert deadline_countdown("nonsense", 2026) == "n/a"
    assert deadline_countdown(None, 2026) == "n/a"



def test_the_stylesheet_makes_no_remote_request():
    """The console claims "no CDN, no network call, no telemetry" in three places.
    
    An earlier theme.py began with a Google Fonts @import, which is a real network request on
    every page load and silently broke that guarantee -- while looking, on screen, like a
    harmless typeface choice. A security tool that phones a CDN the moment an analyst opens it
    leaks the fact that they are analysing cryptography, and cannot run air-gapped at all.
    """
    from engine.theme import CSS
    # Only non-comment CSS is scanned. The stylesheet deliberately NAMES "@import" and a CDN
    # host in a comment explaining why it does not use them, and a whole-file grep would flag
    # that documentation as the very defect it documents -- which is how a guard test quietly
    # stops being trusted by the very person who wrote it.
    code = [ln for ln in CSS.splitlines()
             if not ln.strip().startswith(("*", "/*", "---"))]
    for needle in ("@import", "fonts.googleapis", "http://", "https://", "//cdn"):
        assert needle not in code, (
            f"the stylesheet references {needle!r} in executable CSS; the console promises "
            f"to make no network request. Declare a local font stack instead.")


# ===========================================================================================
# Classical strength, held against NIST SP 800-57 -- a table we did not write.
#
# The reason this file is separate from the rest of the suite is that it is NOT testing our
# implementation against our own expectations. Every other test checks self-consistency. This
# one holds a table we authored against the published standard, because a table that is wrong in
# a way our own suite agrees with is invisible from the inside.
#
# A missing entry is NOT neutral: `_classical_strength` returns 0 for an unknown name, so an
# absent algorithm is published as `classicalSecurityLevel: 0` -- "no security whatsoever". That
# is how Ed25519, ChaCha20 and Blowfish were all reported as worthless before this test existed.
# ===========================================================================================

# NIST SP 800-57 Part 1 Rev 5, Tables 2 and 3.
NIST_SP800_57 = [
    ("RSA", 2048, 112), ("RSA", 3072, 128), ("RSA", 4096, 152),
    ("ECDH", 256, 128), ("ECDH", 384, 192), ("ECDH", 521, 256),
    ("AES-128", 128, 128), ("AES-192", 192, 192), ("AES-256", 256, 256),
    ("SHA-256", None, 128), ("SHA-384", None, 192), ("SHA-512", None, 256),
    ("ChaCha20", None, 256), ("XChaCha20", None, 256),
    # 3DES is 168-bit raw but ~112-bit effective via Sweet32 birthday bounds on its 64-bit block.
    ("3DES", None, 112),
    # Blowfish has a 56-bit effective key: the 64-bit block size caps it regardless of key length.
    ("Blowfish", None, 56),
    # Deliberately zero, and asserted as zero so nobody "fixes" it upward later.
    ("MD5", None, 0), ("RC4", None, 0),
]


@pytest.mark.parametrize("name,bits,want", NIST_SP800_57)
def test_classical_strength_matches_nist_sp_800_57(name, bits, want):
    from engine.cbom import _classical_strength
    got = _classical_strength({"name": name, "key_length": bits}, "x")
    assert got == want, f"{name} ({bits}): NIST SP 800-57 says {want}, we publish {got}"


def test_no_standard_primitive_is_published_as_having_no_security():
    """The silent-gap check. A missing table entry reports 0, so absence reads as "worthless".

    Every one of these was previously absent and therefore reported as `classicalSecurityLevel:
    0`. ChaCha20 in particular is a NIST SP 800-38E standard that TLS prefers on hardware where
    AES-NI is unavailable, so calling it worthless inverts the actual advice.
    """
    from engine.cbom import _classical_strength
    # ECDSA and EC are deliberately NOT in this list. A finding whose curve the scanner could
    # not see is genuinely unknown, and the correct answer is None -- which omits the property.
    # Asserting a number there would be exactly the guess this project refuses to make.
    for name in ("ChaCha20", "Blowfish", "CAST5", "IDEA", "SEED", "Camellia-256", "Twofish",
                 "Ed25519", "DH", "AES-256", "SHA-256"):
        got = _classical_strength({"name": name, "key_length": None}, "x")
        assert got not in (None, 0), (
            f"{name} has no entry in the strength table, so it is published as 0 -- which "
            f"reads as 'no security', not as 'unknown'. Add it, or return None deliberately.")


def test_a_bare_family_name_plus_key_length_resolves_to_its_parameter_set():
    """The scanner emits `{"name": "RSA", "key_length": 2048}`, not `{"name": "RSA-2048"}`.

    Without the length fallback, every finding from our own rules would report strength 0 while
    the information sat in the same dict.
    """
    from engine.cbom import _classical_strength
    assert _classical_strength({"name": "RSA", "key_length": 2048}, "signature") == 112
    assert _classical_strength({"name": "RSA", "key_length": 3072}, "signature") == 128
    assert _classical_strength({"name": "ECDSA", "key_length": 384}, "signature") == 192


def test_exact_parameter_sets_beat_family_defaults():
    """A known curve must report its own strength, not a family average.

    The table once carried "ECDH": 128 as a name-level entry, and because the exact-name lookup
    runs before the key-length logic, `{"name": "ECDH", "key_length": 384}` reported 128 instead
    of 192 -- a P-384 finding made to look like P-256 purely because the table had just been made
    more generous elsewhere. Being imprecise must never be rewarded with a better-looking number.
    """
    from engine.cbom import _classical_strength
    for bits, want in ((256, 128), (384, 192), (521, 256)):
        assert _classical_strength({"name": "ECDH", "key_length": bits}, "x") == want, bits
        assert _classical_strength({"name": "ECDSA", "key_length": bits}, "x") == want, bits


def test_an_unknown_curve_is_omitted_rather_than_guessed():
    """The honest answer to "which curve?" when the scanner could not see it is NOTHING.

    `_classical_strength` returns None, `_algorithm_properties` omits `classicalSecurityLevel`
    entirely, and the CBOM simply does not make the claim. Publishing 0 there would say "no
    security whatsoever" about what is almost always P-256; publishing 256 would claim a curve
    the tool never saw. Omission is the only defensible answer, and the schema has no "unknown"
    member precisely so a tool has to choose this deliberately.
    """
    from engine.cbom import _algorithm_properties, _classical_strength

    assert _classical_strength({"name": "ECDSA", "key_length": None}, "x") is None
    props = _algorithm_properties(
        {"name": "ECDSA", "primitive": "signature", "key_length": None, "uses": "at-rest"},
        "signature")
    assert "classicalSecurityLevel" not in props
    # ...but the quantum verdict is still stated, because that one does not depend on the curve.
    assert props.get("nistQuantumSecurityLevel") == 0


def test_a_dh_group_reports_strength_not_key_length():
    """112, not 2048.

    `classicalSecurityLevel` means security STRENGTH. Writing the key length into it is the
    single most common version of this bug -- it overstates a 2048-bit MODP group by an order of
    magnitude, and RSA-2048 has the same 112-bit figure for the same reason.
    """
    from engine.cbom import _classical_strength
    for name in ("DH", "DHE", "MODP"):
        got = _classical_strength({"name": name, "key_length": None}, "x")
        assert got == 112, f"{name} reports {got}; a 2048-bit MODP group is ~112-bit security"


def test_a_family_name_cannot_shadow_a_family_contained_inside_it():
    """`DH` must not match inside `ECDH`, and `DS` must not match inside `ECDSA`.

    This was a live defect, twice over. The substring fallback iterated the table in insertion
    order, reached the key "DH" while scanning the name "ECDH", and answered 112 -- so every
    curve-based key exchange was reported as a 2048-bit MODP group. mosca.py then selected the
    `lt_128` tier and published "deprecated" for an algorithm whose curve had never been seen:
    an UNRATED unknown turned into a confident verdict, which is the single failure mode this
    project exists to prevent, reintroduced by making a table MORE generous.

    Longest-key-first ordering alone does not fix it -- both fixes are required, and both are
    asserted here.
    """
    from engine.cbom import _classical_strength

    # A curve family with no stated size is UNKNOWN, not a MODP group.
    assert _classical_strength({"name": "ECDH", "key_length": None}, "key-agreement") is None
    assert _classical_strength({"name": "ECDSA", "key_length": None}, "signature") is None
    # ...while a real DH group still resolves.
    assert _classical_strength({"name": "DH", "key_length": None}, "key-agreement") == 112
    assert _classical_strength({"name": "DHE", "key_length": None}, "key-agreement") == 112
    # A composite name containing both must not take the shorter family's value either.
    assert _classical_strength({"name": "ECDH-X25519"}, "key-agreement") in (None, 128)



def test_an_unknown_strength_is_omitted_from_the_document_not_emitted_as_null():
    """A null in the CBOM fails CycloneDX validation and invalidates the whole document.

    The field is a non-nullable integer, so an unknown strength has to leave the property
    ABSENT from the dict rather than present-and-empty. This asserts the emitted document,
    not the intermediate, because the intermediate carrying None was the actual bug.
    """
    import json
    from engine.cbom import generate_cbom

    doc = generate_cbom([{
        "file": "a.py", "line": 1, "type": "algorithm", "name": "ECDSA",
        "primitive": "signature", "evidence_class": "used", "artefact_class": "library",
        "uses": "at-rest", "match": "sign()", "scanner": "s", "key_length": None,
    }])
    text = json.dumps(doc)
    doc = json.loads(generate_cbom([{
        "file": "a.py", "line": 1, "type": "algorithm", "name": "ECDSA",
        "primitive": "signature", "evidence_class": "used", "artefact_class": "library",
        "uses": "at-rest", "match": "sign()", "scanner": "s", "key_length": None,
    }]))
    assert "null" not in text, "a null in the CBOM fails schema validation"

    # Checked on the parsed document, not on a JSON string: json.dumps separator spacing is an
    # implementation detail, and a test that breaks when the library changes it is testing
    # the library rather than the code.
    comp = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert "classicalSecurityLevel" not in comp, "an unknown strength must be omitted"
    # The quantum verdict does not depend on the curve, so it is still stated.
    assert comp.get("nistQuantumSecurityLevel") == 0
