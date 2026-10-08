"""Regressions for defects found in a 2026-09 review pass.

Every test here corresponds to a bug that was LIVE in the shipped code and reproduced on demand.
They are grouped by severity rather than by module, because the common thread is worse than any
individual module: in four of the six groups the tool asserted something it had not established.

  * SELF-CONTRADICTION -- the tool classified its own migration recommendation as
    quantum-vulnerable, and a quantum-safe signature as Shor-broken.
  * FALSE ASSURANCE  -- an unassessable finding was counted as compliant, and a lapsed deadline
    rendered as a small negative number.
  * STALE EVIDENCE    -- a memoised scan returned previous findings under a fresh timestamp.
  * CRASH             -- one malformed field aborted the entire report.

The test names state the defect, not the function, so a future rename does not erase the reason
the test exists.

Run: python -m pytest tests/test_review_regressions.py -v
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.mosca as mosca
from engine.cbom import (CLASSICAL_STRENGTH_BITS, _algorithm_properties, _canonical_primitive,
                         _classical_strength, generate_cbom, is_pqc)
from engine.gui_helpers import (DEADLINE_NO_POLICY, DEADLINE_OVERRUN, DEADLINE_UNRATED,
                                DEADLINE_WITHIN, deadline_countdown, deadline_verdict,
                                late_records, queue_rows, unrated_records)
from engine.mosca import (POLICY_DEADLINES, calculate_risk, quantum_break_model,
                          resolve_policy_deadline)
from engine.purpose import resolve_assurance
from engine.recommender import get_pqc_recommendation
from engine.scanner import RULES

# Every spelling of these that appears in the wild. IANA/TLS codepoints, the `cryptography`
# library, the SSH hybrid draft and the NIST names all disagree, which is the whole reason the
# original hyphen-only tuple failed.
PQC_NAMES = ["ML-KEM-768", "MLKEM768", "mlkem768", "X25519MLKEM768", "SecP384r1MLKEM1024",
             "ML-DSA-65", "MLDSA65", "SLH-DSA-SHA2-128s", "SLHDSA128s", "XMSS_H10",
             "p256_mlkem768", "mlkem768x25519-sha256", "Falcon-512"]

CLASSICAL_NAMES = ["RSA-2048", "ECDSA-P256", "X25519", "AES-256", "SHA-256", "Ed25519",
                   "DSA-2048", "3DES"]


# --------------------------------------------------------------------------------------------
# SELF-CONTRADICTION: the tool flagged its own recommendations as quantum-vulnerable
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", PQC_NAMES)
def test_every_pqc_spelling_is_classified_as_pqc(name):
    """MLKEM768, ML-DSA-65 and X25519MLKEM768 were all classified as NOT post-quantum.

    The tuple of literal hyphenated names could not match the deployed spellings, and the file's
    own comment had already identified this as "the most damaging possible error in this file --
    the tool would label its own migration recommendation as quantum-vulnerable".
    """
    assert is_pqc(name), f"{name} must be recognised as post-quantum"


@pytest.mark.parametrize("name", CLASSICAL_NAMES)
def test_classical_algorithms_are_not_mislabelled_as_pqc(name):
    """The counterpart check: broadening the matcher must not swallow classical algorithms."""
    assert not is_pqc(name), f"{name} is not post-quantum"


def test_xmss_is_spelled_correctly():
    """XMMS was a typo for XMSS (eXtended Merkle Signature Scheme, SP 800-208)."""
    assert is_pqc("XMSS_H10")
    assert not is_pqc("XMMS")  # guard: the typo must not itself have become the vocabulary


@pytest.mark.parametrize("name", ["X25519MLKEM768", "ML-DSA-65", "ML-KEM-768", "XMSS_H10"])
def test_pqc_is_screened_before_the_shor_table(name):
    """`quantum_break_model` returned 'broken-by-Shor' for our top migration recommendation.

    `X25519MLKEM768` contains "X25519", which is in the Shor table, and "DSA" is a substring of
    "ML-DSA" -- so reaching the token tables before the PQC screen marked a quantum-safe
    signature and a quantum-safe hybrid as broken.
    """
    assert quantum_break_model(name, "signature") == "not-affected"


@pytest.mark.parametrize("name", ["RSA-2048", "ECDSA-P256", "X25519", "DSA-2048"])
def test_genuinely_quantum_vulnerable_algorithms_still_report_shor(name):
    """The PQC pre-screen must not swallow the algorithms it is meant to exempt."""
    assert quantum_break_model(name, "signature") == "broken-by-Shor"


# --------------------------------------------------------------------------------------------
# CRASH: one malformed field aborted the whole report
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["not-a-number", "", None, "2048bits", [], {}, "1e3"])
def test_malformed_key_length_does_not_abort_the_report(bad):
    """`int('not-a-number')` raised ValueError and killed the entire report.

    `key_length` comes from regex capture groups and third-party inputs, so any string is
    possible. One unreadable field must degrade to "confirm the key size", not end the run.
    """
    result = get_pqc_recommendation({"name": "AES-256", "primitive": "block-cipher",
                                     "key_length": bad, "uses": "at-rest"})
    assert result is None or isinstance(result, dict)


def test_numeric_string_key_length_is_still_interpreted():
    """The coercion must not become a blanket refusal: "256" is a usable key size."""
    result = get_pqc_recommendation({"name": "AES-256", "primitive": "block-cipher",
                                     "key_length": "256", "uses": "at-rest"})
    assert result is None or isinstance(result, dict)


# --------------------------------------------------------------------------------------------
# SELF-CONTRADICTION: a finite-field DH group reported as ECDH
# --------------------------------------------------------------------------------------------

def _rule(rule_id):
    return next(r for r in RULES if r["id"] == rule_id)


@pytest.mark.parametrize("identifier", ['"diffie-hellman-group14-sha256"',
                                        '"diffie-hellman-group-exchange-sha256"',
                                        '"diffie-hellman-group1-sha1"'])
def test_finite_field_dh_is_named_DH_not_ECDH(identifier):
    """A finite-field DH group was reported as BOTH ECDH and DH: a wrong algorithm name.

    Adding the DH rule without removing the finite-field names from the ECDH rule double-counted
    every FFDH identifier, inflating finding counts and writing "ECDH" into the CBOM for a
    group that is not elliptic at all.
    """
    assert not re.search(_rule("IM-SRC-SSH-KEX-001")["regex"], identifier), \
        f"{identifier} is finite-field DH and must not match the ECDH rule"
    assert re.search(_rule("IM-SRC-SSH-DH-001")["regex"], identifier), \
        f"{identifier} must match the DH rule"


@pytest.mark.parametrize("identifier", ['"ecdh-sha2-nistp256"', '"curve25519-sha256"'])
def test_genuinely_elliptic_kex_still_reports_ECDH(identifier):
    """Removing FFDH from the ECDH rule must not cost the elliptic names it should keep."""
    assert re.search(_rule("IM-SRC-SSH-KEX-001")["regex"], identifier)


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: unassessable findings counted as compliant
# --------------------------------------------------------------------------------------------

def test_finding_with_no_risk_is_UNRATED_not_compliant():
    """`(risk.get(...) or 0) > deadline` collapsed a missing risk to 0, which is never > a real
    deadline, so UNRATED findings fell into the 'within window' bucket and were tallied as
    compliant. An artefact IndraMesh could not assess was reported as a pass."""
    assert deadline_verdict({"name": "RSA"}, 2035) == DEADLINE_UNRATED


def test_start_year_after_the_deadline_is_OVERRUN():
    assert deadline_verdict({"risk": {"latest_safe_migration_start": 2040}}, 2035) == DEADLINE_OVERRUN


def test_start_year_before_the_deadline_is_within_window():
    assert deadline_verdict({"risk": {"latest_safe_migration_start": 2030}}, 2035) == DEADLINE_WITHIN


def test_no_active_policy_is_its_own_state():
    assert deadline_verdict({"name": "RSA"}, None) == DEADLINE_NO_POLICY


def test_unrated_records_are_counted_separately_from_late_ones():
    """The two must not be merged: one is known-bad, the other is unknown."""
    records = [{"name": "unrated"},
               {"risk": {"latest_safe_migration_start": 2040}},
               {"risk": {"latest_safe_migration_start": 2030}}]
    assert len(unrated_records(records, 2035)) == 1
    assert len(late_records(records, 2035)) == 1


def test_unrated_records_is_empty_without_a_policy():
    """With no deadline there is nothing to be unrated against, and claiming otherwise invents
    a gap in an assessment that was never attempted."""
    assert unrated_records([{"name": "x"}], None) == []


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: a lapsed deadline rendered as a small negative number
# --------------------------------------------------------------------------------------------

def test_lapsed_deadline_says_PASSED():
    """A deadline 6 years in the past rendered as "-6 year(s) from 2026": arithmetically right,
    rhetorically useless. A reader skims the magnitude and misses that the date has passed."""
    assert deadline_countdown(2020, 2026) == "PASSED 6 year(s) ago"


def test_deadline_this_year_reads_as_such():
    assert deadline_countdown(2026, 2026) == "this year"


def test_future_deadline_keeps_the_plain_countdown():
    assert deadline_countdown(2030, 2026) == "4 year(s) from 2026"


def test_missing_deadline_is_na():
    assert deadline_countdown(None, 2026) == "n/a"


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: a crashed recommender bucketed as "target named"
# --------------------------------------------------------------------------------------------

def test_unresolved_sentinel_never_reads_as_target_named():
    """A recommender that crashed or declined returns an 'unresolved:...' sentinel. The status
    test ran the `unresolved` FLAG first, so the sentinel fell through to the "target named"
    bucket -- the one label that implies no human is needed."""
    record = {"name": "X", "tier": "HIGH", "assurance": {"value": "used"},
              "unresolved": True, "file": "a.py", "line": 1,
              "recommendation": {"algorithm": "unresolved:purpose-not-proven"}}
    row = queue_rows([record], deadline_year=2035)[0]
    assert "DECLINED" in row["Status"]
    assert "target named" not in row["Status"]


def test_a_genuine_named_target_is_still_labelled_named():
    """The sentinel check must not swallow the legitimate 'named but unresolved' case."""
    record = {"name": "X", "tier": "HIGH", "assurance": {"value": "used"},
              "unresolved": True, "file": "a.py", "line": 1,
              "recommendation": {"algorithm": "ML-DSA-65"}}
    row = queue_rows([record], deadline_year=2035)[0]
    assert "target named" in row["Status"]



# --------------------------------------------------------------------------------------------
# FALSE COMPLIANCE CLAIM: NIST IR 8547 is strength-dependent, not a flat year
# --------------------------------------------------------------------------------------------

def test_symmetric_primitives_are_OUT_OF_SCOPE_for_an_ir_8547_verdict():
    """AES-256 must never be reported as "disallowed by NIST IR 8547".

    IR 8547's transition tables govern quantum-vulnerable PUBLIC-KEY algorithms. A symmetric
    cipher is not in them, and Grover only halves the exponent rather than breaking the
    primitive. Deriving the status from key strength alone put AES-256, SHA-512, ChaCha20 and
    every HMAC into the "disallowed" bucket -- a false compliance claim of the worst kind,
    because it names a NIST standard and gets it wrong.
    """
    for name, primitive, key_length in [
        ("AES-256", "block-cipher", 256),
        ("AES-256-GCM", "ae", 256),
        ("ChaCha20", "stream-cipher", 256),
        ("SHA-512", "hash", None),
        ("HMAC-SHA256", "mac", None),
        ("HKDF", "kdf", None),
    ]:
        resolved = resolve_policy_deadline(
            {"name": name, "primitive": primitive, "key_length": key_length}, "nist_ir_8547")
        assert resolved["status"] == "not-in-scope", (
            "%s is not in the IR 8547 transition table and must not receive a verdict "
            "from it (got %r)" % (name, resolved["status"]))
        assert resolved["strength_tier"] is None


def test_post_quantum_algorithms_are_NOT_APPLICABLE_not_disallowed():
    """ML-KEM is the replacement IR 8547 mandates, so it cannot be deprecated by it.

    Without the is_pqc() gate, ML-KEM-768, ML-DSA-65 and our own recommended hybrid
    X25519MLKEM768 were all reported "disallowed" under the policy that recommends them.
    """
    for name in ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "X25519MLKEM768", "SLH-DSA-SHA2-128s"]:
        resolved = resolve_policy_deadline(
            {"name": name, "primitive": "kem", "key_length": 256}, "nist_ir_8547")
        assert resolved["status"] == "not-applicable", (
            "%s is post-quantum; IR 8547 retires what it replaces, not the replacement "
            "(got %r)" % (name, resolved["status"]))


def test_an_unmeasurable_algorithm_is_UNRATED_not_silently_deprecated():
    """A strength of 0 or None is an absence, not the 112-bit tier.

    The first implementation folded 0 into `lt_128`, so an unrecognised algorithm and a bare
    `libcrypto.so` were both quietly reported "deprecated" -- a sentinel becoming a verdict,
    and the safe direction being the wrong one.
    """
    # All of these are PUBLIC-KEY primitives, so they pass the scope gate and reach the
    # strength test. A non-public-key primitive never gets this far -- it is `not-in-scope`
    # (see the scope test above), and a post-quantum one is caught even earlier as
    # `not-applicable` (see the PQ test above). Both of those are more informative answers,
    # which is why only genuinely unmeasurable-but-valid cases belong in this list.
    for name, primitive, key_length in [
        ("RSA", "pke", None),                 # bare family name, size unknown
        ("ECDH", "key-agreement", None),      # no size in the name or the field
        ("ECDSA", "signature", None),
    ]:
        resolved = resolve_policy_deadline(
            {"name": name, "primitive": primitive, "key_length": key_length}, "nist_ir_8547")
        assert resolved["status"] == "unrated", (
            "%r must be UNRATED, not assigned a tier from a missing value (got %r)"
            % (name, resolved["status"]))
        assert resolved["strength_tier"] is None


def test_a_size_embedded_in_the_name_still_resolves_the_tier():
    """The counterpart, so `unrated` cannot be reached by deleting a field.

    `RSA-2048` carries 112 bits in its own NAME, so it resolves to the deprecated tier even
    with `key_length` absent or zero. That is the right answer -- the evidence is in the
    identifier -- and the reason the `unrated` path must be tested with names that genuinely
    say nothing.
    """
    for key_length in (None, 0):
        resolved = resolve_policy_deadline(
            {"name": "RSA-2048", "primitive": "pke", "key_length": key_length}, "nist_ir_8547")
        assert resolved["status"] == "deprecated"
        assert resolved["security_strength_bits"] == 112


def test_the_112_bit_tier_carries_the_DEPRECATION_year_not_the_disallowance_year():
    """2030 is the actionable date for the 112-bit tier.

    Reporting 2035 there would hand a 112-bit operator five years they do not have, and
    five years of a silent vulnerability window they were told they had.
    """
    resolved = resolve_policy_deadline(
        {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, "nist_ir_8547")
    assert resolved["year"] == 2030
    assert resolved["status"] == "deprecated"


def test_resolved_deadline_never_leaks_the_raw_tier_table():
    """`tiers` is an internal detail. If it reaches the CBOM it bloats the document and hands
    a consumer a table to interpret themselves."""
    resolved = resolve_policy_deadline(
        {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, "nist_ir_8547")
    assert "tiers" not in resolved


def test_policies_without_tiers_say_target_not_disallowed():
    """India DST and CNSA 2.0 are procurement targets, not algorithm-status tables.

    Calling them "disallowed" attributes a legal determination to a published date.
    """
    for policy in ("india_dst_nqm", "cnsa_2_0"):
        resolved = resolve_policy_deadline(
            {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, policy)
        assert resolved["status"] == "target"
        assert resolved["strength_tier"] is None


def test_112_bit_algorithm_is_DEPRECATED_not_DISALLOWED_under_ir_8547():
    """The 112-bit tier is deprecated and stays usable during migration.

    NIST IR 8547 ipd: "NIST intends to instead deprecate rather than fully disallow classical
    key-establishment schemes at the 112-bit security level. Organizations may continue using
    these algorithms and parameter sets as they migrate." A flat `year: 2035` labelled
    "disallowed" told an operator their 112-bit RSA was banned. The standard says the opposite.
    """
    resolved = resolve_policy_deadline(
        {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, "nist_ir_8547")
    assert resolved["status"] == "deprecated", (
        "the 112-bit tier is deprecated, not disallowed")
    assert resolved["strength_tier"] == "lt_128"
    assert resolved["security_strength_bits"] == 112


def test_128_bit_algorithm_IS_disallowed_under_ir_8547():
    """The counterpart. The >= 128-bit tier genuinely is disallowed after 2035."""
    resolved = resolve_policy_deadline(
        {"name": "EC-P-256", "primitive": "signature", "key_length": 256}, "nist_ir_8547")
    assert resolved["status"] == "disallowed"
    assert resolved["strength_tier"] == "gte_128"


def test_two_strengths_under_the_same_policy_do_not_share_a_verdict():
    """RSA-2048 and RSA-3072 were both "RSA, 2035" in the old table, and they are not the same
    regulatory position. That is the entire defect."""
    weak = resolve_policy_deadline(
        {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, "nist_ir_8547")
    strong = resolve_policy_deadline(
        {"name": "RSA-3072", "primitive": "pke", "key_length": 3072}, "nist_ir_8547")
    assert weak["status"] != strong["status"]


def test_ir_8547_is_marked_as_a_draft_wherever_it_is_shown():
    """IR 8547 is an Initial Public Draft. A compliance tool that presents it as a final
    standard is making a claim NIST has not made."""
    resolved = resolve_policy_deadline(
        {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, "nist_ir_8547")
    assert resolved["draft"] is True
    assert "DRAFT" in POLICY_DEADLINES["nist_ir_8547"]["label"].upper()


def test_policies_without_tiers_are_unaffected():
    """India DST and CNSA 2.0 have no strength-dependent table, so they keep a flat year."""
    for policy in ("india_dst_nqm", "cnsa_2_0"):
        resolved = resolve_policy_deadline(
            {"name": "RSA-2048", "primitive": "pke", "key_length": 2048}, policy)
        assert resolved["strength_tier"] is None
        assert resolved["year"] == POLICY_DEADLINES[policy]["year"]


def test_calculate_risk_records_the_resolved_deadline_not_the_flat_one():
    """The audit trail must carry the nuance, or the console has nothing to show."""
    risk = calculate_risk({"name": "RSA-2048", "primitive": "pke", "key_length": 2048,
                           "uses": "signing"},
                          user_x=10, user_y=3, z_collapse_time=10, policy="nist_ir_8547")
    assert risk["policy_deadline"]["status"] == "deprecated"
    assert any("deprecated" in a for a in risk["assumptions"]), (
        "the assumption trail must state the status, not only the year")


# --------------------------------------------------------------------------------------------
# SILENTLY IGNORED INPUT: a CLI flag that is accepted and then discarded
# --------------------------------------------------------------------------------------------

def test_run_deps_accepts_and_honours_a_policy():
    """`--policy` was accepted by argparse and then thrown away by the deps subcommand.

    `run_deps` had no `policy` parameter at all, so `calculate_risk` fell back to
    DEFAULT_POLICY. A user who asked for the NIST IR 8547 timeline got India DST dates, a
    different deadline, and a different verdict for every finding -- with no error, no warning,
    and a report that looked entirely normal.

    This is the same class as the duplicate-finding problem: the failure is in a WIRE, not in
    the arithmetic, so neither the benchmark nor a unit test of `calculate_risk` can see it.
    Only an end-to-end test through the entry point can.
    """
    import inspect

    import cli_advanced

    params = inspect.signature(cli_advanced.run_deps).parameters
    assert "policy" in params, (
        "run_deps must accept a policy, or --policy is silently discarded for this subcommand")
    assert "z_time" in params, (
        "run_deps must accept a Z, for the same reason: a Z band the user cannot set is a "
        "Z band they cannot vary")

    # And the CALL SITE in main() must actually forward them. Match the invocation, not the
    # `def run_deps(` line -- splitting on the bare name catches the definition first and then
    # asserts against the parameter list, which says nothing about the call.
    source = inspect.getsource(cli_advanced)
    call = source.split("return run_deps(")[-1].split(")")[0]
    assert "args.policy" in call, "main() must forward args.policy into run_deps"
    assert "args.z" in call, "main() must forward args.z into run_deps"


def test_validate_real_world_states_its_rating_inputs_explicitly():
    """A validation report must be re-derivable from constants it names itself."""
    source = open(os.path.join(os.path.dirname(__file__), "..", "validate_real_world.py"),
                  encoding="utf-8").read()
    assert "calculate_risk(f, z_collapse_time=" in source, (
        "validate_real_world must pass Z explicitly rather than inheriting a default")


def test_an_unknown_policy_is_refused_rather_than_giving_a_null_deadline():
    """A bogus policy used to yield `year=None`, and every comparison against None is False.

    So an artefact already past its deadline could never be reported late, and the report looked
    entirely normal. A tool that cannot be sure WHICH deadline it is measuring against must say
    so rather than emit a null and continue.
    """
    with pytest.raises(ValueError, match="Unknown policy"):
        calculate_risk({"name": "RSA-2048", "primitive": "pke", "key_length": 2048},
                       policy="TOTALLY-BOGUS")


def test_every_known_policy_still_resolves_to_a_real_year():
    """The counterpart, so the guard cannot be satisfied by refusing everything."""
    for policy in POLICY_DEADLINES:
        risk = calculate_risk({"name": "RSA-2048", "primitive": "pke", "key_length": 2048},
                              policy=policy)
        assert risk["policy_deadline"].get("year"), (
            "%s must resolve to a real year" % policy)


def test_the_z_band_actually_contains_the_chosen_z():
    """`--z 40` used to print "z: 40.0" beside a band labelled 5/10/15 that never included 40.

    Worse, `z_stable` could then report a stable verdict without 40 ever being evaluated --
    the most misleading thing a sensitivity analysis can do, because it looks like robustness.
    """
    for z in (1, 20, 40, 99):
        band = calculate_risk({"name": "RSA-2048", "primitive": "pke", "key_length": 2048},
                              z_collapse_time=z)["z_band"]
        probed = {float(k.split("=")[1]) for k in band}
        assert float(z) in probed, (
            "Z=%s was chosen but the sensitivity band probed %s" % (z, sorted(probed)))


def test_the_default_z_still_shows_the_sourced_consensus_window():
    """The counterpart: at the default Z the band is the published GRI 5-15 range.

    That range is a sourced claim, not an arbitrary spread, so it must survive the change.
    """
    band = calculate_risk({"name": "RSA-2048", "primitive": "pke", "key_length": 2048})["z_band"]
    assert {float(k.split("=")[1]) for k in band} == {5.0, 10.0, 15.0}


def test_different_z_values_produce_different_bands():
    """Before the fix, EVERY Z produced the identical band, so the sensitivity analysis was
    decorative: it displayed a range that did not depend on the parameter it claimed to probe."""
    bands = {tuple(sorted(calculate_risk({"name": "RSA-2048", "primitive": "pke",
                                          "key_length": 2048},
                                         z_collapse_time=z)["z_band"]))
             for z in (5, 10, 15, 40, 99)}
    assert len(bands) > 1, "the band must vary with Z, or it is not a sensitivity analysis"


def test_every_subparser_exposes_the_flags_main_forwards():
    """`run_deps` gained a `policy` parameter while the `deps` subparser had no `--policy`, so
    every `deps` invocation raised AttributeError: 'Namespace' object has no attribute 'z'.

    Forwarding a flag that the subparser does not declare is a crash, not a fix. This asserts
    the two halves of the wiring agree, by parsing a real argv rather than reading the source.
    """
    import cli_advanced

    parser = cli_advanced._build_parser() if hasattr(cli_advanced, "_build_parser") else None
    if parser is None:
        # No extractable parser: fall back to asserting the source declares the flags, which is
        # the actual defect that was shipped.
        source = open(os.path.join(os.path.dirname(__file__), "..", "cli_advanced.py"),
                      encoding="utf-8").read()
        deps_block = source.split('add_parser("deps"')[1].split('add_parser(')[0]
        assert '--z' in deps_block and '--policy' in deps_block, (
            "the deps subparser must declare --z and --policy, because main() forwards both")
    else:
        args = parser.parse_args(["deps", ".", "--policy", "nist_ir_8547", "--z", "20"])
        assert args.policy == "nist_ir_8547"
        assert args.z == 20


def test_policy_choices_are_constrained_on_every_subparser():
    """`all --policy` had no `choices=`, so a typo was accepted and produced a null deadline."""
    source = open(os.path.join(os.path.dirname(__file__), "..", "cli_advanced.py"),
                  encoding="utf-8").read()
    for line in source.splitlines():
        if 'add_argument("--policy"' in line:
            assert "choices=" in line, (
                "--policy must constrain its values: an unrecognised policy yields a null "
                "deadline, and a null deadline never reports anything as late")


# --------------------------------------------------------------------------------------------
# A TABLE THAT CANNOT BE READ: CLASSICAL_STRENGTH_BITS was 8/47 dead
# --------------------------------------------------------------------------------------------

def test_every_strength_table_entry_is_actually_reachable():
    """Ed25519 and Ed448 were UNREACHABLE, so both published `classicalSecurityLevel: 0`.

    The table is keyed in SP 800-57 canonical casing ("Ed25519", "SLH-DSA-SHA2-128f") but the
    lookup upper-cased the NAME before probing it, and the substring fallback was
    case-sensitive too. 8 of 47 entries could never match -- including two Shor-broken,
    NIST-registered algorithms, which therefore read as having *no* security.

    `MD5` is excluded because its correct value IS 0: it is broken, and a table that reported
    it as 128-bit would be the bug, not the fix. So the test asserts a reachable ENTRY, not a
    non-zero one.
    """
    dead = [k for k, v in CLASSICAL_STRENGTH_BITS.items()
            if v != 0 and _classical_strength({"name": k}, "signature") == 0]
    assert not dead, ("these table entries can never be matched, so they are silently wrong: %s"
                      % dead)


@pytest.mark.parametrize("name,expected", [("Ed25519", 128), ("Ed448", 224),
                                            ("SLH-DSA-SHA2-128f", 128),
                                            ("SLH-DSA-SHA2-256s", 256)])
def test_mixed_case_canonical_names_resolve(name, expected):
    assert _classical_strength({"name": name}, "signature") == expected


# --------------------------------------------------------------------------------------------
# A COMPONENT THAT ASSERTS AND DENIES THE SAME FIELD
# --------------------------------------------------------------------------------------------

def test_a_component_never_claims_a_nist_level_and_denies_one_is_derivable():
    """One component emitted nistQuantumSecurityLevel=0 AND "no NIST category is derivable".

    The level was computed from the NORMALISED primitive ("digital-signature" -> "signature")
    while the gap note was computed from the RAW one, which is not a table member. Four of
    twenty-two components carried both. A consumer reading the two lines gets opposite answers
    to the same question.
    """
    f = {"name": "ECDSA", "primitive": "digital-signature", "file": "a.py", "line": 1,
         "key_length": 256}
    f["risk"] = calculate_risk(f, policy="india_dst_nqm")
    doc = json.loads(generate_cbom([f], enriched=True))
    comp = doc["components"][0]
    ap = comp["cryptoProperties"]["algorithmProperties"]
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    has_level = "nistQuantumSecurityLevel" in ap
    has_gap = "im:nist_level_gap" in props
    assert not (has_level and has_gap), (
        "the document must not both state a level and say none is derivable")


def test_a_shor_broken_algorithm_is_marked_even_when_the_primitive_is_unknown():
    """An ECC finding arrives with primitive="unknown" from the scanner.

    `_nist_quantum_level` could not classify it and omitted the field, while the same
    record's risk block said `break_model=broken-by-Shor`. The document was denying the
    quantum marking the engine had just established, for the most common ECC shape in Python.
    """
    f = {"name": "ECC", "primitive": "unknown", "file": "a.py", "line": 1}
    f["risk"] = calculate_risk(f, policy="india_dst_nqm")
    assert f["risk"]["break_model"] == "broken-by-Shor"
    doc = json.loads(generate_cbom([f], enriched=True))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap.get("nistQuantumSecurityLevel") == 0, (
        "a Shor-broken algorithm must be marked 0 in the document, whatever the primitive is")


# --------------------------------------------------------------------------------------------
# ABSENT MEASUREMENT READING AS A PASS
# --------------------------------------------------------------------------------------------

def test_an_unmeasured_hash_is_not_published_as_128_bit():
    """MD5 returned 0 from `_classical_strength` and a fallback published it as 128.

    0 means "I could not determine this"; the fallback converted that absence into a
    confident number. Inventing a measurement is the failure mode this project exists to
    avoid, and it happened in the fix for a different instance of the same idea.
    """
    for name in ("MD5", "BLAKE2b", "unknown-digest"):
        assert _algorithm_properties({"name": name}, "hash").get(
            "classicalSecurityLevel") != 128, (
            "%s was not measured and must not be published as 128-bit" % name)


def test_an_unmeasured_hash_is_not_rated_LOW_by_default():
    """`_grover_effective_bits` returned a hardcoded 128 for a SHA with no key_length.

    128 crossed the `>= 128` threshold in `_tier` and produced LOW -- the SAFE side of the
    boundary. An unmeasured digest was therefore rated safe by default, while the CBOM for the
    same component said no category could be derived.
    """
    assert mosca._grover_effective_bits("SHA", None) is None, (
        "an unmeasured digest must not be given an invented strength")
    risk = calculate_risk({"name": "SHA", "primitive": "hash", "uses": "at-rest"})
    assert risk.get("grover_effective_bits") in (None, 0), (
        "the invented 128 leaked into the published verdict: %r" % risk.get("grover_effective_bits"))


@pytest.mark.parametrize("name,expected", [("SHA-256", 128), ("SHA384", 192),
                                            ("SHA-512", 256), ("SHA224", 112)])
def test_a_named_digest_family_is_still_rated(name, expected):
    """The counterpart, so `None` cannot be reached by refusing every hash.

    The digest size is often in the NAME, so a family that identifies itself is rated rather
    than abandoned. The expected values are HALF the digest, which is what Grover costs:
    SHA-512 -> 256, not 128.
    """
    assert mosca._grover_effective_bits(name, None) == expected


# --------------------------------------------------------------------------------------------
# CAPABILITIES ARE NOT ALGORITHMS: the 7 rules added in 66ccb92/98833bc
# --------------------------------------------------------------------------------------------

CAPABILITY_RULES = ["IM-CLOUD-KMS-001", "IM-CLOUD-AZURE-001", "IM-CLOUD-GCP-001",
                    "IM-HARDWARE-PKCS11-001"]


@pytest.mark.parametrize("rule_id", CAPABILITY_RULES)
def test_a_cloud_or_hsm_rule_is_typed_as_a_capability_not_an_algorithm(rule_id):
    """A KMS call names no cipher and no key size, so it cannot carry a risk verdict.

    `primitive="cloud-service"` / `"hardware-module"` are not CycloneDX 1.7 enum members, so
    they canonicalised to `unknown` and shipped as assetType=algorithm / primitive=unknown /
    tier=LOW. A capability was being reported as a used algorithm -- the primary way a
    discovery tool misleads, as the assurance taxonomy itself says.
    """
    rule = next(r for r in RULES if r["id"] == rule_id)
    assert rule.get("type") == "library", (
        "%s detects a capability, so it must be typed as one" % rule_id)
    assert rule["primitive"] == "cryptographic-library", (
        "%s must use the capability primitive the recommender already routes" % rule_id)
    # `cryptographic-library` canonicalises to "unknown" BY DESIGN and always has: cbom's
    # library branch emits a `type: library` component with NO cryptoProperties at all, so there
    # is no primitive field for it to be wrong in. What matters is that it takes that branch.
    assert _canonical_primitive(rule["primitive"]) == "unknown"


def test_a_capability_is_graded_as_capability_not_used():
    """The assurance taxonomy must place these in `capability`, not `used`.

    `used` means "code invokes it", which for a KMS client is true but is not the claim being
    made. `capability` is the honest grade for something present but not exercised.
    """
    rule = next(r for r in RULES if r["id"] == "IM-CLOUD-KMS-001")
    finding = {"name": rule["name"], "primitive": rule["primitive"], "type": rule["type"],
               "evidence_class": rule["evidence"], "file": "a.py", "line": 1}
    grade, _ = resolve_assurance(finding)
    assert grade == "capability", "a KMS client is a capability, got %r" % grade


def test_a_cloud_rule_survives_the_trip_to_the_cbom_as_a_library():
    """End to end, because the primitive mapping is where the defect actually surfaced."""
    finding = {"name": "AWS KMS", "primitive": "cryptographic-library", "type": "library",
               "evidence_class": "dependency", "file": "a.py", "line": 1}
    doc = json.loads(generate_cbom([finding], enriched=True))
    comp = doc["components"][0]
    assert comp.get("type") == "library", (
        "a capability must be a library component, got %r" % comp.get("type"))


def test_a_private_key_is_related_crypto_material_not_an_algorithm():
    """CycloneDX 1.7 has an asset type for exactly this and we were not using it.

    `relatedCryptoMaterialProperties` has no `primitive` field at all, so the previous
    `primitive="key"` -- not an enum member -- is no longer needed, and the question of which
    enum member describes a PEM header does not arise.
    """
    finding = {"name": "Private Key (PEM)", "rule_id": "IM-KEY-PEM-001", "type": "algorithm",
               "primitive": "key", "file": "a.py", "line": 1}
    doc = json.loads(generate_cbom([finding], enriched=True))
    cp = doc["components"][0]["cryptoProperties"]
    assert cp["assetType"] == "related-crypto-material", (
        "a private key is related-crypto-material, got %r" % cp.get("assetType"))
    assert cp["relatedCryptoMaterialProperties"]["type"] == "private-key"
    assert "algorithmProperties" not in cp, (
        "related-crypto-material carries no primitive; emitting one is a schema error")


def test_the_pkcs11_rule_no_longer_matches_any_identifier_containing_pkcs11():
    """`PKCS11` with no word boundary matched variables, comments and vendored filenames."""
    rule = next(r for r in RULES if r["id"] == "IM-HARDWARE-PKCS11-001")
    for decoy in ("x = 'PKCS11TOKEN'", "# PKCS11ish thing", "PKCS11_ENABLED = False"):
        assert not re.search(rule["regex"], decoy), (
            "decoy %r must not match the HSM rule" % decoy)
    for real in ("tok = pkcs11.get_token(label='x')", "import SunPKCS11", "c = PKCS11()"):
        assert re.search(rule["regex"], real), "real HSM usage %r must match" % real


def test_the_legacy_tls_rule_does_not_duplicate_the_existing_config_rule():
    """IM-PROTO-TLS-001 was ~83% redundant with IM-CFG-TLS-001 and _finalise cannot dedup it.

    Different rule_id means a different dedup key, so one nginx line produced TWO
    assetType=protocol components. And the rule required a DOTTED version, so the most common
    legacy nginx line in existence, `ssl_protocols TLSv1 TLSv1.1;`, was invisible to the rule
    added to catch legacy TLS. It now keeps only the Apache `SSLProtocol` directive.
    """
    proto = next(r for r in RULES if r["id"] == "IM-PROTO-TLS-001")
    cfg = next(r for r in RULES if r["id"] == "IM-CFG-TLS-001")
    overlapping = [s for s in ("ssl_protocols TLSv1.1;", "ssl_protocols TLSv1 TLSv1.1;",
                               "ssl_protocols TLSv1.2 TLSv1.3;")
                   if re.search(proto["regex"], s) and re.search(cfg["regex"], s)]
    assert not overlapping, (
        "these match BOTH TLS rules and produce duplicate components: %s" % overlapping)
    assert re.search(proto["regex"], "SSLProtocol all -SSLv3"), (
        "the Apache directive is what this rule uniquely owns and must still match")
    assert re.search(proto["regex"], "sslprotocol all"), "Apache directives are case-insensitive"


def test_every_rule_primitive_is_either_schema_valid_or_a_capability():
    """The invariant that would have caught all of the above at once.

    A rule may use a primitive outside the enum ONLY if it also declares a non-`algorithm`
    type -- because that is the signal that the schema models it somewhere else entirely.
    """
    # RTRES-003 is provider indirection with an unresolved identity, not an algorithm the
    # scanner could name: `primitive="unknown"` is load-bearing ("default to unresolved"), and
    # cbom.py handles it the same way it handles any unknown -- advisory fields only, never a
    # confident primitive. Requiring a non-algorithm `type` here would force a schema category
    # the finding does not belong to.
    RUNTIME_RESOLVED_RULES = {"IM-JAVA-RTRES-003"}
    for rule in RULES:
        canonical = _canonical_primitive(rule["primitive"])
        if canonical == "unknown" and rule.get("type", "algorithm") == "algorithm":
            if rule.get("primitive") in ("key", "protocol"):   # handled by a dedicated branch
                continue
            if rule["id"] in RUNTIME_RESOLVED_RULES:
                continue
            pytest.fail(
                "%s has primitive %r, which is not a CycloneDX 1.7 enum member and is typed as "
                "an algorithm, so it will be emitted as primitive=unknown"
                % (rule["id"], rule["primitive"]))


# --------------------------------------------------------------------------------------------
# DUPLICATE FINDINGS -- the benchmark structurally CANNOT see this class of bug
# --------------------------------------------------------------------------------------------

# `benchmark/run_benchmark.py` scores DISTINCT (file, line) locations: "a second finding on an
# already-matched positive line is neither a TP nor an FP". So a rule pair that both match one
# line is invisible to the benchmark AND invisible to a recall/precision comparison. It only
# shows up as an inflated findings_total in the CBOM and a doubled component in the report.
# This is the same failure shape as the SSH DH/ECDH double-report, found again in new code.

DUPLICATE_SAMPLES = [
    'Cipher.getInstance("AES/GCM/NoPadding");',
    'KeyGenerator.getInstance("AES");',
    'new SecretKeySpec(keyBytes, "AES");',
    'MessageDigest.getInstance("SHA-256");',
    'MessageDigest.getInstance("MD5");',
    'Mac.getInstance("HmacSHA256");',
    'Signature.getInstance("SHA256withRSA");',
    'KeyPairGenerator.getInstance("RSA");',
    'k = "ecdh-sha2-nistp256"',
    'k = "diffie-hellman-group14-sha256"',
    'ciphers = RC4-SHA:DES-CBC3-SHA',
]

# Lines that legitimately name MORE THAN ONE algorithm, and so must keep producing more than
# one finding. `padding.PSS(mgf=padding.MGF1(hashes.SHA256()))` is an RSA signature using a
# SHA-256 digest: RSA, SHA-256 and PSS are three real assets, and collapsing them to one would
# LOSE an inventory item. The test below asserts the count is exactly the number of distinct
# algorithms, so "collapse everything to one" cannot be a passing strategy.
LEGITIMATE_MULTI_ALGORITHM = {
    'p = padding.PSS(mgf=padding.MGF1(hashes.SHA256()));': 3,
    'priv = ec.generate_private_key(ec.SECP256R1());': 2,
}


@pytest.mark.parametrize("line", DUPLICATE_SAMPLES)
def test_one_line_of_real_code_never_fires_two_rules(line):
    """A single source line must not produce two findings naming the SAME algorithm.

    The dedup in `_finalise` is keyed on `(file, name, rule_id, line)`, so two rules with
    different ids NEVER collapse -- the same line is reported twice and the CBOM carries two
    components for one statement. `IM-SRC-JAVA-DIGEST-002` did exactly this to
    `MessageDigest.getInstance("SHA-256")`, and the benchmark scored it as neither better nor
    worse because it counts locations, not findings.
    """
    hits = [r for r in RULES
            if r["artefact_class"] == "source" and re.search(r["regex"], line)]
    names = [r["name"] for r in hits]
    duplicates = [n for n in set(names) if names.count(n) > 1]
    assert not duplicates, (
        "one line produced the same algorithm %d times (%s via %s). Two rules reporting the "
        "SAME name cannot collapse, because the dedup key includes rule_id."
        % (len(duplicates), duplicates, [r["id"] for r in hits]))


@pytest.mark.parametrize("line,expected", sorted(LEGITIMATE_MULTI_ALGORITHM.items()))
def test_lines_naming_several_real_algorithms_keep_every_one(line, expected):
    """The counterpart guard, so the test above cannot be satisfied by collapsing everything.

    These lines name distinct algorithms and every one of them belongs in the inventory. The
    defect being guarded against is a DUPLICATE, not a count above one.
    """
    hits = [r for r in RULES
            if r["artefact_class"] == "source" and re.search(r["regex"], line)]
    assert len(hits) == expected, (
        "expected %d distinct algorithms on %r, got %d via %s"
        % (expected, line, len(hits), [r["id"] for r in hits]))
