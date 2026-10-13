"""
Tests for the post-migration verifier (`engine/verify_migration.py`), which closes Phase-1
gap G13.

The test that matters most here is `test_a_kyber_draft_marker_is_never_reported_as_ml_kem`.
Phase-1 gap H6 and docs/CODE_REVIEW.md H6 both record a previous revision calling a
pre-standardisation name a post-standardisation one. PQC standards handle
this by treating "pure ML-KEM + deprecated Kyber" as SEPARATE codepoints and badging maturity
`final` vs `draft`; we do the same statically. If that distinction collapses, this module will
tell a team their migration landed when it did not.

Also covered: per-algorithm status, hybrid semantics ("both halves must be broken"), the CLI
exit codes, and the honesty boundary -- a marker proves PRESENCE, not negotiated use.
"""
import os
import re

import pytest

from engine.verify_migration import (ALGO_FN_DSA, ALGO_ML_DSA, ALGO_ML_KEM, ALGO_SLH_DSA,
                                     DEPRECATED_MARKERS, EXIT_INCONCLUSIVE, EXIT_NOT_VERIFIED,
                                     EXIT_VERIFIED, HYBRID_GROUPS, HYBRID_SEMANTICS, NOT_PROVEN,
                                     PQC_ALGORITHMS, STATUS_ABSENT, STATUS_DEPRECATED_VARIANT,
                                     STATUS_PRESENT, STANDARD_MARKERS, VERDICT_INCONCLUSIVE,
                                     VERDICT_NOT_VERIFIED, VERDICT_VERIFIED, MigrationVerifier,
                                     analyse_text, extract_printable_strings, verify_migration,
                                     verify_migration_text)


# ======================================================================== the H6 distinction

def test_a_kyber_draft_marker_is_never_reported_as_ml_kem():
    """THE test. Kyber-768 is the pre-FIPS-203 draft; ML-KEM-768 is the standard.

    Three assertions, because there are three ways to get this wrong: reporting the ALGORITHM as
    present, reporting the VARIANT as present, and exiting 0.
    """
    report = verify_migration_text("we negotiated Kyber768 with the peer")
    kem = report["algorithms"][ALGO_ML_KEM]
    assert kem["status"] == STATUS_DEPRECATED_VARIANT
    assert kem["status"] != STATUS_PRESENT
    assert report["exit_code"] == EXIT_NOT_VERIFIED
    assert report["verified"] is False


@pytest.mark.parametrize("marker", [
    "Kyber512", "Kyber768", "Kyber1024", "kyber-768", "KYBER768",
    "kyber_r3", "kyber-round3", "KyberDraft", "kyber draft",
    "X25519Kyber768", "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00",
    "X25519Kyber512Draft00",
])
def test_no_kyber_spelling_is_ever_ml_kem(marker):
    """Every spelling a real codebase might contain, including the OBSOLETE IANA hybrid codepoint
    names 25497/25498, must land on `deprecated-variant` -- never on `present`."""
    report = verify_migration_text(f"supported_groups: {marker}")
    assert report["algorithms"][ALGO_ML_KEM]["status"] == STATUS_DEPRECATED_VARIANT, marker
    assert report["exit_code"] == EXIT_NOT_VERIFIED, marker


def test_the_obsolete_iana_codepoint_names_cite_the_registry():
    """The two obsolete IANA entries are marked D/OBSOLETE with the note 'Pre-standards version of
    Kyber768. Obsoleted by RFC 10024.' The report must CARRY that citation, because the reader's
    first question is 'who says so?'."""
    report = verify_migration_text("X25519Kyber768Draft00")
    hits = report["deprecated_variants"]
    assert len(hits) == 1
    reason = hits[0]["reason"]
    assert "25497" in reason and "OBSOLETE" in reason
    assert "RFC 10024" in reason
    assert "not X25519MLKEM768" in reason


@pytest.mark.parametrize("marker,family", [
    ("Dilithium2", ALGO_ML_DSA),
    ("Dilithium3", ALGO_ML_DSA),
    ("Dilithium5", ALGO_ML_DSA),
    ("SPHINCS+", ALGO_SLH_DSA),
    ("sphincs-sha256-128f", ALGO_SLH_DSA),
])
def test_pre_standardisation_signature_names_are_deprecated_too(marker, family):
    """H6 is not only about Kyber. Dilithium is the old name for ML-DSA (FIPS 204) and SPHINCS+
    the old name for SLH-DSA (FIPS 205). A `Dilithium3` is not an ML-DSA-65."""
    report = verify_migration_text(f"signature_algorithms: {marker}")
    assert report["algorithms"][family]["status"] == STATUS_DEPRECATED_VARIANT
    assert report["exit_code"] == EXIT_NOT_VERIFIED

def test_a_standardised_marker_alongside_a_draft_verifies_but_names_the_draft():
    """Shipping BOTH is a cleanup item, not a failed migration. The verdict must be `verified`
    AND the deprecated marker must still be reported -- collapsing it would hide the debt."""
    report = verify_migration_text("groups: X25519MLKEM768 legacy:X25519Kyber768Draft00")
    assert report["exit_code"] == EXIT_VERIFIED
    assert report["algorithms"][ALGO_ML_KEM]["status"] == STATUS_PRESENT
    assert [hit["marker"] for hit in report["deprecated_variants"]] == ["X25519Kyber768Draft00"]
    assert "DEPRECATED" in report["verdict_reason"]


def test_every_deprecated_marker_names_the_family_it_is_a_draft_of():
    """A deprecated marker with no stated family cannot drive the per-algorithm status, so the
    signal would be collected and then dropped."""
    for pattern, family, reason in DEPRECATED_MARKERS:
        assert family in PQC_ALGORITHMS, f"{pattern} -> unknown family {family}"
        assert reason and len(reason) > 40, f"{pattern} needs a real explanation"


def test_no_standard_marker_can_match_a_deprecated_name():
    """A structural guard, complementing the behavioural tests: no STANDARD pattern may match any
    string a DEPRECATED pattern matches. If a future regex edit breaks the span-suppression, this
    fails before the behavioural tests do."""
    probes = ["Kyber768", "kyber-512", "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00",
              "Dilithium3", "SPHINCS+", "sphincs-sha256-128f", "X25519Kyber512Draft00",
              "X25519Kyber768", "kyber_r3", "kyber-round3"]
    for probe in probes:
        assert any(re.search(p, probe, re.IGNORECASE) for p, _f, _r in DEPRECATED_MARKERS), \
            f"{probe} is not recognised as deprecated at all"
        for algo, patterns in STANDARD_MARKERS.items():
            for pattern, _reason in patterns:
                assert not re.search(pattern, probe, re.IGNORECASE), (
                    f"standard pattern for {algo} also matches the deprecated marker {probe!r}")


# ======================================================================== per-algorithm status

@pytest.mark.parametrize("text,algorithm", [
    ("ML-KEM-512", ALGO_ML_KEM),
    ("ML-KEM-768", ALGO_ML_KEM),
    ("ML-KEM-1024", ALGO_ML_KEM),
    ("MLKEM768", ALGO_ML_KEM),
    ("ML-KEM", ALGO_ML_KEM),
    ("ML-DSA-44", ALGO_ML_DSA),
    ("ML-DSA-65", ALGO_ML_DSA),
    ("ML-DSA-87", ALGO_ML_DSA),
    ("MLDSA65", ALGO_ML_DSA),
    ("ML-DSA", ALGO_ML_DSA),
    ("SLH-DSA-SHA2-128s", ALGO_SLH_DSA),
    ("SLH-DSA-SHA2-128f", ALGO_SLH_DSA),
    ("SLH-DSA-SHAKE-256s", ALGO_SLH_DSA),
    ("SLH-DSA", ALGO_SLH_DSA),
    ("FN-DSA-205", ALGO_FN_DSA),
    ("FN-DSA-666", ALGO_FN_DSA),
    ("FN-DSA", ALGO_FN_DSA),
])
def test_each_standardised_family_and_parameter_set_is_recognised(text, algorithm):
    """All four FIPS families, with and without an explicit parameter set. A missing parameter
    set is still the family, so it must verify; an unrecognised one must not."""
    report = verify_migration_text(f"the build links {text}")
    assert report["algorithms"][algorithm]["status"] == STATUS_PRESENT, text
    assert report["exit_code"] == EXIT_VERIFIED, text


def test_an_absent_algorithm_is_reported_absent_not_silently_omitted():
    """The brief requires a per-algorithm status. A report listing only what it DID find leaves
    the reader unable to tell 'no ML-DSA here' from 'we never looked for ML-DSA'."""
    report = verify_migration_text("ML-KEM-768 only")
    assert set(report["algorithms"]) == set(PQC_ALGORITHMS)
    for algorithm in (ALGO_ML_DSA, ALGO_SLH_DSA, ALGO_FN_DSA):
        assert report["algorithms"][algorithm]["status"] == STATUS_ABSENT
        assert report["algorithms"][algorithm]["matches"] == []


def test_nist_oids_are_recognised_for_the_standardised_families():
    """An OID is how a certificate or a compiled key names the algorithm. The NIST CSOR arcs are
    .3.4.4 for ML-KEM and .3.4.3.17/.18/.19 for ML-DSA."""
    assert verify_migration_text("OID 2.16.840.1.101.3.4.4.2")["exit_code"] == EXIT_VERIFIED
    report = verify_migration_text("2.16.840.1.101.3.4.3.18")
    assert report["algorithms"][ALGO_ML_DSA]["status"] == STATUS_PRESENT
    assert report["exit_code"] == EXIT_VERIFIED


# ======================================================================== hybrids

def test_hybrid_reports_both_halves_and_the_and_semantics():
    """X25519MLKEM768 = X25519 + ML-KEM-768, IANA 4588, RFC 10024. The semantics must say BOTH
    halves must be broken -- a hybrid is a hedge, not a half-migration."""
    report = verify_migration_text("groups = X25519MLKEM768")
    assert report["exit_code"] == EXIT_VERIFIED
    hybrid = report["hybrids"][0]
    assert hybrid["name"] == "X25519MLKEM768"
    assert hybrid["classical_half"] == "X25519"
    assert hybrid["pqc_half"] == "ML-KEM-768"
    assert hybrid["iana_codepoint"] == 4588
    assert hybrid["specification"] == "RFC 10024"
    assert hybrid["is_hybrid"] is True
    assert "BOTH halves must be broken" in hybrid["semantics"]
    assert "AND" in hybrid["semantics"]


@pytest.mark.parametrize("name,classical,pqc,codepoint", [
    ("X25519MLKEM768", "X25519", "ML-KEM-768", 4588),
    ("SecP256r1MLKEM768", "P-256", "ML-KEM-768", 4587),
    ("SecP384r1MLKEM1024", "P-384", "ML-KEM-1024", 4589),
])
def test_each_rfc_10024_hybrid_is_recognised(name, classical, pqc, codepoint):
    report = verify_migration_text(f"supported_groups: {name}")
    assert report["exit_code"] == EXIT_VERIFIED
    hybrid = next(h for h in report["hybrids"] if h["name"] == name)
    assert hybrid["classical_half"] == classical
    assert hybrid["pqc_half"] == pqc
    assert hybrid["iana_codepoint"] == codepoint
    # A hybrid implies ML-KEM even when the bare family name never appears in the text.
    assert report["algorithms"][ALGO_ML_KEM]["status"] == STATUS_PRESENT


def test_underscore_and_mixed_case_hybrid_spellings_are_recognised():
    """`p384_mlkem` is the Go/BoringSSL-internal spelling of the SecP384r1+ML-KEM construction,
    and real configurations mix case. A case-sensitive match would miss it and report the
    migration as absent -- a false negative on the whole point of the module."""
    for spelling in ("p384_mlkem", "P384_MLKEM", "X25519MLKEM768", "x25519mlkem768",
                     "secp256r1mlkem768"):
        report = verify_migration_text(f"groups: {spelling}")
        assert report["hybrids"], f"{spelling} was not recognised as a hybrid"
        assert report["exit_code"] == EXIT_VERIFIED, spelling


def test_pure_post_quantum_groups_are_not_labelled_hybrids():
    """MLKEM768 (IANA 513) is PURE post-quantum. Calling it a hybrid would assert a classical
    half it does not have -- a fabricated claim in the opposite direction from the Kyber one."""
    report = verify_migration_text("groups = MLKEM768")
    assert report["exit_code"] == EXIT_VERIFIED
    hybrid = next(h for h in report["hybrids"] if h["name"] == "MLKEM768")
    assert hybrid["is_hybrid"] is False
    assert "pure post-quantum" in hybrid["classical_half"]


def test_an_obsolete_hybrid_codepoint_is_not_reported_as_a_hybrid():
    """`X25519Kyber768Draft00` contains a real KEM name, but it is an OBSOLETE draft group. It
    must not appear in `hybrids` -- that list is the set of constructions that count."""
    report = verify_migration_text("X25519Kyber768Draft00")
    assert report["hybrids"] == []
    assert report["exit_code"] == EXIT_NOT_VERIFIED


def test_hybrid_semantics_are_stated_on_every_reported_hybrid():
    for name in HYBRID_GROUPS:
        report = verify_migration_text(name)
        for hybrid in report["hybrids"]:
            assert hybrid["semantics"] == HYBRID_SEMANTICS
            assert "BOTH" in hybrid["semantics"]


def test_every_hybrid_group_declares_both_halves_and_a_source():
    """A hybrid row missing a half would render as a hybrid that pairs with nothing, and a row
    with no `specification` would be an unexplained claim.

    `iana_codepoint` may legitimately be None: the Go-style underscore spellings name a real
    pairing but have no IANA codepoint of their own, and inventing one would be a fabricated
    citation.
    """
    for name, (classical, pqc, codepoint, spec) in HYBRID_GROUPS.items():
        assert classical and pqc, f"{name} must declare both halves"
        assert spec, f"{name} must cite where the construction is defined"
        if codepoint is not None:
            assert isinstance(codepoint, int) and codepoint > 0, f"{name} codepoint"


# ======================================================================== exit codes

def test_exit_codes_are_the_three_documented_values():
    """CLI-usable contract: 0 verified, 1 not verified, 2 inconclusive. A CI gate branches on
    these numbers, so they are part of the interface, not an implementation detail."""
    assert (EXIT_VERIFIED, EXIT_NOT_VERIFIED, EXIT_INCONCLUSIVE) == (0, 1, 2)
    assert (VERDICT_VERIFIED, VERDICT_NOT_VERIFIED, VERDICT_INCONCLUSIVE) == (
        "verified", "not-verified", "inconclusive")


def test_verified_artefact_exits_zero(tmp_path):
    path = tmp_path / "tls_config.c"
    path.write_text("#define GROUP X25519MLKEM768\n", encoding="utf-8")
    assert verify_migration(str(path))["exit_code"] == EXIT_VERIFIED


def test_unmigrated_artefact_exits_one(tmp_path):
    path = tmp_path / "tls_config.c"
    path.write_text("#define GROUP X25519\n", encoding="utf-8")
    report = verify_migration(str(path))
    assert report["exit_code"] == EXIT_NOT_VERIFIED
    assert report["verified"] is False


def test_nothing_examinable_is_inconclusive_not_not_verified(tmp_path):
    """THE honesty case for this module. An empty directory tells us NOTHING about the migration.

    Reporting exit 1 there would tell a team "you have not migrated" when the truth is "we could
    not look", and a team that trusts that will open the wrong work item.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    report = verify_migration(str(empty))
    assert report["exit_code"] == EXIT_INCONCLUSIVE
    assert report["verdict"] == VERDICT_INCONCLUSIVE
    assert report["verified"] is False
    assert report["files_examined"] == 0
    reason = report["verdict_reason"].lower()
    assert "nothing could be examined" in reason
    assert "not a statement about the migration" in reason, (
        "the verdict must disclaim being a statement about the migration at all")


def test_a_missing_path_is_inconclusive_and_named(tmp_path):
    report = verify_migration(str(tmp_path / "no-such-artefact"))
    assert report["exit_code"] == EXIT_INCONCLUSIVE
    assert report["errors"], "the failure must be named, not silently produce an empty verdict"
    assert "does not exist" in report["errors"][0]["reason"]


def test_an_empty_file_is_inconclusive(tmp_path):
    """A zero-byte artefact was not read, so it cannot support a `not-verified` verdict."""
    path = tmp_path / "empty.so"
    path.write_bytes(b"")
    report = verify_migration(str(path))
    assert report["exit_code"] == EXIT_INCONCLUSIVE
    assert report["files_examined"] == 0


def test_an_oversized_artefact_is_refused_and_the_rest_of_the_tree_still_scanned(tmp_path):
    """The read cap is a memory guard. It must not silently reduce the scan to nothing."""
    big = tmp_path / "huge.bin"
    big.write_bytes(b"X25519MLKEM768" + b"\x00" * 4096)
    good = tmp_path / "app.c"
    good.write_text("/* X25519MLKEM768 */\n", encoding="utf-8")
    cap = len(good.read_bytes()) + 1          # big.bin is far over it; app.c is under it
    report = MigrationVerifier(max_bytes=cap).verify(str(tmp_path))
    assert report["exit_code"] == EXIT_VERIFIED, "the small file must still be examined"
    assert report["files_examined"] == 1
    assert any("read cap" in err["reason"] for err in report["errors"]), "the refusal is named"


# ======================================================================== honesty about the evidence

def test_the_report_states_what_it_does_not_prove():
    """A verifier that says "migration verified" and stops is over-claiming. The report must
    carry its own limits -- in particular that a marker proves PRESENCE, not negotiated use."""
    report = verify_migration_text("X25519MLKEM768")
    assert report["not_proven"] == NOT_PROVEN
    joined = " ".join(report["not_proven"]).lower()
    assert "executed" in joined, "presence is not execution"
    assert "negotiated" in joined, "presence is not the negotiated group"
    assert "fingerprinting" in joined, "the Kestrel method is named as NOT implemented here"
    assert report["evidence_class"] == "observed"
    assert "stronger than a dependency-manifest capability" in report["evidence_note"]


def test_no_verdict_ever_claims_the_algorithm_was_negotiated():
    """Regression guard on language. A verdict that said 'negotiated ML-KEM' would be a
    capability-vs-observation conflation in the one place it does real damage."""
    for text in ("X25519MLKEM768", "ML-KEM-768", "Kyber768", "nothing"):
        report = verify_migration_text(text)
        blob = (report["verdict_reason"] + " " + report["evidence_note"]).lower()
        assert "negotiated ml-kem" not in blob


def test_a_deprecated_only_artefact_names_the_draft_in_the_verdict():
    """The single most useful sentence this tool can produce for a Kyber-only user."""
    reason = verify_migration_text("Kyber768 everywhere")["verdict_reason"]
    assert "Kyber768" in reason
    assert "ML-KEM" in reason
    assert "NOT ML-KEM-768" in reason or "not ML-KEM-768" in reason


def test_other_pqc_drafts_are_reported_without_being_counted():
    """NTRU Prime is a real post-quantum KEX draft shipped by OpenSSH, and it is NOT one of the
    four FIPS algorithms. It must be surfaced, and it must not verify the migration."""
    report = verify_migration_text("kex: sntrup761x25519-sha512@openssh.com")
    assert report["exit_code"] == EXIT_NOT_VERIFIED
    assert report["other_pqc_drafts"], "the draft must still be surfaced to the operator"
    assert "NTRU Prime" in report["other_pqc_drafts"][0]["reason"]


def test_the_final_openssh_mlkem_kex_name_is_recognised():
    """OpenSSH 10.0+ names the final hybrid `mlkem768x25519-sha256`. That IS ML-KEM evidence."""
    report = verify_migration_text("kex_algorithms: mlkem768x25519-sha256")
    assert report["exit_code"] == EXIT_VERIFIED
    assert report["algorithms"][ALGO_ML_KEM]["status"] == STATUS_PRESENT
    assert report["ssh_kex"]


# ======================================================================== the pure function

def test_analyse_text_is_pure_and_needs_no_filesystem():
    """Separating the classifier from the walker is what makes the H6 distinction directly
    testable, and it keeps the filesystem policy in one place."""
    result = analyse_text("X25519MLKEM768", source="<inline>")
    assert result["algorithms"][ALGO_ML_KEM]["status"] == STATUS_PRESENT
    assert result["hybrids"][0]["file"] == "<inline>"


def test_evidence_carries_a_line_number():
    """An operator has to be able to go and look at the line. A finding with no location is a
    claim they cannot check."""
    text = "line one\nline two\nsupported_groups = X25519MLKEM768\n"
    assert analyse_text(text, source="c.c")["hybrids"][0]["line"] == 3


def test_repeated_markers_are_reported_once():
    """A binary with 200 references to ML-KEM-768 must not produce 200 findings; the count would
    measure the string table, not the migration.

    It must also produce ONE match, not two: the family-only `ML-KEM` pattern would otherwise
    re-report the same text nested inside `ML-KEM-768`, inflating every count in the report.
    """
    report = verify_migration_text("ML-KEM-768 " * 200)
    assert len(report["algorithms"][ALGO_ML_KEM]["matches"]) == 1
    assert report["algorithms"][ALGO_ML_KEM]["matches"][0]["marker"] == "ML-KEM-768"


def test_extract_printable_strings_finds_a_marker_in_a_binary(tmp_path):
    """A PQC symbol lives in a .so's string table, not in a source file. The printable-string
    path is what makes binary verification work at all."""
    blob = b"\x00\x01\x02" + b"X25519MLKEM768" + b"\x00" * 8 + b"libcrypto.so.3"
    assert any("X25519MLKEM768" in s for s in extract_printable_strings(blob))
    path = tmp_path / "libssl.so"
    path.write_bytes(blob)
    assert verify_migration(str(path))["exit_code"] == EXIT_VERIFIED


# ======================================================================== filesystem policy

def test_a_credential_store_is_never_read_and_is_named(tmp_path):
    """`.env` is on fspolicy's credential-store list. This module reads files looking for
    algorithm names; it has no reason to read one that holds secrets."""
    (tmp_path / ".env").write_text("ML-KEM-768=not-really\n", encoding="utf-8")
    (tmp_path / "app.c").write_text("/* nothing */\n", encoding="utf-8")
    report = verify_migration(str(tmp_path))
    assert any("credential store" in err["reason"] for err in report["errors"])
    assert report["algorithms"][ALGO_ML_KEM]["status"] == STATUS_ABSENT, (
        "a credential store must not contribute evidence")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_symlink_escape_is_not_followed_and_is_named(tmp_path):
    """Same containment guarantee as the other two sensors: a symlink out of the root is never
    read, and the refusal is reported rather than silently skipped."""
    outside = tmp_path.parent / "outside_pqc_blob_for_test.bin"
    outside.write_bytes(b"\x00X25519MLKEM768\x00")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(str(outside), str(root / "linked.so"))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted here")
    try:
        report = verify_migration(str(root))
        assert report["exit_code"] == EXIT_INCONCLUSIVE, "the escape must not be read"
        assert any("escapes the scan root" in err["reason"] for err in report["errors"])
    finally:
        outside.unlink()


def test_a_directory_scan_finds_a_marker_in_any_file(tmp_path):
    """The tree walk must not be limited to particular extensions: a `.txt` or a lockfile is as
    likely to name a group as a `.c` is."""
    for name in ("a.c", "b.txt", "c.yaml", "d"):
        (tmp_path / name).write_text("X25519MLKEM768\n", encoding="utf-8")
    report = verify_migration(str(tmp_path))
    assert report["files_examined"] == 4
    assert report["exit_code"] == EXIT_VERIFIED


# ======================================================================== the CLI entry point

def test_the_cli_subcommands_are_wired_and_return_the_exit_codes(tmp_path, capsys):
    """`cli_advanced.py` is a separate entry point precisely so `cli.py` need not change. This
    asserts both subcommands run and that verify-migration's return value IS the verdict, which
    is what makes `verify-migration && deploy` a usable CI gate."""
    import cli_advanced

    good = tmp_path / "migrated.c"
    good.write_text("X25519MLKEM768\n", encoding="utf-8")
    assert cli_advanced.main(["verify-migration", str(good), "--out", str(tmp_path)]) == 0

    bad = tmp_path / "legacy.c"
    bad.write_text("X25519Kyber768Draft00\n", encoding="utf-8")
    assert cli_advanced.main(["verify-migration", str(bad), "--out", str(tmp_path)]) == 1

    assert cli_advanced.main(["verify-migration", str(tmp_path / "nope"),
                              "--out", str(tmp_path)]) == 2
    assert cli_advanced.main(["deps", str(tmp_path), "--out", str(tmp_path)]) == 0
    capsys.readouterr()


def test_the_deps_cli_names_unreadable_manifests_on_stdout(tmp_path, capsys):
    """The `cryptodeps` pattern: an unreadable manifest is NAMED in the operator's output, not
    only in a JSON field nobody reads."""
    import cli_advanced

    (tmp_path / "package.json").write_text("{ not json", encoding="utf-8")
    cli_advanced.main(["deps", str(tmp_path), "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert "NOT read" in out
    assert "invalid JSON" in out


def test_a_deps_cli_run_emits_assurance_caveat_text(tmp_path, capsys):
    """The word "findings" without the assurance level reads as breaches. The CLI must print it."""
    import cli_advanced

    (tmp_path / "requirements.txt").write_text("pycryptodome\n", encoding="utf-8")
    cli_advanced.main(["deps", str(tmp_path), "--out", str(tmp_path)])
    out = capsys.readouterr().out.lower()
    assert "capability" in out
    assert "proves a call site" in out, "the caveat must say what a finding does NOT prove"
