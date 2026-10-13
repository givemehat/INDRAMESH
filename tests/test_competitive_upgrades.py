"""Regression tests for the core architecture upgrades.

Three groups:

  * DECOYS  -- adversarial fixtures that must NOT produce findings. Precision is only
    meaningful if it is measured against material designed to trigger a false positive.
  * PURPOSE -- a target is refused when the evidence does not settle the purpose.
  * ASSURANCE -- what the evidence proves, kept separate from confidence.

Run: python -m pytest tests/test_competitive_upgrades.py -v
"""
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.purpose import (ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED,
                            ASSURANCE_USED, PURPOSE_KEY_ESTABLISHMENT, PURPOSE_SIGNATURE,
                            PURPOSE_UNRESOLVED, assurance_histogram, proven_use_count,
                            resolve_assurance, resolve_purpose, unresolved_purpose_count)
from engine.recommender import get_pqc_recommendation
from engine.scanner import IndraMeshScanner

DECOY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "decoys")


def _scan_isolated(name, tmp_path):
    """Copy ONE fixture into an empty directory and scan that.

    Isolation matters: scanning the whole decoys/ directory would let one file's findings mask
    another's, which is exactly the kind of sloppy measurement this suite exists to prevent.
    """
    import shutil
    dst = tmp_path / "subject"
    dst.mkdir()
    shutil.copy(os.path.join(DECOY_DIR, name), dst / name)
    scanner = IndraMeshScanner(enable_ml=False)     # hermetic: regex rules only, no torch
    return scanner.scan_directory(str(dst))


# ===========================================================================================
# Rank 1 -- adversarial decoys
# ===========================================================================================

#: Lines in decoy_source.py that are PROSE. A finding attributed to any of these is a false
#: positive, because a comment or docstring is not a call.
PROSE_LINES = range(1, 53)


def test_decoy_python_prose_yields_no_findings(tmp_path):
    """Algorithm names in comments and docstrings must not be reported as uses.

    decoy_source.py is 90% prose: algorithm names appear only in comments, docstrings and plain
    string constants. The tail of the file (from line 53) contains REAL calls and is allowed to
    produce findings, so this test asserts specifically about the prose region rather than
    demanding a blanket zero -- which would be a false claim, not a strict one.
    """
    findings = _scan_isolated("decoy_source.py", tmp_path)
    prose_findings = [f for f in findings if (f.get("line") or 0) in PROSE_LINES]
    assert prose_findings == [], (
        "algorithm names in comments/docstrings must not produce findings; got: "
        + repr([(f.get("name"), f.get("rule_id"), f.get("line")) for f in prose_findings])
    )


def test_decoy_python_real_calls_are_still_detected(tmp_path):
    """The converse control: comment stripping must not become over-aggressive.

    `hashlib.sha256(...)` at line 59 and `hashlib.md5(...)` at line 63 are genuine invocations.
    A fix that blanks too much would silently lose real detections, which is the more dangerous
    failure mode because it looks like a clean scan.
    """
    findings = _scan_isolated("decoy_source.py", tmp_path)
    names = {f["name"] for f in findings}
    assert "SHA256" in names, "a real hashlib.sha256() call must still be detected"
    assert "MD5" in names, "a real hashlib.md5() call must still be detected"


def test_comment_stripping_preserves_line_numbers(tmp_path):
    """Blanking comments must preserve byte offsets, or every reported line number shifts.

    This is the failure mode of the obvious implementation (`.replace` the comment with nothing),
    and it would silently corrupt every location we report.
    """
    src = (
        "import os\n"
        "// a comment mentioning RSA and AES-256 that is quite long indeed\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "d = hashes.Hash(hashes.SHA256())\n"
    )
    d = tmp_path / "src"
    d.mkdir()
    (d / "x.py").write_text(src, encoding="utf-8")
    findings = IndraMeshScanner(enable_ml=False).scan_directory(str(d))
    hits = [f for f in findings if f["name"] == "SHA256"]
    assert hits, "SHA-256 call must be found"
    assert hits[0]["line"] == 4, (
        f"line number shifted by comment stripping: reported {hits[0]['line']}, expected 4")


def test_decoy_java_yields_no_findings(tmp_path):
    """Algorithm names in a Javadoc block are mentions, not uses.

    This test failed before comment stripping was added: `IM-SRC-RSA-003` matched
    `KeyPairGenerator.getInstance("RSA")` inside the Javadoc on line 3 and reported an RSA finding
    for a file that never uses RSA.
    """
    findings = _scan_isolated("Decoy.java", tmp_path)
    assert findings == [], (
        "Decoy.java must yield zero findings; got: "
        + repr([(f.get("name"), f.get("rule_id"), f.get("line")) for f in findings])
    )


def test_decoy_nginx_prose_does_not_invent_algorithm_findings(tmp_path):
    """decoy_nginx.conf is a POSITIVE control for config scanning, but the prose comment naming
    ECDHE-RSA must not produce an algorithm finding of its own."""
    findings = _scan_isolated("decoy_nginx.conf", tmp_path)
    assert findings, "decoy_nginx.conf is a positive control and must yield a config finding"
    for f in findings:
        # Any finding must come from the ssl_ directives, not line 3 (the prose comment).
        assert f.get("line", 0) > 3, f"finding attributed to the prose comment: {f}"


def test_decoy_fixtures_are_present_and_non_trivial():
    """Guard against the decoys being accidentally emptied, which would make the tests vacuous."""
    src = open(os.path.join(DECOY_DIR, "decoy_source.py"), encoding="utf-8").read()
    for token in ("RSA", "AES-256", "ECDSA", "SHA-1", "TLS_RSA_WITH_AES_128_GCM_SHA256"):
        assert token in src, f"decoy fixture lost its decoy token {token!r}; test is now vacuous"
    java = open(os.path.join(DECOY_DIR, "Decoy.java"), encoding="utf-8").read()
    assert "RSA" in java and "ECDSA" in java




# ===========================================================================================
# Rank 3 / item C2 -- purpose resolution, and the refusal to guess
# ===========================================================================================
def test_rsa_pss_call_site_resolves_to_signature():
    purpose, signals, reason = resolve_purpose(
        dict(name="RSA", primitive="pke", uses="signing", match="padding.PSS"))
    assert purpose == PURPOSE_SIGNATURE
    assert signals and reason


def test_rsa_oaep_call_site_resolves_to_key_establishment():
    purpose, _, _ = resolve_purpose(
        dict(name="RSA", primitive="pke", match="Cipher.getInstance(\"RSA/ECB/OAEP\")"))
    assert purpose == PURPOSE_KEY_ESTABLISHMENT


def test_certificate_keyusage_resolves_purpose():
    sig, _, _ = resolve_purpose(dict(name="RSA", key_usage=["digitalSignature", "keyCertSign"]))
    assert sig == PURPOSE_SIGNATURE
    ke, _, _ = resolve_purpose(dict(name="RSA", key_usage=["keyEncipherment"]))
    assert ke == PURPOSE_KEY_ESTABLISHMENT


def test_dual_use_key_usage_is_unresolved():
    """The hard case: a KeyUsage that spans both purposes resolves to nothing, on purpose."""
    purpose, signals, reason = resolve_purpose(
        dict(name="RSA", key_usage=["digitalSignature", "keyEncipherment"]))
    assert purpose == PURPOSE_UNRESOLVED
    assert "KeyUsage" in " ".join(signals)
    assert "both purposes" in reason


def test_key_generation_only_signal_is_unresolved():
    """KeyPairGenerator.getInstance("RSA") proves the primitive is reachable, not its purpose.

    This is the rule-003 pattern our own scanner emits, and it must not resolve to a target.
    """
    purpose, signals, _ = resolve_purpose(
        dict(name="RSA", primitive="pke", match="KeyPairGenerator.getInstance(\"RSA\")"))
    assert purpose == PURPOSE_UNRESOLVED
    assert any("keypairgenerator" in s for s in signals)


def test_unresolved_purpose_refuses_to_name_a_pqc_target():
    """The headline behaviour: no ML-KEM, no ML-DSA, and say what would resolve it."""
    rec = get_pqc_recommendation(
        dict(name="RSA", primitive="pke", match="KeyPairGenerator.getInstance(\"RSA\")"))
    assert "ML-KEM" not in rec["algorithm"]
    assert "ML-DSA" not in rec["algorithm"]
    assert rec["algorithm"].lower().startswith("unresolved")
    assert "RESOLVE" in rec["justification"].upper()
    assert rec["rule_trace"].startswith("RULE-PURPOSE-UNRESOLVED")


def test_resolved_purpose_still_names_the_right_target():
    """The guard must not over-fire: a real signature call site still gets ML-DSA."""
    sig = get_pqc_recommendation(
        dict(name="RSA", primitive="signature", match="padding.PSS"))
    assert "ML-DSA" in sig["algorithm"]
    # A bare pke finding with no purpose signal falls through to the primitive branch.
    transport = get_pqc_recommendation(dict(name="RSA", primitive="pke"))
    assert "ML-KEM" in transport["algorithm"]


# ===========================================================================================
# Rank 2 / item C1 -- assurance: what the evidence proves
# ===========================================================================================
def test_evidence_class_maps_to_assurance():
    assert resolve_assurance(dict(evidence_class="discovered"))[0] == ASSURANCE_USED
    assert resolve_assurance(dict(evidence_class="configured"))[0] == ASSURANCE_DECLARED
    assert resolve_assurance(dict(evidence_class="negotiated"))[0] == ASSURANCE_OBSERVED
    assert resolve_assurance(dict(evidence_class="dependency"))[0] == ASSURANCE_CAPABILITY


def test_assurance_is_distinct_from_confidence():
    """A capability finding can be a CERTAIN identification that proves very little -- which is
    the whole point of separating the two axes."""
    f = dict(name="RSA", confidence=0.99, evidence_class="dependency")
    level, reason = resolve_assurance(f)
    assert level == ASSURANCE_CAPABILITY
    assert f["confidence"] == 0.99, "assurance must not overwrite confidence"
    assert "reachable" in reason.lower()


def test_proven_use_count_excludes_capabilities():
    findings = [
        dict(evidence_class="discovered"),
        dict(evidence_class="configured"),
        dict(evidence_class="dependency"),
        dict(evidence_class="negotiated"),
    ]
    assert proven_use_count(findings) == 2
    hist = assurance_histogram(findings)
    assert hist[ASSURANCE_USED] == 1
    assert hist[ASSURANCE_OBSERVED] == 1
    assert hist[ASSURANCE_CAPABILITY] == 1
    assert hist[ASSURANCE_DECLARED] == 1


def test_unknown_evidence_class_is_treated_as_capability_not_proven_use():
    """Fail safe: an unrecognised evidence class must not inflate the proven-use count."""
    assert resolve_assurance(dict(evidence_class="something-new"))[0] == ASSURANCE_CAPABILITY
    assert proven_use_count([dict(evidence_class="something-new")]) == 0


def test_unresolved_purpose_count_ignores_hashes_and_symmetric():
    """A hash has no purpose ambiguity worth a human's time; counting it would be noise."""
    findings = [
        dict(name="RSA", primitive="pke", match="rsa.newkeys(2048)"),
        dict(name="RSA", primitive="pke", match="rsa.newkeys(2048)"),
        dict(name="SHA256", primitive="hash", match="hashlib.sha256(x)"),
        dict(name="AES", primitive="ae", key_length=256),
    ]
    assert unresolved_purpose_count(findings) == 2


# ===========================================================================================
# Export: assurance and purpose must reach the CBOM, or the model is invisible to consumers
# ===========================================================================================
def test_cbom_exports_assurance_and_purpose():
    import json as _json
    from engine.cbom import generate_cbom as _gen
    finding = dict(name="RSA", primitive="pke", key_length=2048, file="a.py", line=3,
                   evidence_class="discovered", match="KeyPairGenerator.getInstance(\"RSA\")")
    cbom = _json.loads(_gen([finding]))
    props = {p["name"]: p["value"] for p in cbom["components"][0]["properties"]}
    assert props["im:assurance"] == "used"
    assert "strongest claim" in props["im:assurance_meaning"]
    assert props["im:purpose"] == "unresolved"
    assert "keypairgenerator" in props["im:purpose_signals"]


def test_cbom_publishes_proven_use_alongside_the_raw_total():
    """The raw total is meaningless without the proven-use count beside it."""
    import json as _json
    from engine.cbom import generate_cbom as _gen
    findings = [
        dict(name="RSA", primitive="signature", evidence_class="discovered"),
        dict(name="AES", primitive="ae", key_length=256, evidence_class="discovered"),
        dict(name="libcrypto", primitive="cryptographic-library", type="library",
             evidence_class="capability"),
    ]
    coverage = dict(
        files_scanned=3, files_skipped=0, ml_reason="disabled", never_in_scope=[],
        findings_total=3, proven_use=2,
        assurance_histogram={"used": 2, "observed": 0, "declared": 0, "capability": 1},
        unresolved_purpose=0)
    cbom = _json.loads(_gen(findings, coverage=coverage))
    props = {p["name"]: p["value"] for p in cbom["metadata"]["properties"]}
    assert props["im:findings_total"] == "3"
    assert props["im:proven_use"] == "2"
    assert "capability" in props["im:assurance_histogram"]


