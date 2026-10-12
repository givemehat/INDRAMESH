"""End-to-end pipeline test: scan -> Mosca -> recommendation -> CycloneDX CBOM.

Exercises the full path the brief describes, without requiring PyTorch (regex-only mode) so it
runs anywhere the test suite runs.
"""
import json

from engine.scanner import IndraMeshScanner
from engine.mosca import calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom, SPEC_VERSION

RSA_SNIPPET = "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n"
# A real key-agreement call site, not a bare key-pair generator. `ec.generate_private_key()`
# alone establishes neither a signature nor key agreement, and typing it as ECDH made this same
# snippet report as ECDH AND ECDSA -- two mutually exclusive primitives, two different migration
# targets, for one statement. The `.exchange()` is what makes the primitive ECDH.
ECDH_SNIPPET = (
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "priv = ec.generate_private_key(ec.SECP256R1())\n"
    "shared = priv.exchange(peer_public_key)\n"
)


def _pipeline(target, z=10, policy="india_dst_nqm"):
    scanner = IndraMeshScanner(enable_ml=False)
    findings = scanner.scan_directory(target)
    enriched = []
    for f in findings:
        f["risk"] = calculate_risk(f, z_collapse_time=z, policy=policy)
        f["recommendation"] = get_pqc_recommendation(f)
        enriched.append(f)
    # NOTE: findings MUST be passed. `coverage_manifest()` with no argument silently omits
    # findings_total / proven_use / the assurance histogram -- and because the document is still
    # schema-valid, nobody notices the honesty fields have vanished. That is precisely why the
    # integration test below asserts on them.
    cbom = generate_cbom(enriched, enriched=True, subject_name="integration-target",
                         coverage=scanner.coverage_manifest(enriched))
    return scanner, enriched, json.loads(cbom)


def test_full_pipeline_integration(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    (d / "kex.py").write_text(ECDH_SNIPPET, encoding="utf-8")

    scanner, findings, cbom = _pipeline(str(d))

    assert findings, "scanner found nothing"
    assert any(f["name"] == "RSA" for f in findings)
    assert any(f["name"] == "ECDH" for f in findings), "ECC detection is the brief's demo target"

    for f in findings:
        assert f["risk"]["tier"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f["recommendation"]["algorithm"]
        assert f["recommendation"]["rule_trace"]

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == SPEC_VERSION
    assert cbom["components"]
    assert scanner.coverage_manifest()["files_scanned"] >= 2


def test_data_lifetime_drives_the_verdict(tmp_path):
    """The brief requires classification by type, lifetime and criticality. Two identical RSA
    artefacts under different retention obligations must not receive the same verdict."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")

    scanner = IndraMeshScanner(enable_ml=False)
    base = scanner.scan_directory(str(d))
    rsa = [f for f in base if f["name"] == "RSA"][0]

    short = calculate_risk({**rsa, "data_class": "session", "artefact_class": "config"})
    long = calculate_risk({**rsa, "data_class": "statutory-archive", "artefact_class": "source"})

    assert short["tier"] != long["tier"]
    assert long["tier"] == "CRITICAL"
    assert long["hndl_exposed"] is True
    assert short["hndl_exposed"] is False


def test_z_is_tunable_end_to_end(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")

    _scanner, _findings, cbom = _pipeline(str(d), z=15, policy="nist_ir_8547")
    mosca_props = {p["name"]: p["value"] for c in cbom["components"] for p in c["properties"]}
    assert "im:mosca.z" in mosca_props
    assert mosca_props["im:mosca.z"] == "15.0"
    assert mosca_props["im:mosca.policy"] == "nist_ir_8547"
    # RSA is a 112-bit primitive, so IR 8547 puts it in the DEPRECATED tier with a 2030 date,
    # not the 2035 disallowance that applies to the >= 128-bit tier. Assert the status as well
    # as the year: a bare year cannot distinguish a deprecation from a ban, and that
    # distinction is the whole reason `resolve_policy_deadline` exists.
    assert mosca_props["im:mosca.policy_deadline"] == "2030"
    assert mosca_props["im:mosca.policy_status"] == "deprecated"
    assert mosca_props["im:mosca.policy_source_is_draft"] == "true"


# ===========================================================================================
# The seams between modules. Each unit is tested in isolation elsewhere; what breaks HERE and
# nowhere else is the wiring -- a field one module emits that the next one silently ignores.
# ===========================================================================================
def test_assurance_and_purpose_reach_the_cbom_end_to_end(tmp_path):
    """A consumer must be able to tell a proven call site from a capability, and to see when no
    PQC target could be named.

    This is the seam that matters most: the scanner emits `evidence_class`, the purpose model
    consumes it, the emitter writes it. If any link drops, the document still validates and
    nobody notices -- it just quietly stops being honest.
    """
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")

    _scanner, _findings, cbom = _pipeline(str(d))
    props = {p["name"]: p["value"] for c in cbom["components"] for p in c["properties"]}
    assert props.get("im:assurance"), "assurance must reach the CBOM"
    assert props.get("im:purpose"), "purpose must reach the CBOM"
    meta = {p["name"]: p["value"] for p in cbom["metadata"].get("properties", [])}
    assert "im:findings_total" in meta and "im:proven_use" in meta, (
        "the raw total must never appear without the proven-use count beside it")


def test_unresolved_purpose_survives_the_whole_pipeline(tmp_path):
    """A finding whose purpose cannot be resolved must reach the CBOM still marked unresolved.

    Key generation alone settles nothing, so `rsa.generate_private_key` produces a finding with
    no settled purpose. The risk is that some stage in between quietly resolves it to a default
    and names a target. Asserting across the whole pipeline is the only way to catch that.
    """
    d = tmp_path / "app"
    d.mkdir()
    (d / "keygen.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8")

    _scanner, findings, cbom = _pipeline(str(d))
    unresolved = [f for f in findings
                  if f["recommendation"]["rule_trace"].startswith("RULE-PURPOSE-UNRESOLVED")]
    assert unresolved, "key generation alone must not settle purpose"
    for f in unresolved:
        rec = f["recommendation"]
        assert "ML-KEM" not in rec["algorithm"] and "ML-DSA" not in rec["algorithm"]
        assert rec["cost_band"] == "UNKNOWN", "cost is unknown when no target is named"
        assert "RESOLVE" in rec["justification"].upper(), (
            "an unresolved finding must say what evidence would resolve it")
    props = [p for c in cbom["components"] for p in c["properties"]
             if p["name"] == "im:purpose"]
    assert props, "the unresolved purpose must be visible in the CBOM, not just the console"


def test_coverage_manifest_numbers_add_up_end_to_end(tmp_path):
    """files_seen must equal files_scanned + files_skipped.

    A manifest that does not add up is the one artefact whose entire purpose is to be believed.
    Unit tests cover the accounting; this asserts it survives a real walk with in-scope,
    out-of-scope and unreadable files present at once.
    """
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "a.py").write_text(RSA_SNIPPET, encoding="utf-8")                       # in scope
    (d / "b.conf").write_text("ssl_ciphers HIGH:!aNULL;\n", encoding="utf-8")   # in scope
    (d / "notes.rst").write_text("just prose\n", encoding="utf-8")               # out of scope
    (d / "blob.bin").write_bytes(b"\x00\x01\x02" * 50)                            # binary
    (d / "bad.py").write_bytes(b"\xff\xfe\x00\x00not utf8")                       # unreadable

    scanner = IndraMeshScanner(enable_ml=False)
    findings = scanner.scan_directory(str(d))
    manifest = scanner.coverage_manifest(findings)

    seen = manifest["files_seen"]
    accounted = manifest["files_scanned"] + manifest["files_skipped"]
    assert seen == accounted, (
        f"coverage does not add up: seen={seen} scanned={manifest['files_scanned']} "
        f"skipped={manifest['files_skipped']}. An unaccounted file is a silent gap.")
    assert manifest["errors"], "the undecodable file must be named, not silently dropped"


def test_every_finding_gets_a_risk_and_a_recommendation_with_a_trace(tmp_path):
    """No finding may reach the report without both, whatever its shape.

    The weakest finding is the one nobody looks at, so an absent recommendation on a
    low-severity artefact is exactly where a silent gap would hide.
    """
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    (d / "aes.c").write_text("EVP_aes_128_gcm();\n", encoding="utf-8")
    (d / "sha1.py").write_text("hashlib.sha1(b'x')\n", encoding="utf-8")
    (d / "tls.conf").write_text("ssl_protocols TLSv1;\n", encoding="utf-8")

    _scanner, findings, _cbom = _pipeline(str(d))
    assert len(findings) >= 4, "fixture should exercise several rules"
    for f in findings:
        assert f["risk"]["tier"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), f
        assert f["recommendation"]["rule_trace"], f"no trace for {f['name']}"
        assert f["recommendation"]["algorithm"], f"no target for {f['name']}"
        assert f["recommendation"]["justification"], f"no justification for {f['name']}"


def test_the_same_artefact_scanned_twice_gives_the_same_verdict(tmp_path):
    """A verdict must be reproducible, or the tool is a random number generator with a logo.

    Scan the same tree twice through independent scanner instances and compare everything that
    feeds a decision. A timestamp or an iteration-order leak in the risk path would show up here
    and nowhere else.
    """
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    (d / "kex.py").write_text(ECDH_SNIPPET, encoding="utf-8")

    def verdict():
        _s, findings, _cbom = _pipeline(str(d))
        return sorted((f["name"], f["risk"]["tier"], f["risk"]["margin"],
                       f["recommendation"]["algorithm"]) for f in findings)

    assert verdict() == verdict(), "the same input must produce the same verdicts"




def test_critical_risk_is_driven_by_real_inputs_not_detector_confidence(tmp_path):
    """Regression guard: a highly confident detection of short-lived crypto must not outrank a
    less confident detection of long-lived crypto."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    scanner = IndraMeshScanner(enable_ml=False)
    rsa = [f for f in scanner.scan_directory(str(d)) if f["name"] == "RSA"][0]

    short = calculate_risk({**rsa, "dl_confidence": 0.99,
                            "data_class": "session", "artefact_class": "config"})
    long = calculate_risk({**rsa, "dl_confidence": 0.10,
                           "data_class": "health-record", "artefact_class": "source"})
    assert long["tier"] == "CRITICAL"
    assert short["tier"] != "CRITICAL"
    assert long["x"] > short["x"]
