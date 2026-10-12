"""SARIF emitter tests.

SARIF is the only format here that a third party parses without our code, so these tests are
about the CONTRACT, not the styling: a document GitHub accepts, paths it will not reject, and
a level mapping a reviewer can trust. The interesting cases are the ones where a plausible
implementation would silently lose data -- a finding without a line number, a finding without
a risk rating, forty findings from three rules.
"""
import json
import os
import subprocess
import sys

from engine.sarif import SARIF_VERSION, generate_sarif


def _finding(**kw):
    base = {
        "rule_id": "IM-SRC-RSA-001",
        "name": "RSA",
        "primitive": "pke",
        "file": os.path.join("root", "src", "app.py"),
        "line": 42,
        "scanner": "source-scanner",
        "artefact_class": "source",
        "evidence_class": "discovered",
        "risk": {"tier": "HIGH", "x_y": 20, "z": 10, "margin": 10, "hndl_exposed": True,
                 "break_model": "broken-by-Shor"},
        "recommendation": {"algorithm": "ML-DSA-65 (FIPS 204)"},
    }
    base.update(kw)
    return base


def _doc(findings, root=None):
    return json.loads(generate_sarif(findings, root=root))


def test_document_declares_sarif_2_1_0_with_a_single_run():
    doc = _doc([_finding()])
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_rules_are_deduplicated_while_results_are_not():
    """Forty findings from three rules must publish three rules, not forty."""
    findings = [_finding(rule_id=f"IM-RULE-{i % 3}") for i in range(40)]
    run = _doc(findings)["runs"][0]
    assert len(run["results"]) == 40
    assert len(run["tool"]["driver"]["rules"]) == 3
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {res["ruleId"] for res in run["results"]} == rule_ids


def test_every_result_references_a_published_rule():
    run = _doc([_finding(), _finding(rule_id="IM-OTHER-001")])["runs"][0]
    published = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in published for res in run["results"])


def test_paths_are_relative_posix_and_never_absolute(tmp_path):
    """GitHub rejects absolute artifactLocation URIs; they also leak the builder's layout."""
    target = tmp_path / "repo" / "src"
    target.mkdir(parents=True)
    f = _finding(file=str(target / "app.py"))
    run = _doc([f], root=str(tmp_path / "repo"))["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/app.py"
    assert not uri.startswith("/") and ":" not in uri
    assert "\\" not in uri


def test_level_mapping_follows_risk_not_uniformity():
    levels = {tier: _doc([_finding(risk={**_finding()["risk"], "tier": tier})])["runs"][0]
              ["results"][0]["level"]
              for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    assert levels == {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def test_a_finding_without_risk_is_a_warning_not_a_vanished_row():
    """The failure mode this project argues against is silent undercount."""
    run = _doc([_finding(risk=None)])["runs"][0]
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "warning"


def test_a_finding_without_a_line_still_reaches_the_report():
    run = _doc([_finding(line=None)], root=None)["runs"][0]
    assert len(run["results"]) == 1
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in loc, "no line means no region, but the location itself stays"


def test_a_finding_without_a_file_is_emitted_without_a_location():
    run = _doc([_finding(file=None)])["runs"][0]
    assert len(run["results"]) == 1
    assert "locations" not in run["results"][0]


def test_hndl_exposure_is_stated_in_the_message():
    exposed = _doc([_finding()])["runs"][0]["results"][0]["message"]["text"]
    safe = _doc([_finding(risk={**_finding()["risk"], "hndl_exposed": False})])["runs"][0]
    assert "Harvest-now-decrypt-later" in exposed
    assert "Harvest-now-decrypt-later" not in safe["results"][0]["message"]["text"]


def test_fingerprints_are_stable_for_the_same_finding():
    a = _doc([_finding()])["runs"][0]["results"][0]["partialFingerprints"]
    b = _doc([_finding()])["runs"][0]["results"][0]["partialFingerprints"]
    assert a == b


def test_empty_input_produces_a_valid_empty_run():
    run = _doc([])["runs"][0]
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []


def test_coverage_manifest_travels_with_the_run():
    """A Security-tab alert that cannot say 'nothing was read' is half an alert."""
    coverage = {"files_seen": 10, "files_scanned": 10, "files_skipped": 0,
                "errors": [], "never_in_scope": ["HSM / TPM internal keys"]}
    run = json.loads(generate_sarif([_finding()], coverage=coverage))["runs"][0]
    cov = run["properties"]["indramesh/coverage"]
    assert cov["state"] == "covered"
    assert cov["files_seen"] == 10 and cov["files_scanned"] == 10
    assert cov["never_in_scope"] == ["HSM / TPM internal keys"]


def test_unreadable_files_mark_the_coverage_incomplete():
    coverage = {"files_seen": 10, "files_scanned": 9, "files_skipped": 1,
                "errors": [{"file": "a.py", "reason": "binary"}], "never_in_scope": []}
    run = json.loads(generate_sarif([_finding()], coverage=coverage))["runs"][0]
    assert run["properties"]["indramesh/coverage"]["state"] == "incomplete"
    assert run["properties"]["indramesh/coverage"]["unreadable"] == 1


def test_missing_coverage_is_said_out_loud_rather_than_omitted():
    run = _doc([_finding()])["runs"][0]
    assert run["properties"]["indramesh/coverage"]["state"] == "not-supplied"


def test_cli_writes_a_parseable_sarif_file(tmp_path):
    """End to end: the documented flag produces the documented artefact."""
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "cli.py", "./dummy_target", "--format", "sarif",
         "--no-ml", "--out", str(out), "--fail-on", "CRITICAL"],
        capture_output=True, text=True, timeout=300)
    # 0 = under threshold, 1 = threshold tripped; both mean the SARIF was written.
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    path = out / "indramesh.sarif"
    assert path.exists()
    doc = json.loads(path.read_text(encoding="utf-8"))
    results = doc["runs"][0]["results"]
    assert results, "dummy_target ships RSA/MD5 call sites"
    assert all(not r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/")
               for r in results if "locations" in r)
