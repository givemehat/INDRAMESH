"""Enterprise-grade hardening regressions (2026-10-13).

Covers gaps found during task_0001/0003/0004 verification:
  * CBOM per-finding bom-refs are unique and dependencies resolve.
  * metadata.component carries bom-ref == subject (no dangling ref).
  * CBOM dedup is case/whitespace-insensitive but preserves variants
    (RSA-2048 vs RSA-4096 stay separate).
  * Asset graph dedups exact repeats, keeps d1/u.py vs d2/u.py separate,
    and tolerates malformed findings.
  * Coverage reconcile rejects invalid probe statuses (fail-fast).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.cbom import generate_cbom
from engine.coverage_records import Record
from engine.coverage_reconcile import reconcile


def _mk(name="AES-128", file="a.py", line=1, **kw):
    d = {"name": name, "primitive": "block-cipher", "file": file, "line": line}
    d.update(kw)
    return d


def test_cbom_bom_refs_unique_and_resolve():
    findings = [
        _mk("AES-128", "a.py", 1),
        _mk("AES-128", "b.py", 2),
        _mk("RSA", "c.py", 3, primitive="pke", key_length=2048),
        {"name": "OpenSSL", "type": "library", "file": "d.py", "line": 4},
    ]
    doc = json.loads(generate_cbom(findings, subject_name="hardening-subject"))
    comp_refs = [c["bom-ref"] for c in doc["components"]]
    assert len(comp_refs) == len(set(comp_refs)), "component bom-refs must be unique"
    assert len(comp_refs) > 0
    occ_refs = []
    for c in doc["components"]:
        for occ in c.get("evidence", {}).get("occurrences", []):
            assert "bom-ref" in occ
            occ_refs.append(occ["bom-ref"])
    assert len(occ_refs) == len(set(occ_refs)), "occurrence bom-refs must be unique"
    # Every dependsOn target must be a real component bom-ref.
    valid = set(comp_refs)
    for dep in doc.get("dependencies", []):
        for target in dep.get("dependsOn", []):
            assert target in valid, f"dangling dependsOn: {target}"
    # Subject ref must resolve to metadata.component bom-ref.
    for dep in doc.get("dependencies", []):
        assert dep["ref"] == doc["metadata"]["component"]["bom-ref"]


def test_cbom_metadata_component_has_bom_ref():
    doc = json.loads(generate_cbom([], subject_name="my-subject"))
    assert doc["metadata"]["component"]["bom-ref"] == "my-subject"


def test_cbom_dedup_case_insensitive_but_variant_sensitive():
    doc = json.loads(generate_cbom([_mk("AES-128", "a.py", 1),
                                    _mk("aes-128", "b.py", 2),
                                    _mk("  AES-128  ", "c.py", 3)]))
    assert len(doc["components"]) == 1, "case/whitespace variants must dedup"
    assert len(doc["components"][0]["evidence"]["occurrences"]) == 3
    doc2 = json.loads(generate_cbom([
        {"name": "RSA", "primitive": "pke", "file": "a.py", "line": 1, "key_length": 2048},
        {"name": "RSA", "primitive": "pke", "file": "b.py", "line": 2, "key_length": 4096},
    ]))
    assert len(doc2["components"]) == 2, "RSA-2048 vs RSA-4096 must stay separate"


def test_graph_dedup_and_robustness():
    from engine.graph import generate_crypto_graph
    from pyvis.network import Network

    seen_nodes = []
    orig_add = Network.add_node

    def spy(self, n, *a, **k):
        seen_nodes.append(n)
        return orig_add(self, n, *a, **k)

    Network.add_node = spy
    try:
        # Exact duplicates collapse case-insensitively.
        generate_crypto_graph([_mk("AES-128", "a.py", 1), _mk("aes-128", "a.py", 1)])
        artefact_nodes = [n for n in seen_nodes if "____" in str(n)]
        assert len(artefact_nodes) == 1, f"expected 1 artefact node, got {artefact_nodes}"
        seen_nodes.clear()
        # Same basename in different dirs must NOT collapse.
        generate_crypto_graph([_mk("X", "d1/u.py", 1), _mk("X", "d2/u.py", 1)])
        file_nodes = [n for n in seen_nodes if "____" not in str(n) and n != "App"]
        assert len(file_nodes) == 2, f"expected 2 file nodes, got {file_nodes}"
        seen_nodes.clear()
        # Malformed findings must not raise.
        generate_crypto_graph([{"primitive": "hash"}, "not-a-dict", {}])
    finally:
        Network.add_node = orig_add


def test_coverage_rejects_invalid_status():
    recs = [Record(id="A1", name="a", kind="k", location="l", owned=True)]
    try:
        reconcile(records=recs, scan_results={"A1": {"status": "bogus"}}, cloud_rows=[])
    except ValueError:
        return
    raise AssertionError("reconcile must raise ValueError on invalid probe status")
