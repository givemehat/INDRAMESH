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


def test_cbom_occ_refs_stable_across_reorder():
    a = _mk("AES-128", "a.py", 1)
    b = _mk("RSA", "b.py", 2, primitive="pke", key_length=2048)
    doc1 = json.loads(generate_cbom([a, b], subject_name="s1"))
    doc2 = json.loads(generate_cbom([b, a], subject_name="s1"))
    refs1 = sorted(o["bom-ref"] for c in doc1["components"]
                   for o in c.get("evidence", {}).get("occurrences", []))
    refs2 = sorted(o["bom-ref"] for c in doc2["components"]
                   for o in c.get("evidence", {}).get("occurrences", []))
    # Same finding content -> same hash prefix regardless of input order
    # (suffix idx may differ, but the hash stem must match).
    stems1 = sorted(r.rsplit("-", 1)[0] for r in refs1)
    stems2 = sorted(r.rsplit("-", 1)[0] for r in refs2)
    assert stems1 == stems2, f"occ refs not stable: {refs1} vs {refs2}"


def test_cbom_always_emits_dependencies_and_covers_all():
    doc = json.loads(generate_cbom([], subject_name="empty-subject"))
    assert "dependencies" in doc, "dependencies key must always exist"
    assert doc["dependencies"][0]["ref"] == "empty-subject"
    assert doc["dependencies"][0]["dependsOn"] == []
    doc2 = json.loads(generate_cbom([_mk("AES-128", "a.py", 1)], subject_name="s2"))
    valid = {c["bom-ref"] for c in doc2["components"]}
    assert set(doc2["dependencies"][0]["dependsOn"]) == valid, \
        "subject must depend on every discovered asset"


def test_cbom_subject_collision_disambiguated():
    doc = json.loads(generate_cbom([_mk("AES-128", "a.py", 1)],
                                   subject_name="crypto-asset-0"))
    assert doc["metadata"]["component"]["bom-ref"].startswith("subject-")
    assert doc["dependencies"][0]["ref"] == doc["metadata"]["component"]["bom-ref"]


def test_history_store_corrupt_row_skipped(tmp_path, monkeypatch):
    import sqlite3
    from engine import history_store
    p = tmp_path / "h.db"
    monkeypatch.setenv("INDRAMESH_HISTORY_DB", str(p))
    assert history_store.append({"id": "A", "scanned_at": "2026-01-01T00:00:00Z"}) is True
    with sqlite3.connect(str(p)) as conn:
        conn.execute("INSERT OR REPLACE INTO history (id, ts, blob) VALUES (?,?,?)",
                     ("BAD", "2026-01-02T00:00:00Z", "{not-json"))
    listed = history_store.list_recent()
    assert all(isinstance(e, dict) for e in listed)
    assert any(e.get("id") == "A" for e in listed)
    assert history_store.get("BAD") is None


def test_graph_variant_separation():
    from engine.graph import generate_crypto_graph
    from pyvis.network import Network
    seen = []
    orig = Network.add_node

    def spy(self, n, *a, **k):
        seen.append(n)
        return orig(self, n, *a, **k)
    Network.add_node = spy
    try:
        generate_crypto_graph([
            {"name": "RSA", "primitive": "pke", "file": "a.py", "line": 1,
             "key_length": 2048, "risk": {"tier": "CRITICAL"}},
            {"name": "RSA", "primitive": "pke", "file": "a.py", "line": 2,
             "key_length": 4096, "risk": {"tier": "CRITICAL"}},
        ])
        artefacts = [n for n in seen if "____" in str(n)]
        assert len(artefacts) == 2, f"RSA-2048 vs 4096 must not merge in graph: {artefacts}"
    finally:
        Network.add_node = orig


def test_cbom_occ_refs_fully_stable_across_reorder():
    """Per-digest counters make refs fully order-independent (not just stems)."""
    a = _mk("AES-128", "a.py", 1)
    b = _mk("RSA", "b.py", 2, primitive="pke", key_length=2048)
    doc1 = json.loads(generate_cbom([a, b], subject_name="s1"))
    doc2 = json.loads(generate_cbom([b, a], subject_name="s1"))
    refs1 = sorted(o["bom-ref"] for c in doc1["components"]
                   for o in c.get("evidence", {}).get("occurrences", []))
    refs2 = sorted(o["bom-ref"] for c in doc2["components"]
                   for o in c.get("evidence", {}).get("occurrences", []))
    assert refs1 == refs2, f"occ refs must be fully stable: {refs1} vs {refs2}"


def test_graph_tolerates_string_risk_and_library_case():
    from engine.graph import generate_crypto_graph
    # risk as a plain string must not raise (regression: .get on str).
    html = generate_crypto_graph([
        {"name": "AES", "primitive": "block-cipher", "file": "a.py", "line": 1,
         "risk": "CRITICAL"},
        {"name": "OpenSSL", "type": "Library", "file": "b.py", "line": 2,
         "risk": {"tier": "LOW"}},
    ])
    assert isinstance(html, str) and len(html) > 0


def test_history_load_restores_config_and_reinserts(tmp_path, monkeypatch):
    """LOAD from DB must re-insert into memory history and restore last_config."""
    import copy
    from fastapi.testclient import TestClient
    import server
    from engine import history_store
    p = tmp_path / "h2.db"
    monkeypatch.setenv("INDRAMESH_HISTORY_DB", str(p))
    with TestClient(server.app) as client:
        saved = copy.deepcopy(server._STATE)
        try:
            resp = client.post("/api/scan", json={
                "target": "./dummy_target", "enable_ml": False,
                "policy": "india_dst_nqm", "data_class": "operational-record",
                "z_years": 10.0})
            assert resp.status_code == 200, resp.text
            entry_id = server._STATE["history"][0]["id"]
            # Wipe memory completely, then GET must fall back to the store.
            server._STATE["history"] = []
            hist = client.get("/api/history")
            assert hist.status_code == 200, hist.text
            assert any(h["id"] == entry_id for h in hist.json()), \
                "GET /api/history must fall back to durable store"
            # Wipe again, LOAD from DB must work and re-insert.
            server._STATE["history"] = []
            loaded = client.post("/api/history/load", json={"id": entry_id})
            assert loaded.status_code == 200, loaded.text
            assert any(h["id"] == entry_id for h in server._STATE["history"]), \
                "DB-loaded entry must be re-inserted into memory history"
            assert server._STATE.get("last_config", {}).get("policy") == "india_dst_nqm"
        finally:
            server._STATE.clear()
            server._STATE.update(saved)


def test_coverage_inventory_ids_consistent():
    """home_lab.csv must use SLC10 (not SLC010); both scripts must agree."""
    import csv
    inv = ROOT / "docs" / "inventory" / "home_lab.csv"
    with open(inv, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
        ids = [r["id"] for r in rows]
    assert "SLC10" in ids, f"inventory must contain SLC10, got {ids}"
    assert "SLC010" not in ids, f"inventory must not contain SLC010 typo: {ids}"
    assert len(ids) == 12
    # Enterprise-grade: owned must be explicit (no reliance on None->True default).
    for r in rows:
        assert str(r.get("owned", "")).strip() == "1", f"owned must be explicit 1: {r}"


def test_graph_preserves_valid_string_risk_tier():
    from engine.graph import generate_crypto_graph
    from pyvis.network import Network
    colors = {}
    orig = Network.add_node

    def spy(self, n, *a, **k):
        if "____" in str(n):
            colors[n] = k.get("color")
        return orig(self, n, *a, **k)
    Network.add_node = spy
    try:
        generate_crypto_graph([
            {"name": "AES", "primitive": "block-cipher", "file": "a.py", "line": 1,
             "risk": "CRITICAL"},
        ])
        assert colors, "expected artefact node"
        assert list(colors.values())[0] == "#ff4b4b", f"string CRITICAL must keep red: {colors}"
    finally:
        Network.add_node = orig


def test_graph_colors_case_insensitive_and_path_canonicalized():
    from engine.graph import generate_crypto_graph
    from pyvis.network import Network
    seen = []
    orig = Network.add_node

    def spy(self, n, *a, **k):
        seen.append((n, k.get("color")))
        return orig(self, n, *a, **k)
    Network.add_node = spy
    try:
        generate_crypto_graph([
            {"name": "A", "primitive": "p", "file": "./a.py", "line": 1,
             "risk": {"tier": "critical"}},
            {"name": "A", "primitive": "p", "file": "a.py", "line": 1,
             "risk": {"tier": "critical"}},
        ])
        files = [n for n, _ in seen if "____" not in str(n) and n != "App"]
        assert files == ["a.py"], f"./a.py vs a.py must canonicalize: {files}"
        arts = [c for n, c in seen if "____" in str(n)]
        assert arts and arts[0] == "#ff4b4b", f"lowercase critical must map to red: {arts}"
        # Single-quoted remote refs must also be stripped for air-gap.
        html = generate_crypto_graph([{"name": "A", "file": "a.py", "line": 1}])
        assert "https://" not in html or "www.w3.org" in html.replace("https://www.w3.org", "")
        assert "data-removed-remote" in html or "bootstrap css removed" in html
    finally:
        Network.add_node = orig


def test_coverage_out_of_scope_filters_blank_ids():
    recs = [Record(id="A1", name="a", kind="k", location="l", owned=True)]
    report = reconcile(records=recs, scan_results={"A1": {"status": "scanned"}},
                       cloud_rows=[{"id": "CLOUD-01"}, {"id": ""}, {"id": None}, {}])
    assert report["out_of_scope"] == ["CLOUD-01"], report["out_of_scope"]


def test_history_apply_deepcopies_config():
    import copy
    from fastapi.testclient import TestClient
    import server
    with TestClient(server.app):
        saved = copy.deepcopy(server._STATE)
        try:
            r = __import__("fastapi.testclient", fromlist=["TestClient"])
            client = r.TestClient(server.app)
            resp = client.post("/api/scan", json={
                "target": "./dummy_target", "enable_ml": False,
                "policy": "india_dst_nqm", "data_class": "operational-record",
                "z_years": 10.0})
            assert resp.status_code == 200
            eid = server._STATE["history"][0]["id"]
            client.post("/api/history/load", json={"id": eid})
            # Mutating last_config must not mutate the history entry (aliasing guard).
            server._STATE["last_config"]["policy"] = "MUTATED"
            assert server._STATE["history"][0].get("last_config", {}).get("policy") != "MUTATED"
        finally:
            server._STATE.clear()
            server._STATE.update(saved)
