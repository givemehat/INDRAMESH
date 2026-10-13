"""Durable scan history store: disabled by default, round-trips, bounded, fault-tolerant."""

import pytest

from engine import history_store


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """Point the store at a throwaway SQLite file for one test."""
    path = tmp_path / "history.db"
    monkeypatch.setenv("INDRAMESH_HISTORY_DB", str(path))
    return path


def _entry(i, day="2026"):
    return {"id": f"{day}0101_0000{i:02d}", "target": f"./t{i}",
            "scanned_at": f"{day}-01-01T00:00:{i:02d}Z", "findings_count": i,
            "risk_score": float(i), "tier_counts": {}, "cbom_valid": True,
            "policy": "india_dst_nqm", "z_years": 10.0, "bundle": {"i": i},
            "cbom_str": "{}", "cbom_doc": {}, "records": [], "scan_info": {},
            "validation": {}}


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("INDRAMESH_HISTORY_DB", raising=False)
    assert history_store.append(_entry(1)) is False
    assert history_store.list_recent() == []
    assert history_store.get("x") is None


def test_roundtrip(db):
    e = _entry(3)
    assert history_store.append(e) is True
    listed = history_store.list_recent()
    assert [h["id"] for h in listed] == [e["id"]]
    got = history_store.get(e["id"])
    assert got["target"] == e["target"]
    assert got["bundle"] == {"i": 3}


def test_newest_first(db):
    for i in range(3):
        history_store.append(_entry(i))
    assert [h["findings_count"] for h in history_store.list_recent()] == [2, 1, 0]


def test_retention_bounds_the_file(db):
    """More appends than RETAIN must not grow the store past RETAIN rows."""
    import sqlite3

    for i in range(history_store.RETAIN + 5):
        history_store.append(_entry(i, day=f"20{i % 10}"))
    with sqlite3.connect(db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    assert count == history_store.RETAIN


def test_append_rejects_entries_without_id(db):
    assert history_store.append({"target": "no-id"}) is False
    assert history_store.list_recent() == []


def test_get_unknown_and_absent(db):
    """Unknown id, and a configured-but-missing file, both return None."""
    assert history_store.get("does-not-exist") is None
    assert not db.exists()  # env points here, but nothing has created the file yet
    assert history_store.get("anything") is None


def test_server_scan_persists_and_survives_memory_clear(db, monkeypatch):
    """Integration: a scan appends to the store; wiping memory still allows a load."""
    import copy

    from fastapi.testclient import TestClient

    import server

    with TestClient(server.app) as client:
        saved = copy.deepcopy(server._STATE)
        try:
            resp = client.post("/api/scan", json={
                "target": "./dummy_target", "enable_ml": False,
                "policy": "india_dst_nqm", "data_class": "operational-record",
                "z_years": 10.0})
            assert resp.status_code == 200, resp.text
            entry_id = server._STATE["history"][0]["id"]

            # Simulate a restart: memory is gone, the store is not.
            server._STATE["history"] = []
            loaded = client.post("/api/history/load", json={"id": entry_id})
            assert loaded.status_code == 200, loaded.text
        finally:
            server._STATE.clear()
            server._STATE.update(saved)
