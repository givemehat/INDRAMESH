"""End-to-end tests for the FastAPI console and its JSON API.

`server.py` is the product surface an evaluator actually touches -- it is what the Streamlit
replacement ships and the only thing a non-Python user runs. Before this module it had NO
tests: not the scan endpoint, not the rate endpoint, not history, not either report export.
Everything below drives the real ASGI app through `fastapi.testclient.TestClient`, so a
regression in routing, request validation, state handling or report rendering fails here
rather than in a live demo.

The report tests matter most. Both exports exist to answer "what is our quantum exposure?",
and the failure mode this project is built around is a report that reads as reassurance when
the honest answer is "I could not look".
"""
import copy
import json

import pytest
from fastapi.testclient import TestClient

import server
from engine.scanner import RULES

DUMMY_TARGET = "./dummy_target"


@pytest.fixture()
def client():
    """A TestClient with server state reset around each test.

    `server._STATE` is module-level and mutated by every scan, so tests that assert on report
    content would otherwise inherit whatever the previous test (or the module-import auto-seed)
    left behind.
    """
    with TestClient(server.app) as c:
        saved = copy.deepcopy(server._STATE)
        yield c
        server._STATE.clear()
        server._STATE.update(saved)


@pytest.fixture()
def scanned(client):
    """Run one real scan of the bundled dummy_target and return the payload."""
    resp = client.post("/api/scan", json={
        "target": DUMMY_TARGET, "enable_ml": False,
        "policy": "india_dst_nqm", "data_class": "operational-record", "z_years": 10.0,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


# ------------------------------------------------------------------------------------------
# Routing, health and request validation.
# ------------------------------------------------------------------------------------------

def test_status_is_online_and_reports_the_real_rule_count(client):
    body = client.get("/api/status").json()
    assert body["status"] == "online"
    # A hardcoded count here would rot the moment a rule is added; assert it tracks the table.
    assert body["rules_count"] == len(RULES)
    assert "india_dst_nqm" in body["policies"]


def test_scan_of_a_missing_path_is_a_400_not_a_500(client):
    """A typo in a path is a user error; a 500 would read as a broken engine."""
    resp = client.post("/api/scan", json={"target": "./no_such_directory_at_all", "enable_ml": False})
    assert resp.status_code == 400
    assert "does not exist" in resp.json()["detail"]


def test_rate_before_any_scan_is_a_400(client):
    # The module auto-seeds a scan of ./dummy_target at import, so "no scan yet" has to be
    # constructed deliberately -- which is also how a real operator arrives at this branch
    # after a restart with the seed removed.
    server._STATE["last_scan"] = None
    resp = client.post("/api/rate", json={"z_years": 5.0})
    assert resp.status_code == 400
    assert "Run a scan first" in resp.json()["detail"]


def test_history_load_of_an_unknown_id_is_a_404(client):
    resp = client.post("/api/history/load", json={"id": "nope"})
    assert resp.status_code == 404


# ------------------------------------------------------------------------------------------
# The scan payload.
# ------------------------------------------------------------------------------------------

def test_scan_returns_a_coverage_verdict_and_finds_the_dummy_crypto(scanned):
    assert scanned["summary"]["total_findings"] > 0, "dummy_target ships RSA/MD5 call sites"
    verdict = scanned["coverage"]["verdict"]
    assert verdict["state"] in {"covered", "incomplete", "nothing-examined"}
    assert scanned["coverage"]["files_scanned"] > 0
    assert isinstance(scanned["coverage"]["never_in_scope"], list)
    assert scanned["coverage"]["never_in_scope"], "the honest-limits list must never be empty"


def test_scan_records_the_scan_in_history(client, scanned):
    entries = client.get("/api/history").json()
    assert entries and entries[0]["target"] == DUMMY_TARGET


# ------------------------------------------------------------------------------------------
# The executive reports. These leave the building; their honesty is a product requirement.
# ------------------------------------------------------------------------------------------

def test_html_report_states_coverage_and_never_in_scope(client, scanned):
    html_text = client.get("/api/report/html").text
    assert "Scan Coverage" in html_text
    assert "Never in scope" in html_text
    assert "Files seen" in html_text
    # The verdict sentence for a fully-read target, not just a number.
    assert "were read" in html_text or "could not be read" in html_text


def test_json_report_carries_the_coverage_block(client, scanned):
    doc = json.loads(client.get("/api/report/download").text)
    cov = doc["coverage"]
    assert cov["state"] in {"covered", "incomplete", "nothing-examined"}
    assert cov["files_seen"] >= cov["files_scanned"] >= 0
    assert cov["never_in_scope"], "the JSON export must carry the honest-limits list too"


def test_html_report_escapes_hostile_strings_from_the_scan_target(client, scanned):
    """A scanned filename or scope string is attacker-adjacent data rendered into HTML.

    The console escapes its own views; the exported report must not be the hole. A file named
    `<img src=x onerror=alert(1)>` that lands in the coverage error list would otherwise be
    executed by whoever opens the exported report -- typically the most trusting reader.
    """
    hostile = "<img src=x onerror=alert(1)>"
    server._STATE["last_scan"]["coverage"].setdefault("errors", []).append(
        {"file": hostile, "reason": hostile})
    server._STATE["last_scan"]["coverage"].setdefault("never_in_scope", []).append(hostile)
    html_text = client.get("/api/report/html").text
    assert "<img src=x onerror=alert(1)>" not in html_text
    assert "&lt;img" in html_text


def test_html_report_without_a_scan_says_so(client, scanned):
    """Clearing the scan must not leave the previous report on the wire."""
    server._STATE["last_scan"] = None
    assert "No scan available" in client.get("/api/report/html").text
