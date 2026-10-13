"""API token guard: the COMPARISON.md authentication gap, closed and asserted.

`docs/COMPARISON.md` records that the sibling console refuses to start without a token
when bound off-loopback, and lists our missing per-route authentication as a gap. The
response is two-layered: `app.py` refuses off-loopback binds without an explicit flag,
and this module covers the second layer -- when INDRAMESH_TOKEN is set, every /api/*
route (except the /api/status healthcheck the Docker HEALTHCHECK calls) requires it.

These tests mutate the environment around a real TestClient so the middleware is
exercised exactly as it runs in production, including the per-request token read.
"""
import copy

import pytest
from fastapi.testclient import TestClient

import server

TOKEN = "test-token-abc"


@pytest.fixture()
def client():
    with TestClient(server.app) as c:
        saved = copy.deepcopy(server._STATE)
        yield c
        server._STATE.clear()
        server._STATE.update(saved)


@pytest.fixture()
def guarded_client(monkeypatch):
    monkeypatch.setenv("INDRAMESH_TOKEN", TOKEN)
    with TestClient(server.app) as c:
        saved = copy.deepcopy(server._STATE)
        yield c
        server._STATE.clear()
        server._STATE.update(saved)


def test_no_token_configured_means_no_gate(client, monkeypatch):
    """Default dev loop is unchanged: no env var, no challenge."""
    monkeypatch.delenv("INDRAMESH_TOKEN", raising=False)
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/history").status_code == 200


def test_api_rejected_without_token_when_configured(guarded_client):
    resp = guarded_client.get("/api/history")
    assert resp.status_code == 401
    assert "token" in resp.json()["detail"].lower()


def test_wrong_token_rejected(guarded_client):
    resp = guarded_client.get("/api/history", headers={"X-IndraMesh-Token": "wrong"})
    assert resp.status_code == 401
    resp = guarded_client.get("/api/history", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401
    resp = guarded_client.get("/api/history?token=wrong")
    assert resp.status_code == 401


def test_header_token_accepted(guarded_client):
    resp = guarded_client.get("/api/status")
    assert resp.status_code == 200  # exempt regardless
    resp = guarded_client.get("/api/history", headers={"X-IndraMesh-Token": TOKEN})
    assert resp.status_code == 200


def test_bearer_token_accepted(guarded_client):
    resp = guarded_client.get("/api/history", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


def test_query_token_accepted_for_browser_downloads(guarded_client):
    """Browser download links cannot set headers; ?token= is the escape hatch."""
    resp = guarded_client.get(f"/api/history?token={TOKEN}")
    assert resp.status_code == 200


def test_status_healthcheck_exempt_even_when_guarded(guarded_client):
    """The Docker HEALTHCHECK calls /api/status unauthenticated; it must keep working."""
    body = guarded_client.get("/api/status").json()
    assert body["status"] == "online"


def test_console_html_not_gated(guarded_client):
    """The page cannot hold a secret, so gating it would be theatre; the API is the surface."""
    assert guarded_client.get("/").status_code == 200


def test_scan_endpoint_guarded_and_works_with_token(guarded_client):
    """The dangerous route (/api/scan reads arbitrary paths) is behind the token."""
    assert guarded_client.post("/api/scan", json={"target": "./dummy_target",
                                                  "enable_ml": False}).status_code == 401
    resp = guarded_client.post(
        "/api/scan",
        json={"target": "./dummy_target", "enable_ml": False},
        headers={"X-IndraMesh-Token": TOKEN},
    )
    assert resp.status_code == 200, resp.text
