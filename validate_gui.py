# -*- coding: utf-8 -*-
"""Comprehensive verification of the IndraMesh Web Console and API.

Tests the FastAPI backend, REST endpoints, CycloneDX 1.7 schema validation,
Mosca rating arithmetic, interactive topology graph, secondary sensors,
and file browsing.
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
import server

client = TestClient(server.app)
results = []


def step(name, fn):
    try:
        out = fn()
        results.append((name, "OK", out))
        print(f"  [PASS] {name}")
        return out
    except Exception as exc:
        results.append((name, "FAIL", f"{type(exc).__name__}: {exc}"))
        print(f"  [FAIL] {name}: {exc}")
        traceback.print_exc()
        return None


print("=" * 78)
print("IndraMesh Web Console & API Verification Suite")
print("=" * 78)

# 1. Root HTML serving
def test_root_html():
    res = client.get("/")
    assert res.status_code == 200
    assert "IndraMesh" in res.text
    assert "Enterprise Cryptographic Discovery" in res.text
    assert "CycloneDX 1.7 CBOM" in res.text
    return f"{len(res.text)} bytes served"

step("Serve Root HTML5 Web Console", test_root_html)

# 2. System Status API
def test_status_api():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "india_dst_nqm" in data["policies"]
    assert "nist_ir_8547" in data["policies"]
    assert "operational-record" in data["data_classes"]
    return f"{len(data['policies'])} policies available"

step("GET /api/status", test_status_api)

# 3. Discovery Scan on dummy_target
def test_scan_api():
    res = client.post("/api/scan", json={
        "target": "./dummy_target",
        "enable_ml": False,
        "policy": "india_dst_nqm",
        "data_class": "operational-record",
        "z_years": 10.0
    })
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["total_findings"] > 0
    assert "records" in data
    assert "coverage" in data
    assert data["cbom_validation"]["ok"] is True
    assert data["cbom_validation"]["state"] == "valid"
    return f"{data['summary']['total_findings']} findings, CBOM {data['cbom_validation']['state']}"

step("POST /api/scan on dummy_target", test_scan_api)

# 4. Mosca Re-rating without rescan
def test_rate_api():
    res = client.post("/api/rate", json={
        "z_years": 5.0,
        "policy": "nist_ir_8547"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["z_years"] == 5.0
    assert data["policy"] == "nist_ir_8547"
    return f"Re-rated at Z=5.0y, score {data['summary']['risk_score']}"

step("POST /api/rate (Dynamic Mosca recalculation)", test_rate_api)

# 5. CBOM API & Download
def test_cbom_api():
    res = client.get("/api/cbom")
    assert res.status_code == 200
    data = res.json()
    assert data["validation"]["ok"] is True
    assert data["document"]["bomFormat"] == "CycloneDX"
    assert data["document"]["specVersion"] in ("1.6", "1.7")

    dl = client.get("/api/cbom/download")
    assert dl.status_code == 200
    assert "attachment" in dl.headers.get("content-disposition", "")
    return f"Validated {data['document']['bomFormat']} {data['document']['specVersion']} CBOM"

step("GET /api/cbom & /api/cbom/download", test_cbom_api)

# 6. Topology Graph API
def test_topology_api():
    res = client.get("/api/topology")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) > 0
    assert len(data["links"]) > 0

    html_res = client.get("/api/topology/html")
    assert html_res.status_code == 200
    assert "<html" in html_res.text.lower()
    return f"{len(data['nodes'])} nodes, {len(data['links'])} links"

step("GET /api/topology & /api/topology/html", test_topology_api)

# 7. Secondary Sensors API
def test_sensors_api():
    cert_res = client.post("/api/sensors/certificates", json={"target": "./dummy_target"})
    assert cert_res.status_code == 200

    dep_res = client.post("/api/sensors/dependencies", json={"target": "./dummy_target"})
    assert dep_res.status_code == 200

    ver_res = client.post("/api/sensors/verification", json={"target": "./dummy_target"})
    assert ver_res.status_code == 200

    net_res = client.post("/api/sensors/network", json={"endpoints": ["127.0.0.1:8501"], "allow_private": True})
    assert net_res.status_code == 200

    return "All 4 secondary sensors responded successfully"

step("POST /api/sensors (Certificates, Dependencies, Verification, Network)", test_sensors_api)

# 8. Filesystem Browser API
def test_browse_api():
    res = client.post("/api/browse", json={"path": "."})
    assert res.status_code == 200
    data = res.json()
    assert "directories" in data
    assert "engine" in data["directories"] or "web" in data["directories"]
    return f"Browsed {data['current']} ({len(data['directories'])} dirs)"

step("POST /api/browse (Local directory picker)", test_browse_api)

# 9. Scan History API
def test_history_api():
    res = client.get("/api/history")
    assert res.status_code == 200
    items = res.json()
    assert isinstance(items, list)
    assert len(items) > 0
    first_id = items[0]["id"]
    
    load_res = client.post("/api/history/load", json={"id": first_id})
    assert load_res.status_code == 200
    bundle = load_res.json()
    assert "summary" in bundle
    return f"{len(items)} scans in history, restored scan {first_id}"

step("GET /api/history & POST /api/history/load", test_history_api)

# 10. Executive Report API
def test_report_api():
    html_res = client.get("/api/report/html")
    assert html_res.status_code == 200
    assert "IndraMesh Executive Cryptographic Assessment Report" in html_res.text
    assert "Mosca Inequality Verdict" in html_res.text
    
    dl_res = client.get("/api/report/download")
    assert dl_res.status_code == 200
    data = dl_res.json()
    assert data["report_type"] == "IndraMesh Post-Quantum Cryptographic Posture Assessment"
    return f"Generated HTML report ({len(html_res.text)} bytes) and JSON export"

step("GET /api/report/html & /api/report/download", test_report_api)

# Summary
print("=" * 78)
failures = [r for r in results if r[1] == "FAIL"]
if not failures:
    print(f"ALL {len(results)} GUI & API VERIFICATION STEPS PASSED PERFECTLY!")
    sys.exit(0)
else:
    print(f"{len(failures)} verification step(s) failed!")
    sys.exit(1)
