"""IndraMesh Server -- Modern FastAPI backend for Enterprise Cryptographic Discovery & Analysis.

Interfaces directly with `engine/` modules:
- scanner.py (discovery engine)
- mosca.py (quantum risk assessment)
- cbom.py (CycloneDX 1.7 CBOM generation)
- recommender.py (PQC migration paths)
- purpose.py (purpose resolution)
- certificates.py (X.509 sensor)
- dependencies.py (dependency manifest sensor)
- verify_migration.py (post-migration validation)
- netpolicy.py & netprobe.py (vetted network probing)
- graph.py (topology visualization)
- gui_helpers.py (rating, validation, tables)
"""
import asyncio
import datetime
import hmac
import html
import json
import os
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from contextlib import asynccontextmanager

# Ensure IndraMesh directory is on sys.path
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from engine.cbom import generate_cbom
from engine.certificates import scan_certificates
from engine.dependencies import DependencyScanner
from engine.graph import generate_crypto_graph
from engine.history_store import append as history_append
from engine.history_store import get as history_get
from engine.history_store import list_recent as history_list
from engine.gui_helpers import (
    TIER_COLOURS,
    assurance_counts,
    auditor_rows,
    certificate_rows,
    certificate_summary,
    coverage_verdict,
    dependency_rows,
    dependency_summary,
    enrich_findings,
    hndl_records,
    late_records,
    location,
    proven_use,
    queue_rows,
    recommendations_payload,
    tier_counts,
    unrated_records,
    unresolved_split,
    validate_cbom_document,
    verification_rows,
    verification_summary,
    z_basis,
)
from engine.mosca import (
    DATA_CLASS_LIFETIME,
    DEFAULT_Z,
    POLICY_DEADLINES,
    Z_PRESETS,
)
from engine.scanner import IndraMeshScanner, RULES
from engine.theme import risk_score
from engine.verify_migration import verify_migration


# In-memory store for the active/latest scan and scan history
# _STATE_LOCK serialises concurrent /api/scan mutations (insert/slice/last_*)
# so parallel scans cannot interleave and publish a torn bundle. SQLite WAL
# handles the durable side; this handles the in-memory side.
_STATE_LOCK = threading.Lock()
_STATE: Dict[str, Any] = {
    "last_scan": None,
    "last_records": None,
    "last_cbom": None,
    "last_cbom_doc": None,
    "last_cbom_validation": None,
    "last_target": "./dummy_target",
    "last_config": {
        "target": "./dummy_target",
        "enable_ml": False,
        "policy": "india_dst_nqm",
        "data_class": "operational-record",
        "z_years": float(DEFAULT_Z),
        "x_override": None,
        "y_override": None,
    },
    "history": [],
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Auto-seed scan on startup so the console and APIs are immediately populated."""
    # Restore durable history (when INDRAMESH_HISTORY_DB is configured) BEFORE the auto-seed
    # scan below, so the boot scan is prepended on top of the restored past rather than
    # being buried under it. Disabled store -> no-op, old in-memory behaviour.
    try:
        from engine.history_store import RETAIN as _HIST_RETAIN
        import copy as _copy
        restored = history_list(_HIST_RETAIN)
        if restored:
            with _STATE_LOCK:
                _STATE["history"] = restored
                # Enterprise-grade: restore the newest bundle too, so /api/cbom
                # works immediately after reboot instead of 404 despite persisted data.
                newest = restored[0]
                for key, hkey in (("last_scan", "scan_info"), ("last_records", "records"),
                                  ("last_cbom", "cbom_str"), ("last_cbom_doc", "cbom_doc"),
                                  ("last_cbom_validation", "validation"),
                                  ("last_target", "target")):
                    if hkey in newest:
                        _STATE[key] = _copy.deepcopy(newest[hkey])
                # last_config with legacy-row rebuild (mirrors POST /api/history/load).
                cfg = newest.get("last_config")
                if isinstance(cfg, dict) and cfg:
                    _STATE["last_config"] = _copy.deepcopy(cfg)
                else:
                    prev = dict(_STATE.get("last_config") or {})
                    _STATE["last_config"] = {
                        "target": newest.get("target", prev.get("target", "./dummy_target")),
                        "enable_ml": prev.get("enable_ml", False),
                        "policy": newest.get("policy", prev.get("policy", "india_dst_nqm")),
                        "data_class": prev.get("data_class", "operational-record"),
                        "z_years": newest.get("z_years", prev.get("z_years", float(DEFAULT_Z))),
                        "x_override": prev.get("x_override"),
                        "y_override": prev.get("y_override"),
                    }
            print(f"[IndraMesh] Restored {len(restored)} scan(s) from history store")
    except Exception as exc:
        print(f"[IndraMesh] History store restore notice: {exc}")
    try:
        abs_dummy = os.path.join(_REPO_ROOT, "dummy_target")
        if os.path.exists(abs_dummy):
            _compute_scan_bundle(
                target="./dummy_target",
                enable_ml=False,
                policy="india_dst_nqm",
                data_class="operational-record",
                z_years=float(DEFAULT_Z),
                x_override=None,
                y_override=None,
            )
            print("[IndraMesh] Server auto-seeded successfully with ./dummy_target")
    except Exception as exc:
        print(f"[IndraMesh] Startup pre-seed notice: {exc}")
    yield


app = FastAPI(
    title="IndraMesh API",
    description="Enterprise Cryptographic Discovery & Analysis Tool API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------------------
# Optional API token (enterprise deployments).
#
# When INDRAMESH_TOKEN is set, every /api/* route except /api/status requires the token,
# supplied as X-IndraMesh-Token, an Authorization: Bearer header, or a ?token= query
# parameter (the query form exists for browser download links, which cannot set headers).
# /api/status is exempt because the Docker HEALTHCHECK calls it unauthenticated, and it
# exposes only liveness plus counts -- not inventory.
#
# The console HTML itself stays unauthenticated on purpose: a page cannot hold a secret,
# so a token check on `/` would be theatre. The sensitive surface is the API, and it is
# what this guard covers. app.py additionally refuses to bind off-loopback without an
# explicit flag, so exposure is always a second, deliberate decision.
#
# The token is read per request (not at import) so tests can set and clear the variable.
# Comparison is constant-time.
# ------------------------------------------------------------------------------------------
AUTH_EXEMPT_PATHS = {"/api/status"}


def _enforced_token():
    return os.environ.get("INDRAMESH_TOKEN") or None


@app.middleware("http")
async def indramesh_token_guard(request, call_next):
    token = _enforced_token()
    path = request.url.path
    if not token or not path.startswith("/api/") or path in AUTH_EXEMPT_PATHS:
        return await call_next(request)

    supplied = request.headers.get("x-indramesh-token")
    if not supplied:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            supplied = auth[7:]
    if not supplied:
        supplied = request.query_params.get("token")

    if not hmac.compare_digest(supplied or "", token):
        return JSONResponse(
            {"detail": "a valid IndraMesh token is required "
                       "(X-IndraMesh-Token header, Bearer, or ?token=)"},
            status_code=401,
        )
    return await call_next(request)


class ScanRequest(BaseModel):
    target: str = Field(default="./dummy_target", description="Target path or file to scan")
    enable_ml: bool = Field(default=True, description="Enable PyTorch transformer sensor")
    policy: str = Field(default="india_dst_nqm", description="Active compliance policy deadline")
    data_class: str = Field(default="operational-record", description="Data lifetime class (X)")
    z_years: float = Field(default=float(DEFAULT_Z), description="Years until a CRQC (Z)")
    x_override: Optional[float] = Field(default=None, description="Manual X override in years")
    y_override: Optional[float] = Field(default=None, description="Manual Y override in years")


class RateRequest(BaseModel):
    policy: Optional[str] = None
    data_class: Optional[str] = None
    z_years: Optional[float] = None
    x_override: Optional[float] = None
    y_override: Optional[float] = None


class LoadHistoryRequest(BaseModel):
    id: str


class BrowseRequest(BaseModel):
    path: Optional[str] = None


class ProbeRequest(BaseModel):
    endpoints: List[str]
    allow_private: bool = False


def _compute_scan_bundle(target: str, enable_ml: bool, policy: str, data_class: str,
                         z_years: float, x_override: Optional[float], y_override: Optional[float]) -> Dict[str, Any]:
    """Execute scan, enrich findings with Mosca arithmetic, generate and validate CBOM."""
    abs_target = os.path.abspath(target)
    if not os.path.exists(abs_target):
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {target}")

    scanner = IndraMeshScanner(enable_ml=enable_ml)
    findings = scanner.scan_directory(abs_target) if os.path.isdir(abs_target) else scanner._scan_path(abs_target)
    coverage = scanner.coverage_manifest(findings)
    scanned_at = datetime.datetime.now().replace(microsecond=0).isoformat()

    scan_info = {
        "target": target,
        "abs_target": abs_target,
        "enable_ml": enable_ml,
        "findings": findings,
        "coverage": coverage,
        "scanned_at": scanned_at,
    }

    records = enrich_findings(
        findings,
        z_years=z_years,
        policy=policy,
        data_class=data_class,
        x_override=x_override,
        y_override=y_override,
    )

    subject = os.path.basename(abs_target.rstrip("/\\")) or "IndraMesh-Scanned-Artefact"
    cbom_str = ""
    cbom_doc = {}
    validation = {"ok": False, "state": "not-run", "errors": [], "message": "CBOM not yet built"}
    try:
        cbom_str = generate_cbom(records, enriched=True, subject_name=subject, coverage=coverage)
        cbom_doc = json.loads(cbom_str)
        validation = validate_cbom_document(cbom_doc)
    except Exception as exc:
        validation = {"ok": False, "state": "error", "errors": [str(exc)], "message": f"CBOM error: {exc}"}

    # Save to state (locked: parallel /api/scan must not publish a torn bundle).
    with _STATE_LOCK:
        _STATE["last_scan"] = scan_info
        _STATE["last_records"] = records
        _STATE["last_cbom"] = cbom_str
        _STATE["last_cbom_doc"] = cbom_doc
        _STATE["last_cbom_validation"] = validation
        _STATE["last_target"] = target
        _STATE["last_config"] = {
            "target": target,
            "enable_ml": enable_ml,
            "policy": policy,
            "data_class": data_class,
            "z_years": z_years,
            "x_override": x_override,
            "y_override": y_override,
        }

    payload = _build_response_payload(scan_info, records, validation, policy, z_years)

    # Save to history (keep latest RETAIN scans, aligned with the durable store).
    # ID includes micros + random suffix: two scans in the same second must not
    # overwrite each other via INSERT OR REPLACE.
    from engine.history_store import RETAIN as _HIST_RETAIN
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") + "_" + uuid.uuid4().hex[:6]
    history_entry = {
        "id": scan_id,
        "target": target,
        "scanned_at": scanned_at,
        "findings_count": len(records),
        "risk_score": payload["summary"]["risk_score"],
        "tier_counts": payload["summary"]["tier_counts"],
        "cbom_valid": validation.get("ok", False),
        "policy": policy,
        "z_years": z_years,
        "bundle": payload,
        "cbom_str": cbom_str,
        "cbom_doc": cbom_doc,
        "records": records,
        "scan_info": scan_info,
        "validation": validation,
        "last_config": dict(_STATE.get("last_config") or {}),
    }
    with _STATE_LOCK:
        _STATE.setdefault("history", []).insert(0, history_entry)
        if len(_STATE["history"]) > _HIST_RETAIN:
            _STATE["history"] = _STATE["history"][:_HIST_RETAIN]
    try:
        history_append(history_entry)
    except Exception as exc:
        # A broken store must never fail a scan; the in-memory copy still has the entry.
        print(f"[IndraMesh] History store append notice: {exc}")

    return payload


def _build_response_payload(scan_info: dict, records: list, validation: dict, policy: str, z_years: float) -> dict:
    """Pack complete structured analytics for the dashboard."""
    coverage = scan_info["coverage"]
    c_verdict = coverage_verdict(coverage)
    total = len(records)
    proven = proven_use(records)
    capability = total - proven
    declined, named = unresolved_split(records)
    t_counts = tier_counts(records)
    a_counts = assurance_counts(records)
    hndl = hndl_records(records)
    active_policy = POLICY_DEADLINES.get(policy, {})
    deadline = active_policy.get("year")
    late = late_records(records, deadline)
    unrated = unrated_records(records, deadline)
    score_raw = risk_score(records) if records else 0
    score = score_raw.get("score", 0) if isinstance(score_raw, dict) else (score_raw or 0)

    return {
        "target": scan_info["target"],
        "scanned_at": scan_info["scanned_at"],
        "enable_ml": scan_info["enable_ml"],
        "policy": policy,
        "policy_label": active_policy.get("label", ""),
        "policy_deadline": deadline,
        "z_years": z_years,
        "z_basis": z_basis(int(z_years)),
        "summary": {
            "total_findings": total,
            "proven_use": proven,
            "capability_or_declared": capability,
            "unresolved_purpose": len(declined) + len(named),
            "unresolved_declined": len(declined),
            "unresolved_named": len(named),
            "risk_score": score,
            "hndl_count": len(hndl),
            "late_count": len(late),
            "unrated_count": len(unrated),
            "tier_counts": t_counts,
            "assurance_counts": a_counts,
        },
        "coverage": {
            "verdict": c_verdict,
            "files_seen": c_verdict["files_seen"],
            "files_scanned": c_verdict["files_scanned"],
            "files_skipped": c_verdict["files_skipped"],
            "read_fraction": c_verdict["read_fraction"],
            "errors": c_verdict["errors"],
            "scanners_run": coverage.get("scanners_run", []),
            "never_in_scope": coverage.get("never_in_scope", []),
            "ml_reason": coverage.get("ml_reason", "n/a"),
            "ml_window_chars": coverage.get("ml_window_chars", 0),
        },
        "cbom_validation": validation,
        "records": records,
        "auditor_rows": auditor_rows(records),
        "queue_rows": queue_rows(records, deadline_year=deadline),
    }


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/status")
def get_status():
    """Engine health, rule counts, and configuration presets."""
    return {
        "status": "online",
        "app_name": "IndraMesh",
        "title": "Enterprise Cryptographic Discovery & Analysis Tool",
        "version": "2.0.0",
        "hackathon": "Smart India Hackathon 2026 SIH26164 (NTRO)",
        "rules_count": len(RULES),
        "policies": {
            k: {
                "label": v.get("label"),
                "year": v.get("year"),
                "description": v.get("description", ""),
            } for k, v in POLICY_DEADLINES.items()
        },
        "data_classes": DATA_CLASS_LIFETIME,
        "z_presets": Z_PRESETS,
        "default_z": DEFAULT_Z,
        "has_active_scan": _STATE["last_scan"] is not None,
        "last_target": _STATE["last_target"],
        "last_config": _STATE["last_config"],
    }


@app.post("/api/scan")
def run_scan_endpoint(req: ScanRequest):
    """Run full discovery scan against target and rate findings."""
    try:
        return _compute_scan_bundle(
            target=req.target,
            enable_ml=req.enable_ml,
            policy=req.policy,
            data_class=req.data_class,
            z_years=req.z_years,
            x_override=req.x_override,
            y_override=req.y_override,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(exc).__name__}: {exc}")


@app.post("/api/rate")
def rate_findings_endpoint(req: RateRequest):
    """Re-rate existing findings when the user changes Z, Policy, or Data Class (no re-scan needed)."""
    scan_info = _STATE.get("last_scan")
    if not scan_info:
        raise HTTPException(status_code=400, detail="No scan loaded yet. Run a scan first.")

    cfg = _STATE["last_config"]
    policy = req.policy or cfg["policy"]
    data_class = req.data_class or cfg["data_class"]
    z_years = req.z_years if req.z_years is not None else cfg["z_years"]
    x_override = req.x_override if req.x_override is not None else cfg["x_override"]
    y_override = req.y_override if req.y_override is not None else cfg["y_override"]

    records = enrich_findings(
        scan_info["findings"],
        z_years=z_years,
        policy=policy,
        data_class=data_class,
        x_override=x_override,
        y_override=y_override,
    )

    abs_target = scan_info["abs_target"]
    subject = os.path.basename(abs_target.rstrip("/\\")) or "IndraMesh-Scanned-Artefact"
    cbom_str = ""
    cbom_doc = {}
    validation = {"ok": False, "state": "not-run", "errors": [], "message": ""}
    try:
        cbom_str = generate_cbom(records, enriched=True, subject_name=subject, coverage=scan_info["coverage"])
        cbom_doc = json.loads(cbom_str)
        validation = validate_cbom_document(cbom_doc)
    except Exception as exc:
        validation = {"ok": False, "state": "error", "errors": [str(exc)], "message": f"CBOM error: {exc}"}

    _STATE["last_records"] = records
    _STATE["last_cbom"] = cbom_str
    _STATE["last_cbom_doc"] = cbom_doc
    _STATE["last_cbom_validation"] = validation
    _STATE["last_config"].update({
        "policy": policy,
        "data_class": data_class,
        "z_years": z_years,
        "x_override": x_override,
        "y_override": y_override,
    })

    return _build_response_payload(scan_info, records, validation, policy, z_years)


@app.get("/api/cbom")
def get_cbom():
    """Retrieve the generated CycloneDX 1.7 CBOM document and its offline schema validation report."""
    if not _STATE["last_cbom_doc"]:
        raise HTTPException(status_code=404, detail="No CBOM available. Run a scan first.")
    return {
        "validation": _STATE["last_cbom_validation"],
        "document": _STATE["last_cbom_doc"],
    }


@app.get("/api/cbom/download")
def download_cbom():
    """Download the validated CycloneDX 1.7 CBOM as JSON."""
    if not _STATE["last_cbom"]:
        raise HTTPException(status_code=404, detail="No CBOM generated yet.")
    return Response(
        content=_STATE["last_cbom"],
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="indramesh_report.json"'},
    )


@app.get("/api/coverage/download")
def download_coverage():
    """Download the coverage manifest JSON."""
    scan = _STATE.get("last_scan")
    if not scan:
        raise HTTPException(status_code=404, detail="No scan data available.")
    return Response(
        content=json.dumps(scan["coverage"], indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="indramesh_coverage.json"'},
    )


@app.get("/api/recommendations/download")
def download_recommendations():
    """Download the actionable recommendations payload JSON."""
    scan = _STATE.get("last_scan")
    records = _STATE.get("last_records")
    if not scan or not records:
        raise HTTPException(status_code=404, detail="No scan data available.")
    cfg = _STATE["last_config"]
    payload = recommendations_payload(
        records,
        target=scan["target"],
        policy=cfg["policy"],
        z_years=cfg["z_years"],
    )
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="indramesh_recommendations.json"'},
    )


@app.get("/api/history")
def get_scan_history():
    """Return list of past scans (memory first, durable-store fallback)."""
    hist = _STATE.get("history", [])
    if not hist:
        # Enterprise-grade: after a restart without lifespan (or a memory
        # wipe in tests), the DB still has data — serve it instead of [].
        try:
            from engine.history_store import RETAIN as _HIST_RETAIN
            restored = history_list(_HIST_RETAIN)
            if restored:
                with _STATE_LOCK:
                    _STATE["history"] = restored
                hist = restored
        except Exception as exc:
            print(f"[IndraMesh] History store list notice: {exc}")
    return [
        {
            "id": h["id"],
            "target": h["target"],
            "scanned_at": h["scanned_at"],
            "findings_count": h["findings_count"],
            "risk_score": h["risk_score"],
            "tier_counts": h["tier_counts"],
            "cbom_valid": h["cbom_valid"],
            "policy": h["policy"],
            "z_years": h["z_years"],
        }
        for h in _STATE.get("history", [])
    ]


@app.post("/api/history/load")
def load_scan_history(req: LoadHistoryRequest):
    """Load a past scan from history (memory first, then the durable store)."""
    def _apply(h):
        import copy as _copy
        _STATE["last_scan"] = _copy.deepcopy(h["scan_info"])
        _STATE["last_records"] = _copy.deepcopy(h["records"])
        _STATE["last_cbom"] = h["cbom_str"]
        _STATE["last_cbom_doc"] = _copy.deepcopy(h["cbom_doc"])
        _STATE["last_cbom_validation"] = _copy.deepcopy(h["validation"])
        _STATE["last_target"] = h["target"]
        # Enterprise-grade: restore the rating config so POST /api/rate after
        # a load uses the loaded scan's policy/z_years instead of stale state.
        # Older rows predate last_config — rebuild it from policy/z_years/target.
        # Deep-copy so later _STATE["last_config"].update() cannot mutate history.
        cfg = h.get("last_config")
        if isinstance(cfg, dict) and cfg:
            _STATE["last_config"] = dict(cfg)
        else:
            prev = _STATE.get("last_config") or {}
            _STATE["last_config"] = {
                "target": h.get("target", prev.get("target", "./dummy_target")),
                "enable_ml": prev.get("enable_ml", False),
                "policy": h.get("policy", prev.get("policy", "india_dst_nqm")),
                "data_class": prev.get("data_class", "operational-record"),
                "z_years": h.get("z_years", prev.get("z_years", float(DEFAULT_Z))),
                "x_override": prev.get("x_override"),
                "y_override": prev.get("y_override"),
            }
    for h in _STATE.get("history", []):
        if h["id"] == req.id:
            with _STATE_LOCK:
                _apply(h)
            return h["bundle"]
    try:
        h = history_get(req.id)
    except Exception as exc:
        print(f"[IndraMesh] History store read notice: {exc}")
        h = None
    if h and all(k in h for k in ("scan_info", "records", "cbom_str",
                                  "cbom_doc", "validation", "target", "bundle")):
        with _STATE_LOCK:
            _apply(h)
            # Enterprise-grade: a DB-loaded entry must be visible to
            # GET /api/history afterwards — re-insert it at the head.
            if not any(e.get("id") == h.get("id") for e in _STATE.get("history", [])):
                from engine.history_store import RETAIN as _HIST_RETAIN
                _STATE.setdefault("history", []).insert(0, h)
                if len(_STATE["history"]) > _HIST_RETAIN:
                    _STATE["history"] = _STATE["history"][:_HIST_RETAIN]
        return h["bundle"]
    raise HTTPException(status_code=404, detail="Scan history entry not found.")


def generate_executive_report_html() -> str:
    scan = _STATE.get("last_scan")
    records = _STATE.get("last_records") or []
    cbom_val = _STATE.get("last_cbom_validation") or {}
    cfg = _STATE.get("last_config") or {}
    if not scan:
        return "<html><body><h2>No scan available to generate report. Run a scan first.</h2></body></html>"

    cov = scan["coverage"]
    c_verdict = coverage_verdict(cov)
    total = len(records)
    proven = proven_use(records)
    capability = total - proven
    declined, named = unresolved_split(records)
    t_counts = tier_counts(records)
    score = risk_score(records) if records else 0
    if isinstance(score, dict):
        score = score.get("score", 0)
    active_policy = POLICY_DEADLINES.get(cfg.get("policy", "india_dst_nqm"), {})

    crit_count = t_counts.get("CRITICAL", 0)
    high_count = t_counts.get("HIGH", 0)
    med_count = t_counts.get("MEDIUM", 0)
    t_counts.get("LOW", 0)

    q_rows = queue_rows(records, deadline_year=active_policy.get("year"))

    # HONESTY SECTION. The on-screen console headlines the coverage verdict, but this exported
    # report -- the artefact that leaves the building and gets shown to a board -- did not
    # mention coverage at all. `c_verdict` was computed above and then thrown away, which is
    # precisely how a report that says "0 CRITICAL findings" gets read as "you are clean" when
    # the truth is "nothing could be read". A scan's blind spots travel with the scan.
    seen = c_verdict.get("files_seen", 0)
    read_pct = f"{c_verdict.get('read_fraction', 0.0) * 100:.0f}%"
    verdict_state = c_verdict.get("state", "unknown")
    verdict_colour = {"covered": "#16a34a", "incomplete": "#ea580c"}.get(verdict_state, "#dc2626")
    scope_items = "".join(
        f"<li>{html.escape(str(g))}</li>" for g in (cov.get("never_in_scope") or [])
    )
    unreadable = c_verdict.get("errors") or []
    unreadable_items = "".join(
        f"<li><code>{html.escape(str(e.get('file', '?')))}</code> &mdash; "
        f"{html.escape(str(e.get('reason', 'unreadable')))}</li>"
        for e in unreadable[:10]
    )
    if len(unreadable) > 10:
        unreadable_items += f"<li>&hellip; and {len(unreadable) - 10} more</li>"
    coverage_html = f"""
<div class="callout" style="border-left:4px solid {verdict_colour}">
  <strong style="color:#0f172a;font-size:0.95rem">Scan Coverage &amp; Honest Limits:</strong>
  <div style="margin-top:0.35rem;font-size:0.88rem;color:#334155">{html.escape(str(c_verdict.get('message', '')))}</div>
  <div style="margin-top:0.6rem;font-size:0.82rem;color:#475569">
    Files seen <strong>{seen}</strong> &middot; read <strong>{c_verdict.get('files_scanned', 0)}</strong>
    ({read_pct}) &middot; skipped <strong>{c_verdict.get('files_skipped', 0)}</strong>
    &middot; unreadable <strong>{len(unreadable)}</strong>
  </div>
  {f'<div style="margin-top:0.6rem;font-size:0.82rem"><strong style="color:#9a3412">Files that could not be read (NOT evidence of safety):</strong><ul style="margin:0.3rem 0 0 1.1rem;color:#475569">{unreadable_items}</ul></div>' if unreadable_items else ''}
  {f'<div style="margin-top:0.6rem;font-size:0.82rem"><strong style="color:#334155">Never in scope for any scan (require a different sensor or an attestation):</strong><ul style="margin:0.3rem 0 0 1.1rem;color:#475569">{scope_items}</ul></div>' if scope_items else ''}
</div>
"""

    table_rows_html = "".join([
        f"<tr><td><span class='badge tier-{r.get('Risk tier', 'LOW')}'>{r.get('Risk tier')}</span></td>"
        f"<td><strong>{r.get('Artefact', '')}</strong></td>"
        f"<td><code>{r.get('Primitive', '')}</code></td>"
        f"<td><strong>{r.get('Target algorithm', '')}</strong></td>"
        f"<td>{r.get('Latest safe start', '')}</td>"
        f"<td>{r.get('Cost band', '')}</td>"
        f"<td>{r.get('Action', '')}</td></tr>"
        for r in q_rows[:30]
    ])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IndraMesh Executive Cryptographic Assessment Report - {scan['target']}</title>
<style>
  @page {{ size: A4; margin: 1.5cm; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #ffffff; margin: 0; padding: 2rem; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-end; }}
  .title {{ font-size: 1.75rem; font-weight: 700; color: #0f172a; margin: 0; }}
  .subtitle {{ color: #64748b; font-size: 0.9rem; margin-top: 0.25rem; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .tier-CRITICAL {{ background: #fee2e2; color: #991b1b; }}
  .tier-HIGH {{ background: #ffedd5; color: #9a3412; }}
  .tier-MEDIUM {{ background: #fef3c7; color: #92400e; }}
  .tier-LOW {{ background: #d1fae5; color: #065f46; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; background: #f8fafc; }}
  .card-label {{ font-size: 0.75rem; color: #64748b; font-weight: 600; text-transform: uppercase; }}
  .card-value {{ font-size: 1.5rem; font-weight: 700; color: #0f172a; margin-top: 0.25rem; }}
  .callout {{ border-left: 4px solid #0284c7; background: #f0f9ff; padding: 1rem; border-radius: 0 8px 8px 0; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }}
  th, td {{ padding: 0.6rem 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
  code {{ font-family: monospace; background: #e2e8f0; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.8rem; }}
  .footer {{ margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; font-size: 0.75rem; color: #94a3b8; display: flex; justify-content: space-between; }}
  @media print {{
    body {{ padding: 0; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="no-print" style="margin-bottom:1rem;display:flex;justify-content:flex-end">
  <button onclick="window.print()" style="padding:0.5rem 1rem;background:#0284c7;color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600">Print / Save as PDF</button>
</div>
<div class="header">
  <div>
    <h1 class="title">IndraMesh Cryptographic Posture Assessment</h1>
    <div class="subtitle">Smart India Hackathon 2026 SIH26164 (NTRO) &middot; Post-Quantum Cryptography Migration Report</div>
  </div>
  <div style="text-align:right">
    <div style="font-weight:600;font-size:0.9rem">Target: {scan['target']}</div>
    <div style="font-size:0.8rem;color:#64748b">Scanned: {scan['scanned_at']}</div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <div class="card-label">Total Findings</div>
    <div class="card-value">{total}</div>
    <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem">{proven} Proven Use &middot; {capability} Library</div>
  </div>
  <div class="card">
    <div class="card-label">Quantum Risk Score</div>
    <div class="card-value" style="color:{'#dc2626' if score >= 60 else ('#ea580c' if score >= 40 else '#16a34a')}">{score} / 100</div>
    <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem">Policy: {active_policy.get('label', 'NQM')}</div>
  </div>
  <div class="card">
    <div class="card-label">Critical / Shor Break</div>
    <div class="card-value" style="color:#dc2626">{crit_count}</div>
    <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem">{high_count} High &middot; {med_count} Medium</div>
  </div>
  <div class="card">
    <div class="card-label">CycloneDX 1.7 CBOM</div>
    <div class="card-value" style="color:{'#16a34a' if cbom_val.get('ok') else '#dc2626'}">{'CONFORMANT' if cbom_val.get('ok') else 'NON-CONFORMANT'}</div>
    <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem">Ecma-424 Validated</div>
  </div>
</div>

<div class="callout">
  <strong style="color:#0369a1;font-size:0.95rem">Mosca Inequality Verdict (X + Y vs Z):</strong>
  <div style="margin-top:0.35rem;font-size:0.88rem;color:#334155">
    Data sensitivity lifetime <strong>X = {cfg.get('data_class', 'operational-record')}</strong> evaluated against
    quantum horizon <strong>Z = {cfg.get('z_years', 10.0)} years</strong> and policy deadline <strong>{active_policy.get('year', 2030)}</strong>.
    Harvest-Now-Decrypt-Later (HNDL) exposure identified on {crit_count} asymmetric cipher assets requiring immediate PQC replacement planning.
  </div>
</div>

{coverage_html}
<h3 style="margin-top:1.5rem;font-size:1.1rem;color:#0f172a">Actionable Post-Quantum Remediation Workstreams</h3>
<table>
  <thead>
    <tr>
      <th>Tier</th>
      <th>Artefact</th>
      <th>Vulnerable Primitive</th>
      <th>PQC Replacement Target</th>
      <th>Latest Safe Start</th>
      <th>Cost Band</th>
      <th>Migration Action</th>
    </tr>
  </thead>
  <tbody>
    {table_rows_html if table_rows_html else '<tr><td colspan="7">No remediation items pending.</td></tr>'}
  </tbody>
</table>

<div class="footer">
  <div>Generated by IndraMesh v2.0.0 &middot; Offline Ecma-424 / CycloneDX 1.7 Verified Engine</div>
  <div>Compliance: NIST IR 8547 &middot; FIPS 203 (ML-KEM) &middot; FIPS 204 (ML-DSA) &middot; FIPS 205 (SLH-DSA)</div>
</div>
</body>
</html>"""


@app.get("/api/report/html", response_class=HTMLResponse)
def get_executive_report_html():
    """Generate printable executive summary assessment report HTML."""
    return HTMLResponse(content=generate_executive_report_html())


@app.get("/api/report/download")
def download_executive_report_json():
    """Download executive assessment summary JSON."""
    scan = _STATE.get("last_scan")
    records = _STATE.get("last_records") or []
    if not scan:
        raise HTTPException(status_code=404, detail="No scan data available.")
    cfg = _STATE.get("last_config") or {}
    t_counts = tier_counts(records)
    score_raw = risk_score(records) if records else 0
    score_num = score_raw.get("score", 0) if isinstance(score_raw, dict) else (score_raw or 0)
    score_tier = score_raw.get("tier", "low") if isinstance(score_raw, dict) else "low"
    active_policy = POLICY_DEADLINES.get(cfg.get("policy", "india_dst_nqm"), {})

    report = {
        "report_type": "IndraMesh Post-Quantum Cryptographic Posture Assessment",
        "target": scan["target"],
        "scanned_at": scan["scanned_at"],
        "compliance_policy": active_policy,
        "risk_score": score_num,
        "risk_details": score_raw if isinstance(score_raw, dict) else {"score": score_num, "tier": score_tier},
        "summary": {
            "total_findings": len(records),
            "proven_use": proven_use(records),
            "capability_library": len(records) - proven_use(records),
            "tier_breakdown": t_counts,
        },
        "mosca_inequality": {
            "data_class": cfg.get("data_class"),
            "z_years": cfg.get("z_years"),
            "policy_deadline": active_policy.get("year"),
        },
        "cbom_validation": _STATE.get("last_cbom_validation"),
        # The blind spots travel with the report: a JSON export that lists findings but not
        # what could not be read invites the same "0 findings == clean" misreading the console
        # exists to prevent.
        "coverage": {
            **coverage_verdict(scan.get("coverage") or {}),
            "never_in_scope": (scan.get("coverage") or {}).get("never_in_scope", []),
        },
        "remediation_workstreams": queue_rows(records, deadline_year=active_policy.get("year")),
    }
    return Response(
        content=json.dumps(report, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="indramesh_executive_report.json"'},
    )


@app.get("/api/topology")
def get_topology():
    """Return nodes and links for cryptographic topology visualization."""
    records = _STATE.get("last_records") or []
    target = _STATE.get("last_target") or "App"
    root_label = os.path.basename(target.rstrip("/\\")) or "Target Estate"

    nodes = [{"id": "root", "label": root_label, "type": "root", "size": 32, "color": "#00F0FF"}]
    links = []
    file_nodes = set()
    artefact_nodes = set()

    for r in records:
        f_path = location(r).split(":")[0] if location(r) else "unknown"
        f_name = os.path.basename(f_path) or f_path
        f_id = f"file::{f_path}"

        if f_id not in file_nodes:
            file_nodes.add(f_id)
            nodes.append({
                "id": f_id,
                "label": f_name,
                "path": f_path,
                "type": "file",
                "size": 18,
                "color": "#94A3B8",
            })
            links.append({"source": "root", "target": f_id, "type": "contains"})

        art_name = r.get("name") or "crypto-asset"
        art_id = f"art::{f_path}::{art_name}::{r.get('rule_id')}"
        tier = r.get("tier", "LOW")
        color = TIER_COLOURS.get(tier, "#00F0FF")
        is_library = r.get("type") == "library"

        if art_id not in artefact_nodes:
            artefact_nodes.add(art_id)
            rec = r.get("recommendation") or {}
            target_alg = rec.get("algorithm") or ""
            nodes.append({
                "id": art_id,
                "label": f"{art_name} ({tier})",
                "name": art_name,
                "primitive": r.get("primitive", ""),
                "tier": tier,
                "hndl": (r.get("risk") or {}).get("hndl_exposed", False),
                "target_alg": target_alg,
                "type": "library" if is_library else "asset",
                "size": 22 if not is_library else 14,
                "color": "#64748B" if is_library else color,
                "details": {
                    "rule_id": r.get("rule_id"),
                    "scanner": r.get("scanner"),
                    "assurance": (r.get("assurance") or {}).get("value"),
                    "purpose": (r.get("purpose") or {}).get("value"),
                    "margin": (r.get("risk") or {}).get("margin"),
                },
            })
            links.append({
                "source": f_id,
                "target": art_id,
                "type": "library" if is_library else "invokes",
                "color": color,
            })

            # If there's a recommended PQC algorithm, add a PQC target node
            if target_alg and target_alg != "None":
                pqc_id = f"pqc::{target_alg}"
                if pqc_id not in artefact_nodes:
                    artefact_nodes.add(pqc_id)
                    nodes.append({
                        "id": pqc_id,
                        "label": f"PQC: {target_alg}",
                        "name": target_alg,
                        "type": "pqc_target",
                        "size": 24,
                        "color": "#10B981",
                    })
                links.append({
                    "source": art_id,
                    "target": pqc_id,
                    "type": "migrates_to",
                    "color": "#10B981",
                })

    return {"nodes": nodes, "links": links, "total_nodes": len(nodes), "total_links": len(links)}


@app.get("/api/topology/html")
def get_topology_html():
    """Return the raw interactive PyVis force-atlas HTML graph."""
    records = _STATE.get("last_records") or []
    html_content = generate_crypto_graph(records)
    return HTMLResponse(content=html_content)


# -----------------------------------------------------------------------------
# Secondary Sensor Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/sensors/certificates")
def run_certificates_sensor(req: ScanRequest):
    """Run the X.509 Certificate sensor against target."""
    target = req.target or _STATE.get("last_target") or "./dummy_target"
    abs_target = os.path.abspath(target)
    try:
        cert_out = scan_certificates(abs_target)
        records = []
        if isinstance(cert_out, tuple) and len(cert_out) >= 1:
            records = cert_out[0]
        elif isinstance(cert_out, list):
            records = cert_out
        elif isinstance(cert_out, dict):
            records = cert_out.get("findings") or cert_out.get("certificates") or []

        return {
            "status": "success",
            "summary": certificate_summary(records),
            "rows": certificate_rows(records),
            "count": len(records),
        }
    except Exception as exc:
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}", "rows": [], "count": 0}


@app.post("/api/sensors/dependencies")
def run_dependencies_sensor(req: ScanRequest):
    """Run the Dependency Manifest sensor."""
    target = req.target or _STATE.get("last_target") or "./dummy_target"
    abs_target = os.path.abspath(target)
    try:
        findings = DependencyScanner().scan(abs_target)
        return {
            "status": "success",
            "summary": dependency_summary(findings),
            "rows": dependency_rows(findings),
            "count": len(findings),
        }
    except Exception as exc:
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}", "rows": [], "count": 0}


@app.post("/api/sensors/verification")
def run_verification_sensor(req: ScanRequest):
    """Run Post-Migration Verification sensor."""
    target = req.target or _STATE.get("last_target") or "./dummy_target"
    abs_target = os.path.abspath(target)
    try:
        report = verify_migration(abs_target)
        if isinstance(report, tuple):
            report = report[0]
        return {
            "status": "success",
            "summary": verification_summary(report),
            "rows": verification_rows(report),
            "report": report,
        }
    except Exception as exc:
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}", "rows": [], "report": {}}


@app.post("/api/sensors/network")
def run_network_sensor(req: ProbeRequest):
    """Run vetted network handshake sensor against operator-named endpoints."""
    from engine.netprobe import probe_endpoints
    from engine.netpolicy import NetPolicy
    try:
        policy = NetPolicy(allow_private=req.allow_private)
        report = probe_endpoints(req.endpoints, policy=policy, enable=True)
        return {"status": "success", "report": report}
    except Exception as exc:
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}", "report": {}}


@app.post("/api/browse")
def browse_filesystem(req: BrowseRequest):
    """Secure directory browser for the target picker dialog."""
    path = req.path or os.getcwd()
    try:
        p = Path(path).resolve()
        if not p.exists():
            p = Path(os.getcwd()).resolve()

        if p.is_file():
            p = p.parent

        dirs = []
        files = []
        try:
            for item in sorted(p.iterdir()):
                try:
                    if item.is_dir() and not item.name.startswith("."):
                        dirs.append(item.name)
                    elif item.is_file() and not item.name.startswith("."):
                        files.append(item.name)
                except PermissionError:
                    continue
        except PermissionError:
            pass

        return {
            "current": str(p),
            "parent": str(p.parent) if p.parent != p else None,
            "directories": dirs[:100],
            "files": files[:100],
        }
    except Exception as exc:
        return {"error": str(exc), "current": os.getcwd(), "directories": [], "files": []}


# -----------------------------------------------------------------------------
# Static Web App Mount
# -----------------------------------------------------------------------------
_WEB_STATIC = os.path.join(_REPO_ROOT, "web", "static")
if os.path.exists(_WEB_STATIC):
    app.mount("/static", StaticFiles(directory=_WEB_STATIC), name="static")


@app.get("/", response_class=HTMLResponse)
def index_page():
    """Serve the single-page modern cybersecurity HUD web app."""
    index_file = os.path.join(_WEB_STATIC, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>IndraMesh Web UI - static files not found</h2>", status_code=404)


@app.get("/_stcore/health")
def st_health():
    """Handle any lingering browser tabs from the previous Streamlit session."""
    return {"status": "ok"}


@app.get("/_stcore/host-config")
def st_host_config():
    return {"allowedOrigins": ["*"]}


@app.websocket("/_stcore/stream")
async def st_websocket_stream(websocket: WebSocket):
    """Gracefully keep stale Streamlit websocket connections idle so they don't reconnect in a loop."""
    await websocket.accept()
    try:
        while True:
            await asyncio.sleep(60)
    except Exception:
        pass
