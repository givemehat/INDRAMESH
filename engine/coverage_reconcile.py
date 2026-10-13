"""Coverage reconciliation: turns scan state into the expected/10-scanned/1-inaccessible/1-unknown
shape, plus a control-gap report (Liviu's outsider criterion).

Inputs (all optional, env-overridable):
  * INDRAMESH_COVERAGE_INVENTORY   CMDB/cloud CSV (owned=1 local, owned=0 cloud)
  * INDRAMESH_LOCAL_INVENTORY      local CSV this org controls (owned=1)
  * INDRAMESH_COVERAGE_SCAN        JSON id -> {status: scanned|inaccessible|unknown}
  * INDRAMESH_COVERAGE_CLOUD       cloud CSV (out-of-scope rows)

Report fields: expected, scanned, inaccessible, unknown, out_of_scope,
not_in_inventory, control_gap_rows, diff, sample.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path
from typing import Any

from .coverage_records import Record, load_cloud, load_records, load_scan

DEFAULT_OUT = "out/coverage_reconciliation.json"

_PROBE_STATUSES = {"scanned", "inaccessible", "unknown"}


def _bucket(rec):
    if rec.probe_status is None:
        return "unknown"
    if rec.probe_status not in _PROBE_STATUSES:
        raise ValueError("unknown probe status: " + str(rec.probe_status))
    return rec.probe_status


def reconcile(records=None, scan_results=None, cloud_rows=None):
    """Build the coverage report from records plus probe statuses plus the cloud catalog."""
    records = records if records is not None else load_records()
    scan_results = scan_results if scan_results is not None else load_scan()
    cloud_rows = cloud_rows if cloud_rows is not None else load_cloud()

    for rec in records:
        rec.probe_status = scan_results.get(rec.id, {}).get("status", "unknown")
        # Enterprise-grade: fail fast on invalid probe status instead of
        # silently yielding scanned=0/inaccessible=0/unknown=0.
        _bucket(rec)

    scoped = [r for r in records if r.owned]
    out_of_scope = [r.get("id") for r in cloud_rows if r.get("id")]

    control_gap_rows = []
    for rec in records:
        if not rec.owned:
            continue
        if rec.probe_status == "inaccessible":
            control_gap_rows.append({
                "id": rec.id, "name": rec.name, "location": rec.location,
                "reason": "probe failed on instrumented target"})
        elif rec.probe_status == "unknown":
            control_gap_rows.append({
                "id": rec.id, "name": rec.name, "location": rec.location,
                "reason": "no probe issued for controlled target"})

    outsider_ids = {r.id for r in records if not r.owned}
    not_tracked = [r for r in cloud_rows if r.get("id") not in outsider_ids]

    scanned_inventory = {r.id: r for r in scoped if r.probe_status == "scanned"}
    cloud_ids = {r.get("id") for r in cloud_rows if r.get("id")}
    diff = {
        "added": sorted(cloud_ids - set(scanned_inventory)),
        "missing": sorted(set(scanned_inventory) - cloud_ids),
        "changed": [],
    }

    return {
        "expected": len(records),
        "scanned": sum(1 for r in scoped if r.probe_status == "scanned"),
        "inaccessible": sum(1 for r in scoped if r.probe_status == "inaccessible"),
        "unknown": sum(1 for r in scoped if r.probe_status == "unknown"),
        "out_of_scope": out_of_scope,
        "not_in_inventory": [
            {"id": r.get("id"), "name": r.get("name")} for r in not_tracked],
        "control_gap_rows": control_gap_rows,
        "diff": diff,
        "sample": [{
            "id": r.id, "name": r.name, "kind": r.kind,
            "location": r.location, "owned": r.owned}
            for r in sorted(scoped, key=lambda r: r.id)][:12],
    }


def main(argv=None):
    """CLI entry point: write coverage_reconciliation.json to the output path."""
    argv = list(argv or sys.argv[1:])
    out_path = Path(argv.pop(0)) if argv else Path(DEFAULT_OUT)
    report = reconcile()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("[IndraMesh] coverage reconciliation -> " + str(out_path))
    print("[IndraMesh] expected=" + str(report["expected"])
          + " scanned=" + str(report["scanned"])
          + " inaccessible=" + str(report["inaccessible"])
          + " unknown=" + str(report["unknown"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
