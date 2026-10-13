"""Smoke check: build the artifact and validate the four coverage buckets."""
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import engine.coverage_reconcile as cr  # noqa: E402
from engine.coverage_records import Record, _default_path  # noqa: E402


def _load_csv_env(env_name, fallback_name):
    # Enterprise-grade: respect INDRAMESH_* overrides so CI can point at
    # fixtures; fall back to the checked-in home-lab inventory for smoke.
    raw = os.environ.get(env_name, "").strip()
    if raw:
        p = Path(raw)
        if p.exists():
            with open(p, newline="", encoding="utf-8") as fh:
                return list(csv.DictReader(fh))
        return []
    with open(ROOT / "docs" / "inventory" / fallback_name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main():
    home_rows = _load_csv_env("INDRAMESH_LOCAL_INVENTORY", "home_lab.csv")
    cloud_rows = _load_csv_env("INDRAMESH_COVERAGE_CLOUD", "cloud.csv")
    # Fallback: legacy smoke used docs/inventory/cloud.csv directly.
    if not cloud_rows:
        with open(ROOT / "docs" / "inventory" / "cloud.csv", newline="", encoding="utf-8") as fh:
            import csv as _csv
            cloud_rows = list(_csv.DictReader(fh))
    records = [
        Record(id=r["id"], name=r["name"], kind=r["kind"], location=r["location"],
               owned=True)
        for r in home_rows
    ]
    scan = {}
    for r in home_rows:
        if r["id"] == "SLC11":
            scan[r["id"]] = {"status": "inaccessible"}
        elif r["id"] in {"SLC01", "SLC02", "SLC03", "SLC04", "SLC05",
                         "SLC06", "SLC07", "SLC08", "SLC09", "SLC10"}:
            scan[r["id"]] = {"status": "scanned"}
    report = cr.reconcile(records=records, scan_results=scan, cloud_rows=cloud_rows)

    artifact = ROOT / "out" / "coverage_reconciliation.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("[IndraMesh] artifact written ->", artifact)
    print("[IndraMesh] expected=%d scanned=%d inaccessible=%d unknown=%d" % (
        report["expected"], report["scanned"], report["inaccessible"],
        report["unknown"]))
    print("[IndraMesh] out_of_scope:", report["out_of_scope"])
    print("[IndraMesh] not_in_inventory:", report["not_in_inventory"])
    print("[IndraMesh] control_gap_rows:", report["control_gap_rows"])

    assert report["expected"] == 12, report
    assert report["scanned"] == 10, report
    assert report["inaccessible"] == 1, report
    assert report["unknown"] == 1, report
    assert set(report["out_of_scope"]) == {"CLOUD-01", "CLOUD-02", "CLOUD-03"}, report
    assert len(report["not_in_inventory"]) == 3, report
    assert all(g["reason"] for g in report["control_gap_rows"]), report
    print("[IndraMesh] smoke check ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
