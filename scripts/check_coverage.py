"""Smoke check: build the artifact and validate the four coverage buckets."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import engine.coverage_reconcile as cr  # noqa: E402
from engine.coverage_records import Record  # noqa: E402


def _load_csv(name):
    with open(ROOT / "docs" / "inventory" / name, newline="", encoding="utf-8") as fh:
        return list(__import__("csv").DictReader(fh))


def main():
    records = [
        Record(id=r["id"], name=r["name"], kind=r["kind"], location=r["location"],
               owned=True)
        for r in _load_csv("home_lab.csv")
    ]
    cloud_rows = _load_csv("cloud.csv")
    scan = {}
    for r in _load_csv("home_lab.csv"):
        if r["id"] == "SLC11":
            scan[r["id"]] = {"status": "inaccessible"}
        elif r["id"] in {"SLC01", "SLC02", "SLC03", "SLC04", "SLC05",
                         "SLC06", "SLC07", "SLC08", "SLC09", "SLC010"}:
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
