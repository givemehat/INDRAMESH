"""Generate the coverage reconciliation artifact for the demo inventory.

Demo fixtures (all in docs/inventory/):
  home_lab.csv  - 12 systems this org controls (owned=1). Scanned: 10, inaccessible:
                  1 (SLC11), unknown: 1 (SLC12, never probed).
  cloud.csv     - 3 cloud / external rows (owned=0) that no control plane in this org
                  owns; used to demonstrate Liviu's outsider criterion.

The resulting artifact lives at out/coverage_reconciliation.json and carries the
expected/10-scanned/1-inaccessible/1-unknown shape, plus control_gap_rows and the
diff against the cloud catalog.
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import engine.coverage_reconcile as cr  # noqa: E402
from engine.coverage_records import Record  # noqa: E402


def _load(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main():
    records = []
    for row in _load(ROOT / "docs/inventory/home_lab.csv"):
        records.append(
            Record(
                id=row["id"], name=row["name"], kind=row["kind"],
                location=row["location"],                 owned=True,
            )
        )
    cloud_rows = _load(ROOT / "docs/inventory/cloud.csv")
    scan_results = {}
    for row in _load(ROOT / "docs/inventory/home_lab.csv"):
        rid = row["id"]
        if rid == "SLC11":
            scan_results[rid] = {"status": "inaccessible"}
        elif rid in {"SLC01", "SLC02", "SLC03", "SLC04", "SLC05",
                     "SLC06", "SLC07", "SLC08", "SLC09", "SLC10"}:
            scan_results[rid] = {"status": "scanned"}
    report = cr.reconcile(records=records, scan_results=scan_results,
                           cloud_rows=cloud_rows)

    out = ROOT / "out" / "coverage_reconciliation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print("[IndraMesh] coverage artifact -> " + str(out))
    print("[IndraMesh] expected=" + str(report["expected"])
          + " scanned=" + str(report["scanned"])
          + " inaccessible=" + str(report["inaccessible"])
          + " unknown=" + str(report["unknown"]))
    print("[IndraMesh] out_of_scope:", report["out_of_scope"])
    print("[IndraMesh] not_in_inventory:", report["not_in_inventory"])
    print("[IndraMesh] control_gap_rows:", report["control_gap_rows"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
