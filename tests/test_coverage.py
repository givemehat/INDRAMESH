import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.coverage_records import Record, load_records, load_scan, load_cloud
from engine.coverage_reconcile import reconcile


class TestCoverageRecords(unittest.TestCase):
    def test_record_defaults(self):
        r = Record(id="X1", name="test", kind="platform", location="loc", owned=True)
        self.assertEqual(r.id, "X1")
        self.assertEqual(r.name, "test")
        self.assertEqual(r.kind, "platform")
        self.assertEqual(r.location, "loc")
        self.assertTrue(r.owned)
        self.assertIsNone(r.probe_status)

    def test_record_probe_status(self):
        r = Record(id="X1", name="test", kind="platform", location="loc", owned=True,
                   probe_status="scanned")
        self.assertEqual(r.probe_status, "scanned")

    def test_load_records_from_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False,
                                         newline="", encoding="utf-8") as fh:
            fh.write("id,name,kind,location,owned\n")
            fh.write("A1,alpha,platform,loc1,1\n")
            fh.write("B2,beta,registry,loc2,0\n")
            tmp = fh.name
        try:
            records = load_records(tmp)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].id, "A1")
            self.assertTrue(records[0].owned)
            self.assertEqual(records[1].id, "B2")
            self.assertFalse(records[1].owned)
        finally:
            os.unlink(tmp)

    def test_load_records_missing_file(self):
        records = load_records("/nonexistent/path.csv")
        self.assertEqual(records, [])

    def test_load_scan_from_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                         encoding="utf-8") as fh:
            json.dump({"A1": {"status": "scanned"}, "B2": {"status": "inaccessible"}}, fh)
            tmp = fh.name
        try:
            scan = load_scan(tmp)
            self.assertEqual(scan["A1"]["status"], "scanned")
            self.assertEqual(scan["B2"]["status"], "inaccessible")
        finally:
            os.unlink(tmp)

    def test_load_scan_missing_file(self):
        scan = load_scan("/nonexistent/scan.json")
        self.assertEqual(scan, {})

    def test_load_cloud_from_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False,
                                         newline="", encoding="utf-8") as fh:
            fh.write("id,name,kind,location,owned\n")
            fh.write("C1,cloud1,registry,ext1,0\n")
            tmp = fh.name
        try:
            rows = load_cloud(tmp)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["id"], "C1")
        finally:
            os.unlink(tmp)


class TestCoverageReconcile(unittest.TestCase):
    def _make_records(self):
        return [
            Record(id="SLC01", name="s1", kind="networking", location="L1", owned=True),
            Record(id="SLC02", name="s2", kind="networking", location="L2", owned=True),
            Record(id="SLC03", name="s3", kind="networking", location="L3", owned=True),
            Record(id="SLC11", name="t1", kind="telemetry", location="L11", owned=True),
            Record(id="SLC12", name="t2", kind="telemetry", location="L12", owned=True),
        ]

    def test_reconcile_counts(self):
        records = self._make_records()
        scan = {
            "SLC01": {"status": "scanned"},
            "SLC02": {"status": "scanned"},
            "SLC03": {"status": "scanned"},
            "SLC11": {"status": "inaccessible"},
        }
        cloud_rows = [{"id": "CLOUD-01"}, {"id": "CLOUD-02"}]
        report = reconcile(records=records, scan_results=scan, cloud_rows=cloud_rows)

        self.assertEqual(report["expected"], 5)
        self.assertEqual(report["scanned"], 3)
        self.assertEqual(report["inaccessible"], 1)
        self.assertEqual(report["unknown"], 1)

    def test_reconcile_out_of_scope(self):
        records = self._make_records()
        scan = {r.id: {"status": "scanned"} for r in records}
        cloud_rows = [{"id": "CLOUD-01"}, {"id": "CLOUD-02"}, {"id": "CLOUD-03"}]
        report = reconcile(records=records, scan_results=scan, cloud_rows=cloud_rows)

        self.assertEqual(set(report["out_of_scope"]), {"CLOUD-01", "CLOUD-02", "CLOUD-03"})

    def test_reconcile_control_gap_inaccessible(self):
        records = self._make_records()
        scan = {"SLC11": {"status": "inaccessible"}}
        report = reconcile(records=records, scan_results=scan, cloud_rows=[])

        gap_ids = [g["id"] for g in report["control_gap_rows"]]
        self.assertIn("SLC11", gap_ids)
        self.assertTrue(all(g["reason"] for g in report["control_gap_rows"]))

    def test_reconcile_control_gap_unknown(self):
        records = self._make_records()
        scan = {}
        report = reconcile(records=records, scan_results=scan, cloud_rows=[])

        gap_ids = [g["id"] for g in report["control_gap_rows"]]
        self.assertIn("SLC01", gap_ids)
        self.assertIn("SLC12", gap_ids)

    def test_reconcile_not_in_inventory(self):
        records = self._make_records()
        scan = {r.id: {"status": "scanned"} for r in records}
        cloud_rows = [{"id": "CLOUD-01"}, {"id": "CLOUD-02"}]
        report = reconcile(records=records, scan_results=scan, cloud_rows=cloud_rows)

        inv_ids = {r["id"] for r in report["not_in_inventory"]}
        self.assertEqual(inv_ids, {"CLOUD-01", "CLOUD-02"})

    def test_reconcile_diff(self):
        records = self._make_records()
        scan = {"SLC01": {"status": "scanned"}, "SLC02": {"status": "scanned"}}
        cloud_rows = [{"id": "SLC01"}, {"id": "CLOUD-01"}]
        report = reconcile(records=records, scan_results=scan, cloud_rows=cloud_rows)

        self.assertIn("CLOUD-01", report["diff"]["added"])
        self.assertIn("SLC02", report["diff"]["missing"])

    def test_reconcile_sample(self):
        records = self._make_records()
        scan = {r.id: {"status": "scanned"} for r in records}
        report = reconcile(records=records, scan_results=scan, cloud_rows=[])

        self.assertEqual(len(report["sample"]), 5)
        self.assertEqual(report["sample"][0]["id"], "SLC01")

    def test_reconcile_empty(self):
        report = reconcile(records=[], scan_results={}, cloud_rows=[])
        self.assertEqual(report["expected"], 0)
        self.assertEqual(report["scanned"], 0)
        self.assertEqual(report["inaccessible"], 0)
        self.assertEqual(report["unknown"], 0)
        self.assertEqual(report["out_of_scope"], [])
        self.assertEqual(report["control_gap_rows"], [])

    def test_reconcile_unowned_records_excluded_from_scoped(self):
        records = [
            Record(id="A1", name="a", kind="k", location="l", owned=True),
            Record(id="B2", name="b", kind="k", location="l", owned=False),
        ]
        scan = {"A1": {"status": "scanned"}}
        report = reconcile(records=records, scan_results=scan, cloud_rows=[])

        self.assertEqual(report["expected"], 2)
        self.assertEqual(report["scanned"], 1)


if __name__ == "__main__":
    unittest.main()
