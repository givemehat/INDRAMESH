"""CMDB / cloud inventory loading helpers (CSV into Record dataclasses)."""

from dataclasses import dataclass

import csv
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_COVERAGE_INVENTORY = "docs/inventory/home_lab.csv"
DEFAULT_LOCAL_INVENTORY = "docs/inventory/home_lab.csv"
DEFAULT_COVERAGE_SCAN = "out/coverage_scan.json"
DEFAULT_COVERAGE_CLOUD = "out/coverage_cloud.json"

_OWNED_TRUE = {"1", "true", "yes", "y"}


def _default_path(name):
    return os.environ.get(name, "").strip() or {
        "INDRAMESH_COVERAGE_INVENTORY": DEFAULT_COVERAGE_INVENTORY,
        "INDRAMESH_LOCAL_INVENTORY": DEFAULT_LOCAL_INVENTORY,
        "INDRAMESH_COVERAGE_SCAN": DEFAULT_COVERAGE_SCAN,
        "INDRAMESH_COVERAGE_CLOUD": DEFAULT_COVERAGE_CLOUD,
    }[name]


@dataclass
class Record:
    """One inventory item: what exists, where, and whether this org controls it."""

    id: str
    name: str
    kind: str
    location: str
    owned: bool
    probe_status: str | None = None


def _read_csv(path):
    p = Path(path)
    if not p.exists():
        return []
    with p.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _parse_owned(value):
    return str(value or "1").strip().lower() in _OWNED_TRUE


def load_records(inventory_path=""):
    """Read the CMDB / cloud inventory CSV into a list of Record objects."""
    rows = _read_csv(inventory_path or _default_path("INDRAMESH_COVERAGE_INVENTORY")) or []
    records = []
    for row in rows:
        rec_id = str(row.get("id") or row.get("repo") or "").strip()
        # Enterprise-grade: skip blank-id rows so a trailing newline or an
        # untracked placeholder never inflates `expected`.
        if not rec_id:
            continue
        records.append(
            Record(
                id=rec_id,
                name=str(row.get("name") or row.get("repo") or "").strip(),
                kind=str(row.get("kind") or "platform").strip(),
                location=str(row.get("location") or "").strip(),
                owned=_parse_owned(row.get("owned", "1")),
            )
        )
    return records


def load_scan(scan_path=""):
    """Map scan id -> {status} from the coverage scan artifact."""
    path = scan_path or _default_path("INDRAMESH_COVERAGE_SCAN")
    if not Path(path).exists():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {str(k): (v if isinstance(v, dict) else {"status": v}) for k, v in data.items()}


def load_cloud(cloud_path=""):
    """Read the cloud / external inventory CSV (rows not under org control)."""
    return _read_csv(cloud_path or _default_path("INDRAMESH_COVERAGE_CLOUD"))
