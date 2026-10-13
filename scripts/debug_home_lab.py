import csv
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/inventory/home_lab.csv")
with open(path, newline="", encoding="utf-8") as fh:
    rows = list(csv.DictReader(fh))
print("rows:", len(rows))
if rows:
    print("keys:", list(rows[0].keys()))
    for r in rows[:3]:
        print(r)
