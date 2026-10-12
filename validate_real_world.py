"""Real-world validation against a large third-party codebase (Google Tink, Java).

WHY THIS FILE WAS REWRITTEN
---------------------------
The previous version printed "Skipping schema validation due to 404 on schema URL..." and then
imported `jsonschema` and `requests` without using either. It scanned `data/tink-java/src`, a path
that `.gitignore` excludes and that nothing in the repository fetches, so on a clean clone it
failed with a bare FileNotFoundError. It also wrote `examples/tink_scan_output.json` in the OLD
CycloneDX 1.6 shape, with `primitive: "neural-detected"` and un-namespaced properties -- exactly
the defects the code review claimed had been fixed. Shipping that file as evidence of conformance
undermined the claim it was meant to support.

WHAT IT DOES NOW
----------------
  * Fetches the corpus itself, at a PINNED tag, so a clean clone reproduces the run.
  * Validates the emitted document against the vendored CycloneDX 1.7 schema, offline, and
    EXITS NON-ZERO if it does not validate. A validation step that cannot fail is decoration.
  * Refuses to write an example it has not just validated.

    python validate_real_world.py            # fetch if needed, scan, validate, write
    python validate_real_world.py --check    # validate the committed example, write nothing
"""
import argparse
import json
import os
import subprocess
import sys
import time

import jsonschema

from engine.cbom import generate_cbom
from engine.mosca import DEFAULT_POLICY, DEFAULT_Z, calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.scanner import IndraMeshScanner

REPO = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(REPO, "data", "tink-java")
# Pinned so the measurement is reproducible rather than tracking upstream master.
CORPUS_REPO = "https://github.com/tink-crypto/tink-java"
CORPUS_SHA = "v1.15.0"
SCHEMA = os.path.join(REPO, "schemas", "bom-1.7.schema.json")
EXAMPLE = os.path.join(REPO, "examples", "tink_scan_output.json")


def ensure_corpus():
    """Clone the corpus at a pinned tag if it is not already present."""
    if os.path.isdir(os.path.join(CORPUS_DIR, "src")):
        print(f"[*] corpus already present: {os.path.relpath(CORPUS_DIR, REPO)}")
        return True
    os.makedirs(os.path.dirname(CORPUS_DIR), exist_ok=True)
    print(f"[*] fetching {CORPUS_REPO} @ {CORPUS_SHA} (one-off)...")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--branch", CORPUS_SHA,
                        CORPUS_REPO, CORPUS_DIR], check=True, timeout=900)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"[!] could not fetch the corpus: {exc}")
        print("    Fetch it manually, or use the pinned corpora that ARE reachable:")
        print("      python benchmark/run_benchmark.py")
        return False
    return True


def validate_document(document):
    """Validate against the vendored schema. Returns a list of human-readable errors."""
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(document),
                    key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors]


def run(check_only=False):
    if check_only:
        if not os.path.exists(EXAMPLE):
            print(f"[!] no committed example at {os.path.relpath(EXAMPLE, REPO)}")
            return 2
        with open(EXAMPLE, encoding="utf-8") as fh:
            document = json.load(fh)
        print(f"[*] checking committed example: {os.path.relpath(EXAMPLE, REPO)}")
    else:
        if not ensure_corpus():
            return 2
        target = os.path.join(CORPUS_DIR, "src")
        print(f"[*] scanning {os.path.relpath(target, REPO)} ...")
        started = time.time()
        scanner = IndraMeshScanner(enable_ml=False)
        findings = scanner.scan_directory(target)
        elapsed = time.time() - started
        print(f"[*] scanned {scanner.coverage['files_scanned']} files in {elapsed:.1f}s; "
              f"{len(findings)} findings")

        for f in findings:
            # Z and policy are passed EXPLICITLY rather than relying on the defaults, so that
            # this report's numbers are reproducible from the constants named here instead of
            # from whatever the defaults happen to be. A validation report that silently
            # inherits a default is a report nobody can re-derive.
            f["risk"] = calculate_risk(f, z_collapse_time=DEFAULT_Z, policy=DEFAULT_POLICY)
            f["recommendation"] = get_pqc_recommendation(f)
        document = json.loads(generate_cbom(
            findings, enriched=True, subject_name="tink-java",
            subject_version=CORPUS_SHA, coverage=scanner.coverage_manifest(findings)))

        tiers = {}
        for f in findings:
            tiers[f["risk"]["tier"]] = tiers.get(f["risk"]["tier"], 0) + 1
        print(f"[*] tiers: {tiers}")

    errors = validate_document(document)
    print(f"[*] CycloneDX {document.get('specVersion')} schema validation: "
          f"{'VALID' if not errors else 'INVALID'}")
    for e in errors[:10]:
        print(f"    - {e}")
    if errors:
        print(f"\n[!] {len(errors)} schema violation(s). NOT writing the example.")
        return 1

    if not check_only:
        os.makedirs(os.path.dirname(EXAMPLE), exist_ok=True)
        with open(EXAMPLE, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=2)
        print(f"[+] validated example written to {os.path.relpath(EXAMPLE, REPO)}")

    counts = {}
    for c in document.get("components", []):
        counts[c.get("name", "?")] = counts.get(c.get("name", "?"), 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:10]
    print("\n[*] top algorithms: " + ", ".join(f"{n}={c}" for n, c in top))
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="validate the committed example without fetching or writing")
    sys.exit(run(ap.parse_args().check))

