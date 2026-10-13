"""IndraMesh headless scanner for CI/CD pipelines and the command line.

    python cli.py ./target --format cbom --z 10 --policy india-dst-nqm
    python cli.py ./image.tar --format text
    python cli.py . --format cbom --no-ml --out reports/
    python cli.py . --format sarif --out reports/    # upload to GitHub code scanning

Exit codes:  0 = no finding at or above --fail-on   1 = threshold exceeded   2 = scan error
"""
import argparse
import hashlib
import json
import os
import sys

from engine.scanner import IndraMeshScanner
from engine.mosca import calculate_risk, DEFAULT_Z, POLICY_DEADLINES, Z_PRESETS
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom
from engine.sarif import generate_sarif
from engine.attest import build_payload, sign_attestation
from engine.coverage_reconcile import reconcile as reconcile_coverage

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _z_presets_help():
    return ", ".join("{}={}".format(name, preset["years"]) for name, preset in Z_PRESETS.items())


def _write_attestation(out_dir, subject, output_format, coverage, report_path, key):
    """Write a signed attestation sidecar, or skip it visibly when no key is configured.

    The key comes from the argument or the INDRAMESH_ATTEST_KEY environment variable --
    deliberately NOT from a --attest-key flag, because a command-line argument is visible
    in `ps` and shell history on shared CI runners. With no key the attestation is skipped
    loudly rather than emitted unsigned: an unsigned "attestation" is a false assurance.
    """
    if not key:
        key = os.environ.get("INDRAMESH_ATTEST_KEY") or None
    if not key:
        print("[ ] Attestation  -> skipped (set INDRAMESH_ATTEST_KEY to sign this report)")
        return None
    with open(report_path, "rb") as fh:
        report_digest = hashlib.sha256(fh.read()).hexdigest()
    payload = build_payload(subject=subject, output_format=output_format,
                            coverage=coverage, report_digest=report_digest)
    attestation = sign_attestation(payload, key)
    att_path = os.path.join(out_dir, "indramesh_attestation.json")
    with open(att_path, "w", encoding="utf-8") as fh:
        json.dump(attestation, fh, indent=2)
    print(f"[+] Attestation   -> {att_path}")
    return att_path


def run_headless_scan(target_dir, output_format="text", z_time=DEFAULT_Z,
                      policy="india_dst_nqm", enable_ml=True, out_dir=".",
                      fail_on="CRITICAL", subject_name=None, attest_key=None):
    print(f"[*] IndraMesh scan starting on: {target_dir}")
    print(f"    Z={z_time}y  policy={policy}"
          f"  policy deadline={POLICY_DEADLINES.get(policy, {}).get('year', 'n/a')}")

    scanner = IndraMeshScanner(enable_ml=enable_ml)
    findings = scanner.scan_directory(target_dir)
    coverage = scanner.coverage_manifest(findings)

    print(f"[*] Files scanned: {coverage['files_scanned']}  skipped: {coverage['files_skipped']}")
    print(f"    ML engine: {coverage['ml_reason']}")
    # The raw total alone is misleading: it mixes proven call sites with capabilities nothing
    # calls. Both numbers are shown so the reader can tell which is which.
    print(f"[*] Findings: {coverage['findings_total']} total, "
          f"{coverage['proven_use']} with proven use (used/observed), "
          f"{coverage['unresolved_purpose']} with unresolved purpose")
    print(f"    Assurance: {json.dumps(coverage['assurance_histogram'])}")
    if coverage["errors"]:
        print(f"[!] {len(coverage['errors'])} file(s) could not be read -- these are NOT clean:")
        for err in coverage["errors"][:10]:
            print(f"      - {err['file']}: {err['reason']}")
        if len(coverage["errors"]) > 10:
            print(f"      ... and {len(coverage['errors']) - 10} more")

    for f in findings:
        f["risk"] = calculate_risk(f, z_collapse_time=z_time, policy=policy)
        f["recommendation"] = get_pqc_recommendation(f)

    counts = {t: sum(1 for f in findings if f["risk"]["tier"] == t) for t in SEVERITY_ORDER}
    print(f"[*] {len(findings)} artefact(s): "
          + "  ".join(f"{t}={counts[t]}" for t in SEVERITY_ORDER))

    if output_format == "cbom":
        os.makedirs(out_dir, exist_ok=True)
        cbom_path = os.path.join(out_dir, "indramesh_report.json")
        with open(cbom_path, "w", encoding="utf-8") as fh:
            fh.write(generate_cbom(findings, enriched=True,
                                    subject_name=subject_name or os.path.basename(target_dir.rstrip("/\\")),
                                    coverage=coverage))
        recs_path = os.path.join(out_dir, "indramesh_recommendations.json")
        with open(recs_path, "w", encoding="utf-8") as fh:
            json.dump([{"target": f["file"], "line": f.get("line"), "artefact": f["name"],
                        "primitive": f["primitive"], "risk": f["risk"],
                        "recommendation": f["recommendation"]} for f in findings], fh, indent=2)
        cov_path = os.path.join(out_dir, "indramesh_coverage.json")
        with open(cov_path, "w", encoding="utf-8") as fh:
            json.dump(coverage, fh, indent=2)
        print(f"[+] CBOM          -> {cbom_path}")
        print(f"[+] Recommendations-> {recs_path}")
        print(f"[+] Coverage      -> {cov_path}")
        _write_attestation(out_dir,
                           subject_name or os.path.basename(target_dir.rstrip("/\\")),
                           "cbom", coverage, cbom_path, attest_key)
    elif output_format == "sarif":
        # SARIF is the CI-facing format: one file, uploadable to GitHub code scanning, where
        # each finding becomes an annotation on the diff. Paths are made relative to the scan
        # root so the artefact does not leak the builder's directory layout.
        os.makedirs(out_dir, exist_ok=True)
        sarif_path = os.path.join(out_dir, "indramesh.sarif")
        with open(sarif_path, "w", encoding="utf-8") as fh:
            fh.write(generate_sarif(findings, root=target_dir, coverage=coverage))
        print(f"[+] SARIF 2.1.0   -> {sarif_path}")
        print("    upload with:  github/codeql-action/upload-sarif (Security tab annotations)")
        _write_attestation(out_dir,
                           subject_name or os.path.basename(target_dir.rstrip("/\\")),
                           "sarif", coverage, sarif_path, attest_key)
    else:
        for f in findings:
            r = f["risk"]
            flag = " [HNDL EXPOSED]" if r["hndl_exposed"] else ""
            print(f"  - {f['name']:<12} {r['tier']:<9} X+Y={r['x_y']:>6} vs Z={r['z']:<5}"
                  f" margin={r['margin']:>6}{flag}  {f['file']}:{f.get('line')}")
            print(f"      {f['recommendation']['algorithm']}")

    print("\n[-- NOT IN SCOPE (require a different sensor or an attestation) --]")
    for gap in coverage["never_in_scope"]:
        print(f"    - {gap}")

    threshold = SEVERITY_ORDER.index(fail_on)
    breaches = [f for f in findings if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    if breaches:
        print(f"\n[!] {len(breaches)} finding(s) at or above {fail_on}. Failing build.")
        return 1
    print(f"\n[+] No findings at or above {fail_on}.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="IndraMesh headless cryptographic scanner")
    parser.add_argument("target", help="Directory, file or container-image tar to scan")
    parser.add_argument("--format", choices=["text", "cbom", "sarif"], default="text",
                        help="text for humans, cbom for a CycloneDX 1.7 inventory, "
                             "sarif for GitHub code scanning / any SARIF viewer")
    parser.add_argument("--z", type=float, default=DEFAULT_Z,
                        help="Years until a CRQC. Presets: " + _z_presets_help())
    parser.add_argument("--policy", default="india_dst_nqm", choices=sorted(POLICY_DEADLINES))
    parser.add_argument("--out", default=".", help="Output directory for artefacts")
    parser.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    parser.add_argument("--no-ml", action="store_true",
                        help="Disable the PyTorch transformer (regex-only mode; no torch needed)")
    parser.add_argument("--subject", default=None, help="Subject name recorded in the CBOM metadata")
    parser.add_argument("--coverage", action="store_true",
                        help="Run coverage reconciliation and write out/coverage_reconciliation.json")
    args = parser.parse_args(argv)

    if not os.path.exists(args.target):
        print(f"[!] Target not found: {args.target}")
        return 2
    if args.coverage:
        report = reconcile_coverage()
        # Enterprise-grade: default --out "." still lands in the canonical
        # out/coverage_reconciliation.json (coverage_reconcile.DEFAULT_OUT);
        # an explicit --out redirects the artifact there instead.
        from engine.coverage_reconcile import DEFAULT_OUT as _COV_DEFAULT
        if args.out == ".":
            cov_path = _COV_DEFAULT
        else:
            cov_path = os.path.join(args.out, "coverage_reconciliation.json")
        os.makedirs(os.path.dirname(cov_path) or ".", exist_ok=True)
        with open(cov_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] Coverage      -> {cov_path}")
        print(f"    expected={report['expected']} scanned={report['scanned']}"
              f" inaccessible={report['inaccessible']} unknown={report['unknown']}")
        return 0
    return run_headless_scan(args.target, args.format, args.z, args.policy,
                             not args.no_ml, args.out, args.fail_on, args.subject)


if __name__ == "__main__":
    sys.exit(main())
