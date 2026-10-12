"""
IndraMesh certificate sensor entry point: `python cli_certificates.py certs ./target`

SEPARATION, AND WHY
-------------------
`cli.py` is not modified: other work is in flight against it, and a new sensor that can only be
reached by editing a file someone else owns is a sensor that will break under them. This file is
additive, exactly as `cli_advanced.py` is for the dependency sensor.

    python cli_certificates.py certs ./certs                 # certificate inventory only
    python cli_certificates.py certs ./target --format json  # machine-readable
    python cli_certificates.py all    ./target               # source + certificates, one pass

`all` exists to show the two sensors side by side. A certificate finding carries
`evidence_class="observed"`, which engine/purpose.py maps to ASSURANCE_OBSERVED; a source finding
is `discovered` (ASSURANCE_USED). They concatenate into one report because the schema is the same,
and they are never conflated because the assurance tier says which is which.

Exit codes
    certs  0 = scanned, 1 = a finding at/above --fail-on, 2 = a certificate could not be read
    all    0 = nothing breached, 1 = threshold breached, 2 = a scan error
"""
import argparse
import json
import os
import sys

from engine.cbom import generate_cbom
from engine.certificates import scan_certificates
from engine.mosca import calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.scanner import IndraMeshScanner

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _enrich(findings):
    for finding in findings:
        finding["risk"] = calculate_risk(finding)
        finding["recommendation"] = get_pqc_recommendation(finding)
    return findings


def _print_coverage(coverage, label):
    print(f"[*] {label}")
    print(f"    files walked: {coverage['files_seen']}   "
          f"certificate files: {coverage['certificate_files_seen']}   "
          f"certificates parsed: {coverage['certificates_parsed']}   "
          f"failed: {coverage['certificates_failed']}")
    print(f"    KeyUsage present: {coverage['key_usage_present']}   "
          f"purpose resolved: {coverage['purpose_resolved']}   "
          f"purpose unresolved: {coverage['purpose_unresolved']}   "
          f"expired: {coverage['expired']}")
    print(f"    parser backend: {coverage['parser_backend']} ({coverage['parser_backend_reason']})")
    if coverage["private_key_files_passed_over"]:
        print(f"    [!] {coverage['private_key_files_passed_over']} file(s) contained PRIVATE KEY "
              f"material: passed over, never read into a finding")
    for warning in coverage["warnings"][:10]:
        print(f"      ! {warning['file']}: {warning['reason']}")
    if coverage["errors"]:
        # Named, not summarised away. An unreadable certificate is NOT a clean certificate.
        print(f"[!] {len(coverage['errors'])} file(s) NOT read -- these are NOT clean:")
        for error in coverage["errors"][:15]:
            print(f"      - {error['file']}: {error['reason']}")
        if len(coverage["errors"]) > 15:
            print(f"      ... and {len(coverage['errors']) - 15} more")


def run_certs(target, output_format="text", fail_on="CRITICAL", prefer="auto", out_dir="."):
    """Certificate inventory. Emits observed-tier findings and the evidence behind each one."""
    findings, scanner = scan_certificates(target, prefer=prefer)
    coverage = scanner.coverage_manifest(findings)
    _enrich(findings)
    findings.sort(key=lambda f: (f.get("file") or "", f.get("rule_id") or ""))

    _print_coverage(coverage, "Certificate sensor")
    if not findings:
        print("[*] No certificates found. Files that were never certificates are counted in the "
              "coverage above, not treated as clean.")

    if output_format == "json":
        payload = {"findings": findings, "coverage": coverage}
        if out_dir and out_dir != ".":
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, "indramesh-certificates.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            print(f"[*] Wrote {path}")
        print(json.dumps(payload, indent=2))
    else:
        for finding in findings:
            purpose = finding.get("purpose", "-")
            bits = f"{finding['key_length']}-bit" if finding.get("key_length") else ""
            key_usage = ",".join(finding.get("key_usage") or []) or "-"
            print(f"  - {finding['name']:<28} {finding['primitive']:<14} {bits:<10} "
                  f"purpose={purpose:<17} KU={key_usage}")
            print(f"      {finding.get('cert_common_name') or finding.get('match')}")
            if finding.get("not_after"):
                print(f"      expires {finding['not_after']} "
                      f"({finding.get('days_until_expiry')} days)  "
                      f"tier={finding['risk']['tier']}  "
                      f"-> {finding['recommendation']['algorithm']}")
        if out_dir and out_dir != ".":
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, "indramesh-certificates.cbom.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(generate_cbom(findings, enriched=True))
            print(f"[*] Wrote {path}")

    threshold = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else 3
    breached = [f for f in findings
                if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    if scanner.errors and not breached:
        return 2
    return 1 if breached else 0


def run_all(target, output_format="text", fail_on="CRITICAL", enable_ml=False):
    """Source and certificates in one pass, to show the schemas really do concatenate."""
    source = IndraMeshScanner(enable_ml=enable_ml)
    source_findings = source.scan_directory(target)
    certificate_findings, scanner = scan_certificates(target)
    coverage = scanner.coverage_manifest(certificate_findings)

    print(f"[*] Source scanner: {len(source_findings)} finding(s) from "
          f"{source.coverage['files_scanned']} file(s)")
    print(f"[*] Certificate sensor: {len(certificate_findings)} finding(s)")
    _print_coverage(coverage, "Certificate sensor")
    _enrich(source_findings)
    _enrich(certificate_findings)
    findings = source_findings + certificate_findings
    if output_format == "json":
        print(json.dumps({"findings": findings, "coverage": coverage,
                          "source_coverage": source.coverage_manifest(source_findings)}, indent=2))
    else:
        print(f"[*] Combined: {len(findings)} finding(s) from "
              f"{sorted({f['scanner'] for f in findings})}")
    threshold = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else 3
    breached = [f for f in findings if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    if scanner.errors and not breached:
        return 2
    return 1 if breached else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    certs = sub.add_parser("certs", help="Scan for X.509 certificates (PEM, DER, PKCS#7)")
    certs.add_argument("target")
    certs.add_argument("--format", default="text", choices=["text", "json"])
    certs.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    certs.add_argument("--prefer", default="auto", choices=["auto", "der", "cryptography"],
                       help="which parser to try first; both produce the same record")
    certs.add_argument("--out-dir", default=".")

    combined = sub.add_parser("all", help="Source scan and certificate scan in one pass")
    combined.add_argument("target")
    combined.add_argument("--format", default="text", choices=["text", "json"])
    combined.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    combined.add_argument("--ml", action="store_true", help="enable the optional transformer")

    args = parser.parse_args(argv)
    if args.command == "certs":
        return run_certs(args.target, args.format, args.fail_on, args.prefer, args.out_dir)
    return run_all(args.target, args.format, args.fail_on, enable_ml=args.ml)


if __name__ == "__main__":
    sys.exit(main())