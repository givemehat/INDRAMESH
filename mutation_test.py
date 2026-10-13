"""Mutation testing: does the test suite actually DETECT defects, or does it just pass?

A large test count is not alone evidence of correctness. The only evidence is whether
introducing a deliberate defect makes the suite go red.

A "mutant" is the real engine code with one small, semantically meaningful change -- a boundary
made inclusive, a comparison flipped, a return value altered. If the suite still passes with a
mutant in place, that mutant is a testing gap, and we have found a bug our own tests cannot see.

The engine source is MUTATED ON A COPY. The working tree is never modified: each mutant is written
to a temp directory that shadows the repository, and the suite is re-run against it in a
subprocess. This is the only safe way to do mutation testing against live source.

    python mutation_test.py              # run and report
    python mutation_test.py --verbose    # extra detail on survivors

Exit code 0 = every mutant was killed (the suite has teeth).
Exit code 1 = at least one mutant survived (a real testing gap).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "engine")

# Each mutant is (id, source file, regex to find, replacement). These are chosen because each
# is a REAL bug class seen in this field:
#   - an off-by-one on a security boundary (>= vs >)
#   - a silently wrong algorithm mapping (the most damaging bug a crypto tool can have)
#   - a removed guard (hiding a scan error, so 'unread' looks like 'clean')
#   - an inverted severity (understating risk)
MUTANTS = [
    # --- mosca.py: the core inequality and tiering. A wrong boundary silently misclassifies risk. ---
    ("MOSCA-01", "mosca.py", r"if hndl or \(is_vulnerable and margin >= 10\):",
     "if hndl or (is_vulnerable and margin >= 1000):"),
    ("MOSCA-02", "mosca.py", r"(\s+)ratio = min\(1\.0, ast_depth / COMPLEXITY_AST_DEPTH_REFERENCE\)",
     r"\1ratio = min(1.0, ast_depth / (COMPLEXITY_AST_DEPTH_REFERENCE * 1000))"),
    ("MOSCA-03", "mosca.py", r"return HORIZON_CONFIDENTIALITY", "return HORIZON_VERIFIABILITY"),
    ("MOSCA-04", "mosca.py", r"(\s+)if \"sign\" in primitive:", r"\1if False:"),
    ("MOSCA-05", "mosca.py", r"(\s+)if not subject:", r"\1if False:  # mutated: never downgrade"),
    ("MOSCA-06", "mosca.py", r"(\s+)return 0\.0, \"not applicable \(symmetric/hash primitive\)\"",
     r"\1return 30.0, \"mutated\""),
    ("MOSCA-07", "mosca.py", r"if user_x < 0:", "if user_x < -1000:"),

    # --- recommender.py: a wrong PQC target is the most damaging possible defect. ---
    ("REC-01", "recommender.py", r"\"ML-DSA-44 or ML-DSA-65\"", "\"ML-KEM-768\""),
    ("REC-02", "recommender.py", r"\"RULE-SYM-OK: ", "\"RULE-BROKEN: "),
    ("REC-03", "recommender.py", r"\"AES-256\",\n(\s+)\"Upgrade key size",
     "\"AES-128\",\n\\1\"Keep as-is"),

    # --- scanner.py: a guard removal means errors vanish and 'unread' looks like 'clean'. ---
    ("SCAN-01", "scanner.py", r"self\._note_error\(file_path, f\"unreadable",
     "pass  # mutated: swallow the error"),
    ("SCAN-02", "scanner.py", r"if is_credential_store\(fname\):", "if False:"),
    ("SCAN-03", "scanner.py", r"if resolve_within\(real_root, fpath\) is None:", "if False:"),
    ("SCAN-04", "scanner.py", r"content = _strip_comments\(content, file_path\)",
     "content = content  # mutated: no comment stripping"),
    ("SCAN-05", "scanner.py", r"def _note_error\(self, path, reason\):", "def _note_error(self, path, reason):\n        return"),

    # --- purpose.py: purpose resolution. Inverting it swaps ML-KEM and ML-DSA. ---
    ("PURP-01", "purpose.py", r"if sig_bits and ke_bits:", "if False:"),
    ("PURP-02", "purpose.py", r"def resolve_purpose\(finding\):",
     "def resolve_purpose(finding):\n    return 'signature', [], 'mutated: always assume signature'"),

    # --- cbom.py: emitting an invalid field breaks schema conformance downstream. ---
    ("CBOM-01", "cbom.py", r"\"nistQuantumSecurityLevel\"", "\"nistSecurityLevel_XX\""),
    ("CBOM-02", "cbom.py", r"SPEC_VERSION = \"1\.7\"", "SPEC_VERSION = \"9.9\""),
]

# Everything needed to run the suite standalone, mirrored into each mutant directory.
MIRROR = ("engine", "tests", "schemas", "cli.py", "app.py", "validate_cbom.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def build_mutant(mut_id, filename, pattern, replacement, workdir):
    """Materialise a full copy of the repo with one mutant applied. Returns (ok, path_or_reason)."""
    repo = os.path.join(workdir, mut_id)
    os.makedirs(repo, exist_ok=True)
    for item in MIRROR:
        src = os.path.join(HERE, item)
        if not os.path.exists(src):
            continue
        dst = os.path.join(repo, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(src, dst)

    target = os.path.join(repo, "engine", filename)
    original = _read(target)
    mutated, n = re.subn(pattern, replacement, original, count=1)
    if n == 0:
        shutil.rmtree(repo, ignore_errors=True)
        return False, "pattern did not match -- the mutant is stale; the code moved"
    _write(target, mutated)
    return True, repo


def run_suite(repo, timeout=1200):
    """Run the test suite against a mutant. Returns (killed, returncode, tail)."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "-q", "-x", "--no-header",
             "-p", "no:cacheprovider"],
            cwd=repo, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, None, "TIMEOUT (the mutant may have introduced a hang)"
    killed = proc.returncode != 0
    return killed, proc.returncode, (proc.stdout or "")[-300:]


def main():
    ap = argparse.ArgumentParser(
        description="Mutation-test the IndraMesh engine to measure whether the suite has teeth.")
    ap.add_argument("--verbose", action="store_true", help="extra detail on survivors")
    ap.add_argument("--keep", action="store_true", help="keep mutant copies for debugging")
    args = ap.parse_args()

    if not os.path.isdir(ENGINE):
        print("run this from the repository root", file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="indramesh-mutation-")
    results = []
    try:
        print(f"Mutation testing: {len(MUTANTS)} mutants, each in an isolated repo copy\n")
        for mut_id, filename, pattern, replacement in MUTANTS:
            ok, detail = build_mutant(mut_id, filename, pattern, replacement, workdir)
            if not ok:
                results.append((mut_id, "STALE", detail))
                print(f"  [STALE]    {mut_id:<10} {detail}")
                continue
            killed, rc, _tail = run_suite(detail)
            if killed:
                print(f"  [KILLED]   {mut_id:<10} suite failed as it should (rc={rc})")
                results.append((mut_id, "KILLED", ""))
            else:
                print(f"  [SURVIVED] {mut_id:<10} SUITE STILL PASSED -- this is a testing gap")
                if args.verbose:
                    print(f"               mutant: engine/{filename}  {pattern}  ->  {replacement}")
                results.append((mut_id, "SURVIVED", f"engine/{filename}: {pattern}"))
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    killed = sum(1 for _, s, _ in results if s == "KILLED")
    survived = [r for r in results if r[1] == "SURVIVED"]
    stale = [r for r in results if r[1] == "STALE"]
    total = len(results)
    # A STALE mutant was never actually tested: the pattern no longer matches the source, so no
    # mutant was applied and no test ran. Scoring those as anything other than zero would let
    # the score drift upward as the code moves and the harness silently stops measuring.
    score = (100.0 * killed / total) if total else 0.0

    print("\n" + "=" * 74)
    print(f"mutation score: {killed}/{total} killed ({score:.1f}%)")
    if stale:
        print(f"  {len(stale)} STALE   -- the mutant no longer matches the source. That is a")
        print("                        measurement that is out of date, not a pass.")
    if survived:
        print(f"  {len(survived)} SURVIVED -- real testing gaps. A defect of this exact shape")
        print("                        would ship undetected. Each is a test to write next:")
        for mid, _, detail in survived:
            print(f"    - {mid}: {detail}")
    elif not stale:
        print("  Every mutant was killed: the suite detects defects of these shapes.")
    else:
        print("  Every mutant that could be applied was killed -- but see the STALE entries")
        print("  above: the harness did not measure the whole mutation set.")

    # THE EXIT CODE IS THE POINT OF THIS SCRIPT, so it must not be reachable by a run that
    # measured nothing. `return 1 if survived else 0` used to return 0 when EVERY mutant was
    # stale -- the suite never ran, and the harness reported a perfect result. PROVENANCE.md
    # nominates this exact command as the project's proof of correctness, so a false pass here
    # is a false claim in the project's own documentation. An unmeasured run now fails.
    if total == 0:
        print("\nFAIL: no mutants were defined. Nothing was measured.")
        return 2
    if len(stale) == total:
        print(f"\nFAIL: all {total} mutants are STALE. The test suite was never run, so this")
        print("      result says nothing about the suite. Fix the patterns in MUTANTS so they")
        print("      match the current source, then re-run.")
        return 2
    if stale:
        print(f"\nPARTIAL: {len(stale)} of {total} mutants are stale and were not measured.")
        print("        The {killed}/{total} figure above covers only the applicable mutants."
              .format(killed=killed, total=total))
        return 2
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())


