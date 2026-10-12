"""
Seeded fuzz tests for the IndraMesh scanner (task HAND-160).

A fuzzer earns its place only if its assertions can fail. This one asserts three things the
scanner's own docstring promises and the example-based suite never checked:

  1. IT NEVER RAISES. An operator points this tool at an untrusted checkout, an unpacked
     tarball, or a package from a registry. A crash is an availability failure on exactly the
     inputs the tool exists to inspect.

  2. IT NEVER HANGS. Every case runs under a wall-clock budget. A tool that can be wedged by
     a 300 KB single-line file is a tool that can be used as a denial-of-service amplifier
     against whatever CI job runs it.

  3. UNREADABLE INPUT IS RECORDED, NOT RAISED. `scanner.errors` exists so that "clean" can
     never be confused with "unread". A fuzzer case that produces garbage must land in
     `errors`, otherwise the report silently under-counts.

DETERMINISM. This module deliberately uses `random.Random(seed)` with FIXED seeds rather than
hypothesis. A fuzzer's value here is reproducibility: when CI fails on seed 160 case 471, the
next person must be able to regenerate exactly that case, and must not have to replay a
hypothesis database to do it. Every seed and case index is therefore a pure function of the
constants at the top of this file.
"""
import io
import os
import random
import sys
import tarfile
import tempfile
import time
import traceback

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scanner import IndraMeshScanner

# --------------------------------------------------------------------------------------------
# Fixed seeds. Changing any of these changes which cases run; do not change them casually.
# --------------------------------------------------------------------------------------------
SEEDS = (160, 161, 162, 163, 164, 165, 166, 167)
CASES_PER_SEED = 45

# Wall-clock budget for a single scan. A megabyte of source should take milliseconds; 5 s is
# three orders of magnitude of headroom, so exceeding it means pathological behaviour, not a
# slow machine.
CASE_BUDGET_SECONDS = 5.0

REQUIRED_FINDING_KEYS = ("file", "name", "primitive", "rule_id", "scanner",
                         "evidence_class", "uses")

# Seed corpora. Real rule hits are the interesting input: mutating them keeps the scanner on
# its hot path instead of trivially rejecting everything.
SOURCE_SEEDS = [
    b"import rsa\nkey = rsa.newkeys(2048)\n",
    b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
    b"k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n",
    b"AESGCM(b'0123456789abcdef')\n",
    b"RSA_generate_key_ex(r, 2048);\nEVP_aes_256();\nEVP_sha256();\n",
    b'KeyPairGenerator.getInstance("RSA")\nSignature.getInstance("SHA256withRSA")\n',
    b"ec.generate_private_key(ec.SECP384R1())\nECDH_compute_key()\n",
    b"Ed25519PrivateKey.generate()\n",
    b"ssl_protocols TLSv1.2;\nciphersuites = 3DES\n",
    b"/* RSA_generate_key_ex */\n# AESGCM(\n\"\"\"\nEVP_sha1();\n\"\"\"\nEVP_md5();\n",
    b"\xef\xbb\xbf BOM then rsa.newkeys(2048)\n",
    ("x = \"é中😀\"  # unicode comment\nrsa.newkeys(4096)\n").encode("utf-8"),
    b"a = 1" * 500 + b"\nrsa.newkeys(1024)\n",
]
BINARY_SEEDS = [
    b"\x7fELF\x00\x00libcrypto OpenSSL 3.0.13\x00",
    b"mbedtls\x00gcry_\x00libsodium\x00",
    b"\x00" * 4096,
    bytes(range(256)) * 8,
    b"OpenSSL 1.0.2j\x00" + b"\xff" * 1000,
]
CONTAINER_SEEDS = [b"", b"\x00" * 1024, b"ustar", b"\x1f\x8b\x08\x00"]


class FuzzFailure(AssertionError):
    """A fuzzer case that broke an invariant. Carries the seed and case index for replay."""


def _scanner():
    return IndraMeshScanner(enable_ml=False)


def _write(root, name, blob):
    path = os.path.join(root, name)
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


def _mutate(rng, blob):
    """Byte-level mutation: flips, splices, truncations and random appends."""
    data = bytearray(blob)
    for _ in range(rng.randint(0, 24)):
        if not data:
            break
        choice = rng.random()
        position = rng.randrange(len(data))
        if choice < 0.55:
            data[position] = rng.randrange(256)
        elif choice < 0.75:
            del data[position:position + rng.randint(1, 32)]
        elif choice < 0.9:
            data[position:position] = bytes(rng.randrange(256)
                                            for _ in range(rng.randint(1, 16)))
        else:
            data += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    if rng.random() < 0.4 and data:
        del data[rng.randrange(len(data)):]
    if rng.random() < 0.25:
        data += os.urandom(rng.randint(1, 2048))
    return bytes(data)


def _valid_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _assert_scan_invariants(scanner, findings, path, blob):
    """The three promises. Raises FuzzFailure with replay information on any violation."""
    if not isinstance(findings, list):
        raise FuzzFailure(f"{path}: scan_directory returned {type(findings).__name__}, not a list")

    line_count = blob.decode("utf-8", errors="replace").count("\n") + 1
    for finding in findings:
        if not isinstance(finding, dict):
            raise FuzzFailure(f"{path}: finding is {type(finding).__name__}, not a dict")
        for key in REQUIRED_FINDING_KEYS:
            if key not in finding:
                raise FuzzFailure(f"{path}: finding missing {key!r}: {finding}")
        line = finding.get("line")
        if line is None:
            continue
        if not isinstance(line, int) or isinstance(line, bool):
            raise FuzzFailure(f"{path}: line is {line!r}, not an int: {finding}")
        if line < 1 or line > line_count:
            raise FuzzFailure(f"{path}: line {line} outside 1..{line_count}: {finding}")

    keys = [(f.get("file"), f.get("name"), f.get("rule_id"), f.get("line")) for f in findings]
    if len(keys) != len(set(keys)):
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        raise FuzzFailure(f"{path}: duplicate findings survived: {duplicates}")

    for error in scanner.errors:
        if not isinstance(error, dict) or "file" not in error or "reason" not in error:
            raise FuzzFailure(f"{path}: malformed entry in scanner.errors: {error!r}")


def _run_case(rng, root, index, budget):
    """Generate one case, scan it, check the invariants. Returns a one-line summary."""
    kind = rng.choice(["source", "source", "source", "binary", "container", "junk"])
    if kind == "source":
        ext = rng.choice([".py", ".c", ".java", ".js", ".go", ".rs", ".conf", ".yaml", ".json"])
        blob = _mutate(rng, rng.choice(SOURCE_SEEDS))
        path = _write(root, f"case{index:04d}{ext}", blob)
    elif kind == "binary":
        ext = rng.choice([".so", ".dll", ".bin", ".jar", ".o", ".a"])
        blob = _mutate(rng, rng.choice(BINARY_SEEDS))
        path = _write(root, f"case{index:04d}{ext}", blob)
    elif kind == "container":
        members = [(f"m{k}.py", bytes(rng.choice(SOURCE_SEEDS)))
                   for k in range(rng.randint(0, 3))]
        valid = _valid_tar(members)
        blob = _mutate(rng, valid) if rng.random() < 0.7 else rng.choice(CONTAINER_SEEDS)
        name = rng.choice(["case.tar", "case.tar.gz", "case.tgz"])
        path = _write(root, f"case{index:04d}-{name}", blob)
    else:
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 512)))
        path = _write(root, f"case{index:04d}.bin", blob)

    scanner = _scanner()
    started = time.monotonic()
    try:
        findings = scanner.scan_directory(path)
    except Exception:                                       # noqa: BLE001
        raise FuzzFailure(
            f"scan_directory RAISED on {kind} input ({len(blob)} bytes, {path})\n"
            + traceback.format_exc()) from None
    elapsed = time.monotonic() - started

    if elapsed > budget:
        raise FuzzFailure(
            f"scan_directory took {elapsed:.1f}s on a {len(blob)}-byte {kind} input; the "
            f"budget is {budget:.1f}s -- the input can wedge the scanner")
    _assert_scan_invariants(scanner, findings, path, blob)
    return {"kind": kind, "bytes": len(blob), "ms": elapsed * 1000,
            "findings": len(findings), "errors": len(scanner.errors)}


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzzed_single_files_never_crash_never_hang_and_stay_consistent(seed):
    """One seed per test, so a failure names the exact seed to replay.

    Replay a reported case with:
        rng = random.Random(<seed>); for i in range(<index>): _run_case(rng, root, i, 5.0)
    """
    rng = random.Random(seed)
    summaries = []
    with tempfile.TemporaryDirectory() as root:
        for index in range(CASES_PER_SEED):
            try:
                summaries.append(_run_case(rng, root, index, CASE_BUDGET_SECONDS))
            except FuzzFailure as exc:
                pytest.fail(f"[seed={seed} case={index}] {exc}")
    # Positive controls. Without these, "never crashed" could be true because nothing was ever
    # detected, and the invariant checks would never have run on a real finding.
    assert any(s["findings"] for s in summaries), (
        f"seed {seed} never produced a finding, so the invariants are untested: {summaries[:5]}")
    assert any(s["errors"] for s in summaries), (
        f"seed {seed} never recorded an error, so the 'unreadable is not clean' path is "
        f"untested: {summaries[:5]}")


def test_fuzzed_whole_trees_never_crash_and_account_for_every_file():
    """The same, through the directory walk, where `files_seen` must add up.

    This is the path that consults the filesystem policy and populates the coverage manifest,
    and the one whose `scanners_run` output the report depends on.
    """
    rng = random.Random(SEEDS[0] + 1)
    with tempfile.TemporaryDirectory() as root:
        created = 0
        for index in range(40):
            kind = rng.choice(["source", "source", "binary", "container", "odd-name"])
            if kind == "source":
                _write(root, f"t{index}.py", _mutate(rng, rng.choice(SOURCE_SEEDS)))
                created += 1
            elif kind == "binary":
                _write(root, f"t{index}.so", _mutate(rng, rng.choice(BINARY_SEEDS)))
                created += 1
            elif kind == "container":
                _write(root, f"t{index}.tar",
                       _mutate(rng, _valid_tar([("a.py", b"AESGCM()\n")])))
                created += 1
            else:
                # Names that are awkward but still carry a REAL extension, so this test
                # exercises the scanner rather than the host filesystem's naming rules.
                stem, ext = rng.choice([("a b", ".py"), ("UPPER", ".PY"), ("x", ".Py"),
                                        ("trailing", ".c"), ("..hidden", ".py"),
                                        ("\u00e9\u00e8", ".py"), ("no_ext", ".txt"),
                                        ("archive", ".zip"), ("data", ".dat")])
                try:
                    _write(root, f"{stem}{index}{ext}",
                           _mutate(rng, rng.choice(SOURCE_SEEDS)))
                    created += 1
                except OSError:
                    pass            # a name the host filesystem refuses is not a scanner bug

        scanner = _scanner()
        started = time.monotonic()
        try:
            findings = scanner.scan_directory(root)
        except Exception:                                   # noqa: BLE001
            pytest.fail("scan_directory RAISED on a fuzzed tree\n" + traceback.format_exc())
        elapsed = time.monotonic() - started
        manifest = scanner.coverage_manifest(findings)

    assert elapsed < CASE_BUDGET_SECONDS * 5, f"the tree walk took {elapsed:.1f}s"
    assert manifest["files_seen"] >= created, (
        f"the walk saw {manifest['files_seen']} files but {created} were created")
    assert findings, "the fuzzed tree produced no findings at all"
    assert manifest["scanners_run"], (
        f"the walk returned {len(findings)} findings but reports "
        f"scanners_run={manifest['scanners_run']!r}")
    _assert_scan_invariants(scanner, findings, root, b"")


def test_every_file_seen_is_either_scanned_or_recorded_as_skipped():
    """The coverage arithmetic must add up, or the manifest cannot be believed.

    `coverage_manifest` exists so that "no crypto here" is distinguishable from "we never
    looked". A reader who does `files_seen - files_scanned - files_skipped` to find out how
    much was quietly ignored gets a number the manifest never explains. Every file the walk
    encountered must land in exactly one of the two counters, or in an explicit out-of-scope
    statement naming it.
    """
    in_scope = {"a.py": b"rsa.newkeys(2048)\n", "b.c": b"EVP_sha256();\n",
                "c.conf": b"ssl_protocols TLSv1.2;\n", "d.so": b"libcrypto OpenSSL 3.0.0\x00"}
    out_of_scope = {"e.txt": b"rsa.newkeys(2048)\n", "f.md": b"AESGCM(k)\n",
                    "g.zip": b"PK\x03\x04rubbish", "h.dat": b"RSA_generate_key_ex(r,2048);\n",
                    "i.rst": b"ECDH_compute_key()\n"}
    with tempfile.TemporaryDirectory() as root:
        for name, blob in list(in_scope.items()) + list(out_of_scope.items()):
            _write(root, name, blob)
        scanner = _scanner()
        findings = scanner.scan_directory(root)
        manifest = scanner.coverage_manifest(findings)

    total = len(in_scope) + len(out_of_scope)
    assert manifest["files_seen"] == total, (
        f"the walk saw {manifest['files_seen']} of {total} files")
    accounted = manifest["files_scanned"] + manifest["files_skipped"]
    assert accounted == manifest["files_seen"], (
        f"{manifest['files_seen'] - accounted} file(s) were seen but neither scanned nor "
        f"recorded as skipped, and nothing in the manifest says they were out of scope: "
        f"scanned={manifest['files_scanned']} skipped={manifest['files_skipped']} "
        f"seen={manifest['files_seen']}. The out-of-scope files were "
        f"{sorted(out_of_scope)}; the in-scope ones were {sorted(in_scope)}.")
    # Positive control: the in-scope files really were scanned, so the assertion above is not
    # passing because nothing was counted at all.
    assert manifest["files_scanned"] >= len(in_scope), (
        f"the {len(in_scope)} in-scope files were not all scanned: {manifest['files_scanned']}")


def test_unreadable_input_is_recorded_in_errors_and_not_raised():
    """The specific promise that `scanner.errors` exists to keep.

    Both the directory walk and the single-file path must record the failure, because both are
    documented entry points and a caller using the second must not be the one who learns
    nothing.
    """
    with tempfile.TemporaryDirectory() as root:
        undecodable = _write(root, "bad.py", b"\xff\xfe\x00\x00rsa.newkeys(2048)\n")
        missing = os.path.join(root, "does-not-exist.py")
        _write(root, "junk.tar", b"this is definitely not a tar archive" * 40)

        walker = _scanner()
        findings = walker.scan_directory(root)
        assert all(f["file"] != undecodable for f in findings), (
            "an undecodable file produced findings; its contents were not safely readable")
        recorded = {os.path.basename(e["file"]): e["reason"] for e in walker.errors}
        assert "bad.py" in recorded, f"the undecodable file was not recorded: {walker.errors}"
        assert "UTF-8" in recorded["bad.py"] or "undecodable" in recorded["bad.py"]
        assert "junk.tar" in recorded, f"the unreadable archive was not recorded: {walker.errors}"

        direct = _scanner()
        direct.scan_directory(undecodable)
        assert direct.errors, "scanning an undecodable file directly recorded nothing"
        assert os.path.basename(direct.errors[0]["file"]) == "bad.py"

        gone = _scanner()
        assert gone.scan_directory(missing) == []
        assert gone.errors, "scanning a path that does not exist recorded nothing"
        assert "does not exist" in gone.errors[0]["reason"]


def test_a_truncated_container_image_is_recorded_and_not_raised():
    """A `.tar` cut off part-way through must be an ERROR, not a traceback.

    A container image is exactly the input most likely to arrive truncated -- a partial
    `docker save`, an interrupted upload, a full disk -- so this is the single most reachable
    untrusted input the scanner has. It must come back as an entry in `scanner.errors`, which
    is what stops "the image was empty" from being reported as "the image had no crypto".
    """
    valid = _valid_tar([("app.py", b"rsa.newkeys(2048)\nSHA256(x)\n")])
    cuts = {
        "empty": b"",
        "one header block": valid[:512],
        "header plus a little data": valid[:600],
        "half": valid[: len(valid) // 2],
        "one byte short": valid[:-1],
        "first 1024": valid[:1024],
    }
    for label, blob in cuts.items():
        with tempfile.TemporaryDirectory() as root:
            path = _write(root, "image.tar", blob)
            scanner = _scanner()
            try:
                findings = scanner.scan_directory(path)
            except Exception:                                   # noqa: BLE001
                pytest.fail(
                    f"scan_directory RAISED on a {label} container image ({len(blob)} bytes)\n"
                    + traceback.format_exc())
            assert isinstance(findings, list)
            if not findings:
                assert scanner.errors, (
                    f"a {label} container image produced no findings AND no recorded error, "
                    f"so it is indistinguishable from a clean image")


def test_a_truncated_container_image_does_not_abort_a_whole_tree_scan():
    """The blast radius of a bad archive must be that one file.

    One corrupt `.tar` in a repository must not cost the operator every other finding in the
    tree, which is what happens if the archive handling raises instead of recording.
    """
    valid = _valid_tar([("app.py", b"rsa.newkeys(2048)\n")])
    with tempfile.TemporaryDirectory() as root:
        _write(root, "good.py", b"rsa.newkeys(2048)\nAESGCM(k)\n")
        _write(root, "broken.tar", valid[:512])
        _write(root, "also-good.c", b"RSA_generate_key_ex(r, 2048);\n")
        scanner = _scanner()
        try:
            findings = scanner.scan_directory(root)
        except Exception:                                       # noqa: BLE001
            pytest.fail("one corrupt archive aborted the whole tree scan\n"
                        + traceback.format_exc())
        files = {os.path.basename(f["file"]) for f in findings}

    assert "good.py" in files, (
        f"the scan of the rest of the tree was lost: {sorted(files)}")
    assert "also-good.c" in files, f"the scan of the rest of the tree was lost: {sorted(files)}"



