"""
Tests for the dependency-manifest sensor (`engine/dependencies.py`).

Every test is written to be ABLE TO FAIL, and names the defect it catches. A test that cannot
fail is documentation with a runtime cost. The negative cases are the load-bearing ones: this
is the sensor whose worst failure mode is a confident empty report.

Covered, in order of how badly a bug would hurt:
  * the capability semantic -- evidence_class="dependency", never "discovered"
  * the empty-result cases  -- no crypto -> zero findings; malformed -> named, not raised
  * parser correctness per ecosystem, against realistic manifest text
  * the accuracy of the capability map itself (the claim this module stakes its credibility on)
  * filesystem policy       -- credential stores, symlink escape, containment
  * the coverage manifest   -- "could not look" must differ from "found nothing"
"""
import json
import os

import pytest

import engine.dependencies as deps_module
from engine.dependencies import (DependencyScanner, manifest_kind,
                                 normalise_package, parse_dotnet, parse_gemfile, parse_requirements_txt)
from engine.purpose import ASSURANCE_CAPABILITY, resolve_assurance, resolve_purpose
from engine.recommender import get_pqc_recommendation


# ------------------------------------------------------------------ helpers

def write(tmp_path, name, content):
    """Write a manifest and return its path as a str (the sensor records str paths)."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def scan_text(tmp_path, name, content):
    """Scan a single manifest in its own directory and return (findings, scanner)."""
    path = write(tmp_path, name, content)
    scanner = DependencyScanner()
    return scanner.scan(path), scanner


# ------------------------------------------------------------------ the semantic

def test_every_finding_is_capability_evidence_never_discovered(tmp_path):
    """A package name in a manifest is REACHABILITY. The finding must say so, because
    `evidence_class` is what resolves the assurance level everywhere downstream."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "pycryptodome==3.19.0\n")
    assert findings, "expected a finding for pycryptodome"
    for finding in findings:
        assert finding["evidence_class"] == "dependency"
        assert finding["evidence_class"] != "discovered"
        level, reason = resolve_assurance(finding)
        assert level == ASSURANCE_CAPABILITY
        assert "reachable" in reason.lower()


def test_finding_does_not_claim_the_dependency_uses_the_algorithm(tmp_path):
    """The finding carries `provides`, never a claim that the library USES the algorithm.

    A regression that renamed `provides` to `uses` would be subtle in the JSON and catastrophic
    in the report: it would read "pycryptodome USES RSA", i.e. a call site that does not exist.
    """
    findings, _ = scan_text(tmp_path, "requirements.txt", "pycryptodome\n")
    finding = findings[0]
    assert finding["provides"], "the capability list must be present"
    assert "reachability, not use" in finding["provides_note"]
    # `uses` survives as the deployment-CONTEXT label (a single string), never as an algorithm set.
    assert isinstance(finding["uses"], str)


def test_library_finding_recommends_inventory_not_migration(tmp_path):
    """`get_pqc_recommendation` must not tell the operator to migrate a LIBRARY. It has a
    dedicated branch for `type == "library"`; this asserts the finding actually reaches it,
    and that the recommendation it gives is the inventory/consumers one."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "cryptography>=42\n")
    rec = get_pqc_recommendation(findings[0])
    assert "RULE-LIB" in rec["rule_trace"]
    assert "consumer" in rec["justification"].lower()
    assert "not `uses`" in rec["justification"], "implements-vs-uses must be stated"
    # It must NOT name a PQC algorithm to migrate the library to: the migration unit is each
    # consumer's call site, and a library is not one.
    assert "ML-KEM" not in rec["algorithm"] and "ML-DSA" not in rec["algorithm"]


def test_finding_is_typed_as_a_library_not_an_algorithm(tmp_path):
    """`engine/cbom.py` emits a `type == "library"` finding as a library COMPONENT, never as a
    cryptographic-asset with a fabricated primitive. This is the field that decides that."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "pycryptodome\n")
    assert findings[0]["type"] == "library"


def test_one_finding_per_library_not_one_per_algorithm(tmp_path):
    """`cryptography` provides ~20 algorithms. If this ever becomes 20 findings the total stops
    meaning anything: they all carry the same "assess the consumers" recommendation."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "cryptography>=42\n")
    assert len(findings) == 1
    assert len(findings[0]["provides"]) > 10, "detail moves onto `provides`, not the count"


def test_no_purpose_signal_is_smuggled_into_a_dependency_finding(tmp_path):
    """Purpose is resolved from a finding, and a manifest cannot resolve it. Asserted so a
    future "just default the purpose" shortcut fails here rather than in a customer's report."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "rsa\n")
    purpose, signals, _reason = resolve_purpose(findings[0])
    assert purpose in ("unresolved", "key-establishment", "signature")
    assert not any(s in ("sign(", "keypairgenerator", "newkeys") for s in signals)


# ------------------------------------------------------------------ negative cases

def test_manifest_with_no_cryptography_produces_zero_findings(tmp_path):
    """THE negative case. A web app with an ordinary framework in its manifest must produce
    nothing. If this fails, the sensor is padding its output and every number is inflated."""
    findings, scanner = scan_text(
        tmp_path, "requirements.txt",
        "# a perfectly ordinary web app\nflask==3.0.0\nrequests>=2.31\ndjango==5.0\n")
    assert findings == []
    # ...and the manifest WAS read. A clean result and an unreadable file must differ.
    assert scanner.manifests_read, "the manifest should have been read successfully"
    assert scanner.errors == []
    assert scanner.coverage["manifests_parsed"] == 1
    assert scanner.coverage["dependencies_examined"] == 3


def test_malformed_json_manifest_is_named_not_raised(tmp_path):
    """A broken package.json is a REPORTABLE condition, not a stack trace and not a silent skip.

    Two failure modes are excluded at once, and both are real: a crash that aborts a whole tree
    walk, and a skip that makes the tree look clean.
    """
    findings, scanner = scan_text(tmp_path, "package.json", '{"dependencies": {"jose": }')
    assert findings == []
    assert len(scanner.errors) == 1
    assert "invalid JSON" in scanner.errors[0]["reason"]
    assert scanner.errors[0]["file"].endswith("package.json")
    assert scanner.coverage["manifests_parsed"] == 0


def test_json_manifest_with_a_utf8_bom_is_parsed_not_rejected(tmp_path):
    """A BOM must not cost us a whole ecosystem.

    A UTF-8 BOM is invisible in an editor and is written routinely: PowerShell's
    `Set-Content -Encoding utf8`, older Visual Studio, and many CI scripts all emit one. npm and
    Node both accept it, so rejecting it is stricter than the tools the manifest is written for --
    and the failure is invisible, because the manifest is simply absent from the inventory. This
    was found by running the CLI against a manifest PowerShell had just written.
    """
    findings, scanner = scan_text(
        tmp_path, "package.json",
        '﻿{"dependencies": {"jose": "^5.0.0"}}')
    assert scanner.errors == [], f"a BOM must be tolerated; got {scanner.errors}"
    assert scanner.coverage["manifests_parsed"] == 1
    assert [f["name"] for f in findings] == ["jose"], "the npm provider must still be found"


def test_bom_is_tolerated_in_every_json_manifest_shape(tmp_path):
    """The same tolerance must hold for every JSON-shaped manifest we parse, not just npm's.

    `scan_text` writes through `write()`, which would not reproduce a BOM faithfully, so the
    bytes are written directly here -- that is the whole point of the test.
    """
    for name, body in (
        ("composer.json", '﻿{"require": {"phpseclib/phpseclib": "^3.0"}}'),
        ("package.json", '﻿{"dependencies": {"jose": "^5.0.0"}}'),
    ):
        d = tmp_path / name.replace(".", "_")
        d.mkdir()
        raw = body.encode("utf-8")
        assert raw[:3] == b"\xef\xbb\xbf", "fixture must actually carry a BOM"
        (d / name).write_bytes(raw)
        scanner = DependencyScanner()
        findings = scanner.scan(str(d / name))
        assert scanner.errors == [], f"{name} with a BOM must parse; got {scanner.errors}"
        assert scanner.coverage["manifests_parsed"] == 1, name
        assert findings, f"{name} must still yield its crypto provider"



def test_malformed_toml_manifest_is_named_not_raised(tmp_path):
    findings, scanner = scan_text(tmp_path, "pyproject.toml", "[project\nname = broken")
    assert findings == []
    assert len(scanner.errors) == 1
    assert "invalid TOML" in scanner.errors[0]["reason"]


def test_malformed_xml_manifest_is_named_not_raised(tmp_path):
    findings, scanner = scan_text(tmp_path, "pom.xml", "<project><dependencies>")
    assert findings == []
    assert len(scanner.errors) == 1
    assert "invalid XML" in scanner.errors[0]["reason"]


def test_malformed_manifest_does_not_abort_the_rest_of_the_tree(tmp_path):
    """One corrupt manifest must not destroy every other finding in the directory.

    This is the blast-radius defect docs/HAND-160-property-bugs.md records for container images:
    one bad file wiping out an entire tree's results. The fix pattern is the same.
    """
    (tmp_path / "package.json").write_text("{ broken", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("pycryptodome\n", encoding="utf-8")
    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))
    assert len(findings) == 1, "the good manifest must still be reported"
    assert findings[0]["name"] == "pycryptodome"
    assert len(scanner.errors) == 1
    assert scanner.errors[0]["file"].endswith("package.json")


def test_a_file_that_is_not_a_manifest_is_ignored(tmp_path):
    """A README mentioning RSA, a source file, a `package.json.bak`: none are manifests. They
    must produce neither a finding NOR an error -- they were never in scope."""
    write(tmp_path, "README.md", "# uses RSA and AES-256-GCM and pycryptodome everywhere")
    write(tmp_path, "main.py", "from Crypto.Cipher import AES  # not a manifest")
    write(tmp_path, "package.json.bak", '{"dependencies": {"jose": "1.0"}}')
    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))
    assert findings == []
    assert scanner.errors == [], "a non-manifest must not be reported as an error"
    # It was still SEEN, which is what makes "ignored" different from "invisible".
    assert scanner.coverage["files_seen"] == 3
    assert scanner.coverage["manifests_seen"] == 0


def test_single_non_manifest_file_target_is_ignored(tmp_path):
    """Pointed directly at a non-manifest file, the sensor returns nothing and says nothing."""
    path = write(tmp_path, "notes.txt", "RSA ML-KEM-768 pycryptodome")
    scanner = DependencyScanner()
    assert scanner.scan(path) == []
    assert scanner.errors == []


def test_unreadable_manifest_is_named_with_a_reason(tmp_path):
    """Not UTF-8 bytes. `cryptodeps` names what it cannot read; so must we, or "clean" and
    "unreadable" become the same report."""
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xff\xfe\x00\x01pycryptodome\n")
    scanner = DependencyScanner()
    findings = scanner.scan(str(path))
    assert findings == []
    assert len(scanner.errors) == 1
    assert "not UTF-8" in scanner.errors[0]["reason"]


def test_oversized_manifest_is_refused_and_named(tmp_path):
    """A read cap is a security property, but only if the refusal is visible to the operator."""
    path = tmp_path / "requirements.txt"
    path.write_text("pycryptodome\n" * 100, encoding="utf-8")
    original = deps_module.MAX_MANIFEST_BYTES
    try:
        deps_module.MAX_MANIFEST_BYTES = 10
        scanner = DependencyScanner()
        assert scanner.scan(str(path)) == []
        assert len(scanner.errors) == 1
        assert "cap" in scanner.errors[0]["reason"]
    finally:
        deps_module.MAX_MANIFEST_BYTES = original


def test_xml_entity_declaration_is_refused_not_expanded(tmp_path):
    """A `pom.xml` carrying a billion-laughs payload is refused BY NAME, not parsed.

    The scanner points at untrusted trees. XML entity expansion is a denial-of-service and an
    external-entity vector, and a tool that inventories manifests has no reason to expand one.
    """
    payload = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE project [\n'
        '  <!ENTITY a "aaaaaaaaaa">\n'
        '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
        ']>\n'
        '<project><dependencies><dependency><artifactId>bcprov-jdk18on</artifactId>'
        '</dependency></dependencies></project>\n'
    )
    findings, scanner = scan_text(tmp_path, "pom.xml", payload)
    assert findings == []
    assert len(scanner.errors) == 1
    assert "ENTITY" in scanner.errors[0]["reason"]


# ------------------------------------------------------------------ pip / pyproject

def test_requirements_txt_reports_pycryptodome_with_its_declared_algorithms(tmp_path):
    """The brief's worked example: pycryptodome -> RSA, AES, DES, 3DES, MD5, SHA-1.

    These are exactly the algorithms docs/CODE_REVIEW.md calls out as the migration liability,
    and a capability map that omitted DES/3DES would understate the finding.
    """
    findings, _ = scan_text(tmp_path, "requirements.txt", "pycryptodome==3.19.0\n")
    provides = findings[0]["provides"]
    for expected in ("RSA", "AES", "DES", "3DES", "MD5", "SHA-1"):
        assert expected in provides, f"{expected} missing from the capability list"
    assert findings[0]["declared_version"] == "==3.19.0"
    assert findings[0]["ecosystem"] == "pip"


def test_requirements_txt_strips_extras_markers_comments_and_options():
    """Each of these is a real requirements.txt feature that a naive `split('==')` gets wrong,
    and each wrong answer either loses a package or invents a name."""
    content = (
        "# a comment mentioning cryptography\n"
        "-r other-requirements.txt\n"
        "--index-url https://example.invalid/simple\n"
        "cryptography[socks]>=42.0 ; python_version >= '3.8'\n"
        "  PyNaCl==1.5.0  \n"
        "-e .\n"
    )
    deps = parse_requirements_txt(content)
    names = [name.lower() for name, _version, _line in deps]
    assert names == ["cryptography", "pynacl"], "options and includes are not packages"
    version = {n: v for n, v, _l in deps}["cryptography"]
    assert "42.0" in version
    assert "python_version" not in version, "an env marker is a condition, not a version"


def test_pep503_normalisation_matches_the_distribution_name():
    """A requirements file may write `Flask_Login` where the distribution is `flask-login`. A
    literal dict lookup misses it silently, and a silent miss is what this module exists to
    avoid."""
    assert normalise_package("pip", "Flask_Login") == "flask-login"
    assert normalise_package("pip", "zope.interface") == "zope-interface"
    assert normalise_package("pip", "a--b__c.d") == "a-b-c-d"
    scanner = DependencyScanner()
    assert scanner.lookup("pip", "PyNaCl") is not None, "case must not matter"
    # A DASH in the name is a DIFFERENT distribution: PyPI ships both `pynacl` and `py-nacl`,
    # and treating them as one would be a fabricated match.
    assert scanner.lookup("pip", "py-nacl") is None


def test_every_pip_entry_is_reachable_under_pep503_normalisation():
    """Sweep: each pip/pyproject key must be findable under the normalisation that pip itself
    applies, so an entry can never be written in a form the lookup can never match."""
    for ecosystem in ("pip", "pyproject"):
        index = deps_module._CAPABILITY_INDEX[ecosystem]
        for key, entry in index.items():
            assert normalise_package(ecosystem, key) == key, (
                f"{ecosystem}:{key} is not in its own normalised form")


def test_pyproject_reads_pep621_optional_poetry_and_dependency_groups(tmp_path):
    content = (
        "[build-system]\n"
        'requires = ["setuptools>=68"]\n'
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["pycryptodome>=3.19", "paramiko"]\n'
        "[project.optional-dependencies]\n"
        'pqc = ["liboqs-python"]\n'
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'rsa = "^4.0"\n'
        "[tool.poetry.group.dev.dependencies]\n"
        'ecdsa = "^0.18"\n'
        "[dependency-groups]\n"
        'test = ["pyjwt"]\n'
    )
    findings, _ = scan_text(tmp_path, "pyproject.toml", content)
    found = {f["name"] for f in findings}
    assert {"pycryptodome", "paramiko", "liboqs-python", "rsa", "ecdsa", "pyjwt"} <= found
    # `python = "^3.11"` is the interpreter constraint, not a package. Treating it as one
    # would put a fake entry in the inventory.
    assert "python" not in found


def test_pyproject_pins_a_provider_version(tmp_path):
    findings, _ = scan_text(
        tmp_path, "pyproject.toml",
        '[project]\nname="x"\ndependencies=["cryptography==46.0.1"]\n')
    assert findings[0]["declared_version"] == "==46.0.1"


# ------------------------------------------------------------------ npm

def test_package_json_reads_all_four_dependency_sections(tmp_path):
    """devDependencies matter: a test-only crypto library is still a shipped capability in a
    container that installs dev dependencies, and it is invisible if only `dependencies` is
    read."""
    content = json.dumps({
        "name": "demo",
        "dependencies": {"jose": "^5.0.0"},
        "devDependencies": {"node-forge": "1.3.1"},
        "optionalDependencies": {"tweetnacl": "1.0.3"},
        "peerDependencies": {"@noble/curves": "^1.0.0"},
    })
    findings, _ = scan_text(tmp_path, "package.json", content)
    assert {f["name"] for f in findings} == {"jose", "node-forge", "tweetnacl",
                                             "@noble/curves"}


def test_package_json_with_no_crypto_yields_nothing(tmp_path):
    """A React app's manifest must produce zero findings, and the parse must still succeed."""
    content = json.dumps({"name": "app",
                          "dependencies": {"react": "18.2.0", "lodash": "^4.17.21"}})
    findings, scanner = scan_text(tmp_path, "package.json", content)
    assert findings == []
    assert scanner.errors == []
    assert scanner.coverage["dependencies_examined"] == 2


def test_package_json_array_root_is_an_error_not_a_crash(tmp_path):
    """`[1,2,3]` is valid JSON and an invalid manifest. It must be NAMED, not crash on `.get`,
    and not be silently treated as an empty dependency set."""
    findings, scanner = scan_text(tmp_path, "package.json", "[1, 2, 3]")
    assert findings == []
    assert len(scanner.errors) == 1
    assert "not a JSON object" in scanner.errors[0]["reason"]


# ------------------------------------------------------------------ Go

def test_go_mod_reads_block_and_single_line_requires(tmp_path):
    content = (
        "module example.com/app\n\n"
        "go 1.22\n\n"
        "require (\n"
        "\tgithub.com/cloudflare/circl v1.6.4\n"
        "\tgolang.org/x/crypto v0.31.0 // indirect\n"
        ")\n\n"
        "require github.com/golang-jwt/jwt v5.2.1\n"
    )
    findings, _ = scan_text(tmp_path, "go.mod", content)
    assert {f["package"] for f in findings} == {"github.com/cloudflare/circl",
                                               "golang.org/x/crypto",
                                               "github.com/golang-jwt/jwt"}
    circl = next(f for f in findings if f["package"] == "github.com/cloudflare/circl")
    assert circl["declared_version"] == "v1.6.4"


def test_go_indirect_requirement_is_recorded_as_indirect(tmp_path):
    """An indirect dependency is a weaker signal than a direct one, so the distinction is
    preserved rather than discarded -- but it still produces a finding, because a transitive
    crypto library is still reachable code in the build."""
    findings, _ = scan_text(
        tmp_path, "go.mod",
        "module m\n\nrequire (\n\tgolang.org/x/crypto v0.31.0 // indirect\n)\n")
    assert len(findings) == 1
    assert "indirect" in findings[0]["declared_version"]


def test_circl_is_reported_as_a_pqc_capable_provider(tmp_path):
    """CIRCL's README states ML-KEM 512/768/1024 (FIPS 203), ML-DSA 44/65/87 (FIPS 204) and
    twelve SLH-DSA parameter sets (FIPS 205) -- and ALSO ships the deprecated Kyber and
    Dilithium packages. Both halves of that claim are asserted."""
    findings, _ = scan_text(
        tmp_path, "go.mod", "module m\n\nrequire github.com/cloudflare/circl v1.6.4\n")
    finding = findings[0]
    assert finding["provides_pqc"] is True
    assert "ML-KEM-768" in finding["provides"]
    assert "ML-DSA-65" in finding["provides"]
    assert "SLH-DSA" in finding["provides"]
    assert "deprecated" in finding["capability_gate"].lower()


# ------------------------------------------------------------------ Maven

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <artifactId>demo</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78.1</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.13.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <profiles>
    <profile>
      <dependencies>
        <dependency>
          <groupId>org.bouncycastle</groupId>
          <artifactId>bcpkix-jdk18on</artifactId>
          <version>1.78.1</version>
        </dependency>
      </dependencies>
    </profile>
  </profiles>
</project>
"""


def test_pom_xml_reads_direct_and_profile_dependencies(tmp_path):
    """A `<dependency>` inside a `<profile>` is still a declared dependency of the build, and
    a parser that only looks at the top level misses it silently."""
    findings, _ = scan_text(tmp_path, "pom.xml", POM)
    assert {f["name"] for f in findings} == {"bcprov-jdk18on", "tink", "bcpkix-jdk18on"}


def test_pom_xml_retains_scope_in_the_version_field(tmp_path):
    """Maven `<scope>test</scope>` is evidence about how the library is used, so it must
    survive rather than being dropped with the other XML text."""
    findings, _ = scan_text(tmp_path, "pom.xml", POM)
    tink = next(f for f in findings if f["name"] == "tink")
    assert "1.13.0" in tink["declared_version"]
    assert "test" in tink["declared_version"]


def test_bouncycastle_provides_the_weak_primitives_it_is_known_for(tmp_path):
    """BC's classical surface includes DES, 3DES and MD5. Omitting them would make the
    capability claim optimistic in exactly the direction that matters."""
    findings, _ = scan_text(tmp_path, "pom.xml", POM)
    bc = next(f for f in findings if f["name"] == "bcprov-jdk18on")
    for expected in ("RSA", "AES", "DES", "3DES", "MD5", "SHA-1", "Ed25519"):
        assert expected in bc["provides"]


def test_maven_namespaced_pom_is_parsed(tmp_path):
    """The default Maven POM carries an xmlns. A parser that does not strip the namespace sees
    `project:dependencies` and finds nothing -- a silent miss on every real-world pom.xml."""
    findings, _ = scan_text(tmp_path, "pom.xml", POM)
    assert findings, "a namespaced pom.xml must still yield findings"


# ------------------------------------------------------------------ Rust

def test_cargo_toml_reads_dependencies_dev_build_and_target_tables(tmp_path):
    content = (
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
        '[dependencies]\nring = "0.17"\nopenssl = { version = "0.10", features = ["vendored"] }\n'
        'git-dep = { git = "https://example.invalid/x" }\n\n'
        '[dev-dependencies]\nproptest = "1"\n\n'
        '[build-dependencies]\ncc = "1"\n\n'
        "[target.'cfg(unix)'.dependencies]\n"
        'pqcrypto-mlkem = "0.2"\n'
    )
    findings, _ = scan_text(tmp_path, "Cargo.toml", content)
    assert {"ring", "openssl", "pqcrypto-mlkem"} <= {f["name"] for f in findings}


def test_ring_is_not_claimed_to_be_post_quantum(tmp_path):
    """The rustls README states the ring provider 'does not support post-quantum algorithms'.
    A map that marked `ring` PQC-capable would be a fabricated claim about a widely used
    crate -- the kind of error docs/CODE_REVIEW.md H6 calls fatal."""
    findings, _ = scan_text(tmp_path, "Cargo.toml", '[dependencies]\nring = "0.17"\n')
    assert findings[0]["provides_pqc"] is False
    assert not any("ML-KEM" in name for name in findings[0]["provides"])


def test_rustls_pqc_capability_is_attributed_to_its_provider(tmp_path):
    """rustls is a TLS stack: its PQC support is a property of aws-lc-rs vs ring, so the
    capability must not be asserted from the crate name alone."""
    findings, _ = scan_text(tmp_path, "Cargo.toml", '[dependencies]\nrustls = "0.23"\n')
    finding = findings[0]
    assert finding["provides_pqc"] is False
    assert "provider" in finding["capability_gate"].lower()


def test_pqc_capable_rust_crates_are_flagged(tmp_path):
    findings, _ = scan_text(tmp_path, "Cargo.toml",
                            '[dependencies]\npqcrypto-mlkem = "0.1"\npqcrypto-mldsa = "0.2"\n')
    assert {f["name"] for f in findings} == {"pqcrypto-mlkem", "pqcrypto-mldsa"}
    assert all(f["provides_pqc"] for f in findings)


def test_aws_lc_rs_is_the_rust_provider_that_does_carry_pqc(tmp_path):
    """The rustls README describes the aws-lc-rs provider as having 'a complete feature set
    (including post-quantum algorithms)'. That is the documented basis for the claim."""
    findings, _ = scan_text(tmp_path, "Cargo.toml", '[dependencies]\naws-lc-rs = "1.14"\n')
    assert findings[0]["provides_pqc"] is True
    assert "ML-KEM-768" in findings[0]["provides"]


# ------------------------------------------------------------------ Ruby

def test_gemfile_reads_gem_directives_with_parenthesised_form():
    content = (
        "source 'https://rubygems.org'\n"
        "ruby '3.3.0'\n"
        "gem 'openssl', '~> 3.1'\n"
        'gem "rbnacl", "~> 0.5", require: false\n'
        "group :test do\n"
        "  gem 'rspec'\n"
        "end\n"
    )
    names = [name for name, _v, _l in parse_gemfile(content)]
    assert "openssl" in names and "rbnacl" in names
    # `ruby '3.3.0'` and `source ...` are directives, not packages.
    assert "ruby" not in names and "source" not in names


def test_gemfile_with_openssl_reports_a_capability(tmp_path):
    findings, _ = scan_text(tmp_path, "Gemfile", "source 'https://rubygems.org'\ngem 'openssl'\n")
    assert findings[0]["name"] == "openssl"
    # The LINKED OpenSSL version decides the PQC story, not the gem name.
    assert findings[0]["provides_pqc"] is False
    assert "3.5" in findings[0]["capability_gate"]


def test_gemfile_lock_spelling_is_also_parsed():
    """`Gemfile.lock` uses `name (version)`, a different spelling for the same fact. Missing it
    leaves the RESOLVED dependency set -- stronger evidence than the request -- invisible."""
    deps = parse_gemfile("GEM\n  remote: https://rubygems.org/\n  specs:\n"
                         "    openssl (3.2.0)\n    rbnacl (0.5.0)\n")
    assert {name for name, _v, _l in deps} == {"openssl", "rbnacl"}


# ------------------------------------------------------------------ PHP

def test_composer_reads_require_and_require_dev_including_platform_packages(tmp_path):
    """`ext-openssl` is a Composer PLATFORM requirement -- a first-class dependency declaring
    the runtime algorithm set. A parser matching only `vendor/package` misses it, and PHP
    projects state their crypto surface exactly this way."""
    content = json.dumps({
        "require": {"php": ">=8.2", "ext-openssl": "*", "paragonie/sodium_compat": "^2.0"},
        "require-dev": {"phpunit/phpunit": "^10"},
    })
    findings, _ = scan_text(tmp_path, "composer.json", content)
    assert {f["name"] for f in findings} == {"ext-openssl", "paragonie/sodium_compat"}


def test_composer_platform_package_is_not_claimed_to_be_post_quantum(tmp_path):
    """`ext-openssl` with no version constraint says nothing about which OpenSSL is linked, so
    no PQC claim may be made from it."""
    findings, _ = scan_text(tmp_path, "composer.json",
                            json.dumps({"require": {"ext-openssl": "*"}}))
    assert findings[0]["provides_pqc"] is False
    assert "3.5" in findings[0]["capability_gate"]


def test_composer_with_no_crypto_yields_nothing(tmp_path):
    findings, scanner = scan_text(
        tmp_path, "composer.json",
        json.dumps({"require": {"php": ">=8.2", "monolog/monolog": "^3.0"}}))
    assert findings == []
    assert scanner.errors == []


# ------------------------------------------------------------------ .NET

def test_packages_config_and_csproj_are_both_parsed(tmp_path):
    """Both NuGet spellings name real packages; the SENSOR then decides which are crypto."""
    config = ('<?xml version="1.0"?><packages>\n'
              '  <package id="BouncyCastle.Cryptography" version="2.4.0" />\n'
              '  <package id="Newtonsoft.Json" version="13.0.3" />\n'
              '</packages>')
    path = write(tmp_path, "packages.config", config)
    scanner = DependencyScanner()
    findings = scanner.scan(path)
    # Newtonsoft.Json is in the manifest and is NOT cryptography, so it is examined and dropped.
    assert [f["name"] for f in findings] == ["BouncyCastle.Cryptography"]
    assert scanner.coverage["dependencies_examined"] == 2, "both packages were read"
    assert scanner.errors == []

    csproj = ('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>\n'
              '  <PackageReference Include="NSec.Cryptography" Version="24.2.0" />\n'
              '</ItemGroup></Project>')
    names = {name for name, _v, _l in parse_dotnet(csproj)}
    assert names == {"NSec.Cryptography"}


# ------------------------------------------------------------------ the PQC / draft distinction

def test_kyber_package_is_a_deprecated_draft_not_a_pqc_capability(tmp_path):
    """`kyber-py` ships Kyber-768, which is NOT ML-KEM-768. The map must say so.

    This is the module-level expression of the H6 defect: a scanner that reports Kyber as
    post-quantum-ready is telling a team their migration landed when it did not.
    """
    findings, _ = scan_text(tmp_path, "requirements.txt", "kyber-py==0.3.0\n")
    finding = findings[0]
    assert finding["provides_pqc"] is False, "Kyber is a draft; FIPS 203 standardised ML-KEM"
    assert "Kyber768" in finding["provides"]
    assert not any("ML-KEM" in name for name in finding["provides"])
    assert "NOT ML-KEM-768" in finding["capability_note"]


def test_dilithium_and_sphincs_packages_are_drafts_not_the_fips_algorithms(tmp_path):
    """The same rule for the other two pre-standardisation names."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "dilithium-py\nsphincs\n")
    by_name = {f["name"]: f for f in findings}
    assert by_name["dilithium-py"]["provides_pqc"] is False
    assert by_name["sphincs"]["provides_pqc"] is False
    assert "pre-standardisation" in by_name["dilithium-py"]["capability_note"].lower()


def test_liboqs_binding_is_pqc_but_advertises_its_deprecated_half(tmp_path):
    """liboqs genuinely provides ML-KEM (its README calls those names STABLE), but it ALSO still
    builds Kyber and Dilithium. The finding must be PQC-capable AND carry that caveat, because
    the dependency alone cannot tell you which one a caller used."""
    findings, _ = scan_text(tmp_path, "requirements.txt", "liboqs-python\n")
    finding = findings[0]
    assert finding["provides_pqc"] is True
    assert "Kyber" in finding["capability_gate"]
    assert "does not tell you" in finding["capability_note"]


def test_no_pre_standardisation_package_is_silently_marked_pqc_capable():
    """A sweep over the whole map. If someone adds a Kyber/Dilithium/SPHINCS package and marks
    it `pqc=True`, this fails -- the cheapest possible guard against a repeat of H6."""
    offenders = []
    for ecosystem, index in deps_module._CAPABILITY_INDEX.items():
        for name, entry in index.items():
            if not entry["pqc"]:
                continue
            provides = " ".join(entry["provides"]).lower()
            if "kyber" in provides or "dilithium" in provides or "sphincs" in provides:
                offenders.append(f"{ecosystem}:{name} -> {entry['provides']}")
    assert offenders == [], f"pre-standardisation names marked PQC-capable: {offenders}"


# ------------------------------------------------------------------ filesystem policy

def test_credential_store_is_never_read_and_is_named(tmp_path):
    """`.npmrc` holds registry auth tokens. A crypto inventory has no reason to contain one, and
    putting it in a report is a disclosure bug, not a finding (engine/fspolicy.py's rule)."""
    (tmp_path / ".npmrc").write_text("//registry:_authToken=SECRET-TOKEN\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"jose": "1.0"}}), encoding="utf-8")
    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))
    assert [f["name"] for f in findings] == ["jose"]
    assert any("credential store" in err["reason"] for err in scanner.errors)
    assert "SECRET-TOKEN" not in json.dumps(scanner.coverage_manifest())


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_symlink_escaping_the_scan_root_is_not_followed_and_is_named(tmp_path):
    """A symlink named `package.json` pointing outside the root must not be read.

    The same primitive engine/fspolicy.py closes for the source scanner. A new sensor that walks
    a tree inherits the same exposure, so it must apply the same policy.
    """
    outside = tmp_path.parent / "outside_manifest_for_test.json"
    outside.write_text(json.dumps({"dependencies": {"jose": "1.0"}}), encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(str(outside), str(root / "package.json"))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted here")
    try:
        scanner = DependencyScanner()
        findings = scanner.scan(str(root))
        assert findings == [], "a symlinked manifest must not be read"
        assert any("escapes the scan root" in err["reason"] for err in scanner.errors)
    finally:
        outside.unlink()


def test_nonexistent_root_is_named_not_raised(tmp_path):
    scanner = DependencyScanner()
    assert scanner.scan(str(tmp_path / "does-not-exist")) == []
    assert len(scanner.errors) == 1
    assert "does not exist" in scanner.errors[0]["reason"]


# ------------------------------------------------------------------ coverage honesty

def test_clean_manifest_and_unreadable_manifest_produce_different_coverage(tmp_path):
    """The whole point of the `errors` channel. Both runs find nothing; only one of them knows
    what it did. If these two coverage manifests ever compare equal, the contract is broken."""
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    clean_scanner = DependencyScanner()
    clean_findings = clean_scanner.scan(str(clean))
    clean_manifest = clean_scanner.coverage_manifest(clean_findings)

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "requirements.txt").write_bytes(b"\xff\xfe\x00\x01flask\n")
    broken_scanner = DependencyScanner()
    broken_findings = broken_scanner.scan(str(broken))
    broken_manifest = broken_scanner.coverage_manifest(broken_findings)

    assert clean_findings == broken_findings == []
    assert clean_manifest["manifests_parsed"] == 1
    assert clean_manifest["manifests_unreadable"] == 0
    assert broken_manifest["manifests_parsed"] == 0
    assert broken_manifest["manifests_unreadable"] == 1
    assert clean_manifest != broken_manifest


def test_coverage_manifest_states_the_assurance_and_the_blind_spots(tmp_path):
    findings, scanner = scan_text(tmp_path, "requirements.txt", "cryptography\n")
    manifest = scanner.coverage_manifest(findings)
    assert "capability" in manifest["assurance"].lower()
    assert "call site" in manifest["assurance"].lower()
    assert manifest["never_in_scope"], "the blind spots must be stated, not implied"
    assert any("transitive" in gap for gap in manifest["never_in_scope"])
    assert manifest["libraries_in_map"] > 50


def test_findings_flow_through_mosca_and_the_cbom_as_library_components(tmp_path):
    """A dependency finding must survive the same downstream pipeline as a source finding and
    still be modelled as a library, not as an algorithm with a made-up primitive."""
    from engine.cbom import generate_cbom
    from engine.mosca import calculate_risk

    findings, _ = scan_text(tmp_path, "requirements.txt", "pycryptodome\n")
    for finding in findings:
        finding["risk"] = calculate_risk(finding)
        finding["recommendation"] = get_pqc_recommendation(finding)
    document = json.loads(generate_cbom(findings, enriched=True, subject_name="dep-target"))
    component = document["components"][0]
    assert component["type"] == "library"
    properties = {p["name"]: p["value"] for p in component["properties"]}
    assert properties["im:assurance"] == ASSURANCE_CAPABILITY
    assert properties["im:evidence_class"] == "dependency"


# ------------------------------------------------------------------ manifest identification

@pytest.mark.parametrize("basename,expected", [
    ("requirements.txt", "pip"),
    ("Requirements-Prod.txt", "pip"),
    ("requirements.in", "pip"),
    ("pyproject.toml", "pyproject"),
    ("package.json", "npm"),
    ("package-lock.json", "npm"),
    ("go.mod", "gomod"),
    ("pom.xml", "maven"),
    ("Cargo.toml", "cargo"),
    ("Cargo.lock", "cargo"),
    ("Gemfile", "gem"),
    ("Gemfile.lock", "gem"),
    ("composer.json", "composer"),
    ("packages.config", "dotnet"),
    ("main.py", None),
    ("README.md", None),
    ("package.json.bak", None),
    (".npmrc", None),
])
def test_manifest_identification(basename, expected):
    """Basename matching is case-insensitive and prefix-aware, and must not over-match:
    `package.json.bak` is a backup, not a manifest."""
    assert manifest_kind(basename) == expected


def test_every_advertised_ecosystem_has_a_parser_and_an_index():
    """A manifest kind with no parser would read as "no dependencies", which is a silent lie.
    The two structures are asserted to cover each other exactly."""
    assert set(deps_module.PARSERS) == set(deps_module._ECOSYSTEM_LIBS)
    for kind, entries in deps_module._ECOSYSTEM_LIBS.items():
        assert entries, f"ecosystem {kind} has an empty capability index"


def test_every_capability_entry_declares_a_valid_primitive():
    """`primitive` is emitted into the CBOM and consumed by mosca/recommender. A typo would put
    an out-of-vocabulary value into a schema-validated document."""
    allowed = {"pke", "key-agreement", "signature", "ae", "block-cipher", "hash", "mac", "kem",
               "kdf", "xof", "protocol", "drbg", "other"}
    for ecosystem, index in deps_module._CAPABILITY_INDEX.items():
        for name, entry in index.items():
            assert entry["primitive"] in allowed, f"{ecosystem}:{name} -> {entry['primitive']}"


def test_a_library_whose_algorithm_set_is_platform_dependent_declares_no_pqc():
    """A PURE wrapper around a system library must never carry a PQC claim.

    OpenSSL 3.5 added ML-KEM/ML-DSA/SLH-DSA, but a dependency named `openssl` or
    `pyopenssl` does not establish WHICH OpenSSL is linked -- the claim would be unearned, and
    an unearned PQC claim is worse than none: it tells a team their migration landed.

    This is a named denylist, not a heuristic over the `gate` text. `aws-lc-rs` is deliberately
    NOT on it: the rustls README documents that provider as carrying post-quantum algorithms, so
    its claim IS earned, and a keyword test would wrongly fail it.
    """
    pure_wrappers = {
        ("pip", "pyopenssl"), ("cargo", "openssl"), ("cargo", "native-tls"),
        ("gem", "openssl"), ("composer", "ext-openssl"), ("npm", "crypto"),
        ("dotnet", "System.Security.Cryptography"),
    }
    for ecosystem, name in sorted(pure_wrappers):
        # The index is keyed on the normalised (lower-cased) package name.
        entry = deps_module._CAPABILITY_INDEX[ecosystem].get(name.lower())
        assert entry is not None, f"{ecosystem}:{name} should be in the map"
        assert entry["pqc"] is False, (
            f"{ecosystem}:{name} wraps a system library; its PQC set is the LINKED library's, "
            f"so no claim may be made from the dependency name")
        assert entry["gate"], f"{ecosystem}:{name} must state the condition it depends on"
