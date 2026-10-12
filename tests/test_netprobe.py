"""Tests for the live-crypto sensor (`engine/netprobe.py`).

NO NETWORK. The whole suite runs offline by monkeypatching the one function that opens a socket
(`connect_vetted`) and, where a completed handshake is needed, by handing `_report_handshake` a
stub socket. That is deliberate: a test suite that dials the internet is a suite that breaks on a
plane, in CI, and behind a proxy -- and one that proves nothing about SAFETY, which is the part
that has to be right.

The refusal and policy paths are tested FOR REAL, because they are what matter: an endpoint the
operator must never reach must be refused with a reason, and the group must never be invented.
Those paths need no network to exercise, so there is no excuse for not testing them.

Every test is written to be ABLE TO FAIL, and names the defect it catches. The negative cases are
the load-bearing ones: this is the sensor whose worst failure mode is a confident wrong answer.

Covered, in order of how badly a bug would hurt:
  * the opt-in gate -- the sensor must contact NOTHING unless explicitly enabled
  * the group honesty contract -- observed, or explicitly unobserved, NEVER guessed
  * refusals and unreachable endpoints as results, never exceptions
  * finding shape and the evidence-class/sensor provenance
  * the lab-derived marking, and the no-second-resolution guarantee
"""
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import netprobe
from engine.netpolicy import NetPolicy, VettedEndpoint
from engine.netprobe import (GROUP_OBSERVED, GROUP_UNOBSERVED, SENSOR_TLS,
                             STATUS_DISABLED, STATUS_ERROR, STATUS_HANDSHAKE_FAILED,
                             STATUS_NOT_TLS, STATUS_OBSERVED, STATUS_REFUSED,
                             STATUS_UNREACHABLE, _is_pqc_kex, _report_handshake,
                             coverage_manifest, group_unobserved_reason, openssl_supports_group,
                             probe_endpoint, probe_endpoints, probe_tls, read_negotiated_group)

PUBLIC_IP = "93.184.216.34"


def public_policy(**kwargs):
    """A policy permitting exactly one allowlisted public host, with a fake resolver."""
    kwargs.setdefault("allowed_hosts", ["example.com"])
    kwargs.setdefault("resolver", lambda host, port: [(socket.AF_INET, PUBLIC_IP)])
    return NetPolicy(**kwargs)


def endpoint_stub(hostname="example.com", port=443, address=PUBLIC_IP, lab=False):
    """A VettedEndpoint built by hand, so tests never depend on the policy to make one."""
    return VettedEndpoint(hostname=hostname, port=port, address=address,
                          family=socket.AF_INET, lab_derived=lab, verdict="public",
                          reason="test fixture")


class FakeTLSSocket(object):
    """Stands in for a completed `SSLSocket`. Records which accessors the reporter used.

    `group` is None by default because THAT IS THE CASE THIS HOST IS IN: OpenSSL 3.0.18 has no
    `SSLSocket.group`. A fake that always returned a group would let a real "it guessed the
    group" bug pass, so the default fake reproduces the honest, unobserved world.
    """

    def __init__(self, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                 group=None):
        self._version = version
        self._cipher = cipher
        self._group = group
        self.accessed = []

    def version(self):
        self.accessed.append("version")
        return self._version

    def cipher(self):
        self.accessed.append("cipher")
        return self._cipher

    def group(self):
        self.accessed.append("group")
        return self._group

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def no_sockets(monkeypatch):
    """Make ANY socket creation an immediate, obvious test failure.

    The default-off test is only meaningful if we can prove nothing was dialled. Rather than
    trusting that `probe_endpoint` returns early, this replaces `socket.socket` with a bomb: if a
    test that claims to contact nothing opens a socket, it fails loudly instead of quietly
    reaching the network.
    """
    def bomb(*args, **kwargs):
        raise AssertionError("a socket was created in a test that must not touch the network")
    monkeypatch.setattr(netprobe.socket, "socket", bomb)
    return True


@pytest.fixture
def stub_connect(monkeypatch):
    """Replace `connect_vetted` so the transport is under the test's control, not the network's."""
    def _install(result):
        calls = []

        def fake_connect_vetted(endpoint, timeout=None):
            calls.append((endpoint.address, endpoint.port))
            return result
        monkeypatch.setattr(netprobe, "connect_vetted", fake_connect_vetted)
        return calls
    return _install


# ======================================================================== the opt-in gate
def test_the_sensor_is_off_by_default_and_contacts_nothing(no_sockets):
    """THE safety default. A network sensor must not run because it was called.

    `no_sockets` replaces `socket.socket` with a bomb, so this test does not merely assert a
    status string -- it proves no socket was created. "A tool that opens connections because it
    was called reaches networks its operator never chose", which is the whole reason a scanner
    pointed at a checkout should not start dialling third parties.
    """
    result = probe_endpoint("example.com:443", policy=public_policy())
    assert result["status"] == STATUS_DISABLED
    assert result["findings"] == [], "a disabled sensor must not produce findings"
    assert "enable=True" in result["reason"], "the reason must say how to turn it on"


def test_the_batch_is_off_by_default_and_reaches_nothing(no_sockets):
    """The same guarantee at the batch level, which is the level an operator would actually use."""
    report = probe_endpoints(["example.com:443", "example.com:8443"], policy=public_policy())
    assert report["results"] == []
    assert report["refused"] == []
    assert report["coverage"]["enabled"] is False
    assert "OFF by default" in report["coverage"]["reason"]


def test_an_enabled_probe_of_a_refused_endpoint_opens_no_socket(no_sockets):
    """Opting in must not bypass the policy. The gate and the policy are separate controls.

    Without this, "enable=True" would be a master switch that also disabled the SSRF firewall,
    and the two properties would be mutually exclusive in exactly the dangerous case.
    """
    result = probe_endpoint("127.0.0.1:443", policy=public_policy(), enable=True)
    assert result["status"] == STATUS_REFUSED
    assert result["findings"] == []


# ======================================================================== the group contract
def test_an_unobservable_group_is_reported_unobserved_and_never_invents_one():
    """THE honesty property, quoted from the sibling's README and made executable.

    "Reading the actual negotiated group needs OpenSSL 3.5+ locally. Without it the key-exchange
     mechanism stays unobserved rather than being guessed."

    On this host (OpenSSL 3.0.18) `SSLSocket.group` does not exist, so a completed TLS 1.3
    handshake reports a version and a cipher but NO group. The assertions are deliberately
    redundant: the status must say unobserved, `group` must be None, the gap must be recorded,
    and -- most importantly -- NO finding may name a group.
    """
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group=None))

    assert result["status"] == STATUS_OBSERVED
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["group"] is None, "no group was read, so none may be reported"
    assert result["group_status"] == GROUP_UNOBSERVED

    names = [f["name"] for f in result["findings"]]
    assert "TLSv1.3" in names and "TLS_AES_256_GCM_SHA384" in names
    for group in ("X25519", "secp256r1", "P-256", "X448", "ffdhe2048",
                  "X25519MLKEM768", "MLKEM768", "SecP256r1MLKEM768"):
        assert group not in names, "%s must never appear when no group was observed" % group
    # EXACTLY two findings: the protocol and the cipher. A third would mean the group branch ran
    # with nothing to report. This is the assertion that catches an `if True:` in place of the
    # observation gate -- a mutant that emits a finding named `None`, which a "no classical group
    # appears in the names" check sails straight past.
    assert len(result["findings"]) == 2, \
        "an unobserved group must produce no group finding, got %r" % (names,)
    for finding in result["findings"]:
        assert finding["name"], "a finding with no name is a malformed finding, not an observation"
        assert finding["rule_id"] != netprobe.RULE_TLS_GROUP, \
            "a group finding must not be emitted when no group was observed"


def test_an_unobserved_group_is_recorded_as_a_named_gap_not_left_silent():
    """A gap nobody can see is a gap somebody will fill with a guess.

    The result must carry `not_observed` with a reason and a stated consequence, because the
    difference between "this endpoint uses no post-quantum key exchange" and "this endpoint's key
    exchange was not observed on this host" is the difference between a finding and a fabrication.
    """
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group=None))
    assert "not_observed" in result, "an unobserved group must be recorded, not omitted"
    gap = result["not_observed"][0]
    assert gap["status"] == GROUP_UNOBSERVED
    assert "key-exchange group" in gap["item"]
    assert "UNKNOWN" in gap["consequence"], \
        "the consequence must say what is unknown, not merely that something is missing"
    assert "NOT a finding of" in gap["consequence"], \
        "it must distinguish 'unknown' from 'no post-quantum crypto', since only the first is true"


def test_the_unobserved_reason_names_the_requirement_and_refuses_the_inference():
    """The reason a reader sees must pre-empt the inference they are about to make.

    A bare "unobserved" invites "so it's probably X25519". The reason therefore names the
    OpenSSL 3.5+ requirement AND states, explicitly, that the group is not derived from the TLS
    version, the cipher suite, or the client's offered list -- because all three inferences are
    wrong and all three are tempting.
    """
    reason = group_unobserved_reason()
    assert "UNOBSERVED" in reason
    if not openssl_supports_group():
        assert "3.5" in reason, "the requirement must be named so an operator can fix it"
        assert "not the same as" in reason
        assert "suite" in reason.lower(), "it must say the cipher suite does not determine the group"


def test_an_observed_group_is_reported_and_labelled_from_the_iana_registry(monkeypatch):
    """The positive control: when the group IS readable, it is reported and correctly labelled.

    Without this, a "never guess" implementation passes every test above while being useless --
    the same failure as a deny-list with no allow path. The label is what turns an observed group
    into a PQC answer.
    """
    monkeypatch.setattr(netprobe, "openssl_supports_group", lambda: True)
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group="X25519MLKEM768"))

    assert result["group"] == "X25519MLKEM768"
    assert result["group_status"] == GROUP_OBSERVED
    assert "not_observed" not in result, "an observed group must not also be reported as a gap"

    group_findings = [f for f in result["findings"] if f["rule_id"] == netprobe.RULE_TLS_GROUP]
    assert len(group_findings) == 1
    finding = group_findings[0]
    assert finding["name"] == "X25519MLKEM768"
    assert finding["provides_pqc"] is True
    assert finding["classical_half"] == "X25519"
    assert finding["pqc_half"] == "ML-KEM-768"
    assert "BOTH halves" in finding["observation_note"], \
        "a hybrid must state the AND semantics, not read as 'half migrated'"


def test_an_obsolete_kyber_draft_group_is_not_reported_as_ml_kem(monkeypatch):
    """A negotiated Kyber DRAFT is not ML-KEM, and the sensor must not blur them.

    FIPS 203 standardised ML-KEM; Kyber round-3 is a different scheme with different security
    claims. This is docs/CODE_REVIEW.md H6, and on the wire it is a live possibility because the
    obsolete IANA codepoints (25497/25498) are still deployed in the field.
    """
    monkeypatch.setattr(netprobe, "openssl_supports_group", lambda: True)
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group="X25519Kyber768Draft00"))
    finding = [f for f in result["findings"] if f["rule_id"] == netprobe.RULE_TLS_GROUP][0]
    assert finding["provides_pqc"] is False, "a draft codepoint is not a standardised PQC group"
    assert finding["obsolete"] is True
    assert "not ML-KEM-768" in finding["observation_note"]


def test_an_unrecognised_group_is_reported_observed_but_unlabelled(monkeypatch):
    """An observed group we have no registry entry for is reported as-is, not guessed at.

    Inventing a classification for an unknown codepoint is the same error as inventing the group
    itself, one level up. "Observed and unlabelled" is the honest third option.
    """
    monkeypatch.setattr(netprobe, "openssl_supports_group", lambda: True)
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group="someFutureGroup99"))
    finding = [f for f in result["findings"] if f["rule_id"] == netprobe.RULE_TLS_GROUP][0]
    assert finding["name"] == "someFutureGroup99"
    assert finding["provides_pqc"] is False
    assert "not in the PQC registry" in finding["pqc_note"]


def test_reading_the_group_never_raises_and_never_guesses(monkeypatch):
    """A group read that blows up must degrade to 'unobserved', not to an exception or a default.

    TLS 1.2 has no single TLS 1.3-style group, and builds differ in whether they raise or return
    None. Both outcomes must land on the same honest answer.
    """
    class ExplodingSocket(object):
        def group(self):
            raise ValueError("no group negotiated")

    monkeypatch.setattr(netprobe, "openssl_supports_group", lambda: True)
    name, status, reason = read_negotiated_group(ExplodingSocket())
    assert name is None
    assert status == GROUP_UNOBSERVED
    assert "UNOBSERVED" in reason
    assert "cipher suite" in reason, "it must say the suite does not determine the group"


# ======================================================================== failures are results
def test_an_unreachable_endpoint_is_a_recorded_result_not_an_exception(stub_connect):
    """A refused connection or a timeout is a RESULT. An exception would be a defect.

    "The host did not answer" and "we did not ask" must be distinguishable, and an operator
    reading a report has no way to tell them apart if one of them is a traceback.
    """
    calls = stub_connect((None, "connection to %s:443 refused: nothing is listening" % PUBLIC_IP))
    result = probe_tls(endpoint_stub(), timeout=0.1)

    assert result["status"] == STATUS_UNREACHABLE
    assert "refused" in result["reason"]
    assert result["findings"] == [], "a host we could not reach yields no findings"
    assert calls == [(PUBLIC_IP, 443)], "the connect target must be the vetted LITERAL"


def test_a_timeout_is_recorded_with_the_timeout_that_was_used(stub_connect):
    """A timeout must name its duration, or an operator cannot tell a slow host from a dead one."""
    stub_connect((None, "connection to %s:443 timed out after 2.5s" % PUBLIC_IP))
    result = probe_tls(endpoint_stub(), timeout=2.5)
    assert result["status"] == STATUS_UNREACHABLE
    assert "2.5" in result["reason"], "the reason must state the timeout that elapsed"


def test_a_plaintext_service_on_a_tls_port_is_reported_as_not_tls(monkeypatch, stub_connect):
    """A wrong-version-number failure is a PORT problem, not a cipher problem.

    OpenSSL reports "wrong version number" for a plaintext HTTP server on 443. Folding that into
    a generic handshake failure sends the operator hunting a cipher misconfiguration that does not
    exist, so the distinction is a separate status.
    """
    import ssl as _ssl
    stub_connect((object(), None))
    monkeypatch.setattr(netprobe, "_tls_context", lambda: (_ for _ in ()).throw(
        AssertionError("unused")))
    # Drive the classifier directly: this is the mapping that matters.
    from engine.netprobe import _classify_ssl_error
    result = _classify_ssl_error(endpoint_stub(), _ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] "
                                                                  "wrong version number"))
    assert result["status"] == STATUS_NOT_TLS
    assert "not speaking TLS" in result["reason"]


def test_a_handshake_failure_names_the_alert(stub_connect):
    """A server alert is information: it usually means a client certificate is required."""
    import ssl as _ssl
    from engine.netprobe import _classify_ssl_error
    result = _classify_ssl_error(endpoint_stub(), _ssl.SSLError(1, "TLSV1_ALERT_HANDSHAKE_FAILURE"))
    assert result["status"] == STATUS_HANDSHAKE_FAILED
    assert "client certificate" in result["reason"] or "alert" in result["reason"]


def test_an_unexpected_error_inside_a_probe_is_contained_not_raised(monkeypatch):
    """A sensor must never take the caller down, however badly a peer behaves it.

    The batch loop in `probe_endpoints` relies on this: one endpoint raising would end the scan
    and silently truncate the report, which is the "confident empty report" failure mode.
    """
    def explode(endpoint, timeout=None, context=None):
        raise RuntimeError("something nobody predicted")
    monkeypatch.setattr(netprobe, "probe_tls", explode)

    result = probe_endpoint("example.com:443", policy=public_policy(), enable=True)
    assert result["status"] == STATUS_ERROR
    assert "RuntimeError" in result["reason"], "the failure must be named, not swallowed"
    assert result["findings"] == []


# ======================================================================== the connect target
def test_the_probe_never_connects_to_a_hostname(monkeypatch):
    """The rebinding guarantee, asserted at the probe rather than only in the policy.

    `connect_vetted` builds its sockaddr from `endpoint.address`. This pins that the value handed
    to `connect` is the numeric literal and never the operator's hostname -- if someone "simplified"
    this into `socket.create_connection((endpoint.hostname, ...))`, the whole DNS-rebinding defence
    would quietly evaporate, and the policy tests would still pass.
    """
    seen = {}

    class RecordingSocket(object):
        def settimeout(self, value):
            seen["timeout"] = value

        def connect(self, sockaddr):
            seen["sockaddr"] = sockaddr

        def close(self):
            pass

    monkeypatch.setattr(netprobe.socket, "socket",
                        lambda family, kind: RecordingSocket())
    netprobe.connect_vetted(endpoint_stub(hostname="evil.example", address=PUBLIC_IP), timeout=1.0)

    assert seen["sockaddr"] == (PUBLIC_IP, 443)
    assert seen["sockaddr"][0] != "evil.example", "the hostname must never reach connect()"
    assert seen["timeout"] == 1.0, "the timeout must be applied, or a probe can hang a batch"


def test_an_ipv6_endpoint_is_connected_with_a_four_tuple(monkeypatch):
    """AF_INET6 needs (host, port, flowinfo, scopeid); a 2-tuple raises on some platforms.

    Without this, every IPv6 target fails with a confusing error that looks like an unreachable
    host rather than a code bug.
    """
    seen = {}

    class RecordingSocket(object):
        def settimeout(self, value):
            pass

        def connect(self, sockaddr):
            seen["sockaddr"] = sockaddr

        def close(self):
            pass

    monkeypatch.setattr(netprobe.socket, "socket", lambda family, kind: RecordingSocket())
    endpoint = endpoint_stub(hostname="v6.example", port=443, address="2606:4700::1111")
    endpoint.family = socket.AF_INET6
    netprobe.connect_vetted(endpoint, timeout=1.0)
    assert seen["sockaddr"] == ("2606:4700::1111", 443, 0, 0)


# ======================================================================== finding provenance
def test_every_observed_finding_carries_evidence_class_and_names_its_sensor():
    """A finding must say what class of evidence it is, and which sensor produced it.

    `engine/purpose.py::EVIDENCE_TO_ASSURANCE` maps "observed" to ASSURANCE_OBSERVED -- the whole
    reason this sensor exists -- and `coverage_manifest()` builds `scanners_run` from `scanner`.
    An observed finding missing either field is a claim with no witness, and the coverage manifest
    would silently omit the sensor that produced it.
    """
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group=None))
    assert result["findings"], "a completed handshake must produce findings"
    for finding in result["findings"]:
        assert finding["evidence_class"] == "observed", \
            "%s must be observed, not %r" % (finding["name"], finding["evidence_class"])
        assert finding["scanner"] == netprobe.SCANNER_NETWORK
        assert finding["sensor"] == SENSOR_TLS, "every finding must name the sensor that made it"
        assert finding["rule_id"], "a finding without a rule ID cannot be audited or suppressed"
        assert finding["file"] == "example.com:443", "provenance must be the endpoint"
        assert finding["line"] == 0


def test_observed_findings_map_to_the_top_assurance_level():
    """The point of the whole sensor, asserted through the engine's own mapping.

    If `evidence_class` were anything else, `resolve_assurance` would return "capability" or "used"
    and the finding would rank BELOW a static source match -- which would mean the most direct
    evidence this tool can produce is reported as its weakest.
    """
    from engine.purpose import ASSURANCE_OBSERVED, resolve_assurance
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group=None))
    for finding in result["findings"]:
        assurance, _reason = resolve_assurance(finding)
        assert assurance == ASSURANCE_OBSERVED, \
            "%s resolved to %s, not observed" % (finding["name"], assurance)


def test_observed_findings_survive_the_cbom_generator():
    """Integration: the findings must be consumable by `engine/cbom.py` without a crash.

    `generate_cbom` reads specific keys and treats an empty `file` as "no provenance". A finding
    that omits one produces either a crash or a component with no traceable source, several
    modules downstream of the sensor that created it.
    """
    import json
    from engine.cbom import generate_cbom
    result = _report_handshake(endpoint_stub(), FakeTLSSocket(group=None))
    document = json.loads(generate_cbom(result["findings"]))
    assert document["bomFormat"] == "CycloneDX"
    assert document["components"], "the observed algorithms must reach the CBOM as components"


def test_a_lab_target_marks_every_finding_it_produced():
    """The lab-derived mark must travel WITH THE FINDINGS, not merely sit in the result header.

    An operator comparing a lab run against production must not have to cross-reference which host
    was which: the finding itself says where it came from.
    """
    result = _report_handshake(endpoint_stub(lab=True), FakeTLSSocket(group=None))
    assert result["lab_derived"] is True
    assert "LAB-DERIVED" in result["lab_note"]
    assert result["findings"], "a lab handshake still produces findings"
    for finding in result["findings"]:
        assert finding["lab_derived"] is True, "every lab finding must carry the mark"
        assert "LAB-DERIVED" in finding["lab_note"]


def test_a_public_target_carries_no_lab_mark():
    """The other direction, so the mark cannot spread by accident and stop meaning anything."""
    result = _report_handshake(endpoint_stub(lab=False), FakeTLSSocket(group=None))
    assert result["lab_derived"] is False
    assert result["lab_note"] is None
    for finding in result["findings"]:
        assert "lab_derived" not in finding, "a public finding must not be marked lab-derived"


def test_a_lab_probe_through_the_public_api_is_permitted_and_marked(stub_connect):
    """End-to-end: ALLOW_PRIVATE_TARGETS lets a lab target through, and the mark survives the hop.

    This exercises the whole chain -- policy marks the endpoint, the endpoint marks the findings --
    because a mark set on the endpoint but dropped on the way into a finding is the most likely way
    this property would fail in practice.
    """
    policy = NetPolicy(allowed_hosts=["127.0.0.1"], allow_private=True,
                       resolver=lambda host, port: [(socket.AF_INET, "127.0.0.1")])
    stub_connect((None, "connection to 127.0.0.1:443 refused"))
    result = probe_endpoint("127.0.0.1:443", policy=policy, enable=True)
    assert result["status"] == STATUS_UNREACHABLE
    assert result["lab_derived"] is True, "a lab target must stay marked even when unreachable"


# ======================================================================== the report shape
def test_the_batch_report_separates_results_from_refusals(monkeypatch):
    """A report must distinguish "we looked and found this" from "we declined to look".

    Collapsing them produces the confident empty report this project exists to avoid: an operator
    sees no findings and cannot tell whether the host was clean or was never examined.
    """
    policy = public_policy(allowed_hosts=["example.com", "127.0.0.1"])
    monkeypatch.setattr(netprobe, "probe_tls",
                        lambda endpoint, timeout=None, context=None: {
                            "status": STATUS_OBSERVED, "sensor": SENSOR_TLS, "reason": "ok",
                            "findings": [], "lab_derived": False})

    report = probe_endpoints(["example.com:443", "127.0.0.1:443", "example.com:8080"],
                             policy=policy, enable=True)
    assert report["coverage"]["endpoints_probed"] == 1
    assert report["coverage"]["endpoints_refused"] == 2
    assert report["coverage"]["sensors_run"] == [SENSOR_TLS]

    verdicts = {r["verdict"] for r in report["refused"]}
    assert "private-target" in verdicts
    assert "port-not-allowlisted" in verdicts
    for refusal in report["refused"]:
        assert refusal["reason"], "a refusal must carry a reason"
    assert report["coverage"]["policy"]["allowed_hosts"], \
        "the coverage must record the policy that was in force"


def test_the_coverage_manifest_states_the_group_limitation():
    """The manifest must say whether the group is observable ON THIS HOST.

    That is the difference between a report meaning "no post-quantum key exchange here" and one
    meaning "we could not see it here". Only the second is true on OpenSSL under 3.5.
    """
    manifest = coverage_manifest()
    assert manifest["enabled_by_default"] is False
    assert manifest["evidence_class"] == "observed"
    assert manifest["key_exchange_group"] in (GROUP_OBSERVED, GROUP_UNOBSERVED)
    if manifest["key_exchange_group"] == GROUP_UNOBSERVED:
        assert manifest["key_exchange_group_reason"], \
            "an unobservable group must come with a reason in the manifest"
        assert "UNOBSERVED" in manifest["key_exchange_group_reason"]
    joined = " ".join(manifest["not_proven"]).lower()
    assert "unobserved is not the same" in joined, \
        "the manifest must distinguish unknown from absent"
    assert "certificate was not verified" in joined, \
        "the manifest must state that no trust decision was made"


def test_ssh_kex_names_are_labelled_pqc_only_when_the_name_says_so():
    """SSH KEX names are read off the wire and labelled from their spelling -- never inferred.

    NTRU Prime (sntrup761x25519) is a genuine post-quantum draft shipped by OpenSSH, and
    curve25519-sha256 is classical. Both facts are in the name we read, so both are safe to state.
    """
    assert _is_pqc_kex("sntrup761x25519-sha512@openssh.com") is True
    assert _is_pqc_kex("curve25519-sha256") is False
    assert _is_pqc_kex("diffie-hellman-group-exchange-sha256") is False
    assert _is_pqc_kex("") is False
    assert _is_pqc_kex(None) is False
