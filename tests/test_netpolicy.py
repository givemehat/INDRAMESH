"""Tests for the network target policy -- the SSRF firewall (pure: NO NETWORK, NO DNS).

The threat model, quoted from the competitor whose README we studied:

    "The tool takes a filesystem path and a list of hosts over HTTP and acts on both. That is a
     server-side request forgery primitive and an arbitrary file read unless something stands
     between the two."

`tests/test_fspolicy.py` closes the filesystem half of that sentence. This file closes the network
half. Every test here is PURE: resolution is a fake resolver, and the suite makes no socket, no
DNS lookup and no connection. That is a deliberate constraint, not a limitation -- a security
control that is only testable against the live internet is a security control that is never
tested.

Every test is written to be ABLE TO FAIL, and each names the defect it catches. These are the
tests that matter most in the repository, because the failure mode they guard against is silent:
a policy that lets one internal address through produces a report that looks completely normal
while being an SSRF gadget.

THE INVARIANT UNDER TEST, IN ONE LINE
---------------------------------------------------------------------------------------------------
    No input an untrusted caller controls can produce a `VettedEndpoint` whose address is not a
    public unicast address, unless INDRAMESH_ALLOW_PRIVATE_TARGETS is explicitly set -- and cloud
    instance metadata is never reachable, even then.

Covered, in order of how badly a bug would hurt:
  * the address-classification deny list, including the integer/hex spellings `ipaddress` rejects
  * IPv4-in-IPv6 wrappers (mapped, 6to4, Teredo, NAT64, IPv4-compatible)
  * cloud metadata, unconditionally
  * split horizon, the DNS rebinding shape
  * the host and port allowlists, and the endpoint cap
  * the lab-derived marking, and the guarantee that refusals carry reasons
"""
import ipaddress
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.netpolicy import (DEFAULT_ALLOWED_PORTS, DEFAULT_MAX_ENDPOINTS, LAB_DERIVED_NOTE,
                              ENV_ALLOWED_HOSTS, ENV_ALLOWED_PORTS, ENV_ALLOW_PRIVATE,
                              ENV_MAX_ENDPOINTS, VERDICT_DENIED, VERDICT_METADATA,
                              VERDICT_NOT_ALLOWLISTED, VERDICT_PORT_NOT_ALLOWLISTED,
                              VERDICT_PRIVATE, VERDICT_PUBLIC, VERDICT_SPLIT_HORIZON,
                              NetPolicy, Refusal, VettedEndpoint,
                              classify_address, host_allowed, parse_literal, split_endpoint)

# A genuinely public address, used as the "good" answer. TEST-NET-2 would read better, but it is
# `is_private` in CPython's tables, which would make the fixture itself private and quietly
# invert what these tests mean. 93.184.216.34 is example.com's historical address.
PUBLIC_IP = "93.184.216.34"
PUBLIC_IPV6 = "2606:4700:4700::1111"


def fake_resolver(table):
    """A resolver that answers from a dict, so no test ever touches DNS.

    Signature matches NetPolicy._default_resolver: (host, port) -> [(family, ip), ...].
    """
    def _resolve(host, port):
        if host in table:
            return [(socket.AF_INET if ":" not in ip else socket.AF_INET6, ip)
                    for ip in table[host]]
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return _resolve


def policy(**kwargs):
    """Build a policy with sensible test defaults: one allowlisted host, fake DNS."""
    kwargs.setdefault("allowed_hosts", ["example.com"])
    kwargs.setdefault("resolver", fake_resolver({}))
    return NetPolicy(**kwargs)


# ======================================================================== the deny list
@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.1.2.3", "::1",                       # loopback
    "10.0.0.1", "10.255.255.254",                           # RFC 1918 /8
    "172.16.0.1", "172.31.255.254",                         # RFC 1918 /12
    "192.168.1.1",                                          # RFC 1918 /16
    "169.254.1.1",                                          # link-local (metadata caught separately)
    "fe80::1",                                              # IPv6 link-local
    "100.64.0.1", "100.127.255.254",                        # CGNAT, RFC 6598
    "fc00::1", "fd00::1", "fdff::1",                        # unique-local, RFC 4193
    "fec0::1",                                              # deprecated site-local
])
def test_internal_addresses_are_never_public(address):
    """THE core assertion. If this fails, the policy is an SSRF primitive.

    Parametrised over every internal range rather than a single example, because the interesting
    bug is always the range someone forgot: an engineer adds 10/8 and 172.16/12 and forgets
    100.64/10, or forgets fec0::/10, and no single-address test would notice.
    """
    verdict, reason = classify_address(ipaddress.ip_address(address))
    assert verdict != VERDICT_PUBLIC, "%s must never be classed public" % address
    assert reason, "a refusal without a reason is indistinguishable from a missed detection"


def test_cgnat_is_refused_even_though_ipaddress_calls_it_neither_private_nor_global():
    """A specific trap in the stdlib, pinned so a future refactor cannot reintroduce it.

    `ipaddress` reports `is_private == False` AND `is_global == False` for 100.64.0.0/10. A policy
    written as `if addr.is_private: refuse` therefore MISSES carrier-grade NAT entirely, and one
    written as `if addr.is_global: allow` misses it only by accident. CGNAT is real internal
    infrastructure, so it is listed explicitly.
    """
    addr = ipaddress.ip_address("100.64.0.1")
    assert not addr.is_private, "premise: the stdlib does not call CGNAT private"
    assert not addr.is_global, "premise: the stdlib does not call CGNAT global either"
    verdict, reason = classify_address(addr)
    assert verdict == VERDICT_PRIVATE
    assert "carrier-grade NAT" in reason


@pytest.mark.parametrize("address", ["127.0.0.1", "127.1.2.3", "::1", "2130706433"])
def test_loopback_is_refused_SPECIFICALLY_as_loopback_not_merely_as_something_internal(address):
    """The verdict alone is not enough; the REASON has to name loopback.

    `127.0.0.1` is also `is_private` in CPython, so deleting the explicit loopback branch leaves
    every "is this refused?" test green while degrading the refusal to "private address space" --
    and "refused because it is a loopback address" is the single most useful sentence in an SSRF
    refusal log. This test is here because a mutation run showed the verdict-only assertions could
    not tell the difference.
    """
    parsed = parse_literal(address)
    assert parsed is not None, "%r must parse as a literal" % address
    verdict, reason = classify_address(parsed)
    assert verdict == VERDICT_PRIVATE
    assert "loopback" in reason.lower(), \
        "the refusal for %s must say it is a loopback address, got: %s" % (address, reason)


def test_loopback_is_checked_before_the_generic_private_branch():
    """Ordering, pinned. Loopback is named first precisely because the message is more useful.

    If the private-space branch ran first, 127.0.0.1 would be refused as "private address space",
    which is true but tells an operator nothing about why their own machine is being dialled.
    """
    loopback_reason = classify_address(ipaddress.ip_address("127.0.0.1"))[1]
    rfc1918_reason = classify_address(ipaddress.ip_address("10.0.0.1"))[1]
    assert "loopback" in loopback_reason.lower()
    assert "loopback" not in rfc1918_reason.lower(), \
        "an RFC 1918 address must not borrow the loopback explanation"



@pytest.mark.parametrize("address", [
    "224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1",   # multicast
    "240.0.0.1", "255.255.255.255",                          # reserved / broadcast
    "0.0.0.0", "::",                                         # unspecified
    "192.0.2.1", "198.51.100.1", "203.0.113.1",              # documentation, RFC 5737
    "198.18.0.1",                                            # benchmarking, RFC 2544
])
def test_non_routable_addresses_are_refused(address):
    """Multicast, reserved, unspecified and documentation space have no host to talk to.

    Documentation ranges are here because 192.0.2.0/24 is `is_private` in CPython, so a policy
    leaning on `is_private` alone refuses it for the wrong reason -- and one leaning on
    `is_global` alone would admit it on a host whose tables differ.
    """
    verdict, _reason = classify_address(ipaddress.ip_address(address))
    assert verdict in (VERDICT_DENIED, VERDICT_PRIVATE), address
    assert verdict != VERDICT_PUBLIC, "%s must never be classed public" % address


@pytest.mark.parametrize("address", [PUBLIC_IP, PUBLIC_IPV6, "8.8.8.8", "1.1.1.1"])
def test_genuinely_public_addresses_are_permitted(address):
    """The negative control. Without this, "refuse everything" passes every test above.

    A deny-list with no allow-path is a denial of service, not a policy, and it is the failure
    mode a paranoid rewrite produces. The sensor has to reach a real host to be useful.
    """
    verdict, reason = classify_address(ipaddress.ip_address(address))
    assert verdict == VERDICT_PUBLIC, \
        "%s should be public, got %s (%s)" % (address, verdict, reason)


# ======================================================================== integer and hex forms
@pytest.mark.parametrize("text,expected", [
    ("2130706433", "127.0.0.1"),      # 0x7f000001 as a decimal integer: loopback
    ("0x7f000001", "127.0.0.1"),      # the same address in hex
    ("0X7F000001", "127.0.0.1"),      # hex, upper case
    ("127.1", "127.0.0.1"),           # the two-part inet_aton form
    ("127.0.1", "127.0.0.1"),         # the three-part form
    ("0177.0.0.1", "127.0.0.1"),      # leading zero is OCTAL to inet_aton
    ("0x7f.0x0.0x0.0x1", "127.0.0.1"),  # hex octets
    ("127.0.0.1", "127.0.0.1"),       # the ordinary form, for contrast
])
def test_legacy_numeric_spellings_decode_to_loopback(text, expected):
    """`ipaddress` raises ValueError on every one of these; the kernel accepts them all.

    This is the bypass, stated as a test. `ipaddress.ip_address("2130706433")` is a ValueError,
    so a policy built on `ipaddress` treats it as "not an IP, therefore a hostname" and hands it
    to the resolver, which connects to 127.0.0.1. The octal case is included because it is the
    one that looks like a bug: "0177.0.0.1" is 127.0.0.1 to `inet_aton`, and reproducing that
    faithfully is the point -- the policy must agree with the kernel about the destination.
    """
    parsed = parse_literal(text)
    assert parsed is not None, "%r must be recognised as a numeric literal" % text
    assert str(parsed) == expected
    assert classify_address(parsed)[0] != VERDICT_PUBLIC, \
        "%r decodes to %s and must not be public" % (text, expected)


def test_a_public_address_written_in_a_legacy_form_is_still_public():
    """The control for the test above: the legacy parser must not refuse everything.

    If `parse_literal` were over-eager -- say, treating any digits as a loopback -- the previous
    test would pass while the sensor could never reach a real host. Both directions are needed.
    """
    for text, expected in (("8.8.8.8", "8.8.8.8"), ("0x08080808", "8.8.8.8"),
                           ("8.8.8.8", "8.8.8.8")):
        parsed = parse_literal(text)
        assert parsed is not None and str(parsed) == expected, text
        assert classify_address(parsed)[0] == VERDICT_PUBLIC, \
            "%r is a public address and must stay probeable" % text


def test_a_name_is_not_mistaken_for_a_numeric_literal():
    """The other direction, and the one that keeps the parser honest.

    A parser that treats anything unparseable as a number is as broken as one that treats every
    number as a name. "localhost" and "dead.beef" must go to the resolver, where the address
    policy judges the answer -- not be silently turned into an integer.
    """
    for text in ("example.com", "localhost", "dead.beef", "1-2-3", "host.example.com"):
        assert parse_literal(text) is None, "%r is a name, not a literal" % text


# ======================================================================== IPv4-in-IPv6 wrappers
@pytest.mark.parametrize("wrapper,inner", [
    ("::ffff:127.0.0.1", "127.0.0.1"),                    # IPv4-mapped
    ("::ffff:169.254.169.254", "169.254.169.254"),        # IPv4-mapped metadata
    ("::ffff:10.0.0.1", "10.0.0.1"),                      # IPv4-mapped RFC 1918
    ("2002:7f00:0001::", "127.0.0.1"),                    # 6to4
    ("2002:a00:1::", "10.0.0.1"),                         # 6to4 RFC 1918
    ("64:ff9b::7f00:1", "127.0.0.1"),                     # NAT64 well-known prefix
    ("64:ff9b::a00:1", "10.0.0.1"),                       # NAT64 RFC 1918
    ("::127.0.0.1", "127.0.0.1"),                         # deprecated IPv4-compatible
])
def test_a_wrapper_carrying_an_internal_address_is_refused(wrapper, inner):
    """A denied address is still reachable wearing a costume, and the costume is not a defence.

    Each of these is an IPv6 address that delivers a packet to an IPv4 host. A policy that
    classifies the OUTER form sees an ordinary global v6 address and permits it; only unwrapping
    the embedded address and judging THAT sees the loopback underneath. The test asserts on the
    refusal reason naming the wrapper, because "refused for an unstated reason" is how a future
    maintainer convinces themselves the unwrapping branch is dead code.
    """
    addr = ipaddress.ip_address(wrapper)
    verdict, reason = classify_address(addr)
    assert verdict != VERDICT_PUBLIC, "%s carries %s and must be refused" % (wrapper, inner)
    assert inner in reason, "the refusal must name the host actually reached: %s" % reason


def test_a_wrapper_carrying_a_public_address_is_still_not_a_probe_target():
    """The subtle half. Unwrapping must not become a way to smuggle odd addresses through.

    6to4/NAT64/Teredo addresses whose embedded host is public are not internal, so the SSRF
    argument does not apply -- but they are still not addresses anyone can TLS-handshake
    reproducibly, and letting them through would put a tunnelled address into the connect path.
    The policy refuses them and says why, rather than quietly permitting a wrapper.
    """
    verdict, reason = classify_address(ipaddress.ip_address("2002:0808:0808::1"))
    assert verdict == VERDICT_DENIED
    assert "6to4" in reason


def test_teredo_is_judged_on_both_embedded_addresses():
    """Teredo embeds a server AND an obfuscated client; the client is the attacker-controlled one.

    `2001:0:4136:e378:8000:63bf:3fff:fdd2` has a documentation-range client half (192.0.2.45).
    If only the server half were examined the policy would miss that half of the tunnel entirely,
    so the test pins the behaviour on a real Teredo address rather than a synthetic one.
    """
    teredo = ipaddress.ip_address("2001:0:4136:e378:8000:63bf:3fff:fdd2")
    assert teredo.teredo is not None, "premise: this address really is Teredo"
    verdict, reason = classify_address(teredo)
    assert verdict != VERDICT_PUBLIC, "a Teredo address must not be classed public"
    assert "Teredo" in reason


# ======================================================================== cloud metadata
@pytest.mark.parametrize("address", [
    "169.254.169.254",      # AWS IMDS, Azure IMDS, GCP metadata, DigitalOcean, OpenStack
    "169.254.170.2",        # AWS ECS task metadata
    "100.100.100.200",      # Alibaba Cloud metadata
    "192.0.0.192",          # Oracle Cloud legacy
    "fd00:ec2::254",        # AWS IMDSv6
    "::ffff:169.254.169.254",  # the same address, IPv4-mapped -- the wrapper must not help
])
def test_cloud_metadata_is_refused_unconditionally(address):
    """The one address class that no environment variable can unlock.

    `INDRAMESH_ALLOW_PRIVATE_TARGETS` exists so an operator can point the sensor at a lab server on
    127.0.0.1. It is not a request to be able to read instance credentials, and no lab needs it.
    An SSRF gadget whose metadata path is a config option will be configured that way by someone
    at 2am, so there is deliberately no variable for it.
    """
    verdict, reason = classify_address(ipaddress.ip_address(address))
    assert verdict == VERDICT_METADATA, "%s must be classified as metadata" % address
    assert "metadata" in reason.lower()


def test_metadata_stays_metadata_even_when_wrapped():
    """The wrapper must not downgrade metadata into ordinary private space.

    `::ffff:169.254.169.254` unwraps to 169.254.169.254, and the recursive call classifies the
    inner address correctly -- but the OUTER verdict is what the caller acts on. If the wrapper
    branch ever stopped propagating the inner verdict, metadata would silently become
    `private-target`, and `INDRAMESH_ALLOW_PRIVATE_TARGETS` would then unlock it. That is precisely
    the configuration this module refuses to have, so the propagation is pinned here.
    """
    verdict, reason = classify_address(ipaddress.ip_address("::ffff:169.254.169.254"))
    assert verdict == VERDICT_METADATA, \
        "a mapped metadata address must stay metadata, not become %s" % verdict
    assert "169.254.169.254" in reason


def test_a_lab_private_target_is_still_marked_lab_derived(monkeypatch):
    """ALLOW_PRIVATE_TARGETS permits a lab target and MARKS it. The mark is not optional.

    The dangerous outcome is not "a loopback was probed" -- an operator who sets the variable
    asked for that. The dangerous outcome is a loopback finding sitting in a report beside real
    public findings with no indication it came from 127.0.0.1. So the mark travels with the
    data, into every finding the probe produces.
    """
    p = policy(allowed_hosts=["127.0.0.1"], allow_private=True)
    result = p.vet_endpoint("127.0.0.1:443")
    assert isinstance(result, VettedEndpoint), "a lab target must be permitted when asked for"
    assert result.lab_derived is True, "a permitted private target must be marked lab-derived"
    assert result.address == "127.0.0.1"


def test_a_private_target_is_refused_when_the_lab_flag_is_off(monkeypatch):
    """The default. Off means off, and the refusal names the variable that changes it."""
    p = policy(allowed_hosts=["127.0.0.1"], allow_private=False)
    result = p.vet_endpoint("127.0.0.1:443")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_PRIVATE
    assert ENV_ALLOW_PRIVATE in result.reason, \
        "the refusal must name the switch, or the operator cannot proceed"


def test_allow_private_does_not_unlock_cloud_metadata():
    """THE assertion that keeps this from being a config-flag SSRF gadget.

    `allow_private=True` is a lab convenience. If it also permitted 169.254.169.254, the module
    would have shipped an environment variable that turns a crypto scanner into a cloud
    credential reader, and the docstring's claim that it does not would be a lie.
    """
    p = policy(allowed_hosts=["169.254.169.254", "169.254.170.2", "100.100.100.200"],
               allow_private=True)
    for spec in ("169.254.169.254:443", "169.254.170.2:443", "100.100.100.200:443"):
        result = p.vet_endpoint(spec)
        assert isinstance(result, Refusal), "%s must stay refused" % spec
        assert result.verdict == VERDICT_METADATA, \
            "%s must stay metadata even with allow_private on, got %s" % (spec, result.verdict)


def test_a_public_target_is_never_marked_lab_derived():
    """The other direction of the marking rule, so the mark cannot spread by accident.

    If `lab_derived` were set from "the policy allowed it" rather than "the target is private",
    every finding would be marked and the mark would mean nothing.
    """
    p = policy(allowed_hosts=["example.com"], allow_private=True,
               resolver=fake_resolver({"example.com": [PUBLIC_IP]}))
    result = p.vet_endpoint("example.com:443")
    assert isinstance(result, VettedEndpoint)
    assert result.lab_derived is False, "a public target is not lab-derived"
    assert LAB_DERIVED_NOTE.startswith("LAB-DERIVED"), "the note must be self-identifying"

# ======================================================================== split horizon
def test_a_name_resolving_to_public_and_private_is_refused_entirely():
    """THE DNS rebinding shape, and the case a first implementation gets wrong.

    A policy that loops over the resolved addresses and returns the first acceptable one produces
    a perfectly working probe here -- and is still broken, because "pick the public address" is
    only safe while you assume there is no second resolution. There is a test below that pins the
    single-resolution property; this one pins that a mixed answer is refused rather than filtered.
    """
    p = policy(allowed_hosts=["rebind.example"],
               resolver=fake_resolver({"rebind.example": [PUBLIC_IP, "127.0.0.1"]}))
    result = p.vet_endpoint("rebind.example:443")
    assert isinstance(result, Refusal), "a mixed public/private answer must be refused whole"
    assert result.verdict == VERDICT_SPLIT_HORIZON
    assert PUBLIC_IP in result.reason and "127.0.0.1" in result.reason, \
        "the refusal must show BOTH answers, or the operator cannot tell what happened"


def test_a_name_resolving_to_public_and_metadata_is_refused():
    """Metadata in the answer is refused, and named as metadata rather than as rebinding.

    The verdict is now `cloud-metadata` rather than `split-horizon`. Both refuse the endpoint, but
    the metadata verdict is the one that must not depend on DNS answer ORDER: the check used to
    read only the first blocking answer, so `[169.254.169.254, 10.1.2.3]` refused as
    cloud-metadata while `[10.1.2.3, 169.254.169.254]` did not refuse the metadata address at
    all. An unconditional refusal cannot be a function of which answer the resolver listed first.
    """
    p = policy(allowed_hosts=["rebind.example"],
               resolver=fake_resolver({"rebind.example": [PUBLIC_IP, "169.254.169.254"]}))
    result = p.vet_endpoint("rebind.example:443")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_METADATA
    assert "169.254.169.254" in result.reason, \
        "the refusal must name the metadata address it refused on"


def test_metadata_refusal_does_not_depend_on_dns_answer_order():
    """The same two answers, reversed, must produce the same refusal.

    This is the regression the ordering bug hid behind: with a private address listed FIRST, the
    metadata address was never examined, so a lab-permitted private answer masked it.
    """
    for order in ([PUBLIC_IP, "169.254.169.254"], ["169.254.169.254", PUBLIC_IP]):
        p = policy(allowed_hosts=["rebind.example"],
                   resolver=fake_resolver({"rebind.example": order}))
        result = p.vet_endpoint("rebind.example:443")
        assert isinstance(result, Refusal), \
            "order %r must still refuse" % (order,)
        assert result.verdict == VERDICT_METADATA, \
            "order %r must refuse as metadata" % (order,)


def test_a_lab_permitted_private_answer_cannot_mask_a_metadata_answer():
    """Allowing private targets must not enable a metadata endpoint.

    With `ALLOW_PRIVATE_TARGETS` on, a private answer is permitted. That permission previously
    short-circuited the metadata check whenever the private address was listed first, so the
    metadata address was vetted and connected to. The docstring calls the metadata refusal
    unconditional; this is the test that makes it so.
    """
    p = policy(allowed_hosts=["lab.example"], allow_private=True,
               resolver=fake_resolver({"lab.example": ["10.1.2.3", "169.254.169.254"]}))
    result = p.vet_endpoint("lab.example:443")
    assert isinstance(result, Refusal), "a lab permission must not permit a metadata endpoint"
    assert result.verdict == VERDICT_METADATA


def test_a_name_resolving_to_several_public_addresses_is_fine():
    """The control. Multi-homed public DNS is normal and must not be mistaken for rebinding.

    Any real CDN name resolves to several public addresses. If "more than one address" were the
    refusal condition, the sensor would be useless against exactly the hosts it most needs to
    inventory -- so the rule is specifically public AND internal, not "several".
    """
    p = policy(allowed_hosts=["cdn.example"],
               resolver=fake_resolver({"cdn.example": [PUBLIC_IP, "1.1.1.1", PUBLIC_IPV6]}))
    result = p.vet_endpoint("cdn.example:443")
    assert isinstance(result, VettedEndpoint), "several public addresses must be permitted"
    assert result.address in (PUBLIC_IP, "1.1.1.1", PUBLIC_IPV6)


def test_a_name_resolving_only_to_private_addresses_is_refused_as_private():
    """No public address in the answer means no split horizon -- it is just a private target.

    The distinction matters for the operator: split-horizon says "this name is untrustworthy",
    private says "this is an internal host". Conflating them would make the first warning
    meaningless.
    """
    p = policy(allowed_hosts=["internal.example"],
               resolver=fake_resolver({"internal.example": ["10.0.0.5", "192.168.1.5"]}))
    result = p.vet_endpoint("internal.example:443")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_PRIVATE, "no public address means no split-horizon verdict"


def test_the_name_is_resolved_exactly_once(monkeypatch):
    """The property that makes the rebinding window closed rather than merely narrow.

    A counting resolver proves the probe cannot win a second lookup. If any code path resolved
    the name again -- at connect time, on retry, inside `socket.create_connection` -- the count
    would rise and the guarantee would be gone. This is the closest thing to a proof that the
    check-then-connect pattern was actually followed rather than merely intended.
    """
    calls = []

    def counting_resolver(host, port):
        calls.append((host, port))
        return [(socket.AF_INET, PUBLIC_IP)]

    p = policy(allowed_hosts=["example.com"], resolver=counting_resolver)
    result = p.vet_endpoint("example.com:443")
    assert isinstance(result, VettedEndpoint)
    assert len(calls) == 1, "the name must be resolved exactly once, got %r" % (calls,)
    # And the thing the caller will connect to is the LITERAL, not the name.
    assert result.address == PUBLIC_IP
    assert result.connect_target() == (PUBLIC_IP, 443)

# ======================================================================== the allowlists
def test_an_empty_host_allowlist_denies_everything():
    """Fail-closed. A fresh checkout must not be able to reach anything.

    This is the single most important configuration test in the file. If the default were
    "allow", then anyone who ran the sensor before configuring it would have a network-reachable
    crypto scanner, and the failure would be invisible until someone abused it.
    """
    p = policy(allowed_hosts=[])
    result = p.vet_endpoint("%s:443" % PUBLIC_IP)
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_NOT_ALLOWLISTED
    assert "deny all" in result.reason.lower()


def test_a_host_outside_the_allowlist_is_refused_even_when_it_is_public():
    """A public address is not thereby a permitted target. The allowlist is the operator's grant.

    Without this, the address checks would be the only barrier, and "any public host" would be
    the effective policy -- which is a port scanner with a TLS client attached.
    """
    p = policy(allowed_hosts=["example.com"], resolver=fake_resolver({"evil.example": ["8.8.8.8"]}))
    result = p.vet_endpoint("evil.example:443")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_NOT_ALLOWLISTED


def test_the_allowlist_supports_zones_without_matching_suffix_impostors():
    """`.example.com` must permit `a.example.com` and NOT permit `notexample.com`.

    The impostor is the whole test. `name.endswith("example.com")` accepts "notexample.com", and
    that is the same prefix/suffix confusion `fspolicy.resolve_within` exists to refuse: a
    containment check written with a bare `startswith`/`endswith` is the standard way a
    containment check gets bypassed.
    """
    allowed = [".example.com"]
    assert host_allowed("example.com", allowed)
    assert host_allowed("www.example.com", allowed)
    assert host_allowed("a.b.example.com", allowed)
    assert not host_allowed("notexample.com", allowed), "a suffix impostor must not match"
    assert not host_allowed("example.com.evil.test", allowed), "a prefix append must not match"
    assert not host_allowed("example.co", allowed)


def test_the_allowlist_is_case_insensitive_and_tolerates_a_trailing_dot():
    """DNS is case-insensitive and a fully-qualified name may end in a dot. Both are normal."""
    allowed = ["Example.COM"]
    assert host_allowed("example.com", allowed)
    assert host_allowed("EXAMPLE.com", allowed)
    assert host_allowed("example.com.", allowed)


def test_ipv6_allowlist_entries_match_with_or_without_brackets():
    """An allowlist written the way the operator typed the endpoint must match itself.

    `split_endpoint("[::1]:443")` yields the host "::1", so a list containing "[::1]" would fail
    to match -- a control that silently fails closed on the one address family most likely to be
    typed by hand is a trap rather than a safeguard.
    """
    for entry in ("::1", "[::1]"):
        assert host_allowed("::1", [entry]), "allowlist entry %r should match ::1" % entry
        assert host_allowed("[::1]", [entry]), "allowlist entry %r should match [::1]" % entry


# ======================================================================== the port allowlist
def test_a_port_outside_the_allowlist_is_refused_even_for_an_allowlisted_host():
    """THE anti-port-scanner property. The host allowlist alone is not a port allowlist.

    A TLS-capable tool will happily attempt a full handshake on any port, so without this check
    an operator who allowlisted one host would have handed out a port scanner aimed at it. The
    port list is checked BEFORE any DNS lookup, so a refused port costs nothing.
    """
    p = policy(allowed_hosts=["example.com"], resolver=fake_resolver({"example.com": [PUBLIC_IP]}))
    result = p.vet_endpoint("example.com:8080")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_PORT_NOT_ALLOWLISTED

# ======================================================================== the endpoint cap
def test_the_endpoint_cap_drops_the_excess_and_names_it():
    """A cap that aborts the batch is a denial of service; a cap that names the excess is a limit.

    The operator who submits 20 endpoints and receives an error has learned nothing about the 16
    that were fine. The operator who receives 16 results and 4 named refusals knows exactly what
    happened -- which is the difference between a control and an outage.
    """
    hosts = ["h%d.example.com" % i for i in range(20)]
    table = {h: [PUBLIC_IP] for h in hosts}
    p = policy(allowed_hosts=hosts, max_endpoints=16, resolver=fake_resolver(table))
    vetted, refusals, _errors = p.vet_endpoints(["%s:443" % h for h in hosts])
    assert len(vetted) == 16, "the cap must be enforced"
    assert len(refusals) == 4, "every dropped endpoint must be accounted for"
    for refusal in refusals:
        assert "cap" in refusal.reason.lower()
        assert ENV_MAX_ENDPOINTS in refusal.reason, "the refusal must name the knob"


def test_one_bad_endpoint_does_not_discard_the_rest_of_the_scan():
    """THE robustness property. A refused endpoint is a result, not an abort.

    Losing 40 good targets because one was malformed is how a sensor ends up reporting "no
    findings" on a system that has plenty. The count of refusals plus vetted must equal the count
    submitted, so an endpoint can never silently vanish.
    """
    specs = ["example.com:443", "127.0.0.1:443", "example.com:8080", "evil.test:443",
             "https://example.com:443", "example.com:0", "example.com:8443"]
    p = policy(allowed_hosts=["example.com", "127.0.0.1", "evil.test"],
               resolver=fake_resolver({"example.com": [PUBLIC_IP], "evil.test": [PUBLIC_IP]}))
    vetted, refusals, _errors = p.vet_endpoints(specs)
    assert len(vetted) + len(refusals) == len(specs), \
        "every submitted endpoint must be either vetted or refused, never dropped"
    assert [v.port for v in vetted] == [443, 443, 8443], \
        "the three good endpoints must survive: %r" % [v.to_dict() for v in vetted]
    for refusal in refusals:
        assert refusal.reason, "every refusal must carry a reason"


def test_every_refusal_carries_a_machine_readable_verdict_and_a_reason():
    """Refusals must be groupable by a report, and readable by a human.

    A bare boolean "refused" forces a downstream report to either drop the information or
    re-derive it, and re-deriving it is how a tool starts guessing at causes.
    """
    specs = ["127.0.0.1:443", "169.254.169.254:443", "example.com:8080", "evil.test:443",
             "garbage", "example.com:0"]
    p = policy(allowed_hosts=["example.com", "127.0.0.1", "169.254.169.254", "evil.test"],
               resolver=fake_resolver({"example.com": [PUBLIC_IP], "evil.test": [PUBLIC_IP]}))
    _vetted, refusals, _errors = p.vet_endpoints(specs)
    for refusal in refusals:
        assert refusal.verdict, "a refusal must have a verdict category"

# ======================================================================== environment configuration
def test_from_env_reads_every_knob():
    """The four documented variables must all actually work, since the docs name all four."""
    p = NetPolicy.from_env(environ={
        ENV_ALLOWED_HOSTS: "a.example.com, b.example.com",
        ENV_ALLOWED_PORTS: "443 8443",
        ENV_MAX_ENDPOINTS: "3",
        ENV_ALLOW_PRIVATE: "yes",
    }, resolver=fake_resolver({}))
    assert set(p.allowed_hosts) == {"a.example.com", "b.example.com"}
    assert p.allowed_ports == frozenset({443, 8443})
    assert p.max_endpoints == 3
    assert p.allow_private is True


def test_from_env_defaults_to_denying_every_host():
    """With no configuration at all, the answer is no.

    A tool that reaches the network must be inert until configured. The alternative default --
    "no restriction" -- is how a scanner ends up pointed at something it should not have touched.
    """
    p = NetPolicy.from_env(environ={}, resolver=fake_resolver({}))
    assert p.allowed_hosts == ()
    assert isinstance(p.vet_endpoint("%s:443" % PUBLIC_IP), Refusal)


def test_an_unparseable_port_list_denies_all_ports_rather_than_allowing_them():
    """Garbage in the port list must fail CLOSED, and the naming is the point.

    This is the non-obvious one. A parser that ignores an unparseable value effectively treats it
    as "no restriction", so a typo in a config file silently becomes a port scanner -- the exact
    failure the port allowlist exists to prevent. Refusing every port is the only safe reading of
    a list we could not understand.
    """
    for value in ("not-a-port", "", "   ", "http", "0", "-1", "99999"):
        p = NetPolicy.from_env(environ={ENV_ALLOWED_PORTS: value, ENV_ALLOWED_HOSTS: "example.com"},
                               resolver=fake_resolver({}))
        assert p.allowed_ports == frozenset(), \
            "%r must yield no allowed ports, got %r" % (value, p.allowed_ports)


def test_a_malformed_endpoint_cap_falls_back_to_the_default_rather_than_zero():
    """A broken cap must not become "reject everything" or "accept everything"."""
    for value in ("", "abc", "0", "-5", "1.5"):
        p = NetPolicy.from_env(environ={ENV_MAX_ENDPOINTS: value}, resolver=fake_resolver({}))
        assert p.max_endpoints == DEFAULT_MAX_ENDPOINTS, \
            "%r must fall back to the default cap" % value


def test_the_policy_describes_its_own_limits():
    """A coverage manifest is only useful if it records what was NOT permitted.

    `scanner.coverage_manifest()` already carries a `never_in_scope` list; this is the network
    equivalent, and it must state the limits (empty allowlist denies; metadata refused) rather
    than only the grants.
    """
    described = policy(allowed_hosts=["example.com"]).describe()
    assert described["allowed_hosts"] == ["example.com"]
    assert described["max_endpoints"] == DEFAULT_MAX_ENDPOINTS
    assert described["allow_private_targets"] is False
    assert "169.254.169.254" in described["note"], "the metadata refusal must be stated"
    assert "empty" in described["note"].lower()


def test_the_default_port_list_is_tls_shaped_and_does_not_include_everything():
    """Pinned so a well-meaning edit cannot quietly widen the grant."""
    assert set(DEFAULT_ALLOWED_PORTS) == {22, 443, 465, 587, 636, 993, 995, 3306, 5432, 8443}
    assert 22 in DEFAULT_ALLOWED_PORTS, "SSH is in scope; competitors ship an SSH sensor"
    for port in (21, 23, 25, 80, 445, 1433, 1521, 2375, 3389, 5432 + 1, 8080, 9200, 27017):
        assert port not in DEFAULT_ALLOWED_PORTS, \
            "%d must not be in the default port allowlist" % port


def test_a_port_out_of_range_is_a_malformed_endpoint_not_a_silent_default():
    """:0 and :99999 are refused, not quietly treated as 443.

    Falling back to a default port on a parse error would be a small SSRF hole: an operator
    asking for port 0 (which means "any port" to some resolvers) would get a connection to 443.
    """
    for spec in ("example.com:0", "example.com:99999", "example.com:-1", "example.com:http"):
        result = policy().vet_endpoint(spec)
        assert isinstance(result, Refusal), "%r must be refused" % spec
        assert result.verdict == VERDICT_DENIED


def test_an_endpoint_with_no_port_uses_the_default_tls_port():
    """A bare hostname means 443, and that default is itself subject to the allowlist."""
    p = policy(allowed_hosts=["example.com"], resolver=fake_resolver({"example.com": [PUBLIC_IP]}))
    result = p.vet_endpoint("example.com")
    assert isinstance(result, VettedEndpoint)
    assert result.port == 443


def test_sni_is_not_set_when_the_operator_named_a_literal_address():
    """RFC 6066 forbids an IP literal in SNI, and a server that receives one may misroute.

    So a literal target carries `as_sni() == None`. The name is not needed for identification
    there, and sending it would be a protocol violation at best.
    """
    p = policy(allowed_hosts=[PUBLIC_IP])
    result = p.vet_endpoint("%s:443" % PUBLIC_IP)
    assert isinstance(result, VettedEndpoint)
    assert result.as_sni() is None


# ======================================================================== endpoint spec parsing
@pytest.mark.parametrize("spec,expected", [
    ("example.com", ("example.com", 443)),
    ("example.com:8443", ("example.com", 8443)),
    ("EXAMPLE.com:443", ("EXAMPLE.com", 443)),
    ("  example.com:443  ", ("example.com", 443)),
    ("127.0.0.1:443", ("127.0.0.1", 443)),
    ("[2606:4700::1111]:443", ("2606:4700::1111", 443)),
    ("[::1]", ("::1", 443)),
])
def test_well_formed_specs_split_into_host_and_port(spec, expected):
    """The ordinary cases, including the bracketed IPv6 form that makes a port unambiguous."""
    assert split_endpoint(spec) == expected


@pytest.mark.parametrize("spec", [
    "https://example.com:443",     # a URL, not a target spec
    "example.com/path",            # a path means the string is not a target
    "user:pass@example.com:443",   # credentials must never be smuggled through a target spec
    "example.com?a=b",             # a query
    "example.com#frag",            # a fragment
    "exam ple.com:443",            # embedded whitespace
    "example.com:443:444",         # ambiguous
    "[::1",                        # unclosed bracket
    "", "   ", None, 12345,
])
def test_malformed_or_url_shaped_specs_are_refused_rather_than_normalised(spec):
    """A target spec is not a URL, and the difference is a security boundary.

    Every rejected form here is a way to make two different strings mean the same destination, or
    to smuggle credentials into a field that ends up in a log. Normalising instead of refusing
    would mean the operator's log says one thing and the socket connects to another -- and the
    userinfo case in particular is how a password ends up written to disk in a report.
    """
    assert split_endpoint(spec) is None, "%r must not be parsed as an endpoint" % (spec,)


def test_a_url_shaped_spec_is_refused_end_to_end_not_just_by_the_parser():
    """The parser test above is not enough on its own: the policy must refuse it too.

    Otherwise a future caller could hand the raw spec to something other than `split_endpoint`
    and quietly reintroduce URL parsing. The end-to-end assertion is the one that matters.
    """
    p = policy(allowed_hosts=["example.com"], resolver=fake_resolver({"example.com": [PUBLIC_IP]}))
    result = p.vet_endpoint("https://example.com:443")
    assert isinstance(result, Refusal)
    assert result.verdict == VERDICT_DENIED


def test_bare_ipv6_without_brackets_is_accepted_with_the_default_port():
    """`::1` has several colons, so a port can only be present if there is exactly one.

    Treating it as a host rather than as `host:port`-plus-junk is the only reading that lets an
    operator paste an IPv6 address they got from `ip addr` without adding brackets first.
    """
    assert split_endpoint("::1") == ("::1", 443)
    assert split_endpoint("2606:4700::1111") == ("2606:4700::1111", 443)


