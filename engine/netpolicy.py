"""Network target policy: the SSRF firewall in front of the live-crypto sensor.

WHY THIS FILE EXISTS, AND WHY IT COMES FIRST
---------------------------------------------------------------------------------------------------
Our coverage manifest lists, as NEVER IN SCOPE:

    "network-negotiated crypto (requires a capture sensor)"

That is the single most valuable evidence class we lack. It is the only sensor that can report
ASSURANCE "observed" for wire-negotiated algorithms: a source scan proves a library is REACHABLE,
and a dependency manifest proves it is AVAILABLE, but only a completed handshake proves that this
connection, right now, negotiated this algorithm. Enterprise discovery tools ship a TLS handshake
sensor for exactly this reason.

The cost of getting network probing wrong is severe, and is the reason this
module is written before `engine/netprobe.py`:

    "The tool takes a filesystem path and a list of hosts over HTTP and acts on both. That is a
     server-side request forgery primitive and an arbitrary file read unless something stands
     between the two."

We closed the filesystem half with `engine/fspolicy.py` (item C5). The network half is this file.
A probe that takes a hostname from a caller and opens a socket to it is exactly that SSRF
primitive, and a crypto scanner is an unusually GOOD SSRF gadget: it can report the contents of an
internal endpoint as structured evidence. A probe is worthless without this policy, and dangerous
with a broken one. So the policy is correct-by-construction and independently testable, and the
probe cannot be reached without passing through `NetPolicy.vet_endpoint`.

THE FOUR FAILURE MODES THIS CLOSES
---------------------------------------------------------------------------------------------------
1. **Judging a NAME by how it LOOKS.** Every decision here is made on the resolved ADDRESS and on
   what that address IS, never on the spelling of the name. "localhost", "127.0.0.1",
   "2130706433", "0x7f000001", "127.1" and "::ffff:127.0.0.1" are all the same host, and all are
   refused. This is not hypothetical: `socket.inet_aton` accepts every one of those spellings and
   `ipaddress.ip_address` accepts NONE of them, so a policy built on `ipaddress` alone silently
   defers the decision to the next layer, which is `getaddrinfo`, which does not care either.

2. **Wrapper addresses.** A denied address is still reachable wearing a costume. IPv4-mapped
   (`::ffff:127.0.0.1`), 6to4 (`2002:7f00:0001::`), Teredo and NAT64 (`64:ff9b::7f00:1`) all
   deliver a packet to an internal host. Each is UNWRAPPED and the EMBEDDED address is judged,
   because that is the host the bytes actually reach.

3. **Check-then-connect: the DNS rebinding window.** The classic bypass is to validate a name, then
   hand the NAME to `socket.create_connection`, which resolves it AGAIN. Between the two
   resolutions an attacker-controlled authoritative server can answer `93.184.216.34` the first
   time and `169.254.169.254` the second. `getaddrinfo` is not even required to be that
   adversarial -- a 1-second TTL is enough. Therefore: resolve ONCE, validate the LITERAL, and
   connect to that literal. The hostname survives only as TLS SNI, which is not a routing
   instruction. `VettedEndpoint.address` is the only thing `engine/netprobe.py` may pass to
   `socket.connect`, and it is always a numeric literal.

4. **Split horizon.** A name resolving to BOTH a public and an internal address is refused
   ENTIRELY -- not "we picked the public one". That shape IS DNS rebinding, and "pick the public
   address" is only safe until the second resolution, which is the one we no longer perform. There
   is no partial credit here: a name with one internal address in its answer is refused whole.


CONFIGURATION (all environment-driven, all fail-closed)
---------------------------------------------------------------------------------------------------
    INDRAMESH_ALLOWED_HOSTS          Hostname allowlist. EMPTY = DENY ALL. Fail-closed on purpose: a
                                 fresh checkout must not be able to reach anything, and a policy
                                 that defaults to "permit" is a policy nobody reads.
    INDRAMESH_ALLOWED_PORTS          Port allowlist, default "22 443 465 587 636 993 995 3306 5432
                                 8443". Deliberately not "any port": without it, the HOST
                                 allowlist is a port scanner, because a tool that completes a
                                 TLS handshake will happily try all 65535 of them.
    INDRAMESH_MAX_ENDPOINTS          Batch cap, default 16, so one request cannot become a sweep.
    INDRAMESH_ALLOW_PRIVATE_TARGETS  Off by default. If enabled, private and loopback targets are
                                 permitted FOR A LAB, and every result is marked `lab_derived`
                                 so a loopback finding can never be mistaken for evidence about
                                 a real deployment.

CLOUD METADATA IS REFUSED EVEN WHEN PRIVATE TARGETS ARE ALLOWED
---------------------------------------------------------------------------------------------------
`169.254.169.254` is the address whose whole purpose is to hand temporary cloud credentials to
anything that asks. `INDRAMESH_ALLOW_PRIVATE_TARGETS` exists so an operator can point this at a lab
server on 127.0.0.1; it is not a request to be able to read instance metadata, and no lab needs
it. There is no environment variable that turns it on, because an SSRF gadget whose metadata path
is a configuration option is an SSRF gadget that will be configured that way by someone at 2am.

REFUSALS ARE RESULTS
---------------------------------------------------------------------------------------------------
Every refusal is returned WITH a reason, and one bad endpoint never discards the rest of the scan
(`vet_endpoints` returns accepted endpoints and refusals side by side). An unexplained omission is
indistinguishable from a missed detection, which is the failure mode this project exists to avoid:
if the operator cannot tell "refused" from "not there", a clean report means nothing.
"""
import ipaddress
import os
import socket


# ---------------------------------------------------------------------------------------------
# Verdict categories. A refusal always carries one of these plus a human-readable reason.
# ---------------------------------------------------------------------------------------------
VERDICT_PUBLIC = "public"                  # routable on the public internet: the only kind probed
VERDICT_PRIVATE = "private-target"         # RFC1918 / unique-local / loopback / CGNAT / link-local
VERDICT_METADATA = "cloud-metadata"        # instance credential endpoint; refused unconditionally
VERDICT_DENIED = "denied"                  # multicast, reserved, unspecified, broadcast
VERDICT_SPLIT_HORIZON = "split-horizon"    # public AND internal in one answer
VERDICT_NOT_ALLOWLISTED = "not-allowlisted"        # host not in INDRAMESH_ALLOWED_HOSTS
VERDICT_PORT_NOT_ALLOWLISTED = "port-not-allowlisted"
VERDICT_UNRESOLVED = "unresolved"          # name did not resolve at all

# Categories that may be probed only when INDRAMESH_ALLOW_PRIVATE_TARGETS is on.
PRIVATE_VERDICTS = frozenset({VERDICT_PRIVATE, VERDICT_METADATA})

# Cloud instance-metadata endpoints, in every spelling we can recognise. Refused ALWAYS.
# AWS/Azure/GCP + OpenStack, plus the IPv6 form, plus Alibaba and Oracle.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",      # AWS IMDS, Azure IMDS, GCP metadata, DigitalOcean, OpenStack
    "169.254.170.2",        # AWS ECS task metadata
    "100.100.100.200",      # Alibaba Cloud metadata
    "192.0.0.192",          # Oracle Cloud (legacy)
    "fd00:ec2::254",        # AWS IMDSv6
})

# The default port allowlist. TLS-capable ports, and nothing else. If a host list cannot be
# separated from a port list, an allowlisted host becomes a port scanner.
DEFAULT_ALLOWED_PORTS = (22, 443, 465, 587, 636, 993, 995, 3306, 5432, 8443)
DEFAULT_MAX_ENDPOINTS = 16

# Port assumed when an endpoint names a host and no port. 443 because this is a TLS sensor.
DEFAULT_PORT = 443

# Every result produced against a private/loopback target carries this note, so the mark travels
# with the data instead of living only in a log line the operator may not have read.
LAB_DERIVED_NOTE = (
    "LAB-DERIVED: this target is not a public host. It was reached only because "
    "INDRAMESH_ALLOW_PRIVATE_TARGETS was set. It says nothing about any real deployment."
)

# Environment variable names, named once so the policy and its tests cannot drift apart.
ENV_ALLOWED_HOSTS = "INDRAMESH_ALLOWED_HOSTS"
ENV_ALLOWED_PORTS = "INDRAMESH_ALLOWED_PORTS"
ENV_MAX_ENDPOINTS = "INDRAMESH_MAX_ENDPOINTS"
ENV_ALLOW_PRIVATE = "INDRAMESH_ALLOW_PRIVATE_TARGETS"

_TRUTHY = frozenset({"1", "true", "yes", "on", "enable", "enabled"})


# Carrier-grade NAT. RFC 6598 100.64.0.0/10.
# EXPLICIT because `ipaddress` reports `is_private == False` AND `is_global == False` for this
# block: it is neither, which means a policy written as `is_private or not is_global` catches it
# only by accident, and one written as `not is_private` waves it straight through. It is also a
# real SSRF target -- CGNAT space is where carrier and cloud edge infrastructure lives.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Deprecated site-local IPv6 (fec0::/10). `is_private` is False and `is_global` is True, so it is
# INVISIBLE to both halves of the naive check. Kept for internal routing, still perfectly capable
# of naming an internal service.
_SITE_LOCAL = ipaddress.ip_network("fec0::/10")

# NAT64 prefixes (RFC 6052 well-known 64:ff9b::/96, and the RFC 8215 local-use 64:ff9b:1::/48).

# =============================================================================================
# RESULTS
# =============================================================================================
class VettedEndpoint(object):
    """An endpoint that has been fully checked and is SAFE TO CONNECT TO.

    The two address fields are deliberately different things, and conflating them is the bug this
    type exists to prevent:

        `address`   the vetted LITERAL. This is the ONLY value that may be handed to
                    socket.connect. It is always numeric, so no second resolution can happen and
                    the DNS rebinding window is closed.
        `hostname`  the name the operator typed. It is carried ONLY as TLS SNI, which affects
                    which certificate and which virtual host the server selects. It is not a
                    routing instruction, and it is never resolved again.

    `lab_derived` is True when the target was permitted only because INDRAMESH_ALLOW_PRIVATE_TARGETS
    was set. It propagates into every finding, so evidence from a loopback lab server is never
    silently mixed with evidence about a real deployment.
    """

    __slots__ = ("hostname", "port", "address", "family", "lab_derived", "verdict", "reason")

    def __init__(self, hostname, port, address, family, lab_derived, verdict, reason):
        self.hostname = hostname          # for SNI only
        self.port = port
        self.address = address            # the vetted literal: the ONLY connect target
        self.family = family              # socket.AF_INET / socket.AF_INET6
        self.lab_derived = lab_derived
        self.verdict = verdict
        self.reason = reason

    def connect_target(self):
        """The exact argument for socket.connect: (address, port). Literal, never a name.

        Exists so there is ONE way to get the connect target, and a test can assert that the
        thing being connected to is a literal and not the hostname.
        """
        return (self.address, self.port)

    def as_sni(self):
        """The value for SSLContext.wrap_socket(server_hostname=...).

        None when the operator named a literal address, because SNI must not be an IP literal:
        RFC 6066 forbids it, and sending it produces a server that either ignores it or, worse,
        treats it as a hostname. `check_hostname` is off in the probe for the same reason.
        """
        import ipaddress as _ip
        try:
            _ip.ip_address(self.hostname)
            return None
        except ValueError:
            return self.hostname

    def to_dict(self):
        return {"hostname": self.hostname, "port": self.port, "address": self.address,
                "lab_derived": self.lab_derived, "verdict": self.verdict, "reason": self.reason}

    def __repr__(self):
        return "VettedEndpoint(%s:%s -> %s, lab_derived=%s)" % (
            self.hostname, self.port, self.address, self.lab_derived)


class Refusal(object):
    """An endpoint that was NOT probed, and exactly why. A result, never an exception.

    `spec` is echoed back verbatim so the operator can match the refusal to what they asked for,
    and `verdict` is a stable machine-readable category so a report can group refusals without
    matching on English prose.
    """

    __slots__ = ("spec", "verdict", "reason")

    def __init__(self, spec, verdict, reason):
        self.spec = spec
        self.verdict = verdict
        self.reason = reason

    def to_dict(self):
        return {"endpoint": self.spec, "verdict": self.verdict, "reason": self.reason}

    def __repr__(self):
        return "Refusal(%r, %s)" % (self.spec, self.verdict)


class NetworkPolicyError(Exception):
    """Raised only for programming errors. Refusals of real endpoints are `Refusal` values."""


# =============================================================================================
# HOST ALLOWLIST MATCHING
# =============================================================================================
def _strip_brackets(text):
    """Remove one layer of [ ] from an IPv6 literal, so allowlists match either spelling."""
    text = str(text).strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def host_allowed(host, allowed_hosts):
    """True if `host` matches the allowlist. An EMPTY allowlist allows NOTHING.

    Fail-closed on an empty list is the whole design: a tool that reaches the network must be
    unable to do so until an operator has said, in configuration, what it may reach. A default of
    "permit" is how a scanner ends up pointed at something it should not have touched.

    Matching is case-insensitive (DNS is), and a leading "." or "*.:" is honoured so an operator
    can allowlist a zone: ".example.com" permits "www.example.com" and "example.com".

    Deliberately NOT a suffix test on the raw string. "notexample.com" ends with "example.com"
    and a naive `endswith` would permit it -- the same prefix-lookalike bug that
    `engine/fspolicy.py::resolve_within` exists to refuse, in a different costume.
    """
    if not allowed_hosts:
        return False
    name = _strip_brackets(host or "").strip().rstrip(".").lower()
    if not name:
        return False
    for pattern in allowed_hosts:
        # Brackets are stripped from BOTH sides. `split_endpoint` unwraps "[::1]:443" to "::1",
        # so an allowlist written the way the operator typed the endpoint would otherwise fail to
        # match itself -- and an allowlist that silently fails closed on the one address family an
        # operator is most likely to allowlist by hand is a trap, not a control.
        pat = _strip_brackets(pattern).strip().rstrip(".").lower()
        if not pat:
            continue
        if pat.startswith("*."):
            pat = pat[2:]
        elif pat.startswith("."):
            pat = pat[1:]
        else:
            if name == pat:
                return True
            continue
        # Zone pattern: matches the apex and any subdomain, but NOT a suffix impostor.
        if name == pat or name.endswith("." + pat):
            return True
    return False


# =============================================================================================
# THE POLICY
# =============================================================================================
class NetPolicy(object):
    """Decides whether a named endpoint may be connected to, and to WHICH LITERAL.

    Construction is explicit rather than implicit in the call sites, so a test can build a policy
    with a fake resolver and a known allowlist and get the same decisions the environment would
    produce. `from_env()` is the production entry point.
    """

    def __init__(self, allowed_hosts=(), allowed_ports=DEFAULT_ALLOWED_PORTS,
                 max_endpoints=DEFAULT_MAX_ENDPOINTS, allow_private=False, resolver=None):
        self.allowed_hosts = tuple(str(h).strip() for h in allowed_hosts if str(h).strip())
        self.allowed_ports = frozenset(int(p) for p in allowed_ports)
        self.max_endpoints = int(max_endpoints)
        self.allow_private = bool(allow_private)
        # Injectable so tests NEVER touch DNS. Signature: (host, port) -> list of (family, ip).
        self._resolver = resolver or self._default_resolver

    # ------------------------------------------------------------------ configuration
    @classmethod
    def from_env(cls, environ=None, resolver=None):
        """Build a policy from the environment. Every value fails closed on garbage.

        A malformed `INDRAMESH_ALLOWED_PORTS` does not mean "any port" and does not raise: it means
        NO ports, because a configuration value we cannot understand must not become a wider grant
        than the operator intended. A scanner that silently widens its own permissions when its
        config file is corrupted is a scanner with a remote exploit.
        """
        env = os.environ if environ is None else environ
        hosts = _split_list(env.get(ENV_ALLOWED_HOSTS, ""))
        ports = _parse_ports(env.get(ENV_ALLOWED_PORTS, ""))
        max_endpoints = _parse_positive_int(env.get(ENV_MAX_ENDPOINTS), DEFAULT_MAX_ENDPOINTS)
        allow_private = str(env.get(ENV_ALLOW_PRIVATE, "")).strip().lower() in _TRUTHY
        return cls(allowed_hosts=hosts, allowed_ports=ports, max_endpoints=max_endpoints,
                   allow_private=allow_private, resolver=resolver)

    def describe(self):
        """A JSON-safe summary, for a coverage manifest. Reports the LIMITS, not just the grants."""
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": sorted(self.allowed_ports),
            "max_endpoints": self.max_endpoints,
            "allow_private_targets": self.allow_private,
            "default_port": DEFAULT_PORT,
            "note": ("An empty allowed_hosts list denies every target. Cloud instance-metadata "
                     "addresses (169.254.169.254 and friends) are refused even when "
                     "allow_private_targets is true."),
        }

    # ------------------------------------------------------------------ resolution
    @staticmethod
    def _default_resolver(host, port):
        """Resolve a NAME to [(family, ip_string)]. The ONLY place a name is ever resolved.

        Wrapped in a helper so there is exactly one `getaddrinfo` call in the codebase and a test
        can assert that `vet_endpoint` performs it exactly once. That single call is the entire
        DNS rebinding defence: there is no second resolution for an attacker to win.
        """
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        out = []
        for family, _type, _proto, _canon, sockaddr in infos:
            # sockaddr is (ip, port) for IPv4 and (ip, port, flow, scope) for IPv6.
            out.append((family, sockaddr[0]))
        return out

    def _resolve(self, host, port):
        """Resolve, never raise. Returns (addresses, error_reason)."""
        try:
            return self._resolver(host, port), None
        except socket.gaierror as exc:
            return [], "name does not resolve: %s" % (exc.strerror or exc,)
        except (OSError, ValueError) as exc:
            return [], "resolution failed: %s" % (exc,)

    def _port_text(self):
        return " ".join(str(p) for p in sorted(self.allowed_ports)) or "empty -- deny all"

    # ------------------------------------------------------------------ the decision
    def vet_endpoint(self, spec, default_port=DEFAULT_PORT):
        """Vet ONE endpoint spec. Returns a `VettedEndpoint` or a `Refusal`. Never raises.

        The order of the checks is the security property, and it is:

          1. parse the spec           -- refuse junk before interpreting anything
          2. port allowlist           -- cheap, and stops a host list being a port list
          3. host allowlist           -- operator's explicit grant; empty list denies all
          4. resolve ONCE             -- names are never re-resolved later
          5. classify EVERY address   -- and refuse the name outright if they disagree
          6. return the vetted LITERAL

        Step 5 is why this is not a loop that returns the first acceptable address. A name that
        resolves to one public and one internal address is refused WHOLE, because "pick the
        public one" only looks safe while you still believe there is no second resolution.
        """
        parsed = split_endpoint(spec, default_port=default_port)
        if parsed is None or not parsed[0] or parsed[1] is None:
            return Refusal(spec, VERDICT_DENIED,
                           "not a usable endpoint. Expected 'host', 'host:port' or '[v6]:port' "
                           "with a port in 1-65535 and no scheme, path or credentials.")

        host, port = parsed

        # 2. Port allowlist. Checked before DNS so a disallowed port costs no lookup at all.
        if port not in self.allowed_ports:
            return Refusal(spec, VERDICT_PORT_NOT_ALLOWLISTED,
                           "port %d is not in the allowed port list (%s). The port allowlist is "
                           "what stops an allowlisted host from being used to scan every port."
                           % (port, self._port_text()))

        # 3. Host allowlist.
        if not host_allowed(host, self.allowed_hosts):
            return Refusal(spec, VERDICT_NOT_ALLOWLISTED,
                           "host %r is not in INDRAMESH_ALLOWED_HOSTS (%s). An empty allowlist denies "
                           "every target by design."
                           % (host, ", ".join(self.allowed_hosts) or "empty -- deny all"))

        # 4. Numeric literal, or resolve the name exactly once.
        literal = parse_literal(host)
        if literal is not None:
            candidates = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, literal)]
        else:
            resolved, error = self._resolve(host, port)
            if error:
                return Refusal(spec, VERDICT_UNRESOLVED, "%s: %s" % (host, error))
            candidates = []
            for family, ip_text in resolved:
                try:
                    candidates.append((family, ipaddress.ip_address(ip_text)))
                except ValueError:
                    # A resolver that hands back junk gets no benefit of the doubt.
                    return Refusal(spec, VERDICT_UNRESOLVED,
                                   "%s: resolver returned %r, which is not an address"
                                   % (host, ip_text))
            if not candidates:
                return Refusal(spec, VERDICT_UNRESOLVED, "%s: no addresses returned" % host)

        # 5. Classify EVERY address this name resolved to. Not just the first, and not "the first
        #    acceptable one": every answer is judged, and any disagreement refuses the whole name.
        verdicts = [(addr, classify_address(addr)) for _family, addr in candidates]
        blocking = [(addr, v) for addr, v in verdicts if v[0] != VERDICT_PUBLIC]
        lab_derived = False
        if blocking:
            # EVERY blocking answer is judged, not just the first. A name answering
            # [10.1.2.3, 169.254.169.254] was previously decided by blocking[0] alone, so the
            # ordering decided whether the cloud-metadata endpoint was refused: private-first
            # passed the metadata address through to a real socket, metadata-first refused.
            # An unconditional refusal must not depend on DNS answer order.
            metadata_hits = [a for a, v in blocking if v[0] == VERDICT_METADATA]
            if metadata_hits:
                # Unconditional. Not reachable by INDRAMESH_ALLOW_PRIVATE_TARGETS; see the docstring.
                return Refusal(spec, VERDICT_METADATA,
                               "%s resolves to the cloud instance-metadata endpoint %s, which "
                               "hands out temporary credentials. Refused unconditionally, "
                               "whatever else the name resolves to; INDRAMESH_ALLOW_PRIVATE_TARGETS "
                               "does not enable it."
                               % (host, ", ".join(str(a) for a in metadata_hits)))
            addr, (verdict, reason) = blocking[0]
            publics = [a for a, v in verdicts if v[0] == VERDICT_PUBLIC]
            # Split horizon: a MIX of public and internal is the DNS rebinding shape exactly. It
            # is refused on THAT ground rather than on the internal address's own merits, because
            # what the operator must learn is that the NAME is untrustworthy, not merely that one
            # of its addresses is unroutable.
            if publics and verdict in (VERDICT_PRIVATE, VERDICT_METADATA):
                return Refusal(spec, VERDICT_SPLIT_HORIZON,
                               "%s resolves to BOTH public (%s) and internal (%s). A name with an "
                               "internal address in its answer is the DNS rebinding shape, so it "
                               "is refused ENTIRELY rather than probed at the public address."
                               % (host, ", ".join(str(a) for a in publics), reason))
            if verdict == VERDICT_PRIVATE:
                if not self.allow_private:
                    return Refusal(spec, VERDICT_PRIVATE,
                                   "%s. Set %s to permit a lab target; every result from one is "
                                   "marked lab-derived." % (reason, ENV_ALLOW_PRIVATE))
                # Permitted for a lab. The mark is set here and travels into every finding, so
                # evidence from 127.0.0.1 can never be read as evidence about a real deployment.
                lab_derived = True
            else:
                return Refusal(spec, verdict, reason)

        family, addr = candidates[0]
        if literal is not None:
            family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        verdict, reason = verdicts[0][1]

        # 6. The vetted literal. THIS, and only this, is what engine/netprobe.py connects to.
        #    The hostname is retained solely as TLS SNI. See VettedEndpoint.
        return VettedEndpoint(hostname=host, port=port, address=str(addr), family=family,
                              lab_derived=lab_derived, verdict=verdict, reason=reason)

    # ------------------------------------------------------------------ batches
    def vet_endpoints(self, specs, default_port=DEFAULT_PORT):
        """Vet a LIST of endpoint specs. Returns (vetted, refusals, errors).

        One bad endpoint never discards the rest of the scan. The cap is applied by DROPPING the
        excess and SAYING SO, not by aborting: an operator who passes 20 endpoints and gets an
        error has learned nothing about the 19 that were fine, whereas an operator who gets 16
        results and 4 named refusals has learned exactly what happened.

        The cap counts ACCEPTED endpoints, not submitted ones, so padding the list with junk does
        not consume the budget: junk is refused for being junk and the real targets still run.
        """
        vetted, refusals = [], []
        for spec in (specs or []):
            if len(vetted) >= self.max_endpoints:
                refusals.append(Refusal(
                    spec, VERDICT_DENIED,
                    "endpoint cap of %d reached; this endpoint was not considered. Raise %s if "
                    "this is intended." % (self.max_endpoints, ENV_MAX_ENDPOINTS)))
                continue
            result = self.vet_endpoint(spec, default_port=default_port)
            if isinstance(result, Refusal):
                refusals.append(result)
            else:
                vetted.append(result)
        return vetted, refusals, []


# =============================================================================================
# ENVIRONMENT PARSING -- every helper fails CLOSED
# =============================================================================================
def _split_list(value):
    """Split a comma/whitespace separated env value into a tuple of non-empty strings."""
    if not value:
        return ()
    if isinstance(value, (list, tuple)):
        items = []
        for entry in value:
            items.extend(_split_list(entry))
        return tuple(items)
    text = str(value).replace(",", " ").replace(";", " ")
    return tuple(part for part in text.split() if part)


def _parse_ports(value):
    """Parse a port allowlist. Garbage in, NO ports out.

    An unparseable entry is DROPPED rather than ignored, and if nothing valid remains the result
    is the empty frozenset, which refuses every port. The alternative -- treating an unreadable
    value as "no restriction" -- turns a typo in a config file into a port scanner, which is the
    exact failure the port allowlist exists to prevent.
    """
    ports = set()
    for part in _split_list(value):
        # Accept "443" and "443/tcp"; a named service is NOT accepted, because a name we cannot
        # resolve offline would have to be guessed at.
        number = part.split("/", 1)[0]
        if number.isdigit():
            port = int(number)
            if 1 <= port <= 65535:
                ports.add(port)
    return frozenset(ports)


def _parse_positive_int(value, default):
    """Parse a positive integer, falling back to `default` on anything unusable."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if number < 1:
        return default
    return number

# Both can carry an IPv4 destination that is otherwise unreachable, so both are unwrapped and the
# embedded address is judged.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")


# =============================================================================================
# ADDRESS CLASSIFICATION -- the decision is made on WHAT AN ADDRESS IS
# =============================================================================================
def _embedded_ipv4(addr):
    """If `addr` is a wrapper carrying an IPv4 destination, return (label, IPv4Address).

    Returns None when the address is not a recognised wrapper. The EMBEDDED address is what the
    bytes actually reach, so it is what must be judged -- `::ffff:127.0.0.1` is not "an IPv6
    address", it is 127.0.0.1 wearing a costume, and judging the outer form is how a policy gets
    bypassed by `ssh -6` or by any client that normalises the notation before connecting.

    The four wrapper families, and what each one is for:

      IPv4-mapped  ::ffff:a.b.c.d         RFC 4291. A v4 address in v6 clothing. `is_loopback` and
                                          friends ALREADY follow this in CPython, but we unwrap
                                          anyway so the refusal reason names the real host.
      6to4         2002:aabb:ccdd::/48   RFC 3056. The v4 address is bytes 2..6.
      Teredo       2001:0000::/32         RFC 4380. Server and client v4 are both embedded, with
                                          the client XOR-obfuscated. The client is the one an
                                          attacker controls, so BOTH are judged.
      NAT64        64:ff9b::/96           RFC 6052. The v4 address is the low 4 bytes.
    """
    if addr.version == 4:
        return None

    # IPv4-mapped and IPv4-compatible (::a.b.c.d). `ipv4_mapped` covers the ::ffff: form; the
    # deprecated compatible form ::a.b.c.d is handled by the explicit low-byte test below.
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return ("IPv4-mapped", mapped)
    if addr in _NAT64_WELL_KNOWN or addr in _NAT64_LOCAL:
        label = "NAT64" if addr in _NAT64_WELL_KNOWN else "NAT64 (local-use)"
        tail = int(addr) & 0xFFFFFFFF
        return (label, ipaddress.IPv4Address(tail))
    sixtofour = addr.sixtofour
    if sixtofour is not None:
        return ("6to4", sixtofour)
    teredo = addr.teredo
    if teredo is not None:
        # (teredo_server, teredo_client). The client address is obfuscated in the wire format and
        # `ipaddress` de-obfuscates it for us. Judged as a PAIR: a Teredo endpoint whose client
        # half is internal is an internal endpoint.
        server, client = teredo
        internal = [a for a in (server, client) if a.is_private or a.is_loopback or not a.is_global]
        if internal:
            return ("Teredo (client %s)" % internal[0], internal[0])
        return ("Teredo", server)

    # Deprecated IPv4-compatible form ::a.b.c.d (not :: and not ::1). `ipv4_mapped` returns None
    # for these, and `is_private` is False while `is_global` is True, so nothing else catches it.
    packed = int(addr)
    if packed <= 0xFFFFFFFF and addr not in (ipaddress.IPv6Address("::"),
                                              ipaddress.IPv6Address("::1")):
        return ("IPv4-compatible", ipaddress.IPv4Address(packed))
    return None


def classify_address(addr):
    """Judge ONE resolved address by what it IS. Returns (verdict, reason).

    This is the whole security boundary, and it takes an already-resolved `ipaddress` object --
    never a string, never a name. The caller cannot shortcut it by passing a hostname, which is
    the point: the name was already resolved exactly once, upstream.

    Order matters and is deliberate:

      1. unwrap any IPv4-in-IPv6 costume and judge the address underneath
      2. metadata endpoints (refused unconditionally, see the module docstring)
      3. loopback -> private
      4. link-local -> private   (169.254.169.254 is caught at step 2, before this)
      5. CGNAT -> private
      6. RFC1918 / unique-local -> private
      7. multicast, reserved, unspecified, site-local -> denied
      8. anything not global -> private, as a catch-all

    Step 8 is the belt to the braces of steps 3-7. `is_global` is the one predicate that
    actually agrees with "can the public internet route to this", and any block that the
    explicit lists above forgot is still refused by it. The reverse error is the dangerous one
    and it is not present: nothing reaches the allow path without passing `is_global`.
    """
    if isinstance(addr, str):
        addr = ipaddress.ip_address(addr)
    if addr.version != 4 and addr.version != 6:
        return VERDICT_DENIED, "not an IPv4 or IPv6 address (%r)" % (addr,)

    # 1. Unwrap. The embedded address is what the packet reaches.
    wrapped = _embedded_ipv4(addr)
    if wrapped is not None:
        label, inner = wrapped
        inner_verdict, inner_reason = classify_address(inner)
        if inner_verdict != VERDICT_PUBLIC:
            return (inner_verdict,
                    "%s wrapper: %s carries %s, so it reaches an internal host (%s)"
                    % (label, addr, inner, inner_reason))
        # The embedded host is public, so the wrapper is not an internal route. Still not allowed
        # to be probed as-is: a 6to4/NAT64 address is not a destination anyone can TLS-handshake
        # in a reproducible way, and treating it as public would put a non-global address into
        # the connect path. Refuse it, and say why in terms of the wrapper.
        return (VERDICT_DENIED,
                "%s wrapper %s: embedded %s is public, but a tunnelled address is not a "
                "probe target" % (label, addr, inner))

    text = str(addr)

    # 2. Cloud instance metadata. UNCONDITIONAL: not reachable via ALLOW_PRIVATE_TARGETS.
    if text in METADATA_ADDRESSES:
        return (VERDICT_METADATA,
                "%s is a cloud instance-metadata endpoint that hands out temporary credentials. "
                "Refused unconditionally; INDRAMESH_ALLOW_PRIVATE_TARGETS does not enable it."
                % text)

    # 3. Loopback. Named first because "refused because it is a loopback address" is the single
    #    most useful sentence in an SSRF refusal log.
    if addr.is_loopback:
        return (VERDICT_PRIVATE, "%s is a loopback address (RFC 1122 3.2.1.3)" % text)

    # 4. Link-local. Covers 169.254.0.0/16 and fe80::/10. The metadata address is already gone.
    if addr.is_link_local:
        return (VERDICT_PRIVATE, "%s is link-local (RFC 3927 / RFC 4291), reachable only from "
                                 "this host's own network" % text)

    # 5. Carrier-grade NAT. `is_private` is False here; see the _CGNAT comment.
    if addr in _CGNAT:
        return (VERDICT_PRIVATE, "%s is carrier-grade NAT space (RFC 6598 100.64.0.0/10), which "
                                 "routes to carrier and edge infrastructure, not the internet"
                           % text)

    # 6. Private / unique-local. Checked AFTER the not-routable cases below, because `::` and
    #    0.0.0.0 are both `is_private` AND `is_unspecified`, and "is the unspecified address" is
    #    the more useful sentence of the two for an operator staring at a refusal log.
    if addr.version == 6 and addr in _SITE_LOCAL:
        return (VERDICT_PRIVATE, "%s is deprecated site-local IPv6 (fec0::/10)" % text)

    # 7. Not routable at all.
    if addr.is_multicast:
        return (VERDICT_DENIED, "%s is multicast; there is no host to connect to" % text)
    if addr.is_unspecified:
        return (VERDICT_DENIED, "%s is the unspecified address, which routes to this host only"
                               % text)
    if addr.is_reserved:
        return (VERDICT_DENIED, "%s is reserved address space" % text)
    if addr.is_private:
        return (VERDICT_PRIVATE, "%s is private address space (RFC 1918, RFC 4193 or an "
                                 "IANA special-purpose block)" % text)

    # 8. Catch-all. Anything not global is refused, whatever the lists above missed.
    if not addr.is_global:
        return (VERDICT_PRIVATE, "%s is not a globally routable address" % text)

    return VERDICT_PUBLIC, "%s is a public unicast address" % text





def parse_literal(text):
    """Parse a NUMERIC address literal, including the legacy integer and hex forms.

    Returns an `ipaddress` object, or None if `text` is not a numeric literal at all.

    WHY THIS EXISTS. `ipaddress.ip_address("2130706433")` raises ValueError. So does
    `ipaddress.ip_address("0x7f000001")`, and `"127.1"`, and `"0177.0.0.1"`. But
    `socket.inet_aton` accepts ALL FOUR, and so does `getaddrinfo`, and so does every HTTP client
    and every TLS library in the language. That is the entire bypass: a policy that only
    understands dotted-quad calls `ipaddress`, gets a ValueError, and if it then treats "not a
    valid IP" as "therefore a hostname, therefore fine" it hands `2130706433` to `getaddrinfo`,
    which connects to 127.0.0.1.

    So the correct behaviour is the opposite of the intuitive one: an unparseable literal is NOT
    presumed safe, it is presumed to be a NAME and goes to the resolver, and the resolver's
    answer is judged as an address. `2130706433` is parsed here into 127.0.0.1 and refused as
    loopback, which is the same host the integer denotes.

    The accepted forms are exactly those of `inet_aton`, which is the function the platform
    resolver itself uses, so this function and the kernel cannot disagree about what a string
    means:

        a.b.c.d            four dotted decimal octets
        a.b.c               c is a 24-bit value
        a.b                 b is a 24-bit value
        a                   a is a 32-bit value
        0x...              hex, in any of the above
        0...               leading zero means OCTAL in inet_aton, not decimal

    Note the octal case: "0127.0.0.1" is 87.0.0.1, NOT 127.0.0.1. We reproduce that faithfully
    rather than "fixing" it, because the point is to agree with the kernel about the destination.
    """
    if not isinstance(text, str):
        return None
    candidate = text.strip()
    if not candidate:
        return None
    # Bracketed IPv6 literal, as it appears in an endpoint spec.
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    # Fast path: the ordinary dotted-quad / IPv6 forms.
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    # Only bare digit/dot/hex tokens can be a legacy numeric form. A token containing a letter
    # other than in a 0x prefix, or any character outside this set, is a NAME and goes to DNS.
    # Enumerated rather than regex-matched so the accepted character set is visible right here.
    allowed = set("0123456789abcdefABCDEFxX.")
    if not candidate or not set(candidate) <= allowed:
        return None

    try:
        packed = socket.inet_aton(candidate)
    except (OSError, ValueError, UnicodeError):
        return None
    return ipaddress.IPv4Address(packed)


def split_endpoint(spec, default_port=DEFAULT_PORT):
    """Split "host:port" / "[v6]:port" / "host" into (host, port). Returns None if unusable.

    Deliberately NOT a URL parser. This is a target spec, not a URL: there is no scheme, no path,
    no userinfo and no query, because every one of those is a way to make two different strings
    mean the same destination. A spec containing any of them is refused rather than normalised.
    """
    if not isinstance(spec, str):
        return None
    text = spec.strip()
    if not text:
        return None
    # Refuse URL-ish input outright instead of quietly stripping a scheme and path.
    for forbidden in ("://", "/", "@", "?", "#"):
        if forbidden in text:
            return None
    if any(ch.isspace() for ch in text):
        return None

    if text.startswith("["):
        # Bracketed IPv6, with an optional :port.
        end = text.find("]")
        if end == -1:
            return None
        host = text[1:end]
        rest = text[end + 1:]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            return None
        return host, _parse_port(rest[1:])

    if text.count(":") > 1:
        # More than one colon means this can only be a bare IPv6 literal, because a `host:port`
        # split has exactly one. Requiring it to ACTUALLY parse as IPv6 is what stops
        # "example.com:443:444" from being waved through as a host: a string full of colons is
        # not automatically an address, and treating it as one would let an operator's typo --
        # or an attempt to hide a port from the port allowlist -- reappear as a hostname.
        literal = parse_literal(text)
        if literal is None or literal.version != 6:
            return None
        return text, default_port
    if ":" in text:
        host, _, port_text = text.partition(":")
        return (host or None), _parse_port(port_text)
    return text, default_port


def _parse_port(text):
    """Return a valid port number, or None. Rejects 0, negatives, junk and absurd values."""
    if not text or not text.isdigit():
        return None
    try:
        port = int(text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return port
