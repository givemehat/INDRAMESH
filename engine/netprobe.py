"""Live-crypto sensor: what did this connection ACTUALLY negotiate?

THE GAP THIS CLOSES
---------------------------------------------------------------------------------------------------
`engine/scanner.py` lists, in its coverage manifest, as NEVER IN SCOPE:

    "network-negotiated crypto (requires a capture sensor)"

That line is the reason this module exists. Every other sensor here is static: the source scanner
proves a call site exists, the config scanner proves a policy permits an algorithm, and the
dependency scanner (HAND-160) proves a package is reachable. `engine/purpose.py` draws the line
between them precisely -- those are ASSURANCE "used", "declared" and "capability".

Only a completed handshake is ASSURANCE "observed" -- the top of `ASSURANCE_RANK`. It is the only
evidence class that answers the question a CISO actually asks about a SaaS dependency or a
third-party boundary: not *what crypto is in our code* but *what crypto is on the wire to me
right now*. Modern ACDI architectures require a TLS handshake sensor for exactly this reason.

WHAT IS CLAIMED, AND WHAT IS NOT
--------------------------------------------------------------------------------------------------
This sensor observes a NEGOTIATION on ONE connection to ONE endpoint at ONE moment. It does not
establish:

  * that the server is configured this way for every client, region, or moment
  * that any client ever connected -- we complete a handshake as a client, and a server may
    negotiate differently for a browser, a health check, or a different SNI
  * anything about data at rest, or about the peer's own storage
  * that the negotiated suite is SAFE. A TLS 1.3 handshake is not a security assessment.

Every finding carries `evidence_class="observed"` and names the sensor that produced it, because
`coverage_manifest()` reports `scanners_run` from exactly that field, and an observed finding with
no sensor is an assertion with no witness.

THE GROUP IS NOT GUESSED. EVER.
--------------------------------------------------------------------------------------------------
This is the most important honesty property in the module, and it is quoted from the sibling's
README because it is the mistake a handshake sensor is most likely to make:

    "Reading the actual negotiated group needs OpenSSL 3.5+ locally. Without it the key-exchange
     mechanism stays unobserved rather than being guessed."

The key-exchange group is the whole point of a PQC handshake sensor -- it is where ML-KEM-768 and
X25519MLKEM768 live, and the only place a wire observation can distinguish a post-quantum exchange
from a classical one. Inferring it is tempting and it is a trap:

  * "TLS 1.3 was negotiated" does NOT imply any particular group. TLS 1.3 negotiates the group
    independently of the suite, and the client offers a LIST.
  * "the suite was TLS_AES_256_GCM_SHA384" does NOT imply a group. The SHA384 in a TLS 1.3 suite
    name is the HKDF hash, not the key exchange.
  * the server's PREFERENCE ORDER is not the negotiated value. A ClientHello carries an offer, and
    choosing from an offer we did not finish reading is a guess.

So when `SSLSocket.group()` is unavailable -- this host runs OpenSSL 3.0.18, where it does not
exist -- the result is `group_status == "unobserved"` with a reason naming the requirement, and NO
group finding is emitted. An unobserved group is a visible gap in the evidence, and a visible gap
is worth more than a confident answer that might be wrong.

SAFETY: THIS MODULE CANNOT REACH ANYTHING ON ITS OWN
---------------------------------------------------------------------------------------------------
A socket-opening primitive driven by a caller-supplied hostname is the SSRF gadget the sibling's
README warns about, so there is no path from an endpoint string to a socket that does not go
through `probe_endpoint` -> `NetPolicy.vet_endpoint`. The only value that reaches `connect()` is
`VettedEndpoint.address`, a vetted numeric literal; the hostname survives only as TLS SNI. The
policy module enforces and tests that; this module's job is to not provide a way around it.

The sensor is also OFF BY DEFAULT and requires explicit opt-in (`enable=True`). A scanner that
opens connections because it was called is a scanner that surprises someone on a network they did
not intend to touch.

Refusals and failures are RESULTS. An unreachable endpoint, a refused connection, a timeout, a
non-TLS service on a TLS port, a truncated banner -- each is recorded with a reason, and none of
them is an exception. "It did not answer" and "we did not ask" must be distinguishable, or a
clean report means nothing.
"""
import socket
import ssl
import struct

from engine.netpolicy import LAB_DERIVED_NOTE, NetPolicy, Refusal

# ---------------------------------------------------------------------------------------------
# Statuses. A result ALWAYS has one; there is no "no status" path.
#
# The distinction that matters: STATUS_REFUSED means WE declined (policy), STATUS_UNREACHABLE
# means the network declined. Collapsing them into "error" destroys the only information an
# operator needs to act -- a refusal is fixed by configuration, an unreachable host by the network.
# ---------------------------------------------------------------------------------------------
STATUS_OBSERVED = "observed"                  # handshake completed; the crypto is on the wire
STATUS_REFUSED = "refused"                    # the policy declined; nothing was sent
STATUS_UNREACHABLE = "unreachable"            # connect failed: refused, unroutable, timed out
STATUS_NOT_TLS = "not-tls"                    # connected, but the peer is not speaking TLS
STATUS_HANDSHAKE_FAILED = "handshake-failed"  # TLS started and did not finish
STATUS_DISABLED = "disabled"                  # the sensor was not opted into
STATUS_ERROR = "error"                        # an unexpected failure, named

# Sensor identities. Recorded on every finding, because `coverage_manifest()` builds
# `scanners_run` from the `scanner` field, and an observed finding with no sensor is an assertion
# with no witness.
SENSOR_TLS = "tls-handshake-sensor"
SENSOR_SSH = "ssh-banner-sensor"
SCANNER_NETWORK = "network-probe"

# Rule IDs in the IM-NET-* namespace, so they sort apart from the static scanners in a report.
RULE_TLS_PROTOCOL = "IM-NET-TLS-PROTO-001"
RULE_TLS_CIPHER = "IM-NET-TLS-CIPHER-001"
RULE_TLS_GROUP = "IM-NET-TLS-GROUP-001"
RULE_SSH_KEX = "IM-NET-SSH-KEX-001"
# NOTE: there is deliberately no RULE_SSH_HOSTKEY. Reading a server's host-key ALGORITHM list is
# one more name-list in the same KEXINIT packet, so it would be easy to add -- and shipping an
# unused rule ID would imply a sensor we do not have, which is the over-claim this project exists
# to avoid. If it is added later, it will be added with a test and a docstring, not in advance.

# Group observation status.
GROUP_OBSERVED = "observed"
GROUP_UNOBSERVED = "unobserved"

# IANA TLS Supported Groups that are POST-QUANTUM or PQC-hybrid, and what they are made of.
# Used only to LABEL a group that was genuinely observed -- never to select or infer one.
#
# Sources: the IANA TLS Supported Groups registry. 4587/4588/4589 are the RFC 10024 hybrids
# (Recommended=Y); 512/513/514 are the pure ML-KEM groups. The OBSOLETE Kyber drafts are listed
# separately below so a negotiated draft is reported as the draft it is rather than as ML-KEM.
PQC_GROUPS = {
    "X25519MLKEM768": ("X25519", "ML-KEM-768", "hybrid"),
    "SecP256r1MLKEM768": ("P-256", "ML-KEM-768", "hybrid"),
    "SecP384r1MLKEM1024": ("P-384", "ML-KEM-1024", "hybrid"),
    "MLKEM512": ("(none: pure post-quantum)", "ML-KEM-512", "pure"),
    "MLKEM768": ("(none: pure post-quantum)", "ML-KEM-768", "pure"),
    "MLKEM1024": ("(none: pure post-quantum)", "ML-KEM-1024", "pure"),
}

# The OBSOLETE pre-RFC-10024 codepoints. A server still negotiating one is NOT post-quantum in
# the standardised sense, and reporting it as "ML-KEM" is exactly the FIPS 203 confusion that
# docs/CODE_REVIEW.md H6 and `engine/verify_migration.py` exist to prevent.
OBSOLETE_PQC_GROUPS = {
    "X25519Kyber768Draft00": "IANA 25497, marked OBSOLETE: a Kyber round-3 DRAFT, not ML-KEM-768",
    "SecP256r1Kyber768Draft00": "IANA 25498, marked OBSOLETE: a Kyber draft, not ML-KEM-768",
    "X25519Kyber512Draft00": "an experimental Kyber-512 draft hybrid, not ML-KEM-512",
}

# Bounds. A probe that reads without limit is a denial-of-service tool, and this one is reachable
# from a batch loop, so every read is capped and every connect carries a timeout.
DEFAULT_TIMEOUT = 5.0                  # seconds, per endpoint
MAX_BANNER_BYTES = 255                 # RFC 4253: an identification string is at most 255 bytes
MAX_SSH_PACKET = 262144                # RFC 4253: packets are at most 256 KB
SSH_KEXINIT = 20                       # SSH_MSG_KEXINIT
SSH_MAX_LINES_BEFORE_BANNER = 8        # servers may emit pre-banner lines; do not read forever

# What an observed handshake does NOT establish. Carried in every result, for the same reason
# `engine/verify_migration.py` carries its own NOT_PROVEN: a sensor that reports a number without
# stating its limits is asking the reader to supply the limits themselves, and they will guess.
NOT_PROVEN = (
    "This is ONE connection to ONE endpoint at ONE moment. It is not a configuration review: a "
    "server may negotiate differently for a different client, SNI, region or moment.",
    "The certificate was NOT verified. This sensor reports what the peer put on the wire; it makes "
    "no trust decision and must not be cited as evidence that the peer is who it claims to be.",
    "A negotiated suite is not a safety assessment. This tool inventories algorithms; judging "
    "whether a configuration is acceptable is the operator's decision, against their own policy.",
    "Key exchange may be UNOBSERVED on this host (see group_reason). Unobserved is NOT the same "
    "as classical, and must never be reported as 'no post-quantum cryptography'.",
    "Nothing is inferred about data at rest, the peer's own storage, or any other client.",
)


# =============================================================================================
# THE NEGOTIATED GROUP -- observed, or explicitly not
# =============================================================================================
def openssl_supports_group():
    """True if this Python's ssl module can report the negotiated key-exchange group.

    `SSLSocket.group()` arrived in CPython alongside OpenSSL 3.5. On an older local OpenSSL the
    attribute does not exist at all, which is why this is a capability check rather than a version
    string comparison: a feature test cannot be wrong about a build that patched around it.
    """
    return hasattr(ssl.SSLSocket, "group")


def group_unobserved_reason():
    """The sentence that appears in the report when the group could not be read.

    It names the requirement AND states what is therefore unknown. A report saying only
    "unobserved" invites the reader to fill the gap with a guess -- and every guess available for
    a TLS 1.3 group is wrong in at least one real deployment. Saying so out loud is the
    difference between a gap in the evidence and a wrong answer in a report someone acts on.
    """
    if openssl_supports_group():
        return ("the group API is present but returned nothing usable; the key-exchange mechanism "
                "is UNOBSERVED and is not inferred from the cipher suite")
    return ("the negotiated key-exchange group is UNOBSERVED: reading it needs OpenSSL 3.5+ with "
            "CPython's ssl.SSLSocket.group(), and this host does not have it (%s). The group is NOT "
            "guessed from the TLS version, the cipher suite, or the client's offered list -- TLS 1.3 "
            "negotiates the group independently of the suite, the SHA384 in a suite name is the HKDF "
            "hash rather than the key exchange, and an offered list is a preference order rather "
            "than a decision. Treat post-quantum key exchange as UNKNOWN for this endpoint, which "
            "is not the same as absent." % ssl.OPENSSL_VERSION)


def read_negotiated_group(sock):
    """Return (group_name_or_None, status, reason). Never raises; NEVER guesses.

    `sock.group()` returns the group actually negotiated, e.g. "X25519MLKEM768" or "secp256r1".
    When it is unavailable, or returns something empty, the answer is (None, "unobserved", ...)
    -- not a default, not the client's first offer, and never a hard-coded curve.
    """
    if not openssl_supports_group():
        return None, GROUP_UNOBSERVED, group_unobserved_reason()
    try:
        name = sock.group()
    except (AttributeError, ValueError, ssl.SSLError, OSError) as exc:
        # A TLS 1.2 connection has no single "group" in the TLS 1.3 sense, and some builds raise
        # rather than returning None. Either way the honest answer is unobserved.
        return None, GROUP_UNOBSERVED, (
            "the negotiated key-exchange group is UNOBSERVED for this connection (%s). It is not "
            "inferred from the cipher suite: a suite name states the AEAD and the HKDF hash, not "
            "the key exchange." % (exc.__class__.__name__,))
    if not name:
        return None, GROUP_UNOBSERVED, group_unobserved_reason()
    return str(name), GROUP_OBSERVED, "read from the completed handshake via SSLSocket.group()"


# =============================================================================================
# CONNECTING -- the only place a socket is opened
# =============================================================================================
def connect_vetted(endpoint, timeout=DEFAULT_TIMEOUT):
    """Open a TCP connection to a VETTED endpoint. Returns (sock, error_reason).

    Two properties this function exists to guarantee:

    1. The address connected to is `endpoint.address`, a numeric literal already judged by the
       policy. `socket.create_connection` is deliberately NOT used: it takes a host string and will
       happily resolve it, which is precisely the second resolution the policy exists to prevent.
       Here the sockaddr is built by hand from the vetted literal, so no name lookup can occur at
       connect time. That is the DNS rebinding window CLOSED, not merely narrowed.

    2. Every failure is a RETURNED reason, not an exception. An unreachable host is a result the
       operator needs to see; a traceback is not.
    """
    family = endpoint.family or socket.AF_INET
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        return None, "could not create a socket: %s" % (exc,)
    try:
        sock.settimeout(timeout)
        if family == socket.AF_INET6:
            # (host, port, flowinfo, scopeid) -- a 2-tuple raises on an AF_INET6 socket.
            sock.connect((endpoint.address, endpoint.port, 0, 0))
        else:
            sock.connect((endpoint.address, endpoint.port))
        return sock, None
    except socket.timeout:
        _close(sock)
        return None, "connection to %s:%d timed out after %.1fs" % (
            endpoint.address, endpoint.port, timeout)
    except ConnectionRefusedError:
        _close(sock)
        return None, "connection to %s:%d refused: nothing is listening" % (
            endpoint.address, endpoint.port)
    except socket.gaierror as exc:
        _close(sock)
        return None, "address %s could not be used: %s" % (endpoint.address, exc)
    except OSError as exc:
        _close(sock)
        return None, "connection to %s:%d failed: %s" % (
            endpoint.address, endpoint.port, exc.strerror or exc)


def _close(sock):
    """Close a socket without letting a close error mask the real failure."""
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _result(endpoint, status, reason, sensor=None, **extra):
    """Build a result dict. Every result has the same shape, so a report can rely on it."""
    result = {
        "endpoint": "%s:%s" % (endpoint.hostname, endpoint.port) if endpoint else None,
        "hostname": endpoint.hostname if endpoint else None,
        "port": endpoint.port if endpoint else None,
        "address": endpoint.address if endpoint else None,
        "status": status,
        "reason": reason,
        "sensor": sensor,
        "evidence_class": "observed" if status == STATUS_OBSERVED else None,
        "lab_derived": bool(endpoint.lab_derived) if endpoint else False,
        "findings": [],
    }
    result.update(extra)
    return result


def _lab_note(endpoint):
    """The lab-derived caveat, attached to any result produced against a private target."""
    return LAB_DERIVED_NOTE if (endpoint and endpoint.lab_derived) else None


# =============================================================================================
# THE TLS PROBE
# =============================================================================================
def _tls_context():
    """A permissive client context. See `probe_tls` for why verification is off."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_tls(endpoint, timeout=DEFAULT_TIMEOUT, context=None):
    """Complete a TLS handshake with a vetted endpoint and report what was NEGOTIATED.

    Returns a result dict. Never raises: a refused connection, a timeout, a plaintext service on a
    TLS port and a failed handshake are four different STATUSES with four different reasons,
    because "it did not answer" and "we did not ask" must never look the same in a report.

    CERTIFICATE VERIFICATION IS OFF, DELIBERATELY, and every result says so.

    We are an inventory sensor, not a client: the question is "which algorithms did this peer put
    on the wire", and a self-signed certificate, or one that does not match the address we dialled,
    must not stop us answering it. Verification on would mean reporting nothing for every internal
    or misconfigured host, which is a confident EMPTY report -- the worst failure mode this project
    has. The cost is stated plainly (`certificate_verified: False`, plus NOT_PROVEN), so nobody
    mistakes this for a trust decision. Authenticating a peer is a different job with different
    requirements, and conflating the two is how a scanner becomes a security liability.
    """
    sock, error = connect_vetted(endpoint, timeout=timeout)
    if sock is None:
        return _result(endpoint, STATUS_UNREACHABLE, error, sensor=SENSOR_TLS)

    try:
        ctx = context or _tls_context()
        try:
            tls = ctx.wrap_socket(sock, server_hostname=endpoint.as_sni())
        except ssl.SSLCertVerificationError as exc:
            _close(sock)
            return _result(endpoint, STATUS_HANDSHAKE_FAILED,
                           "TLS handshake failed on certificate verification: %s" % exc,
                           sensor=SENSOR_TLS, certificate_verified=False)
        except ssl.SSLError as exc:
            _close(sock)
            return _classify_ssl_error(endpoint, exc)
        except socket.timeout:
            _close(sock)
            return _result(endpoint, STATUS_UNREACHABLE,
                           "TLS handshake to %s:%d timed out after %.1fs" % (
                               endpoint.address, endpoint.port, timeout), sensor=SENSOR_TLS)
        except OSError as exc:
            _close(sock)
            return _result(endpoint, STATUS_UNREACHABLE,
                           "connection failed during the handshake: %s" % (exc,), sensor=SENSOR_TLS)
        with tls:
            return _report_handshake(endpoint, tls)
    finally:
        _close(sock)


def _classify_ssl_error(endpoint, exc):
    """Turn an SSLError into a status an operator can act on.

    A plaintext HTTP server on port 443 is a common and confusing case: OpenSSL reports it as a
    handshake failure ("wrong version number"), which reads like a TLS problem when it is actually
    "that port is not TLS". Naming that distinction is the difference between an operator fixing a
    port number and an operator hunting a cipher misconfiguration that does not exist.
    """
    text = str(exc).lower()
    reason = str(exc)
    if "wrong version number" in text or "unknown protocol" in text:
        return _result(endpoint, STATUS_NOT_TLS,
                       "the peer on %s:%d is not speaking TLS (it answered with something that is "
                       "not a TLS ServerHello). Either the port is wrong or the service is "
                       "plaintext. Reported separately from a handshake failure because the fix is "
                       "different." % (endpoint.address, endpoint.port), sensor=SENSOR_TLS)
    if "handshake failure" in text or "alert" in text:
        return _result(endpoint, STATUS_HANDSHAKE_FAILED,
                       "the TLS handshake failed and the server sent an alert: %s. The peer may "
                       "require a client certificate, or may share no cipher suite with us."
                       % reason, sensor=SENSOR_TLS)
    return _result(endpoint, STATUS_HANDSHAKE_FAILED,
                   "the TLS handshake failed: %s" % reason, sensor=SENSOR_TLS)


# =============================================================================================
# FINDINGS
# =============================================================================================
def _finding(endpoint, rule_id, name, primitive, uses, sensor, match, where, note, **extra):
    """Build one finding in the shape the rest of IndraMesh expects.

    The shape is load-bearing rather than cosmetic. `engine/cbom.py` reads `name`, `primitive`,
    `type`, `file` and `evidence_class`; `engine/purpose.py::resolve_purpose` reads `uses` and
    `rule_id`; `EVIDENCE_TO_ASSURANCE` maps `evidence_class` to an assurance level; and
    `coverage_manifest()` builds `scanners_run` from `scanner`. A finding missing one of these is a
    latent crash or a silent downgrade several modules downstream, which is the class of defect
    `tests/test_properties.py` exists to catch.

    `file` holds "host:port" and `line` is 0, because the location of a network observation is an
    endpoint rather than a source line. `generate_cbom` treats an EMPTY `file` as "no provenance",
    and that would be a lie here: we know exactly where this came from.
    """
    finding = {
        "file": where,
        "line": 0,
        "name": name,
        "type": "protocol" if primitive == "protocol" else "algorithm",
        "primitive": primitive,
        "rule_id": rule_id,
        "scanner": SCANNER_NETWORK,
        # THE load-bearing field. "observed" -> ASSURANCE_OBSERVED, the only class that means
        # "this happened on the wire" rather than "this is reachable or configured".
        "evidence_class": "observed",
        "artefact_class": "network",
        "uses": uses,
        "match": match,
        # Which sensor produced this. A finding without a witness is an assertion.
        "sensor": sensor,
        "observation_note": note,
        "network_endpoint": where,
        "network_address": endpoint.address,
        "network_hostname": endpoint.hostname,
        "network_port": endpoint.port,
        "observed_at": "live handshake",
    }
    if endpoint.lab_derived:
        # The mark travels WITH THE DATA. A finding from a lab server must never be
        # indistinguishable from one about a real deployment.
        finding["lab_derived"] = True
        finding["lab_note"] = LAB_DERIVED_NOTE
    finding.update(extra)
    return finding


# =============================================================================================
# REPORTING A COMPLETED HANDSHAKE
# =============================================================================================
def _report_handshake(endpoint, tls):
    """Turn a live `SSLSocket` into findings. Runs only after a COMPLETED handshake.

    The ordering matters for honesty: the protocol and the cipher suite are properties of the
    negotiated connection and are always readable. The GROUP is read through a separate capability
    gate, and when that gate is closed the group finding is simply NOT EMITTED. There is no branch
    anywhere below that invents one.
    """
    version = tls.version()
    cipher = tls.cipher()
    cipher_name = cipher[0] if cipher else None
    cipher_protocol = cipher[1] if cipher and len(cipher) > 1 else None
    cipher_bits = cipher[2] if cipher and len(cipher) > 2 else None

    group, group_status, group_reason = read_negotiated_group(tls)

    result = _result(
        endpoint, STATUS_OBSERVED,
        "completed a %s handshake with %s and read the negotiated parameters from the wire"
        % (version or "TLS", endpoint.address),
        sensor=SENSOR_TLS,
        tls_version=version,
        cipher=cipher_name,
        cipher_protocol=cipher_protocol,
        cipher_bits=cipher_bits,
        group=group,
        group_status=group_status,
        group_reason=group_reason,
        certificate_verified=False,       # stated, not implied. See `probe_tls`.
        lab_note=_lab_note(endpoint),
        local_openssl=ssl.OPENSSL_VERSION,
        not_proven=list(NOT_PROVEN),
    )

    where = "%s:%d" % (endpoint.hostname, endpoint.port)
    findings = [
        _finding(endpoint, rule_id=RULE_TLS_PROTOCOL, name=version or "TLS",
                 primitive="protocol", uses="tls", sensor=SENSOR_TLS,
                 match="%s negotiated with %s" % (version, cipher_name or "an unnamed suite"),
                 where=where, protocol=version,
                 note="Read from a completed handshake. This is the version actually negotiated, "
                      "not the list of versions the server is willing to accept."),
    ]

    if cipher_name:
        findings.append(_finding(
            endpoint, rule_id=RULE_TLS_CIPHER, name=cipher_name, primitive="ae", uses="tls",
            sensor=SENSOR_TLS,
            match="%s %s %s bits" % (cipher_name, cipher_protocol or "", cipher_bits or ""),
            where=where, key_length=cipher_bits, cipher_protocol=cipher_protocol,
            note="The AEAD suite actually negotiated. The suite name states the AEAD and the HKDF "
                 "hash; it does NOT state the key-exchange mechanism."))

    # The group finding is emitted ONLY on the observed branch. This `if` is the point of the
    # module: there is no else-branch that supplies a plausible default.
    if group_status == GROUP_OBSERVED and group:
        findings.append(_group_finding(endpoint, group, where))
    # When it is not observed, the ABSENCE is recorded in `not_observed` below rather than papered
    # over with a guess.

    result["findings"] = findings
    if group_status != GROUP_OBSERVED:
        result["not_observed"] = [{
            "item": "negotiated key-exchange group",
            "status": GROUP_UNOBSERVED,
            "reason": group_reason,
            "consequence": "Whether this endpoint uses a post-quantum key exchange is UNKNOWN. "
                           "That is NOT a finding of 'no post-quantum crypto' -- it is an absence "
                           "of evidence, and must not be reported as a clean result.",
        }]
    return result


def _group_finding(endpoint, group, where):
    """Build the group finding, LABELLED from the IANA registry. Only called when observed."""
    label = PQC_GROUPS.get(group)
    obsolete = OBSOLETE_PQC_GROUPS.get(group)
    extra = {"group": group, "group_status": GROUP_OBSERVED, "provides_pqc": bool(label)}

    if label:
        classical, pqc, kind = label
        extra.update({"classical_half": classical, "pqc_half": pqc})
        if kind == "hybrid":
            semantics = ("A hybrid holds only if BOTH halves are broken. Do not read it as 'half "
                         "migrated': it is a genuine hedge, and an AND, not an OR.")
        else:
            semantics = "No classical half is involved; this is a pure post-quantum exchange."
        note = ("The key-exchange group actually negotiated on this connection. Classical half: %s. "
                "Post-quantum half: %s. %s Read from the completed handshake, so it describes this "
                "connection rather than the server's configuration." % (classical, pqc, semantics))
    elif obsolete:
        extra.update({"provides_pqc": False, "obsolete": True})
        note = ("The key-exchange group actually negotiated is %s, which is %s. This is a "
                "pre-standardisation DRAFT and is NOT the standardised algorithm: Kyber round-3 is "
                "not ML-KEM-768, because FIPS 203 standardised a different scheme with different "
                "security claims." % (group, obsolete))
    else:
        extra["pqc_note"] = ("group name is not in the PQC registry, so it is classical or "
                             "unrecognised; reported as observed and NOT labelled")
        note = ("The key-exchange group actually negotiated is %s. It is not a name this project "
                "recognises as post-quantum, so it is reported as observed and unlabelled rather "
                "than guessed at." % group)

    return _finding(endpoint, rule_id=RULE_TLS_GROUP, name=group, primitive="key-agreement",
                    uses="tls", sensor=SENSOR_TLS, match="negotiated group %s" % group,
                    where=where, note=note, **extra)


# =============================================================================================
# THE SSH PROBE -- banner and KEXINIT only, no authentication
# =============================================================================================
def probe_ssh(endpoint, timeout=DEFAULT_TIMEOUT):
    """Read an SSH server's identification banner and its offered KEX algorithms.

    WHY THIS IS CHEAP AND SAFE ENOUGH TO DO BY DEFAULT. Everything here is pre-authentication and
    public: RFC 4253 requires both peers to send an identification string before anything else,
    and the server sends its KEXINIT -- the list of algorithms it will accept -- immediately after
    receiving ours. We send an identification string and read two messages. No credential is
    offered, no key is tried, no session is opened, and nothing is written to disk.

    WHAT IT DOES NOT ESTABLISH, which is most of what an operator will want to ask:

      * the algorithms are the server's OFFER, not a negotiated choice. We never complete a key
        exchange, so "the server supports X25519MLKEM768" means it WILL ACCEPT it, not that it
        chose it. The result says `offered`, never `negotiated` -- the same discipline the TLS
        group path applies, for the same reason.
      * nothing about the host key, the server's configuration for other clients, or its patch
        level. A server may offer a strong algorithm and a weak one in the same list.
    """
    sock, error = connect_vetted(endpoint, timeout=timeout)
    if sock is None:
        return _result(endpoint, STATUS_UNREACHABLE, error, sensor=SENSOR_SSH)

    try:
        banner = _read_ssh_banner(sock)
        if banner is None:
            return _result(endpoint, STATUS_NOT_TLS,
                           "the peer on %s:%d did not send an SSH identification string. Either it "
                           "is not SSH, or it is not speaking SSH on this port."
                           % (endpoint.address, endpoint.port), sensor=SENSOR_SSH,
                           ssh_banner=None)
        # Send OUR identification string. RFC 4253 requires both directions before KEX, and a
        # server will not send KEXINIT until it has seen ours. This is the only thing we write.
        try:
            sock.sendall(b"SSH-2.0-indramesh_probe\r\n")
        except OSError as exc:
            return _result(endpoint, STATUS_UNREACHABLE,
                           "could not send the SSH identification string: %s" % (exc,),
                           sensor=SENSOR_SSH, ssh_banner=banner)

        kex, kex_status, kex_reason = _read_ssh_kex_algorithms(sock)
        return _ssh_result(endpoint, banner, kex, kex_status, kex_reason)
    except socket.timeout:
        return _result(endpoint, STATUS_UNREACHABLE,
                       "timed out reading the SSH banner from %s:%d" % (
                           endpoint.address, endpoint.port), sensor=SENSOR_SSH)
    except OSError as exc:
        return _result(endpoint, STATUS_UNREACHABLE,
                       "SSH read failed: %s" % (exc.strerror or exc,), sensor=SENSOR_SSH)
    finally:
        _close(sock)


def _read_ssh_banner(sock):
    """Read the identification string. Returns it, or None if the peer is not speaking SSH.

    A server may emit lines before its banner (RFC 4253 allows this), so we skip a bounded number
    of them. The bound matters: without it a peer that never sends "SSH-" would keep us reading
    forever, and this loop is reachable from a batch.
    """
    for _ in range(SSH_MAX_LINES_BEFORE_BANNER):
        line = _read_line(sock, MAX_BANNER_BYTES)
        if line is None:
            return None
        if line.startswith(b"SSH-"):
            return line.decode("utf-8", errors="replace").strip()
    return None


def _read_line(sock, limit):
    """Read one CRLF/LF-terminated line, up to `limit` bytes. Returns bytes without the newline."""
    buf = b""
    while len(buf) < limit:
        chunk = sock.recv(1)
        if not chunk:
            return None if not buf else buf
        if chunk in (b"\n", b"\r"):
            return buf
        buf += chunk
    return buf


def _read_exactly(sock, count):
    """Read exactly `count` bytes, or return None if the peer closed first."""
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_ssh_kex_algorithms(sock):
    """Read the server's KEXINIT and return (algorithms, status, reason).

    KEXINIT is the first binary packet: a 4-byte big-endian length, a padding-length byte, the
    message type (20), sixteen random cookie bytes, then sixteen name-lists. We want the FIRST of
    those -- kex_algorithms -- and we stop there.

    `status` is "offered", never "negotiated". The server's KEXINIT is an OFFER, and calling it a
    negotiation would be the SSH equivalent of the group guess the TLS path refuses to make.
    """
    header = _read_exactly(sock, 4)
    if header is None or len(header) < 4:
        return None, "unread", ("the server closed the connection before sending KEXINIT, so its "
                               "algorithm list was not read")
    (length,) = struct.unpack(">I", header)
    if length < 2 or length > MAX_SSH_PACKET:
        return None, "unread", ("the server announced an SSH packet of %d bytes, outside the "
                                "RFC 4253 limit, so it was not read" % length)
    payload = _read_exactly(sock, length)
    if payload is None or len(payload) < 2:
        return None, "unread", "the KEXINIT packet was truncated before it could be read"
    if payload[1] != SSH_KEXINIT:
        return None, "unread", ("expected SSH_MSG_KEXINIT (20) but the first packet was type %d, so "
                               "the algorithm list was not read" % payload[1])
    # payload[0] is padding_length; the body starts after it. Skip the 16-byte cookie, then read
    # the first name-list: a 4-byte length followed by that many bytes.
    body = payload[1:]
    cursor = 16  # the cookie
    if cursor + 4 > len(body):
        return None, "unread", "the KEXINIT packet was too short to contain a kex_algorithms list"
    (name_len,) = struct.unpack(">I", body[cursor:cursor + 4])
    cursor += 4
    if name_len > len(body) - cursor:
        return None, "unread", "the kex_algorithms name-list length is inconsistent with the packet"
    names = body[cursor:cursor + name_len].decode("utf-8", errors="replace").split(",")
    algorithms = [n for n in names if n]
    if not algorithms:
        return None, "unread", "the server's kex_algorithms list was empty"
    return algorithms, "offered", ("read from the server's SSH_MSG_KEXINIT. This is the list the "
                                   "server is WILLING to accept, not a completed negotiation: no "
                                   "key exchange was performed, so nothing was chosen")


# SSH KEX method names that are post-quantum or PQC-hybrid. Used to LABEL an offered name that was
# genuinely read off the wire -- never to infer one. NTRU Prime (sntrup*) is a real post-quantum
# KEX draft shipped by OpenSSH and is NOT one of the four FIPS algorithms, so it is labelled as a
# draft rather than counted as a standard migration.
PQC_KEX_MARKERS = ("sntrup", "ntruprime", "kyber", "mlkem", "ml-kem", "frodo", "sike")


def _is_pqc_kex(name):
    """True if an SSH kex_algorithms NAME, read off the wire, is post-quantum or hybrid."""
    lowered = (name or "").lower()
    return any(marker in lowered for marker in PQC_KEX_MARKERS)


def _ssh_result(endpoint, banner, kex, kex_status, kex_reason):
    """Build the SSH result. A banner alone is an observation; an unread KEX list is a gap."""
    if kex is None:
        return _result(endpoint, STATUS_OBSERVED,
                       "read the SSH identification string from %s but NOT its algorithm list"
                       % endpoint.address, sensor=SENSOR_SSH,
                       ssh_banner=banner, kex_algorithms=None, kex_status=kex_status,
                       kex_reason=kex_reason, lab_note=_lab_note(endpoint),
                       not_proven=list(NOT_PROVEN))

    where = "%s:%d" % (endpoint.hostname, endpoint.port)
    pqc = [name for name in kex if _is_pqc_kex(name)]
    classical = [name for name in kex if not _is_pqc_kex(name)]
    result = _result(endpoint, STATUS_OBSERVED,
                     "read the SSH identification string and the kex_algorithms OFFER from %s"
                     % endpoint.address, sensor=SENSOR_SSH,
                     ssh_banner=banner, kex_algorithms=kex, kex_status=kex_status,
                     kex_reason=kex_reason, pqc_kex_offered=pqc, classical_kex_offered=classical,
                     lab_note=_lab_note(endpoint), not_proven=list(NOT_PROVEN))
    result["findings"] = [
        _finding(endpoint, rule_id=RULE_SSH_KEX, name=name, primitive="key-agreement", uses="ssh",
                 sensor=SENSOR_SSH, match="kex_algorithms offers %s" % name, where=where,
                 provides_pqc=_is_pqc_kex(name), offered_not_negotiated=True,
                 note="From the server's SSH_MSG_KEXINIT: what the server is WILLING to accept, not "
                      "what it chose, because no key exchange was completed. %s"
                      % ("A post-quantum or hybrid KEX." if _is_pqc_kex(name)
                         else "A classical KEX."))
        for name in kex
    ]
    return result


# =============================================================================================
# THE PUBLIC API -- opt-in, and every path goes through the policy
# =============================================================================================
def probe_endpoint(spec, policy=None, timeout=DEFAULT_TIMEOUT, enable=False, ssh=False,
                   context=None):
    """Probe ONE operator-named endpoint. Returns a result dict. Never raises.

    `enable=False` by default, and this is the single most important line in the module's
    interface. A network sensor that runs because it was called is a sensor that surprises someone
    on a network they never chose to touch, so reaching the network requires an explicit, visible
    opt-in. With `enable=False` NO SOCKET IS CREATED and the reason says so.

    `policy` defaults to `NetPolicy.from_env()`, which with no configuration denies every host.
    There is no path from `spec` to a socket that skips `vet_endpoint`.
    """
    if not enable:
        return {
            "endpoint": spec, "status": STATUS_DISABLED, "sensor": None,
            "reason": ("the network sensor is OFF by default and was not enabled, so nothing was "
                       "contacted. Pass enable=True to probe a named endpoint. This is deliberate: "
                       "a tool that opens connections because it was called reaches networks its "
                       "operator never chose."),
            "findings": [], "lab_derived": False,
        }

    active = policy if policy is not None else NetPolicy.from_env()
    vetted = active.vet_endpoint(spec)
    if isinstance(vetted, Refusal):
        # A refusal is a RESULT, not an error, reported as one so the operator can see that the
        # endpoint was considered and declined rather than silently skipped.
        return {
            "endpoint": spec, "status": STATUS_REFUSED, "sensor": None,
            "reason": vetted.reason, "verdict": vetted.verdict,
            "findings": [], "lab_derived": False,
        }

    try:
        if ssh:
            return probe_ssh(vetted, timeout=timeout)
        return probe_tls(vetted, timeout=timeout, context=context)
    except Exception as exc:                      # the sensor must never take the caller down
        return _result(vetted, STATUS_ERROR,
                       "the probe failed unexpectedly (%s): %s" % (exc.__class__.__name__, exc),
                       sensor=SENSOR_SSH if ssh else SENSOR_TLS)


def probe_endpoints(specs, policy=None, timeout=DEFAULT_TIMEOUT, enable=False, ssh=False,
                    context=None):
    """Probe a list of endpoints. Returns a report dict. Never raises.

    One bad endpoint never discards the rest, and one unreachable host is never an exception. The
    report separates three things a reader must be able to tell apart:

        results[]   what each endpoint actually produced
        refused[]   what the POLICY declined, with the reason and the verdict category
        coverage    what was never examined at all, and why

    That last one is the point. `engine/scanner.py` closes its manifest with a `never_in_scope`
    list precisely so "not found" and "not examined" are distinguishable, and a network sensor
    that reports a clean run without saying which endpoints it declined has reproduced the exact
    ambiguity this project exists to avoid.
    """
    active = policy if policy is not None else NetPolicy.from_env()
    report = {
        "results": [],
        "refused": [],
        "coverage": {
            "enabled": bool(enable),
            "endpoints_requested": len(list(specs or [])),
            "endpoints_probed": 0,
            "endpoints_refused": 0,
            "sensors_run": [],
            "policy": active.describe(),
            "not_proven": list(NOT_PROVEN),
        },
    }
    if not enable:
        report["coverage"]["reason"] = (
            "the network sensor is OFF by default; no endpoint was contacted. Pass enable=True to "
            "probe operator-named endpoints.")
        return report

    sensors = set()
    for spec in (specs or []):
        result = probe_endpoint(spec, policy=active, timeout=timeout, enable=True, ssh=ssh,
                                context=context)
        if result["status"] == STATUS_REFUSED:
            report["refused"].append({"endpoint": spec, "verdict": result.get("verdict"),
                                      "reason": result["reason"]})
        else:
            report["results"].append(result)
            if result.get("sensor"):
                sensors.add(result["sensor"])
    coverage = report["coverage"]
    coverage["endpoints_probed"] = len(report["results"])
    coverage["endpoints_refused"] = len(report["refused"])
    coverage["sensors_run"] = sorted(sensors)
    return report


def coverage_manifest(policy=None):
    """What this sensor can and cannot see, for a coverage manifest.

    Stating the limits next to the results is the difference between "this endpoint uses no
    post-quantum key exchange" and "this endpoint's key exchange was not observed on this host".
    Only the second is true on OpenSSL older than 3.5, and only the second is safe to act on.
    """
    active = policy if policy is not None else NetPolicy.from_env()
    return {
        "sensor": "network-negotiated crypto",
        "enabled_by_default": False,
        "sensors": [SENSOR_TLS, SENSOR_SSH],
        "evidence_class": "observed",
        "policy": active.describe(),
        "key_exchange_group": GROUP_OBSERVED if openssl_supports_group() else GROUP_UNOBSERVED,
        "key_exchange_group_reason": (None if openssl_supports_group()
                                      else group_unobserved_reason()),
        "local_openssl": ssl.OPENSSL_VERSION,
        "not_proven": list(NOT_PROVEN),
    }
