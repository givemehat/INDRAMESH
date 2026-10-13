"""Filesystem safety policy for the scanner.

Enforces containment boundaries and prevents arbitrary file reads during static scanning.

The scanner is a tool an operator points at a path -- possibly an untrusted checkout, an unpacked
tarball, or a package from a registry. Two guarantees matter:

  1. CONTAINMENT: a symlink inside the scan root must not let us read outside it. `os.walk` does
     not follow directory symlinks, but it does hand back symlinked FILES -- a link named
     `config.py` pointing at `~/.ssh/id_rsa` would be read, and its contents would land in the
     evidence snippet and therefore in the CBOM.

  2. NON-EXECUTION: we only read bytes. We never run `setup.py`, a Makefile, a package lifecycle
     hook, or a test. Stating this is a security property, not a disclaimer (PQCensus's posture).

Credential stores are never read at all: a cryptographic inventory has no reason to contain the
contents of a private key, and putting them in a report is a disclosure bug, not a finding.
"""
import os

# Files whose contents must never enter a CBOM, regardless of where the scan root points.
CREDENTIAL_STORE_NAMES = {
    "shadow", "gshadow", "master.passwd", "passwd-", ".netrc", "_netrc",
    ".git-credentials", ".gitconfig", ".npmrc", ".yarnrc", ".pypirc", ".dockercfg",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netlify", ".env", ".envrc",
    "credentials", "credentials.json", "service-account.json", "master.key",
    "known_hosts", "authorized_keys", "keystore", "truststore",
    "azure.keyvault", "artifactory-props", ".htpasswd",
}

# Synthetic filesystems that must never be walked.
PSEUDO_FS_PREFIXES = ("/proc", "/sys", "/dev", "/run")


class FilesystemPolicyError(Exception):
    """Raised when a requested path is refused outright."""


def resolve_within(root, path):
    """Return the real path of `path` only if it stays inside `root`, else None.

    Uses realpath on BOTH sides, so a symlink anywhere in the chain (including a symlinked
    directory component) is caught rather than only a symlinked leaf.
    """
    try:
        real_root = os.path.realpath(root)
        real_path = os.path.realpath(path)
    except OSError:
        return None
    if real_path == real_root:
        return real_path
    if real_path.startswith(real_root.rstrip(os.sep) + os.sep):
        return real_path
    return None


def is_credential_store(basename):
    low = basename.lower()
    if low in CREDENTIAL_STORE_NAMES:
        return True
    # id_rsa, id_ed25519.pem, server.key, .env.local, *_rsa, *_ed25519 ...
    for stem in CREDENTIAL_STORE_NAMES:
        if stem.startswith(".") and low.startswith(stem + "."):
            return True
    for suffix in ("_rsa", "_dsa", "_ed25519", "_ecdsa"):
        if low.endswith(suffix):
            return True
    if low.endswith(".pem") and low.startswith("id_"):
        return True
    return False


def check_root(root):
    """Validate a scan root before walking it. Raises on a refusal."""
    real = os.path.realpath(root)
    if not os.path.exists(real):
        raise FilesystemPolicyError(f"path does not exist: {root}")
    if not os.path.isdir(real):
        raise FilesystemPolicyError(f"not a directory: {root}")
    if any(real == p or real.startswith(p.rstrip("/") + "/") for p in PSEUDO_FS_PREFIXES):
        raise FilesystemPolicyError(f"refusing to scan a synthetic filesystem: {root}")
    return real
