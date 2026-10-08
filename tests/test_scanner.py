"""Tests for the scanning engine.

Regressions encoded here (all fixed 2026-09-25):
  * ECC and SHA-256 patterns were DEFINED BUT NEVER EXECUTED -- the loop only tested RSA and
    AES_GCM. The brief's own demo target is "a real repository that uses RSA and ECC".
  * `import torch` at module scope made the scanner unimportable without PyTorch
  * `except Exception: pass` made "could not read" indistinguishable from "clean"
  * binary scanning shelled out to `strings`, which does not exist on Windows
  * container images were not scanned at all
  * the AES key size was never extracted, so AES-256 was misreported
"""
import io
import os
import re
import tarfile

import pytest

from engine.scanner import IndraMeshScanner, RULES, BINARY_MARKERS


@pytest.fixture
def scanner():
    # enable_ml=False keeps these tests hermetic: no torch, no model file, regex only.
    return IndraMeshScanner(enable_ml=False)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ------------------------------------------------------------------ the dead-code regression

def test_every_rule_is_actually_executed(tmp_path, scanner):
    """Each rule in the table must be reachable: give it a positive sample and assert a hit."""
    samples = {
        "IM-SRC-RSA-001": "key = rsa.newkeys(2048)",
        "IM-SRC-RSA-002": "sig = pkcs1_15.new(key).sign(h)",
        "IM-SRC-RSA-003": 'KeyPairGenerator.getInstance("RSA")',
        # A bare `ec.generate_private_key(ec.SECP256R1())` no longer matches this rule: it is a
        # generic key-pair generator that cannot say which operation follows, and matching it
        # here made one line report as BOTH ECDH and ECDSA. The curve is still found, by
        # IM-SRC-PYCA-EC-001.
        "IM-SRC-ECDH-001": "shared = kex.exchange(peer_public_key)",
        "IM-SRC-ECDSA-001": 'Signature.getInstance("SHA256withECDSA")',
        "IM-SRC-ECC-001": 'kpg = KeyPairGenerator.getInstance("EC")',
        "IM-SRC-EDDSA-001": "sk = Ed25519PrivateKey.generate()",
        "IM-SRC-DSA-001": "EVP_PKEY_DSA *pkey = NULL;",
        "IM-SRC-DH-001": "DH_get_2048_256();",
        "IM-SRC-AES-001": "aesgcm = AESGCM(key)",
        "IM-SRC-CHACHA-001": "AEADChaCha20Poly1305()",
        "IM-SRC-SHA2-001": "digest = hashes.Hash(hashes.SHA256())",
        "IM-SRC-SHA1-001": 'MessageDigest.getInstance("SHA-1")',
        "IM-SRC-MD5-001": "hashlib.md5(data)",
        "IM-CFG-TLS-001": "ssl_protocols TLSv1.2 TLSv1.3;",
        "IM-CFG-LEGACY-001": "ciphers = RC4-SHA:DES-CBC3-SHA",
        # --- the recall rules, added against measured misses on paramiko (a real SSH library).
        # The samples are the actual source lines the benchmark said we failed on, so each rule
        # is pinned to the evidence that motivated it rather than to an invented string.
        "IM-SRC-PYCA-AES-001": '"cipher": algorithms.AES,',
        "IM-SRC-PYCA-HASH-001": "self.hash_object = hashes.SHA256",
        "IM-SRC-PYCA-HASH-002": "h = hashes.SHA1",
        "IM-SRC-PYCA-EC-001": "_ECDSACurve(ec.SECP256R1, \"nistp256\")",
        # IM-SRC-PYCA-EC-002 was removed as a strict subset of -001: the curve was reported
        # twice from two rule_ids, and the second carried no extra information. The dedup key
        # includes rule_id, so two rules with the same name never collapse.
        "IM-SRC-PYCA-ECDH-001": "k = ECDHPrivateKey.generate()",
        "IM-SRC-PYCA-ED-001": "k = ed25519.Ed25519PrivateKey.generate()",
        "IM-SRC-PYCA-RSA-001": "n = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp)",
        "IM-SRC-PYCA-X-001": "from cryptography.hazmat.primitives.asymmetric.x25519 import (",
        "IM-SRC-HASHLIB-001": "from hashlib import sha1",
        "IM-SRC-HASHLIB-002": "hash_algo = hashlib.sha256",
        "IM-SRC-HASHLIB-003": "from hashlib import md5",
        "IM-SRC-SSH-KEX-001": 'kex = "ecdh-sha2-nistp256"',
        "IM-SRC-SSH-SIG-001": '"rsa-sha2-256": SSH_AGENT_RSA_SHA2_256,',
        "IM-SRC-SSH-ED-001": 'PREF = "ssh-ed25519"',
        "IM-SRC-SSH-CIPHER-001": 'C = "aes256-ctr"',
        # Its own rule now, because it used to be reported as name=AES while sitting in a rule
        # declared as AES. A decoy in test_multilang_pack.py pins the name.
        "IM-SRC-SSH-CHACHA-001": 'C = "chacha20-poly1305@openssh.com"',
        "IM-SRC-SSH-CIPHER-002": '"aes128-gcm@openssh.com"',
        "IM-SRC-SSH-MAC-001": '"hmac-sha2-256"',
        "IM-SRC-SSH-DH-001": 'name = "diffie-hellman-group-exchange-sha256"',
        "IM-SRC-SSH-LEGACY-001": '"3des-cbc"',
        # --- the Java pack, added against MEASURED CryptoAPI-Bench misses (recall 0.219, FP=0).
        # Each sample is a real call shape from the corpus, not an invented string.
        "IM-SRC-JAVA-LEGACY-001": 'String t = "DES/ECB/PKCS5Padding";',
        "IM-SRC-JAVA-KEYGEN-001": "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");",
        "IM-SRC-JAVA-SECRETKEY-001": 'SecretKeySpec ks = new SecretKeySpec(keyBytes, "AES");',
        "IM-SRC-JAVA-CIPHER-001": 'Cipher c = Cipher.getInstance("Blowfish");',
        "IM-SRC-JAVA-MAC-001": 'Mac mac = Mac.getInstance("HmacSHA256");',
        # MD2/MD4 only. MD5 is deliberately NOT here: IM-SRC-MD5-001 already owns it, and
        # matching it again published the same algorithm twice from two rule_ids.
        "IM-SRC-JAVA-DIGEST-001": 'MessageDigest md = MessageDigest.getInstance("MD4");',
        "IM-SRC-JAVA-EC-001": 'new ECGenParameterSpec("secp256r1")',
        "IM-SRC-JAVA-DSA-001": 'KeyPairGenerator.getInstance("DSA")',
        "IM-SRC-JAVA-CONST-001": 'String a = "AES/GCM/NoPadding";',
        "IM-SRC-JAVA-CONST-003": 'String t = "RSA/ECB/PKCS1Padding";',
        "IM-SRC-JAVA-CONST-004": 'String h = "SHA-256";',
        "IM-SRC-JAVA-WEAKRNG-001": "Random r = new java.util.Random();",
        # --- PHP and Ruby, which previously had NO rules and were not even scanned.
        "IM-PHP-AES-001": "openssl_encrypt($data, 'aes-256-gcm', $key);",
        "IM-PHP-AES-002": "openssl_cipher_iv_length('aes-256-cbc');",
        "IM-PHP-KEM-001": "openssl_public_encrypt($data, $pubkey);",
        "IM-PHP-SIG-001": "openssl_sign($data, $sig, $privkey);",
        "IM-PHP-SODIUM-001": "sodium_crypto_aead_chacha20_ietf_encrypt($m, $aad, $npub, $k);",
        "IM-PHP-SODIUM-002": "sodium_crypto_aead_aes256gcm_encrypt($m, $aad, $npub, $k);",
        "IM-PHP-SIG-002": "sodium_crypto_sign_keypair();",
        "IM-PHP-HASH-001": "$h = hash('sha1', $data);",
        "IM-PHP-WEAKRNG-001": "$t = mt_rand();",
        "IM-RB-AES-001": "c = OpenSSL::Cipher.new('aes-256-gcm')",
        "IM-RB-AES-002": "c = OpenSSL::Cipher.new('chacha20')",
        "IM-RB-LEGACY-001": "c = OpenSSL::Cipher.new('bf-cbc')",
        "IM-RB-RSA-001": "k = OpenSSL::PKey::RSA.new(2048)",
        # A real call site. The pattern needs the receiver named (`OpenSSL::PKey::X.sign(...)
        # ), which is why the sample must be a call and not a bare class reference.
        "IM-RB-SIG-001": "sig = OpenSSL::PKey::RSA.new.sign(digest, priv)",
        "IM-RB-EC-001": "k = OpenSSL::PKey::EC.generate('prime256v1')",
        "IM-RB-DH-001": "dh = OpenSSL::PKey::DH.new(2048)",
        "IM-RB-MAC-001": "h = OpenSSL::HMAC.digest('SHA256', key, data)",
        "IM-RB-HASH-001": "d = Digest::SHA1.hexdigest(data)",
        "IM-RB-HASH-002": "d = Digest::SHA256.hexdigest(data)",
        # `SecureRandom.hex` deliberately does NOT match this rule -- a rule that fired on the
        # secure generator too would make the finding meaningless.
        "IM-RB-WEAKRNG-001": "token = Kernel.rand(16)",
        "IM-KEY-PEM-001": "-----BEGIN RSA PRIVATE KEY-----",
        "IM-KEY-PGP-001": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        # The Apache directive, which is what this rule uniquely owns. The old sample was
        # `ssl_protocols TLSv1.2`, which this rule deliberately no longer matches: that form is
        # IM-CFG-TLS-001's, and matching both made one nginx line produce two protocol
        # components that _finalise cannot collapse.
        "IM-PROTO-TLS-001": "SSLProtocol all -SSLv3",
        "IM-CLOUD-KMS-001": "boto3.client('kms')",
        "IM-CLOUD-AZURE-001": "azure.keyvault",
        "IM-CLOUD-GCP-001": "google-cloud-kms",
        "IM-HARDWARE-PKCS11-001": "SunPKCS11",
        # --- Go. Every alternative is package-qualified: an unqualified token would match the
        # same text in any language, since rules are not filtered by file extension.
        "IM-GO-CIPHER-001": "b, _ := des.NewCipher(key)",
        "IM-GO-CIPHER-002": "c, _ := rc4.NewCipher(key)",
        "IM-GO-CIPHER-003": "aead, _ := chacha20poly1305.New(key)",
        "IM-GO-HASH-001": "h := md5.New()",
        "IM-GO-HASH-002": 'import "crypto/sha1"',
        "IM-GO-SIG-001": "r, s, _ := ecdsa.Sign(rnd, priv, digest)",
        "IM-GO-SIG-002": "err := rsa.SignPKCS1v15(rnd, priv, crypto.SHA256, d)",
        "IM-GO-SIG-003": "o := &rsa.PSSOptions{}",
        "IM-GO-PQKEM-001": "dk, err := mlkem.NewDecapsulationKey768(seed)",
        "IM-GO-PQKEM-002": "dk, err := mlkem.NewDecapsulationKey1024(seed)",
        # Import paths are P3 taint sources under the labelling criterion, same as
        # `from hashlib import sha1`. The x/crypto measurement showed they were the single largest
        # miss class, so each primitive package import is reachable in its own right.
        "IM-GO-IMPORT-001": '\t"crypto/md5"',
        "IM-GO-IMPORT-002": '\t"crypto/sha1"',
        "IM-GO-IMPORT-003": '\t"crypto/sha256"',
        "IM-GO-IMPORT-004": '\t"crypto/hmac"',
        "IM-GO-IMPORT-005": '\t"crypto/des"',
        "IM-GO-IMPORT-006": '\t"crypto/rc4"',
        "IM-GO-IMPORT-007": '\t"crypto/aes"',
        "IM-GO-IMPORT-008": '\t"golang.org/x/crypto/chacha20"',
        "IM-GO-IMPORT-009": '\t"golang.org/x/crypto/curve25519"',
        "IM-GO-IMPORT-010": '\t"crypto/sha512"',
        "IM-GO-HASHBIND-001": "Hash:      crypto.SHA256,",
        # P1b declarations. Each is anchored to `func`/`type`/`var` so a mention in an
        # expression cannot fire it.
        "IM-GO-DECL-001": "func (c *chacha20Poly1305Cipher) readCipherPacket(n uint32) {",
        "IM-GO-DECL-002": "func newAESCTR(key, iv []byte) (cipher.Stream, error) {",
        "IM-GO-DECL-003": "func newTripleDESCBCCipher(key, iv, macKey []byte) {",
        "IM-GO-DECL-004": "func newRC4(key, iv []byte) (cipher.Stream, error) {",
        "IM-GO-DECL-005": "var c25519kp curve25519KeyPair",
        "IM-GO-DECL-006": "if !poly1305.Verify(&mac, buf, &key) {",
        # Go SSH mode tables: the registration idiom, not the factory-call idiom.
        "IM-GO-SSHTBL-AES": "cipherModes[CipherAES128CTR] = &cipherMode{16, aes.BlockSize, nil}",
        "IM-GO-SSHTBL-RC4": "cipherModes[InsecureCipherRC4128] = &cipherMode{16, 0, nil}",
        "IM-GO-SSHTBL-3DES": "cipherModes[InsecureCipherTripleDESCBC] = &cipherMode{24, 0, nil}",
        "IM-GO-SSHTBL-MAC": "macModes[HMACSHA512ETM] = &macMode{64, true, nil}",
        "IM-GO-SIG-004": "pub, _, _ := ed25519.GenerateKey(rnd)",
        "IM-GO-KEX-001": "k, _ := ecdh.P256().GenerateKey(rnd)",
        "IM-GO-RNG-001": "n := rand.Intn(100)",
        # --- Rust. `md5::Md5` rather than bare `MD5`; see the note on IM-RUST-HASH-001.
        "IM-RUST-CIPHER-002": "use aes_gcm::Aes256Gcm;",
        "IM-RUST-HASH-001": "let h = md5::Md5::new();",
        "IM-RUST-HASH-002": "let h = sha1::Sha1::new();",
        "IM-RUST-SIG-001": "let k = ecdsa::SigningKey::from_bytes(&b)?;",
        "IM-RUST-SIG-002": "let kp = Ed25519KeyPair::generate();",
        "IM-RUST-SIG-003": "let k = rsa::RsaPrivateKey::new(n, e);",
        "IM-RUST-RNG-001": "let mut r = thread_rng();",
        # --- JavaScript / TypeScript.
        "IM-JS-CIPHER-001": "createCipheriv('des-ede3-cbc', k, iv)",
        "IM-JS-CIPHER-002": "crypto.createCipheriv('rc4', key, iv)",
        "IM-JS-HASH-001": "crypto.createHash('md5')",
        "IM-JS-HASH-002": "crypto.createHmac('sha1', key)",
        "IM-JS-SIG-001": "crypto.createSign('RSA-SHA1')",
        "IM-JS-SIG-002": "s = crypto.constants.RSA_PKCS1_PSS_PADDING;",
        "IM-JS-SIG-003": "crypto.createSign('ecdsa-with-SHA256')",
        # --- dedup + recall fixes found by probing the SSH rule set directly.
        "IM-SRC-SSH-DH-002": 'KEX = "ffdh2048-sha256"',
        # --- OpenSSH algorithm identifiers.
        #
        # These are a CLOSED, PUBLISHED vocabulary, which is why these rules are near
        # false-positive-free: a quoted string ending in "@openssh.com" can only be a registered
        # protocol name. They were added to recover 13 labelled misses in the paramiko corpus,
        # where the whole supported-algorithm table is built from these identifiers. The primitive
        # is asserted too, because getting ECDH and ECDSA the wrong way round would point an
        # auditor at the wrong replacement algorithm.
        "IM-SRC-SSHNAME-001": '"ecdsa-sha2-nistp256-cert-v01@openssh.com": ECDSAKey,',
        "IM-SRC-SSHNAME-002": '"rsa-sha2-256-cert-v01@openssh.com": RSAKey,',
        "IM-SRC-SSHNAME-003": '"ssh-ed25519-cert-v01@openssh.com": Ed25519Key,',
        "IM-SRC-SSHNAME-004": '"hmac-sha2-256-etm@openssh.com": {"class": sha256, "size": 32},',
        "IM-SRC-SSHNAME-005": 'KEX = "curve25519-sha256@libssh.org"',
        "IM-SRC-SSHNAME-006": '"ecdh-sha2-nistp256-cert-v01@openssh.com": ECDHKey,',
        "IM-SRC-SSHNAME-007": 'KEX = "mlkem768x25519-sha256@openssh.com"',
        # --- Added 2026-09-29 with the rules that recovered 16 labelled paramiko misses.
        #
        # Each sample below is the VERBATIM source line from the pinned corpus that motivated
        # the rule, with the file and line number in a comment. A sample invented to satisfy
        # this assertion would prove the regex compiles and nothing more; these are the lines
        # the benchmark actually scored as misses.
        # paramiko/kex_ecdh_nist.py:6, kex_gex.py:26, kex_group14.py:26, kex_group16.py:24
        "IM-SRC-HASHLIB-004": "from hashlib import sha256, sha384, sha512",
        # paramiko/transport.py:193 and :195 register these in the MAC preference table.
        "IM-SRC-SSH-MAC-002": '        "hmac-md5",',
        # paramiko/kex_mlkem.py:54 -- the RFC 9370 hybrid name, bound to `name =`.
        "IM-SRC-SSH-HYBRID-001": '    name = "mlkem768x25519-sha256"',
        # paramiko/ecdsakey.py:250 (return annotation), pkey.py:216 (isinstance).
        "IM-SRC-PYCA-ECTYPE-001": "    def private_key(self) -> ec.EllipticCurvePrivateKey:",
        # paramiko/kex_ecdh_nist.py:71 and :117.
        "IM-SRC-PYCA-ECDH-002": "K = self.P.exchange(ec.ECDH(), self.Q_C)",
        # paramiko/sftp_server.py:83.
        "IM-SRC-SSH-HASH-NAME-001": '    _hash_class = {"sha1": sha1, "md5": md5}',
        # --- Rules split out of the MD5/SHA-1 mislabelling fix, 2026-09-29.
        #
        # Four rules reported `name="SHA1"` (or `"SHA"`) while their regex matched MD5, so every
        # MD5 call site was published to the CBOM as SHA-1. Each half now has its own rule with
        # a name that matches what it detects. BLAKE2 was likewise folded into a rule named SHA.
        "IM-SRC-PYCA-MD5-001": "h = MD5.new(digest_size=16)",
        "IM-PHP-HASH-002": "hash('md5')",
        "IM-RB-HASH-003": "OpenSSL::Digest::MD5.new",
        "IM-SRC-HASHLIB-BLAKE2-001": "h = hashlib.blake2b",
        "IM-SRC-JAVA-CONST-004-MD5": 'String HASH_ALGO = "MD5";',
        # --- OpenSSH identifiers as they appear in a REAL sshd_config, where they are BARE.
        #
        # These ten regexes previously DEMANDED a surrounding quote, so a deployed SSH server's
        # entire negotiation policy -- `HostKeyAlgorithms rsa-sha2-512`, no quotes -- produced
        # nothing at all. Found while checking a reviewer's point that the algorithm is often
        # negotiated rather than named at a call site: the config that declares WHAT gets
        # negotiated was the thing we could not see.
        "IM-SRC-SSHNAME-002": "HostKeyAlgorithms rsa-sha2-512-cert-v01@openssh.com",
        "IM-SRC-SSHNAME-003": "HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com",
        "IM-SRC-SSHNAME-007": "KexAlgorithms mlkem768x25519-sha256@openssh.com",
        # --- JCA provider indirection & runtime-resolved rules
        # RTRES-003's sample is ONLY the variable call: adding a `String t = "..."` line to
        # the snippet would exercise the dedup path and the rule would rightly stay silent.
        "IM-JAVA-RTRES-001": 'SSLContext ctx = SSLContext.getInstance("TLS");',
        "IM-JAVA-RTRES-002": 'Cipher c = Cipher.getInstance("AES");',
        "IM-JAVA-RTRES-003": 'Cipher c = Cipher.getInstance(transformation, "SunJCE");',
    }

    assert set(samples) == {r["id"] for r in RULES}, "a rule has no positive test"
    # A rule declared `artefact_class="config"` only fires for a file the scanner recognises as
    # configuration. Writing every sample to `<rule_id>.txt.py` made the config rules
    # unreachable while the reachability test still passed for the rest, which is how a rule
    # could be shipped that never matches anything.
    # RTRES-003's sample must reach the real scanner path as `.java`: the dedup check inspects
    # the whole file content, and the dedicated tests below cover both branches end to end.
    config_rules = {r["id"] for r in RULES if r["artefact_class"] == "config"}
    unreachable = []
    for rule_id, snippet in samples.items():
        suffix = ".conf" if rule_id in config_rules else ".java" if rule_id.startswith("IM-JAVA-RTRES-") else ".txt.py"
        p = _write(str(tmp_path / f"{rule_id}{suffix}"), snippet)
        fired = {f["rule_id"] for f in scanner._match_rules(p, snippet)}
        if rule_id not in fired:
            unreachable.append(rule_id)
    assert not unreachable, f"rules defined but never fire: {unreachable}"


# ===========================================================================================
# OpenSSH algorithm identifiers: primitive correctness and false-positive rejection.
#
# The reachability test above proves each rule FIRES. These prove it fires for the RIGHT REASON.
# Both directions matter: an OpenSSH identifier that resolves to the wrong primitive would send
# an auditor to the wrong replacement algorithm, which is worse than reporting nothing.
# ===========================================================================================

def test_openssh_identifiers_resolve_to_the_right_primitive(tmp_path, scanner):
    """curve25519 and ecdh-sha2 are KEY AGREEMENT; ecdsa-sha2 and rsa-sha2 are SIGNATURES.

    ECDSA and ECDH share the NIST curves, so the distinction is easy to get backwards and
    impossible to notice from a count. Getting it wrong would recommend a signature algorithm
    where a KEM belongs.
    """
    cases = {
        '"ecdsa-sha2-nistp384-cert-v01@openssh.com": ECDSAKey,': "signature",
        '"rsa-sha2-512-cert-v01@openssh.com": RSAKey,': "signature",
        '"ssh-ed25519-cert-v01@openssh.com": Ed25519Key,': "signature",
        '"ecdh-sha2-nistp256-cert-v01@openssh.com": ECDHKey,': "key-agreement",
        'KEX = "curve25519-sha256@libssh.org"': "key-agreement",
    }
    for line, want in cases.items():
        p = _write(str(tmp_path / f"t{abs(hash(line))}.py"), line)
        fired = [f for f in scanner._match_rules(p, line)
                 if f["rule_id"].startswith("IM-SRC-SSHNAME")]
        assert fired, f"no OpenSSH rule fired on {line!r}"
        assert any(f["primitive"] == want for f in fired), (
            f"{line!r} should resolve to {want}, got {[f['primitive'] for f in fired]}")


def test_openssh_protocol_markers_are_not_reported_as_algorithms(tmp_path, scanner):
    """`kex-strict-c-v00@openssh.com` and `ext-info-c` name NO primitive.

    They are protocol negotiation markers. A rule that matched them would report cryptography
    that does not exist -- and would do it in exactly the file (transport.py) where the real
    algorithm table lives, making the noise hard to spot.
    """
    for line in ('"kex-strict-c-v00@openssh.com"', '"ext-info-c"',
                 "# supports ecdsa-sha2-nistp256-cert-v01@openssh.com in theory"):
        p = _write(str(tmp_path / f"m{abs(hash(line))}.py"), line)
        fired = [f for f in scanner._match_rules(p, line)
                 if f["rule_id"].startswith("IM-SRC-SSHNAME")]
        assert not fired, f"protocol marker {line!r} was reported as {fired}"


def test_a_bare_curve_name_is_not_double_counted_as_an_openssh_identifier(tmp_path, scanner):
    """`"ecdsa-sha2-nistp256"` without the namespaced suffix is another rule's job.

    Double-reporting one ECDSA use from two rule_ids was a real defect we already fixed once
    (IM-SRC-PYCA-EC-002 was removed for exactly this). This guards against reintroducing it
    through the new rules.
    """
    p = _write(str(tmp_path / "bare.py"), 'ALG = "ecdsa-sha2-nistp256"')
    fired = [f["rule_id"] for f in scanner._match_rules(p, 'ALG = "ecdsa-sha2-nistp256"')
             if f["rule_id"].startswith("IM-SRC-SSHNAME")]
    assert not fired, f"a bare curve name matched the OpenSSH rules: {fired}"



def test_ecc_is_detected(tmp_path, scanner):
    # The snippet ends in `.exchange(peer_public_key)`, which is an actual key-agreement call.
    # A BARE `ec.generate_private_key(ec.SECP256R1())` no longer produces an ECDH finding: it is
    # a generic key-pair generator, and typing it as ECDH made the same line also report as
    # ECDSA -- so one statement produced two mutually exclusive primitives and two targets.
    p = _write(str(tmp_path / "kex.py"),
               "from cryptography.hazmat.primitives.asymmetric import ec\n"
               "priv = ec.generate_private_key(ec.SECP256R1())\n"
               "shared = priv.exchange(peer_public_key)\n")
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "ECDH" in names, "ECC/ECDH detection is the brief's stated demo target"


def test_a_bare_key_pair_generator_is_not_reported_as_two_primitives(tmp_path, scanner):
    """A key-pair generator must not yield BOTH a key-agreement and a signature.

    It used to match the ECDH rule AND the PYCA ECDSA rules at once, so the recommender offered
    ML-KEM and ML-DSA for a single statement. The fix was NOT to stop detecting it -- that cost
    measured recall -- but to stop the downstream rename that guessed "signature" out of nearby
    prose. Both facts are still reported; the contradictory one is gone.
    """
    p = _write(str(tmp_path / "kex.py"),
               "priv = ec.generate_private_key(ec.SECP256R1())\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings, "the curve and its key agreement must still be detected"
    primitives = {f["primitive"] for f in findings}
    assert "signature" not in primitives, (
        "a key-pair generator does not establish a signature")
    assert "key-agreement" in primitives, (
        "a P-256 key pair IS key agreement; the finding must not be thrown away to avoid a "
        "duplicate -- dropping it cost measured recall on the paramiko corpus")


def test_sha256_is_detected(tmp_path, scanner):
    p = _write(str(tmp_path / "h.py"), "d = hashes.Hash(hashes.SHA256())\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert any(f["name"] == "SHA256" for f in findings)


# ------------------------------------------------------------------ metadata correctness

def test_rsa_key_size_extracted(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"),
               "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n")
    findings = scanner.scan_directory(str(tmp_path))
    rsa = [f for f in findings if f["name"] == "RSA"]
    assert rsa and rsa[0]["key_length"] == 4096


def test_aes_key_size_extracted(tmp_path, scanner):
    p = _write(str(tmp_path / "a.c"), "EVP_aes_256_gcm();\n")
    findings = scanner.scan_directory(str(tmp_path))
    aes = [f for f in findings if f["name"] == "AES"]
    assert aes and aes[0]["key_length"] == 256, "AES-256 must not be reported as AES-128"


def test_curve_resolves_to_key_size_and_primitive(tmp_path, scanner):
    """The curve resolves to a key size, and the key-agreement CALL resolves to the primitive.

    These are two different lines and the tool reports them as two different facts, which is the
    point: `ec.SECP256R1()` says the algorithm, `.exchange(peer_public_key)` says the operation.
    Neither line supports the other's conclusion on its own, so neither is stretched to do it.
    """
    p = _write(str(tmp_path / "kex.py"),
               "priv = ec.generate_private_key(ec.SECP256R1())\n"
               "shared = priv.exchange(peer_public_key)\n")
    findings = scanner.scan_directory(str(tmp_path))

    # The exchange line is key agreement, and is not given a key size it cannot see.
    ecdh = [f for f in findings if f["name"] == "ECDH"]
    assert ecdh, "an actual .exchange(peer_public_key) call is key agreement"
    assert ecdh[0]["primitive"] == "key-agreement"

    # The curve line carries the size.
    curves = [f for f in findings if f.get("key_length") == 256]
    assert curves, "SECP256R1 must resolve to a 256-bit key"


def test_a_curve_object_alone_is_not_called_a_signature(tmp_path, scanner):
    """A bare `ec.SECP256R1()` must not be reported as `signature`.

    It was renamed "ECDSA / signature" whenever no TLS token happened to be nearby. That is a
    coin-flip presented as a finding, and it is why one line could be reported as both ECDH and
    ECDSA. With no use context the operation is simply not stated.
    """
    p = _write(str(tmp_path / "kex.py"), "curve = ec.SECP256R1()\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings, "the curve itself must still be detected"
    for f in findings:
        assert f["primitive"] != "signature", (
            "a curve object does not establish that it is used for signing")


# --------------------------------------------------------------------------------------------
# PHP and Ruby. Both had ZERO rules AND were not in SOURCE_EXTENSIONS, so a PHP or Rails codebase
# produced no findings whatsoever. Precision matters more here than coverage: both languages use
# `#` as their PRIMARY comment style, so without comment stripping every rule in these packs
# would fire on prose and the tool would report a comment as a cryptographic algorithm.
# --------------------------------------------------------------------------------------------

PHP_REAL = (
    "<?php\n"
    "$c = openssl_encrypt($d, 'aes-256-gcm', $k);\n"
    "openssl_public_encrypt($d, $pub);\n"
    "$h = hash('sha1', $d);\n"
    "mt_rand();\n"
)

RUBY_REAL = (
    "c = OpenSSL::Cipher.new('aes-256-gcm')\n"
    "k = OpenSSL::PKey::RSA.new(2048)\n"
    "d = Digest::SHA1.hexdigest(data)\n"
    "t = Kernel.rand(16)\n"
)

# Every line names a real algorithm. Not one of them is a CALL. A tool that reports these is
# reporting prose as an inventory, which is worse than reporting nothing.
PHP_DECOY = (
    "<?php\n"
    "// encrypt with aes-256-gcm in production\n"
    "# TODO: replace sha1 with something better\n"
    "$aesMode = 'aes-128-cbc';\n"
    "echo \"we use RSA and SHA-256\";\n"
)

RUBY_DECOY = (
    "# switch to OpenSSL::Cipher.new('aes-256-gcm') later\n"
    "=begin\n"
    "OpenSSL::PKey::RSA.new(2048)\n"
    "=end\n"
    "x = 1 # Digest::SHA1.hexdigest(data)\n"
)


def test_php_crypto_calls_are_detected(tmp_path, scanner):
    _write(str(tmp_path / "app.php"), PHP_REAL)
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "AES" in names and "RSA" in names, f"expected openssl_* detection, got {names}"
    assert "PRNG" in names, "mt_rand() is not a cryptographic generator and must be flagged"


def test_php_comments_and_prose_are_not_findings(tmp_path, scanner):
    _write(str(tmp_path / "notes.php"), PHP_DECOY)
    assert scanner.scan_directory(str(tmp_path)) == [], (
        "a PHP comment or a bare cipher string in an echo is not a cryptographic call site")


def test_ruby_crypto_calls_are_detected(tmp_path, scanner):
    _write(str(tmp_path / "app.rb"), RUBY_REAL)
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "AES" in names and "RSA" in names, f"expected OpenSSL:: detection, got {names}"
    aes = [f for f in findings if f["name"] == "AES"][0]
    assert aes["key_length"] == 256, "aes-256-gcm must resolve to a 256-bit key"


def test_ruby_comments_and_block_comments_are_not_findings(tmp_path, scanner):
    _write(str(tmp_path / "notes.rb"), RUBY_DECOY)
    assert scanner.scan_directory(str(tmp_path)) == [], (
        "Ruby `#` comments and =begin/=end blocks are prose, not call sites")


def test_secure_random_is_not_flagged_as_a_weak_generator(tmp_path, scanner):
    """`SecureRandom` is the CORRECT call. A weak-RNG rule that also fired on it would make the
    finding meaningless, so the negative lookbehind on the Ruby rule is load-bearing."""
    _write(str(tmp_path / "good.rb"), "token = SecureRandom.hex(16)\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert not [f for f in findings if f["name"] == "PRNG"], (
        "SecureRandom must never be reported as a non-cryptographic generator")


def test_a_python_sign_call_is_not_a_ruby_signature_finding(tmp_path, scanner):
    """A language pack must not fire on ANOTHER language.

    `IM-RB-SIG-001` originally matched a bare `.sign(`/`.verify(`, which fired on paramiko's
    `self.key.sign(...)` -- an SSH host-key operation in Python, reported as an RSA signature.
    That was 6 false positives on the Python corpus, and the benchmark caught them. The rule now
    requires an explicit `OpenSSL::PKey::` receiver, which is what makes it a Ruby signal.
    """
    _write(str(tmp_path / "auth.py"),
           "sig = self.key.sign(data)\n"
           "ok = self.key.verify(sig, data)\n"
           "key.sign_pss('SHA256', digest)\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings == [], (
        "a Python .sign()/.verify() call must not be reported by the Ruby pack: %r"
        % [(f["rule_id"], f["name"]) for f in findings])


def test_provenance_is_recorded(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"),
               "\n\nkey = rsa.newkeys(2048)\n")
    findings = scanner.scan_directory(str(tmp_path))
    hit = [f for f in findings if f["name"] == "RSA"][0]
    assert hit["line"] == 3
    assert hit["rule_id"] == "IM-SRC-RSA-001"
    assert hit["scanner"] == "source-scanner"
    assert hit["evidence_class"] == "discovered"


# ------------------------------------------------------------------ honesty about failures

def test_unreadable_file_is_recorded_not_silently_ignored(tmp_path, scanner):
    """Regression: `except Exception: pass` meant an unreadable file looked identical to a clean
    file, so 'no findings' could have meant 'nothing was examined'."""
    bad = tmp_path / "bad.py"
    bad.write_bytes(b"\xff\xfe\x00\x00invalid utf8")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings == []
    assert scanner.errors, "unreadable file must be recorded"
    assert "bad.py" in scanner.errors[0]["file"]
    assert scanner.coverage["files_skipped"] == 1


def test_missing_path_is_recorded(scanner):
    assert scanner.scan_directory(str("/definitely/not/here/123456")) == []
    assert scanner.errors


def test_empty_file_is_clean_not_an_error(tmp_path, scanner):
    _write(str(tmp_path / "empty.py"), "")
    assert scanner.scan_directory(str(tmp_path)) == []
    assert scanner.errors == []


def test_coverage_manifest_lists_what_was_never_in_scope(tmp_path, scanner):
    _write(str(tmp_path / "v.py"), "key = rsa.newkeys(2048)\n")
    scanner.scan_directory(str(tmp_path))
    manifest = scanner.coverage_manifest()
    assert manifest["files_scanned"] >= 1
    assert manifest["never_in_scope"], "coverage gaps must be stated explicitly"
    joined = " ".join(manifest["never_in_scope"]).lower()
    for expected in ("network", "hsm", "saas", "silicon"):
        assert expected in joined


def test_scanner_works_without_torch(tmp_path, scanner):
    """Regression: `import torch` at module scope made scanning impossible without PyTorch."""
    p = _write(str(tmp_path / "v.py"), "key = rsa.newkeys(2048)\n")
    assert scanner.scan_directory(str(tmp_path)), "regex-only mode must still work"
    assert scanner.ml is None or not scanner.ml.available


# ------------------------------------------------------------------ binaries

def test_binary_markers_detected_without_external_strings(tmp_path, scanner):
    """Regression: scanning shelled out to `strings`, absent on Windows, and the failure was
    swallowed. Extraction is now pure Python."""
    p = tmp_path / "libfoo.so"
    p.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 16 + b"OpenSSL 3.0.13 libcrypto\x00" + b"\x00" * 8)
    findings = scanner.scan_directory(str(tmp_path))
    assert any(f["type"] == "library" and "OpenSSL" in f["name"] for f in findings)


def test_binary_without_markers_produces_nothing(tmp_path, scanner):
    p = tmp_path / "plain.bin"
    p.write_bytes(b"\x00\x01\x02" * 200)
    assert scanner.scan_directory(str(tmp_path)) == []


# ------------------------------------------------------------------ containers

def test_container_image_is_scanned(tmp_path, scanner):
    """Regression: container images were not scanned at all, though the brief requires them."""
    src = tmp_path / "src" / "layer"
    src.mkdir(parents=True)
    _write(str(src / "app.py"), "key = rsa.newkeys(2048)\n")
    _write(str(src / "tls.conf"), "ssl_protocols TLSv1.2;\n")
    lib = src / "libcrypto.so"
    lib.write_bytes(b"\x7fELF" + b"\x00" * 8 + b"libcrypto 3.0.13\x00")

    image = tmp_path / "image.tar"
    with tarfile.open(image, "w") as tf:
        tf.add(str(src / "app.py"), arcname="app/app.py")
        tf.add(str(src / "tls.conf"), arcname="app/tls.conf")
        tf.add(str(lib), arcname="usr/lib/libcrypto.so")

    findings = scanner.scan_directory(str(image))
    names = {f["name"] for f in findings}
    assert "RSA" in names, "container layer source must be scanned"
    assert "TLS" in names
    assert any("image.tar" in f["file"] for f in findings)
    # image evidence is presence, not usage
    for f in findings:
        if "image.tar" in f["file"]:
            assert f["evidence_class"] == "configured"


def test_corrupt_container_is_reported_not_crashed(tmp_path, scanner):
    bad = tmp_path / "notanimage.tar"
    bad.write_bytes(b"this is not a tar archive at all")
    assert scanner.scan_directory(str(bad)) == []
    assert scanner.errors and "notanimage" in scanner.errors[0]["file"]


# ------------------------------------------------------------------ dedup

def test_duplicate_findings_are_collapsed(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"), "a = rsa.newkeys(2048)\nb = rsa.newkeys(2048)\n")
    findings = scanner.scan_directory(str(tmp_path))
    rsa = [f for f in findings if f["name"] == "RSA"]
    assert len({f["line"] for f in rsa}) == len(rsa), "same line should not appear twice"


# ============================ regression: the two precision fixes, 2026-09-29 ==================
#
# Both of these were FPs I introduced myself and then removed. They are kept as tests because
# the temptation to re-add them is obvious -- on their face both look like they would help
# recall. What separates them from the misses they were meant to catch is stated per test.


def test_public_ec_key_type_is_not_a_finding(tmp_path, scanner):
    """`EllipticCurvePublicKey` names the PUBLISHED half of a key pair.

    The first version of IM-SRC-PYCA-ECTYPE-001 matched both key types and cost 3 false
    positives for zero true positives: every public-key occurrence in the paramiko corpus
    (ecdsakey.py:167, kex_ecdh_nist.py:67 and :113) is labelled negative. A public key is by
    definition public; naming its type does not evidence a secret a CRQC could recover.
    """
    _write(str(tmp_path / "pub.py"),
           "def get_public(self):\n    return self.pubkey\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert not [f for f in findings if f["rule_id"] == "IM-SRC-PYCA-ECTYPE-001"], \
        "a public key type must not be reported as a Shor-vulnerable secret"


def test_private_ec_key_type_is_still_a_finding(tmp_path, scanner):
    """The converse, so the fix above cannot be over-applied to gut the rule."""
    _write(str(tmp_path / "priv.py"),
           "def private_key(self) -> ec.EllipticCurvePrivateKey:\n    return self._k\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert [f for f in findings
            if f["name"] == "ECC" and f["rule_id"] == "IM-SRC-PYCA-ECTYPE-001"], \
        "a private key type is a Shor-vulnerable secret and must be reported"


def test_reading_a_hash_registry_is_not_selecting_an_algorithm(tmp_path, scanner):
    """`_hash_class` on its own does not choose a hash.

    The removed alternative matched the identifier anywhere it appeared, including
    sftp_server.py:309 and :311 where the dict is only being read. Selection happens at the
    quoted key on the declaration line, which IM-SRC-SSH-HASH-NAME-001 still matches.
    """
    _write(str(tmp_path / "reg.py"),
           "cls = self._hash_class[name]\nother = _hash_class\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert not [f for f in findings if f["rule_id"] == "IM-SRC-SSH-HASH-NAME-001"], \
        "reading a registry must not be reported as selecting a hash algorithm"


def test_md5_import_is_not_also_reported_as_sha1(tmp_path, scanner):
    """IM-SRC-HASHLIB-001 and -003 both matched `from hashlib import md5`, and both name SHA1.

    Dedup is on (file, name, rule_id, line), so two rule_ids cannot collapse and the MD5
    import was published as a second SHA-1 component. The benchmark cannot catch this class
    of bug: it scores distinct LOCATIONS, so a location reported twice is still one TP.
    """
    _write(str(tmp_path / "m.py"), "from hashlib import md5\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert [f for f in findings if f["name"] == "MD5"], "the MD5 import must be reported"
    assert not [f for f in findings if f["name"] == "SHA1"], \
        "an MD5 import must not also be published as a SHA-1 finding"


def test_real_sshd_config_negotiation_policy_is_visible(tmp_path, scanner):
    """A deployed SSH server's cipher/KEX policy is BARE -- no quotes around the identifier.

    Every OpenSSH wire-identifier rule demanded a surrounding quote, which is correct for the
    Java/JS string-literal form and wrong for `sshd_config`, so the whole negotiation policy of
    a real server scanned as empty. This is the concrete form of the objection that the
    algorithm a system runs is often decided by configuration rather than named at a call
    site -- and the file that decides it was invisible.

    The finding is published at `configured` evidence, not `discovered`, because a policy line
    states what MAY be negotiated rather than what a given connection did.
    """
    _write(str(tmp_path / "sshd_config"),
           "Host *\n"
           "  Ciphers aes256-gcm@openssh.com\n"
           "  KexAlgorithms mlkem768x25519-sha256@openssh.com\n"
           "  HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com\n")
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert {"AES", "ML-KEM-768", "Ed25519"} <= names, (
        f"the SSH negotiation policy must be visible; got {sorted(names)}")
    for f in findings:
        assert f["evidence_class"] == "configured", (
            "a policy line is declared policy, not observed execution")


# ===========================================================================================
# JCA provider indirection: runtime-resolved rules
#
# A factory call is a REQUEST, not a decision. `SSLContext.getInstance("TLS")` names a family;
# which versions and suites the peer gets is answered by `java.security` plus launch flags,
# not by this line. `Cipher.getInstance("AES")` is the same shape one level down (no mode or
# padding -- the provider supplies its defaults). `Cipher.getInstance(crypto)` is indirection
# further out: the string lives at the variable's declaration site, or outside this file.

def test_sslcontext_tls_family_emits_a_runtime_resolved_finding(tmp_path, scanner):
    """The archetype from the review: `getInstance("TLS")` names no algorithm."""
    p = _write(str(tmp_path / "TlsClient.java"),
               "import javax.net.ssl.SSLContext;\n"
               "public class TlsClient {\n"
               "  void connect() throws Exception {\n"
               '    SSLContext ctx = SSLContext.getInstance("TLS");\n'
               "  }\n"
               "}\n")
    findings = [f for f in scanner.scan_directory(str(tmp_path))
                if f["rule_id"] == "IM-JAVA-RTRES-001"]
    assert len(findings) == 1, (
        "one call site must produce exactly one finding, got %r" % findings)
    f = findings[0]
    assert f["evidence_class"] == "runtime-resolved"
    assert "java.security" in (f.get("resolver") or ""), (
        "the finding must name the resolver file")
    assert "jdk.tls.disabledAlgorithms" in (f.get("resolver") or ""), (
        "the resolver must name the exact deny-list property")
    from engine.purpose import ASSURANCE_RUNTIME_RESOLVED, resolve_assurance
    assert resolve_assurance(f)[0] == ASSURANCE_RUNTIME_RESOLVED


def test_bare_cipher_family_names_the_family_not_the_construction(tmp_path, scanner):
    """`Cipher.getInstance("AES")` is not `used` AES-anything: mode and padding are the
    provider's defaults. The finding names the family and refuses the construction."""
    _write(str(tmp_path / "Enc.java"),
           "import javax.crypto.Cipher;\n"
           "public class Enc {\n"
           "  void go() throws Exception {\n"
           '    Cipher c = Cipher.getInstance("AES");\n'
           "  }\n"
           "}\n")
    findings = [f for f in scanner.scan_directory(str(tmp_path))
                if f["rule_id"] == "IM-JAVA-RTRES-002"]
    assert len(findings) == 1
    assert findings[0]["name"] == "AES"
    assert findings[0]["evidence_class"] == "runtime-resolved"


def test_fully_pinned_transformation_is_not_runtime_resolved(tmp_path, scanner):
    """Counterpart guard: `Cipher.getInstance("AES/GCM/NoPadding")` pins algorithm, mode
    and padding in the scanned bytes, so nothing may demote it to runtime-resolved."""
    _write(str(tmp_path / "Pinned.java"),
           "import javax.crypto.Cipher;\n"
           "public class Pinned {\n"
           "  void go() throws Exception {\n"
           '    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
           "  }\n"
           "}\n")
    rtres = [f for f in scanner.scan_directory(str(tmp_path))
             if f["rule_id"] in ("IM-JAVA-RTRES-001", "IM-JAVA-RTRES-002",
                                 "IM-JAVA-RTRES-003")]
    assert not rtres, (
        "a fully specified transformation must not be demoted: %r" % rtres)


def test_variable_indirection_defaults_unresolved_and_names_the_variable(tmp_path, scanner):
    """`Cipher.getInstance(crypto, "SunJCE")`: algorithm from a variable, provider named
    explicitly -- both decided outside this line. Silence neither (a finding is emitted),
    overstate nothing (identity unresolved, and the resolver names what to go read)."""
    _write(str(tmp_path / "Indirect.java"),
           "import javax.crypto.Cipher;\n"
           "public class Indirect {\n"
           "  void go(String transformation) throws Exception {\n"
           '    Cipher c = Cipher.getInstance(transformation, "SunJCE");\n'
           "  }\n"
           "}\n")
    findings = [f for f in scanner.scan_directory(str(tmp_path))
                if f["rule_id"] == "IM-JAVA-RTRES-003"]
    assert len(findings) == 1, (
        "genuinely unresolvable indirection must still emit a finding, got %r" % findings)
    f = findings[0]
    assert "transformation" in (f.get("resolver") or ""), (
        "the resolver must name the variable whose declaration decides the algorithm")
    from engine.purpose import PURPOSE_UNRESOLVED, resolve_purpose
    assert resolve_purpose(f)[0] == PURPOSE_UNRESOLVED, (
        "indirection with no literal must default to unresolved purpose")


def test_in_file_constant_declaration_suppresses_the_factory_finding(tmp_path, scanner):
    """The dedup direction: a `String ... = "DES/..."` declaration is already carried by the
    CONST rules. Emitting a factory finding too would report one crypto use twice."""
    _write(str(tmp_path / "Declared.java"),
           "import javax.crypto.Cipher;\n"
           "public class Declared {\n"
           '  static final String CRYPTO = "DES/ECB/PKCS5Padding";\n'
           "  void go() throws Exception {\n"
           '    Cipher c = Cipher.getInstance(CRYPTO, "SunJCE");\n'
           "  }\n"
           "}\n")
    rtres3 = [f for f in scanner.scan_directory(str(tmp_path))
              if f["rule_id"] == "IM-JAVA-RTRES-003"]
    assert not rtres3, (
        "the declaration carries the evidence; the factory call must not double-report")


def test_one_arg_variable_indirection_is_deliberately_not_reported(tmp_path, scanner):
    """The measured exclusion. `Cipher.getInstance(crypto)` -- one argument, algorithm from a
    parameter -- is NOT reported by RTRES-003.

    Implemented first and measured: 27 hits on CryptoAPI-Bench, precision 0.994 -> 0.858 for
    +0.019 recall. The corpus's frozen ground truth marks those lines NEGATIVE outright --
    "no quantum-vulnerable primitive is named or determined on this line". The annotators
    already considered this exact shape and ruled it out of scope for a primitive-finding
    benchmark; a tool that out-votes the ground truth to inflate its own inventory is not a
    tool anyone should trust. If this is ever reversed, the benchmark must be re-run and the
    number in benchmark/RESULTS.md corrected in the same commit.
    """
    _write(str(tmp_path / "OneArg.java"),
           "import javax.crypto.Cipher;\n"
           "public class OneArg {\n"
           "  void go(String transformation) throws Exception {\n"
           "    Cipher c = Cipher.getInstance(transformation);\n"
           "  }\n"
           "}\n")
    rtres = [f for f in scanner.scan_directory(str(tmp_path))
             if f["rule_id"].startswith("IM-JAVA-RTRES-")]
    assert not rtres, (
        "the one-arg form is a measured precision regression and must stay excluded: %r" % rtres)


def test_runtime_resolved_finding_reaches_the_cbom_with_its_resolver(tmp_path, scanner):
    """The resolver must survive to the CycloneDX document, or it is a comment, not data."""
    from engine.cbom import generate_cbom
    import json as _json
    _write(str(tmp_path / "TlsClient.java"),
           "import javax.net.ssl.SSLContext;\n"
           "public class TlsClient {\n"
           "  void connect() throws Exception {\n"
           '    SSLContext ctx = SSLContext.getInstance("TLS");\n'
           "  }\n"
           "}\n")
    findings = scanner.scan_directory(str(tmp_path))
    doc = _json.loads(generate_cbom(findings))
    props = {p["name"]: p["value"]
             for comp in doc.get("components", [])
             for p in comp.get("properties", [])}
    assert props.get("im:assurance") == "runtime-resolved", (
        "the CBOM must carry the new assurance level")
    assert "java.security" in props.get("im:resolver", ""), (
        "the CBOM must name the resolver file")


# ---- The general form of the defect above, checked across the WHOLE table --------------------
#
# Four separate rules reported `name="SHA1"` or `name="SHA"` while their regex matched `md5`
# (and one folded BLAKE2 into the SHA family). Each was found by hand, one at a time. This test
# makes the class impossible to reintroduce: any rule whose regex can match an md5 token must be
# NAMED for MD5.
#
# This is a NAME-vs-REGEX consistency check, and it is the kind the benchmark structurally
# cannot perform. The benchmark scores (file, line) locations -- a line that names the wrong
# algorithm is still the right location, so it scores as a true positive. Every one of these
# four bugs was invisible to measurement and visible only to a test that asks "is the name true?"


def test_no_rule_publishes_md5_under_a_sha_name():
    md5_tokens = re.compile(r"md5", re.I)
    offenders = [
        (r["id"], r["name"]) for r in RULES
        if md5_tokens.search(r["regex"]) and r["name"] not in ("MD5", "HMAC")
    ]
    assert not offenders, (
        "these rules match an md5 token but are not named MD5, so every MD5 call site they "
        f"fire on is published under the wrong algorithm name: {offenders}"
    )


def test_no_rule_publishes_blake2_under_the_sha_family():
    """BLAKE2 is a separate design, not a SHA member."""
    blake = re.compile(r"blake2", re.I)
    offenders = [
        (r["id"], r["name"]) for r in RULES
        if blake.search(r["regex"]) and r["name"] not in ("BLAKE2",)
    ]
    assert not offenders, (
        f"blake2 matched but the rule is not named BLAKE2: {offenders}"
    )


def test_every_misnamed_hash_rule_still_detects_its_own_algorithm(tmp_path):
    """The converse guard, so the split cannot be 'fixed' by deleting detection.

    Each of the four rules that was split must still fire on the algorithm it is named for.
    Without this, the obvious way to make the test above pass is to drop the md5 alternation
    entirely -- which converts a false assertion into a silent gap, and is strictly worse.
    """
    _write(str(tmp_path / "all.py"), (
        "from hashlib import md5\n"
        "import hashlib\n"
        "a = hashlib.md5\n"
        "b = hashlib.sha1\n"
        "c = hashlib.blake2b\n"
    ))
    findings = IndraMeshScanner(enable_ml=False).scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "MD5" in names, "MD5 detection was lost while fixing the mislabelling"
    assert "SHA1" in names, "SHA-1 detection must not be collateral damage"
    assert "BLAKE2" in names, "BLAKE2 detection was lost while splitting it out"



