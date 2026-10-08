# IndraMesh external-accuracy benchmark results

Reproduce everything in this file with one command:

```
python benchmark/run_benchmark.py
```

## Which corpus is this, and is it external or hand-labelled?

**Both corpora are EXTERNAL and were fetched from the network. The line-level ground
truth is hand-annotated by the author of this harness, not supplied by the corpus
authors, because neither published corpus labels *quantum vulnerability* -- they label
*API misuse*. That distinction is the single most important caveat in this document and
is repeated in every table below.**

| corpus | external? | pinned commit | what it is |
|---|---|---|---|
| `cryptoapi_bench` | yes (git clone) | `e6b6b50fef69` | 203 Java micro-programmes, published and third-party. Note: these are CONSTRUCTED benchmark cases, not production code. |
| `xcrypto_ssh_algorithms` | yes (git clone) | `7a4a4d6beae2` | Real production library, not a constructed benchmark. N NARROW scope: three hand-read files from the ssh/ package (the cipher, MAC and ML-KEM algorithm tables). Chosen because they enumerate the algorithm surface, and because they are the only files in the package that have been read in full. The other 28 non-test files in ssh/ are NOT annotated and NOT scanned. This corpus contains REAL post-quantum code: ssh/mlkem.go implements a hybrid ML-KEM-768 + X25519 SSH key exchange (draft-kampanakis-curdle-ssh-pq-ke-05). |
| `paramiko` | yes (git clone) | `142f593e40ad` | Real production library, not a constructed benchmark. Scoped to the 'paramiko/' package directory; 'tests/' and 'sites/' are excluded, and that exclusion is part of the declared measurement scope. |

### Why the ground truth had to be hand-made

CryptoAPI-Bench ships `CryptoAPI-Bench_details.xlsx` with 182 rows of *misuse* labels
(28 categories: `Constant Seed`, `Usage of ECB`, `RSA keysize 1024 bits`, `DES used`,
`PBE iteration < 1000`, ...). IndraMesh is a **quantum**-vulnerability detector. Those are
different properties, so scoring IndraMesh against the published labels would be a category
error, and we do not report such a number as an accuracy figure. Instead each corpus
carries a hand-annotated label set whose unit is one `(file, line)` location and whose
criterion is stated in full below and in `benchmark/labels/README.md`.

## Labelling criterion (identical for both corpora)

A `(file, line)` location is **POSITIVE** iff it *names*, or *binds a name to*, a
quantum-vulnerable cryptographic primitive in a position that determines the algorithm:

- `P1` a factory call that selects the algorithm, e.g. `Cipher.getInstance` with an AES literal, `KeyGenerator.getInstance(keyAlgo)` where `keyAlgo` holds DES, `hashlib.sha256`, `rsa.generate_private_key(...)`;
- `P1b` naming a quantum-vulnerable primitive identifier in executable code,
  including type annotations and `isinstance` checks, e.g. `X25519PrivateKey.generate()`;
- `P2` a key-spec / hash-constant binding -- `new SecretKeySpec(bytes, "AES")`,
  `hashes.SHA256`;
- `P3` a *taint source* -- a literal that determines the algorithm further down, e.g.
  `public static final String DEFAULT_CRYPTO = "IDEA";`, `from hashlib import sha1`;
- `P4` an SSH/OpenSSL algorithm identifier naming a quantum-vulnerable primitive, e.g.
  `"ecdh-sha2-nistp256"`, `"ssh-ed25519"`, `"aes256-ctr"`, `"hmac-sha2-256"`.

A location that merely **operates** on a primitive chosen elsewhere -- `cipher.init`,
`md.update`, `cipher.encryptor()`, `.digest()`, `compute_hmac(...)` -- is **NEGATIVE in**
**L1** and **POSITIVE in L2**. Comments, PRNGs (`SecureRandom`, `random`), IVs and salts,
PBKDF parameter objects, key-store container formats (`JKS`) and key/block-size plumbing
are negative in both, each with a recorded reason.

This criterion **favours IndraMesh**: every excluded operation line is a location the tool
did not report and would otherwise have counted as a false negative. That is exactly why
L2 is reported next to L1 rather than buried.

Break models follow NIST/`engine/mosca.py`: `shor` = broken outright (RSA, DSA, DH, ECDH,
ECDSA, EdDSA, ElGamal, X25519); `grover` = quadratic speed-up only, not retroactive (AES,
DES, 3DES, Blowfish, RC2, RC4, IDEA, ChaCha20, MD2/4/5, SHA-1/2, HMAC).

## Headline numbers (line level)

`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`. Every ratio is shown with the
counts it came from; no ratio is reported without them.

| corpus | labels | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| `cryptoapi_bench` | L1 | 165 | 1 | 45 | 0.994 = 165/166 | 0.7857 = 165/210 | 0.8777 |
| `cryptoapi_bench` | L2 | 165 | 1 | 158 | 0.994 = 165/166 | 0.5108 = 165/323 | 0.6748 |
| `xcrypto_ssh_algorithms` | L1 | 47 | 4 | 0 | 0.9216 = 47/51 | 1.0 = 47/47 | 0.9592 |
| `xcrypto_ssh_algorithms` | L2 | 49 | 2 | 0 | 0.9608 = 49/51 | 1.0 = 49/49 | 0.98 |
| `paramiko` | L1 | 172 | 17 | 68 | 0.9101 = 172/189 | 0.7167 = 172/240 | 0.8019 |
| `paramiko` | L2 | 172 | 17 | 87 | 0.9101 = 172/189 | 0.6641 = 172/259 | 0.7679 |

### File-level view (secondary)

| corpus | labels | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| `cryptoapi_bench` | L1 | 106 | 1 | 4 | 0.9907 | 0.9636 |
| `cryptoapi_bench` | L2 | 106 | 1 | 13 | 0.9907 | 0.8908 |
| `xcrypto_ssh_algorithms` | L1 | 3 | 0 | 0 | 1.0 | 1.0 |
| `xcrypto_ssh_algorithms` | L2 | 3 | 0 | 0 | 1.0 | 1.0 |
| `paramiko` | L1 | 16 | 0 | 3 | 1.0 | 0.8421 |
| `paramiko` | L2 | 16 | 0 | 3 | 1.0 | 0.8421 |

### Recall by primitive (L1)

| corpus | primitive (break model) | labelled | detected | recall |
|---|---|---|---|---|
| `cryptoapi_bench` | AES (grover) | 82 | 72 | 0.878 |
| `cryptoapi_bench` | Blowfish (grover) | 12 | 8 | 0.6667 |
| `cryptoapi_bench` | DES (grover) | 15 | 12 | 0.8 |
| `cryptoapi_bench` | HMAC (grover) | 3 | 3 | 1.0 |
| `cryptoapi_bench` | IDEA (grover) | 12 | 8 | 0.6667 |
| `cryptoapi_bench` | MD2 (grover) | 10 | 6 | 0.6 |
| `cryptoapi_bench` | MD4 (grover) | 10 | 6 | 0.6 |
| `cryptoapi_bench` | MD5 (grover) | 10 | 6 | 0.6 |
| `cryptoapi_bench` | RC2 (grover) | 12 | 8 | 0.6667 |
| `cryptoapi_bench` | RC4 (grover) | 12 | 8 | 0.6667 |
| `cryptoapi_bench` | RSA (shor) | 17 | 17 | 1.0 |
| `cryptoapi_bench` | SHA-1 (grover) | 10 | 6 | 0.6 |
| `cryptoapi_bench` | SHA-256 (grover) | 5 | 5 | 1.0 |
| `xcrypto_ssh_algorithms` | 3DES (grover) | 4 | 4 | 1.0 |
| `xcrypto_ssh_algorithms` | AES (grover) | 9 | 9 | 1.0 |
| `xcrypto_ssh_algorithms` | ChaCha20 (grover) | 10 | 10 | 1.0 |
| `xcrypto_ssh_algorithms` | HMAC (grover) | 7 | 7 | 1.0 |
| `xcrypto_ssh_algorithms` | RC4 (grover) | 6 | 6 | 1.0 |
| `xcrypto_ssh_algorithms` | SHA1 (grover) | 1 | 1 | 1.0 |
| `xcrypto_ssh_algorithms` | SHA256 (grover) | 4 | 4 | 1.0 |
| `xcrypto_ssh_algorithms` | SHA512 (grover) | 1 | 1 | 1.0 |
| `xcrypto_ssh_algorithms` | X25519 (shor) | 5 | 5 | 1.0 |
| `paramiko` | 3DES (grover) | 2 | 2 | 1.0 |
| `paramiko` | AES (grover) | 27 | 27 | 1.0 |
| `paramiko` | Curve25519 (shor) | 2 | 2 | 1.0 |
| `paramiko` | Diffie-Hellman (shor) | 3 | 3 | 1.0 |
| `paramiko` | EC (shor) | 1 | 0 | 0.0 |
| `paramiko` | ECDH (shor) | 30 | 11 | 0.3667 |
| `paramiko` | ECDSA (shor) | 42 | 14 | 0.3333 |
| `paramiko` | ED25519 (shor) | 1 | 1 | 1.0 |
| `paramiko` | Ed25519 (shor) | 19 | 7 | 0.3684 |
| `paramiko` | EllipticCurvePrivateKey (shor) | 3 | 3 | 1.0 |
| `paramiko` | HMAC (grover) | 16 | 16 | 1.0 |
| `paramiko` | MD5 (grover) | 5 | 4 | 0.8 |
| `paramiko` | RSA (shor) | 37 | 35 | 0.9459 |
| `paramiko` | SHA-1 (grover) | 3 | 1 | 0.3333 |
| `paramiko` | SHA-256 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA-384 (grover) | 1 | 1 | 1.0 |
| `paramiko` | SHA-512 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA1 (grover) | 5 | 5 | 1.0 |
| `paramiko` | SHA256 (grover) | 7 | 6 | 0.8571 |
| `paramiko` | SHA512 (grover) | 1 | 1 | 1.0 |
| `paramiko` | X25519 (shor) | 22 | 20 | 0.9091 |
| `paramiko` | secp256r1 (shor) | 3 | 3 | 1.0 |
| `paramiko` | secp384r1 (shor) | 2 | 2 | 1.0 |
| `paramiko` | secp521r1 (shor) | 2 | 2 | 1.0 |

## Coverage and scan honesty

`files_skipped` and `errors` are reported so that "the tool found nothing here" can
never be confused with "the tool could not look here".

| corpus | files seen | files scanned | files skipped | scan errors |
|---|---|---|---|---|
| `cryptoapi_bench` | 203 | 203 | 0 | 0 |
| `xcrypto_ssh_algorithms` | 0 | 3 | 0 | 0 |
| `paramiko` | 42 | 42 | 0 | 0 |

Findings emitted for `cryptoapi_bench`, by rule:

| rule | findings |
|---|---|
| DES | IM-SRC-JAVA-LEGACY-001 | 44 |
| AES | IM-SRC-JAVA-KEYGEN-001 | 31 |
| AES | IM-SRC-AES-001 | 23 |
| AES | IM-SRC-JAVA-CIPHER-001 | 21 |
| AES | IM-SRC-JAVA-SECRETKEY-001 | 15 |
| MD5 | IM-SRC-JAVA-CONST-004-MD5 | 12 |
| LEGACY-CIPHER | IM-CFG-LEGACY-001 | 8 |
| AES | IM-SRC-JAVA-CONST-001 | 7 |
| RSA | IM-SRC-RSA-003 | 6 |
| SHA256 | IM-SRC-SHA2-001 | 5 |
| SHA | IM-SRC-JAVA-CONST-004 | 4 |
| MD5 | IM-SRC-JAVA-DIGEST-001 | 4 |
| HMAC | IM-SRC-JAVA-MAC-001 | 3 |
| SHA1 | IM-SRC-SHA1-001 | 2 |
| MD5 | IM-SRC-MD5-001 | 2 |
| PRNG | IM-SRC-JAVA-WEAKRNG-001 | 1 |
Findings emitted for `xcrypto_ssh_algorithms`, by rule:

| rule | findings |
|---|---|
| AES | IM-GO-SSHTBL-AES | 6 |
| HMAC | IM-GO-SSHTBL-MAC | 6 |
| ChaCha20 | IM-GO-DECL-001 | 5 |
| ChaCha20 | IM-GO-CIPHER-003 | 4 |
| RC4 | IM-GO-SSHTBL-RC4 | 3 |
| AES | IM-GO-DECL-002 | 2 |
| Poly1305 | IM-GO-DECL-006 | 2 |
| SHA256 | IM-GO-IMPORT-003 | 2 |
| SHA256 | IM-GO-HASHBIND-001 | 2 |
| X25519 | IM-GO-DECL-005 | 2 |
| ECDH | IM-SRC-ECDH-001 | 2 |
| DES | IM-GO-CIPHER-001 | 1 |
| RC4 | IM-GO-CIPHER-002 | 1 |
| 3DES | IM-GO-SSHTBL-3DES | 1 |
| DES | IM-GO-IMPORT-005 | 1 |
| RC4 | IM-GO-IMPORT-006 | 1 |
| AES | IM-GO-IMPORT-007 | 1 |
| ChaCha20 | IM-GO-IMPORT-008 | 1 |
| 3DES | IM-GO-DECL-003 | 1 |
| RC4 | IM-GO-DECL-004 | 1 |
| ChaCha20 | IM-SRC-CHACHA-001 | 1 |
| SHA1 | IM-GO-HASH-002 | 1 |
| SHA1 | IM-GO-IMPORT-002 | 1 |
| SHA512 | IM-GO-IMPORT-010 | 1 |
| HMAC | IM-GO-IMPORT-004 | 1 |
| ML-KEM-768 | IM-GO-PQKEM-001 | 1 |
| X25519 | IM-GO-IMPORT-009 | 1 |
Findings emitted for `paramiko`, by rule:

| rule | findings |
|---|---|
| ECDSA | IM-SRC-SSH-SIG-001 | 30 |
| ECDH | IM-SRC-ECDH-001 | 22 |
| AES | IM-SRC-SSH-CIPHER-001 | 14 |
| RSA | IM-SRC-PYCA-RSA-001 | 13 |
| HMAC | IM-SRC-SSH-MAC-001 | 12 |
| ECDH | IM-SRC-SSH-KEX-001 | 11 |
| DH | IM-SRC-SSH-DH-001 | 10 |
| AES | IM-SRC-PYCA-AES-001 | 9 |
| SHA | IM-SRC-PYCA-HASH-001 | 7 |
| ECC | IM-SRC-PYCA-EC-001 | 7 |
| SHA256 | IM-SRC-HASHLIB-004 | 6 |
| RSA | IM-SRC-SSHNAME-002 | 6 |
| SHA1 | IM-SRC-HASHLIB-001 | 4 |
| ECC | IM-SRC-PYCA-ECTYPE-001 | 4 |
| Ed25519 | IM-SRC-SSH-ED-001 | 4 |
| MD5 | IM-SRC-SSH-MAC-002 | 4 |
| AES | IM-SRC-SSH-CIPHER-002 | 4 |
| HMAC | IM-SRC-SSHNAME-004 | 4 |
| SHA1 | IM-SRC-SHA1-001 | 3 |
| X25519 | IM-SRC-SSH-HYBRID-001 | 3 |
| Ed25519 | IM-SRC-EDDSA-001 | 3 |
| MD5 | IM-SRC-HASHLIB-003 | 3 |
| ECDSA | IM-SRC-SSHNAME-001 | 3 |
| ECDSA | IM-SRC-ECDSA-001 | 2 |
| Ed25519 | IM-SRC-SSHNAME-003 | 2 |
| SHA | IM-SRC-HASHLIB-002 | 2 |
| X25519 | IM-SRC-PYCA-X-001 | 2 |
| ECDH | IM-SRC-PYCA-ECDH-002 | 2 |
| AES | IM-SRC-JAVA-CONST-001 | 2 |
| ECDH | IM-SRC-SSHNAME-005 | 2 |
| 3DES | IM-SRC-SSH-LEGACY-001 | 2 |
| ECDH | IM-SRC-PYCA-ECDH-001 | 1 |
| Ed25519 | IM-SRC-PYCA-ED-001 | 1 |
| AES | IM-SRC-AES-001 | 1 |
| SHA256 | IM-SRC-SHA2-001 | 1 |
| MD5 | IM-SRC-MD5-001 | 1 |
| SHA1 | IM-SRC-SSH-HASH-NAME-001 | 1 |
## Explicit false positives -- `cryptoapi_bench`, L1 (1)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `src/main/java/org/cryptoapi/bench/untrustedprng/UntrustedPRNGCase1.java:9` | line was not a labelling candidate | PRNG | IM-SRC-JAVA-WEAKRNG-001 |

## Explicit false positives -- `cryptoapi_bench`, L2 (1)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `src/main/java/org/cryptoapi/bench/untrustedprng/UntrustedPRNGCase1.java:9` | line was not a labelling candidate | PRNG | IM-SRC-JAVA-WEAKRNG-001 |

## Explicit false positives -- `xcrypto_ssh_algorithms`, L1 (4)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `ssh/cipher.go:710` | poly1305.Verify operates on a MAC chosen at construction [variant L2] | Poly1305 | IM-GO-DECL-006 |
| `ssh/cipher.go:737` | line was not a labelling candidate | ChaCha20 | IM-GO-DECL-001 |
| `ssh/cipher.go:781` | poly1305.Sum operates on a MAC chosen at construction [variant L2] | Poly1305 | IM-GO-DECL-006 |
| `ssh/mlkem.go:34` | line was not a labelling candidate | ML-KEM-768 | IM-GO-PQKEM-001 |

## Explicit false positives -- `xcrypto_ssh_algorithms`, L2 (2)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `ssh/cipher.go:737` | line was not a labelling candidate | ChaCha20 | IM-GO-DECL-001 |
| `ssh/mlkem.go:34` | line was not a labelling candidate | ML-KEM-768 | IM-GO-PQKEM-001 |

## Explicit false positives -- `paramiko`, L1 (17)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001, IM-SRC-PYCA-ECDH-001 |
| `paramiko/kex_curve25519.py:37` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:112` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/pkey.py:128` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/pkey.py:134` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |

## Explicit false positives -- `paramiko`, L2 (17)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001, IM-SRC-PYCA-ECDH-001 |
| `paramiko/kex_curve25519.py:37` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:112` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/pkey.py:128` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/pkey.py:134` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |

## Explicit false negatives -- `cryptoapi_bench`, L1 (45)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:12` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:18` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:15` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:17` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:17` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:19` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:16` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:18` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:16` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:18` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:12` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:14` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:13` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:18` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:18` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:18` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:13` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:13` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:13` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:18` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:12` | SHA-1 (grover) | `crypto = new CryptoHash1("SHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:29` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:14` | MD5 (grover) | `crypto = new CryptoHash2("MD5");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:31` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:14` | MD4 (grover) | `crypto = new CryptoHash3("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:31` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:14` | MD2 (grover) | `crypto = new CryptoHash4("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:31` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:14` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:18` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:17` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:19` | AES (grover) | `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");` |

## Explicit false negatives -- `cryptoapi_bench`, L2 (158)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:12` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:18` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:15` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:17` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:17` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:19` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:20` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:16` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:18` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:16` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:18` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:12` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:14` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase7.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC5.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:32` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:35` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:32` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:35` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:13` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:18` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:18` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:18` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:13` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:13` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:13` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase5.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase6.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase7.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase8.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:18` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC1.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC2.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC3.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC4.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase1.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase2.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase3.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase4.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:12` | SHA-1 (grover) | `crypto = new CryptoHash1("SHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:29` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:30` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:14` | MD5 (grover) | `crypto = new CryptoHash2("MD5");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:31` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:14` | MD4 (grover) | `crypto = new CryptoHash3("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:31` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:14` | MD2 (grover) | `crypto = new CryptoHash4("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:31` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase1.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase2.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase3.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase4.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashCorrected.java:11` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:56` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,keySpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:57` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:14` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:18` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:35` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:25` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:25` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:24` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:32` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:26` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:21` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:24` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:56` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,keySpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:57` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:33` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:26` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:36` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:20` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:17` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:19` | AES (grover) | `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:27` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:50` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |

## Explicit false negatives -- `xcrypto_ssh_algorithms`, L1 (0)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

None.

## Explicit false negatives -- `xcrypto_ssh_algorithms`, L2 (0)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

None.

## Explicit false negatives -- `paramiko`, L1 (68)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `paramiko/__init__.py:70` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/__init__.py:71` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/__init__.py:115` | Ed25519 (shor) | `key_classes = [RSAKey, Ed25519Key, ECDSAKey]` |
| `paramiko/client.py:34` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/client.py:35` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/client.py:690` | ECDSA (shor) | `for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):` |
| `paramiko/client.py:730` | ECDSA (shor) | `(ECDSAKey, "ecdsa"),` |
| `paramiko/client.py:731` | Ed25519 (shor) | `(Ed25519Key, "ed25519"),` |
| `paramiko/ecdsakey.py:20` | ECDSA (shor) | `ECDSA keys` |
| `paramiko/ecdsakey.py:41` | ECDSA (shor) | `class _ECDSACurve:` |
| `paramiko/ecdsakey.py:43` | ECDSA (shor) | `Represents a specific ECDSA Curve (nistp256, nistp384, etc).` |
| `paramiko/ecdsakey.py:68` | ECDSA (shor) | `class _ECDSACurveSet:` |
| `paramiko/ecdsakey.py:70` | ECDSA (shor) | `A collection to hold the ECDSA curves. Allows querying by oid and by key` |
| `paramiko/ecdsakey.py:71` | ECDSA (shor) | `format identifier. The two ways in which ECDSAKey needs to be able to look` |
| `paramiko/ecdsakey.py:97` | ECDSA (shor) | `class ECDSAKey(PKey):` |
| `paramiko/ecdsakey.py:99` | ECDSA (shor) | `Representation of an ECDSA key which can be used to sign and verify SSH2` |
| `paramiko/ecdsakey.py:103` | ECDSA (shor) | `_ECDSA_CURVES = _ECDSACurveSet(` |
| `paramiko/ecdsakey.py:137` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(c_class)` |
| `paramiko/ecdsakey.py:149` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(` |
| `paramiko/ecdsakey.py:152` | ECDSA (shor) | `key_types = self._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:176` | ECDSA (shor) | `return cls._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:256` | ECDSA (shor) | `Generate a new private ECDSA key.  This factory function can be used to` |
| `paramiko/ecdsakey.py:260` | ECDSA (shor) | `:returns: A new private key (`.ECDSAKey`) object` |
| `paramiko/ecdsakey.py:263` | ECDSA (shor) | `curve = cls._ECDSA_CURVES.get_by_key_length(bits)` |
| `paramiko/ecdsakey.py:269` | ECDSA (shor) | `return ECDSAKey(vals=(private_key, private_key.public_key()))` |
| `paramiko/ecdsakey.py:302` | ECDSA (shor) | `curve = self._ECDSA_CURVES.get_by_key_format_identifier(name)` |
| `paramiko/ecdsakey.py:318` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(curve_class)` |
| `paramiko/ed25519key.py:30` | Ed25519 (shor) | `class Ed25519Key(PKey):` |
| `paramiko/ed25519key.py:32` | Ed25519 (shor) | `Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.` |
| `paramiko/ed25519key.py:35` | Ed25519 (shor) | `Ed25519 key support was added to OpenSSH in version 6.5.` |
| `paramiko/kex_curve25519.py:16` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_curve25519.py:17` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_curve25519.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:51` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:58` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:61` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_curve25519.py:63` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_curve25519.py:97` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:2` | ECDH (shor) | `Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange` |
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
| `paramiko/pkey.py:173` | ECDSA (shor) | `from paramiko import ECDSAKey, Ed25519Key, RSAKey` |
| `paramiko/pkey.py:215` | Ed25519 (shor) | `key_class = Ed25519Key` |
| `paramiko/pkey.py:217` | ECDSA (shor) | `key_class = ECDSAKey` |
| `paramiko/pkey.py:234` | Ed25519 (shor) | `For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``` |
| `paramiko/pkey.py:235` | Ed25519 (shor) | `will (if successful) return a new `.Ed25519Key`.` |
| `paramiko/pkey.py:238` | Ed25519 (shor) | `The key type, eg ``"ssh-ed25519"``.` |
| `paramiko/pkey.py:268` | ECDSA (shor) | `implementation suffices; see `.ECDSAKey` for one example of an` |
| `paramiko/pkey.py:338` | RSA (shor) | `example, ``"ssh-rsa"``).` |
| `paramiko/pkey.py:852` | ECDSA (shor) | `it was (e.g. ECDSA.)` |
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/util.py:149` | SHA256 (grover) | `as ``hashlib.sha256``.` |

## Explicit false negatives -- `paramiko`, L2 (87)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `paramiko/__init__.py:70` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/__init__.py:71` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/__init__.py:115` | Ed25519 (shor) | `key_classes = [RSAKey, Ed25519Key, ECDSAKey]` |
| `paramiko/client.py:34` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/client.py:35` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/client.py:690` | ECDSA (shor) | `for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):` |
| `paramiko/client.py:730` | ECDSA (shor) | `(ECDSAKey, "ecdsa"),` |
| `paramiko/client.py:731` | Ed25519 (shor) | `(Ed25519Key, "ed25519"),` |
| `paramiko/ecdsakey.py:20` | ECDSA (shor) | `ECDSA keys` |
| `paramiko/ecdsakey.py:41` | ECDSA (shor) | `class _ECDSACurve:` |
| `paramiko/ecdsakey.py:43` | ECDSA (shor) | `Represents a specific ECDSA Curve (nistp256, nistp384, etc).` |
| `paramiko/ecdsakey.py:68` | ECDSA (shor) | `class _ECDSACurveSet:` |
| `paramiko/ecdsakey.py:70` | ECDSA (shor) | `A collection to hold the ECDSA curves. Allows querying by oid and by key` |
| `paramiko/ecdsakey.py:71` | ECDSA (shor) | `format identifier. The two ways in which ECDSAKey needs to be able to look` |
| `paramiko/ecdsakey.py:97` | ECDSA (shor) | `class ECDSAKey(PKey):` |
| `paramiko/ecdsakey.py:99` | ECDSA (shor) | `Representation of an ECDSA key which can be used to sign and verify SSH2` |
| `paramiko/ecdsakey.py:103` | ECDSA (shor) | `_ECDSA_CURVES = _ECDSACurveSet(` |
| `paramiko/ecdsakey.py:137` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(c_class)` |
| `paramiko/ecdsakey.py:149` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(` |
| `paramiko/ecdsakey.py:152` | ECDSA (shor) | `key_types = self._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:176` | ECDSA (shor) | `return cls._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:256` | ECDSA (shor) | `Generate a new private ECDSA key.  This factory function can be used to` |
| `paramiko/ecdsakey.py:260` | ECDSA (shor) | `:returns: A new private key (`.ECDSAKey`) object` |
| `paramiko/ecdsakey.py:263` | ECDSA (shor) | `curve = cls._ECDSA_CURVES.get_by_key_length(bits)` |
| `paramiko/ecdsakey.py:269` | ECDSA (shor) | `return ECDSAKey(vals=(private_key, private_key.public_key()))` |
| `paramiko/ecdsakey.py:302` | ECDSA (shor) | `curve = self._ECDSA_CURVES.get_by_key_format_identifier(name)` |
| `paramiko/ecdsakey.py:318` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(curve_class)` |
| `paramiko/ed25519key.py:30` | Ed25519 (shor) | `class Ed25519Key(PKey):` |
| `paramiko/ed25519key.py:32` | Ed25519 (shor) | `Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.` |
| `paramiko/ed25519key.py:35` | Ed25519 (shor) | `Ed25519 key support was added to OpenSSH in version 6.5.` |
| `paramiko/kex_curve25519.py:16` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_curve25519.py:17` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_curve25519.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:51` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:58` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:61` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_curve25519.py:63` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_curve25519.py:90` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_curve25519.py:97` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:129` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_ecdh_nist.py:2` | ECDH (shor) | `Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange` |
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:91` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:137` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_gex.py:236` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_gex.py:278` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:117` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:141` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/kex_mlkem.py:141` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:160` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_mlkem.py:194` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:212` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
| `paramiko/pkey.py:173` | ECDSA (shor) | `from paramiko import ECDSAKey, Ed25519Key, RSAKey` |
| `paramiko/pkey.py:215` | Ed25519 (shor) | `key_class = Ed25519Key` |
| `paramiko/pkey.py:217` | ECDSA (shor) | `key_class = ECDSAKey` |
| `paramiko/pkey.py:234` | Ed25519 (shor) | `For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``` |
| `paramiko/pkey.py:235` | Ed25519 (shor) | `will (if successful) return a new `.Ed25519Key`.` |
| `paramiko/pkey.py:238` | Ed25519 (shor) | `The key type, eg ``"ssh-ed25519"``.` |
| `paramiko/pkey.py:268` | ECDSA (shor) | `implementation suffices; see `.ECDSAKey` for one example of an` |
| `paramiko/pkey.py:338` | RSA (shor) | `example, ``"ssh-rsa"``).` |
| `paramiko/pkey.py:403` | None (not-affected) | `b64ed = encodebytes(hashy.digest())` |
| `paramiko/pkey.py:852` | ECDSA (shor) | `it was (e.g. ECDSA.)` |
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/sftp_server.py:350` | None (not-affected) | `sum_out += hash_obj.digest()` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/transport.py:1896` | None (not-affected) | `out = sofar = hash_algo(m.asbytes()).digest()` |
| `paramiko/transport.py:1902` | None (not-affected) | `digest = hash_algo(m.asbytes()).digest()` |
| `paramiko/transport.py:1924` | None (not-affected) | `return cipher.encryptor()` |
| `paramiko/transport.py:1926` | None (not-affected) | `return cipher.decryptor()` |
| `paramiko/util.py:149` | SHA256 (grover) | `as ``hashlib.sha256``.` |
| `paramiko/util.py:166` | None (not-affected) | `digest = hash_obj.digest()` |


## Limitations, stated plainly

1. **The ground truth is ours, not the corpus authors'.** It was annotated by the author
   of this harness. Every label records its verbatim source line, and the harness re-reads
   each one from the pinned corpus and aborts on mismatch, so the label set is auditable
   and tamper-evident -- but it is still one annotator's judgement, with no second
   annotator and no inter-annotator agreement figure. We do not claim otherwise.
2. **CryptoAPI-Bench is a constructed benchmark.** Its 203 files are small, deliberately
   written Java micro-programmes, not production code. It is genuinely third-party and
   peer-reviewed, but it is not evidence about messy real-world code. `paramiko` is
   included precisely because it is real production code.
3. **The L1 criterion favours the tool.** Operation lines (`cipher.init`, `.digest()`) are
   excluded from L1 and included in L2. L2 is the lower bound on recall; read it before
   quoting a recall number.
4. **IndraMesh was run with `enable_ml=False`.** The optional PyTorch classifier is therefore
   absent from these numbers, and `dl_confidence` is not populated. This is deliberate: the
   benchmark must be hermetic and reproducible on a machine with no model file.
5. **Regex-rule coverage is the whole story here.** Every number above is a measurement of
   the hand-written rule table plus primitive naming. Nothing in this benchmark validates
   the CBOM, the Mosca arithmetic, or the recommender.
6. **Line-level matching is strict.** A finding one line away from a labelled positive is a
   false positive AND that positive is a false negative. The file-level table is given as
   a coarser cross-check for exactly that reason.

