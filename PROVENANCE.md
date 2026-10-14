# Provenance and Originality Statement

**SIH26164 · IndraMesh · Enterprise Cryptographic Discovery & Analysis Tool (v2.4 PQC)**

This document exists to answer one question unambiguously: **what in this repository is ours?**

---

## 1. The Short Answer

**All executable code in `engine/`, `app.py`, `cli.py`, `cli_advanced.py`, `cli_certificates.py`, `benchmark/`, and `tests/` was written from first principles for this project.** No third-party source code was copied, vendored, or adapted from any competitor or external proprietary tool.

---

## 2. Standards Consulted and Mathematical Formalisms

Public standards and academic literature were studied, as any engineering team would. We maintain a strict boundary between **reading an open specification** and **taking code**:

| Standard / Literature | Authority / Source | What Was Taken & How It Was Used |
|---|---|---|
| **CycloneDX 1.7 Specification** | ECMA / OWASP published standard | The **vocabulary** (`cryptoProperties`, `primitive`, `nistQuantumSecurityLevel`, `assetType`). The official JSON Schema (`schemas/bom-1.7.schema.json`) is vendored directly from the official CycloneDX release, unmodified, and verified offline. |
| **NIST Post-Quantum Standards** | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 (FN-DSA / Falcon), SP 800-52r2, IR 8547 | **Normative parameters, key lengths, security categories (Levels 1–5), and algorithm identifiers.** These are mathematical constants and protocol specifications, implemented in `engine/verify_migration.py` and `engine/recommender.py`. |
| **Mosca's Theorem & Risk Horizons** | Dr. Michele Mosca (Univ. of Waterloo), GRI / evolutionQ surveys | The **inequality ($X + Y > Z$)** and quantum arrival projections. We extended this with **Empirical Velocity $Y$** calibrated against historical enterprise migrations (SHA-1, TLS 1.0) and **Zero-Slack ($0.0\text{y}$) Boundary Flagging** in `engine/mosca.py`. |
| **IETF RFC Specifications** | RFC 8446 (TLS 1.3), RFC 5280 (X.509 PKI), RFC 4253 (SSH Transport Layer) | Protocol state machine definitions, ASN.1 KeyUsage / ExtendedKeyUsage bitmask mappings, and hybrid post-quantum named group identifiers (e.g. `X25519MLKEM768`), implemented independently in `engine/netprobe.py` and `engine/certificates.py`. |

All architectural modules — including the dual-axis assurance taxonomy, the runtime resolution engine, the empirical Mosca horizon calculator, and the 5-sensor mesh — were designed and implemented independently with our own signatures, type systems, error handlers, and test coverage.

---

## 3. Current Architectural Milestones (Post-1,000+ Tests)

The repository reflects the following verified milestones:
1. **145 Detection Rules across 9 Languages:** Curated patterns covering Python, Java, Go, Rust, C/C++, JavaScript/TypeScript, C#, PHP, and Ruby (`engine/scanner.py`), accompanied by byte-offset-preserving comment and docstring blanking.
2. **5-Sensor Discovery Mesh:** Full integration of Source, Dependency Manifests (9 ecosystems), X.509 Certificates, Container archives, and live Network TLS/SSH probes (`engine/netprobe.py`, `engine/netpolicy.py`).
3. **1,034 Automated Tests Passing with 0 Regressions:** Comprehensive test suite spanning unit tests, property-based Hypothesis fuzzing, contract tests, and API validation.
4. **100% Mutation Test Kill Rate (19/19):** `mutation_test.py` injects deliberate AST and behavioural faults across core engines, ensuring the test suite actively detects subtle cryptographic bugs.
5. **Air-Gapped, Zero-CDN Web Console & API:** High-performance FastAPI server (`app.py`) on port 8501 providing a local cyber console, self-contained printable HTML/JSON reports, and live Mosca parameter re-ranking without external web requests.

---

## 4. Third-Party Code in the Working Tree: Corpora vs. Engine

`benchmark/corpora/` contains **cloned upstream open-source repositories used exclusively as benchmark measurement inputs**:

| Corpus | Licence | Role |
|---|---|---|
| **CryptoAPI-Bench** | Apache 2.0 / MIT | Benchmark measurement input (Java cryptographic API test cases) |
| **paramiko** | LGPL-2.1 | Benchmark measurement input (Python SSH implementation) |
| **golang.org/x/crypto** | BSD-3-Clause | Benchmark measurement input (Go standard cryptographic library slice) |

- **Excluded from Version Control:** All cloned corpora are excluded via `.gitignore` and have **never been committed to git history** (verified with `git log --all -- benchmark/corpora`, which returns empty).
- **Read as Data Only:** Nothing in `engine/`, `app.py`, or `cli.py` imports from or links against these repositories. They are scanned purely as raw input files during benchmark execution.
- **Reproducible Harness:** `benchmark/run_benchmark.py` fetches pinned commit SHAs on demand, ensuring accuracy benchmarks are reproducible without redistributing external source trees.

---

## 5. Third-Party Runtime Dependencies

All external libraries are standard, audited open-source packages declared in `requirements.txt` and installed from PyPI:
- `fastapi`, `uvicorn`, `starlette` (Web console and REST API)
- `jsonschema` (Offline validation of CycloneDX 1.7 JSON schemas)
- `cryptography`, `pyOpenSSL` (X.509 certificate and cryptographic structure parsing)
- `pytest`, `hypothesis` (Testing, property verification, and fuzzing)
- `torch`, `scikit-learn`, `numpy` (Optional AST depth and machine learning classifier in `engine/ml/`)

---

## 6. How to Verify Every Claim on This Page

```powershell
# 1. Verify that no external benchmark corpora are tracked in git
git log --all --oneline -- benchmark/corpora      # must return empty
git ls-files benchmark/corpora                     # must return empty

# 2. Verify clean imports: our code imports only stdlib and declared dependencies
Select-String -Path engine\*.py,app.py,cli.py,cli_advanced.py -Pattern '^\s*(from|import)\s+\S+'

# 3. Verify the complete 1,000+ test suite
python -m pytest tests -q                         # 1,034 tests collected, 0 failures

# 4. Verify fault detection via mutation testing
python mutation_test.py                           # 19/19 mutants caught and killed

# 5. Verify the air-gapped Web Console & REST API
python validate_gui.py                            # 10/10 automated tests pass
```

---

## 7. Statement of Integrity

IndraMesh was developed as an honest, defensible, production-grade post-quantum discovery platform for the Smart India Hackathon 2026. Where industry insights highlighted systemic shortcomings in existing ACDI tools (such as treating ambiguous runtime calls as closed static hits, or ignoring empirical migration velocity), we responded by researching the underlying mathematics and engineering robust, clean-room solutions from zero.
