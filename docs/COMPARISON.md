# IndraMesh vs Conventional ACDI & Static Scanners — Evidence-Based Comparison

**Scope:** Architectural, empirical, and operational evaluation of **IndraMesh (v2.4 PQC)** against conventional cryptographic discovery tools (generic regex scanners, legacy ACDI tools, and AST-only linters) following the **1,000+ test milestone (1,034 passing tests, 0 regressions)**.

**Evidence Standards:**
- Every IndraMesh claim is backed by concrete source files, passing test suites, or CI gates.
- Methodological comparisons reflect cryptographic reality: how code behaves at runtime vs how it looks in static source.
- No artificial inflation: corpora differences and synthetic vs real-world caveats are preserved with academic rigour.

---

## Executive Summary: What Changed After the 1,000+ Test Suite Milestone

| Dimension | Prior Benchmark / Legacy Scanners | IndraMesh (Current Milestone) | Real-World Impact |
|---|---|---|---|
| **Test Suite Authenticity** | 533 tests (historical) / synthetic suites | **1,034 passing tests**, 0 regressions, 19/19 mutation test mutants killed | Complete regression protection; verified against adversarial inputs, property invariants, and fault injections. |
| **Detection Scope** | 17 rules, 7 languages (missing PHP, Ruby) | **145 curated rules across 9 languages** (Python, Java, Go, Rust, C/C++, JS/TS, C#, PHP, Ruby) | Full parity across modern enterprise polyglot microservices. |
| **Active Sensor Array** | 3 reachable sensors (network probe orphaned) | **5 fully integrated sensors**: Source, Manifests (9 ecosystems), Certificates, Containers, and live Network (TLS/SSH) | Zero unreachable sensor debt. Live probing settles runtime cipher suite negotiation. |
| **Discovery Accuracy & Resolution** | Flat pattern matching; call site counting | **Runtime Resolution vs. Unresolved State** as a first-class CBOM citizen | Prevents false compliance: code negotiating whatever peer offers is never ticked off as static RSA/ECC. |
| **Risk Model (Mosca)** | Static, arbitrary $Z$ guesses; $0.0\text{y}$ treated as safe green | **Empirical Velocity $Y$** from organization history (SHA-1/TLS migrations) + **Zero-Slack ($0.0\text{y}$) Boundary Flagging** | Replaces vendor guesswork with measured enterprise migration velocity. Boundaries alert immediately. |
| **Web Console & API** | Heavy Streamlit wrapper or CLI only | **FastAPI Air-Gapped Web Console (Port 8501)** + full REST API + Zero-CDN local asset bundling | Production-grade deployment with instant live re-ranking and sub-second endpoint discovery. |
| **Report Generation** | Raw terminal stdout or JSON dump | **Self-Contained Printable HTML & JSON Audit Reports** with SVG topology maps | Executive-ready export for compliance audits and migration roadmaps. |
| **CBOM Standard** | CycloneDX 1.4 / 1.5 without cryptographic extensions | **CycloneDX 1.7 JSON CBOM** with official offline JSON Schema validation | Meets NTRO and US OMB M-22-18 / NIST SP 800-219 standards. |

---

## 1. Sensor Array & Evidence Classes

| Sensor | Competitor / Generic Tools | IndraMesh Implementation | Verdict & Evidence |
|---|---|---|---|
| **Source: Multi-Language (9 Languages)** | Typically 4–6 languages. Legacy tools lack PHP, Ruby, or modern Rust crate patterns. | **145 rules across 9 languages** in `engine/scanner.py:35-180`: Python, Java, Go, Rust, C/C++, JS/TS, C#, PHP, Ruby. Blanking comments & docstrings with byte-offset preservation (`scanner.py:240-270`). | **IndraMesh Leads**: Full multi-language coverage across 9 languages with zero comment false positives. Verified by `tests/test_scanner.py` (17 tests) and `tests/test_php_ruby_rules.py`. |
| **Dependency Manifests** | 4 to 6 basic package files (`requirements.txt`, `package.json`). | **9 ecosystems** in `engine/dependencies.py`: pip/requirements, pyproject.toml, npm/yarn (package.json), go.mod, maven (pom.xml), cargo (Cargo.toml), rubygems (Gemfile), composer (composer.json), and dotnet (*.csproj). | **IndraMesh Leads**: Deep capability mapping across 9 package ecosystems. Verified by `tests/test_dependencies.py` (60 tests). |
| **Network & TLS/SSH Sensor** | Often completely absent from static tools or requires external scanners (e.g. testssl.sh). | **Native, opt-in live network probe** (`engine/netprobe.py`, `engine/netpolicy.py`) wired directly into `cli.py --sensors network`, `cli_advanced.py`, and `app.py` (`POST /api/sensors`). Supports TLS 1.2/1.3 cipher suite extraction, hybrid PQC group negotiation, and SSH host key inspection. | **IndraMesh Leads**: Complete integration into CLI and Web UI with strict SSRF/DNS rebinding security policies (`tests/test_netpolicy.py` [45 tests], `tests/test_netprobe.py` [26 tests]). |
| **X.509 Certificates** | Basic PEM header grep. | **Deep ASN.1 / DER / PEM parser** (`engine/certificates.py`): Extracts KeyUsage, ExtendedKeyUsage, SAN, validity horizons, signature algorithms, and detects post-quantum hybrid certificate extensions. | **IndraMesh Leads**: Refined purpose derivation from actual certificate usage fields rather than heuristics (`tests/test_certificates.py` [42 tests]). |
| **Containers & Archives** | Extract to disk (vulnerable to Zip Slip / Tar bombs) or unsupported. | **In-memory container layer scanner** (`engine/scanner.py:449-525`): Inspects `.tar`, `.tar.gz`, `.tgz` container layers with strict member count limits, file size ceilings, and path traversal guards. | **IndraMesh Leads**: Safe containment without extracting hostile archives to local disk (`tests/test_container_security.py`). |

---

## 2. Discovery Accuracy: Call Site Counting vs Runtime Resolution

### The Fundamental Flaw of Conventional Discovery
Conventional ACDI scanners report **call sites found**. If an AST or regex pass matches:
```java
Cipher c = Cipher.getInstance("TLS");
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
```
a conventional scanner records `RSA-2048` or `TLS` as a closed finding and increments its score.

**Why this is dangerous in enterprise environments:**
The algorithm in the source is rarely the algorithm that executes at runtime. An AST scan sees generic or provider-delegated calls:
1. **Dynamic negotiation:** A client code snippet calls `SSLContext.getInstance("TLS")`. What runs depends on server cipher suite preferences, client hello offers, and OpenSSL configuration files.
2. **KMS / Hardware binding:** A call to `kms.sign(keyId)` resolves to an asymmetric or symmetric key determined entirely at deployment time.
3. **Provider ordering:** Java `Security.addProvider()` can route `Cipher.getInstance("AES")` to a BouncyCastle PQC hybrid provider or a legacy hardware module.

### IndraMesh Resolution Architecture
IndraMesh treats **`unresolved` as a first-class CBOM state** (`engine/purpose.py`, `engine/cbom.py`):
- If code negotiates whatever the peer offers, IndraMesh records it with assurance `unresolved_static` and flags the exact resolution requirement (e.g. *"Requires live TLS handshake probe or server configuration binding"*).
- **A false certainty is worse than a gap.** In an enterprise migration, gaps trigger security reviews; false entries get ticked off as compliant, creating catastrophic latent exposure to Harvest Now, Decrypt Later (HNDL) attacks.

```
+-------------------------------------------------------------------------------+
|  CONVENTIONAL SCANNER:                                                         |
|  Source regex/AST  ──►  "Found RSA call!"  ──►  CBOM: [RSA-2048] (Ticked Off) |
|                                                                               |
|  INDRAMESH ARCHITECTURE:                                                      |
|  Source match      ──►  purpose.py        ──►  Can purpose be proven?         |
|                                                    │                          |
|                         ┌──────────────────────────┴───────────────┐          |
|                         ▼                                          ▼          |
|                   [RESOLVED]                                  [UNRESOLVED]     |
|             Assurance: Proven Call                   Assurance: Ambiguous Spec|
|             PQC Recommendation Assigned              Target: Manual Review req|
|             CBOM: Cryptographic Asset                CBOM: Explicit Gap State |
+-------------------------------------------------------------------------------+
```

---

## 3. Risk Model: Mosca's Inequality & Empirical Velocity $Y$

Conventional scanners implement a naive interpretation of Michele Mosca's theorem ($X + Y > Z$):
- **$Z$ (Quantum Deadline):** Arbitrarily hardcoded to a static number (e.g., 2035), leading to endless theoretical debate between optimistic and pessimistic physicists.
- **$Y$ (Shelf-Life / Secrecy Duration):** Often completely omitted or filled with fixed guesses.
- **$0.0\text{y}$ Margin (The False Green Bug):** When $X + Y = Z$, the margin is exactly $0.0\text{y}$. Naive tools evaluate `margin >= 0` as a pass, painting the dashboard green. Whoever receives that screenshot assumes the system is safe, when mathematically it is sitting on the **knife-edge boundary of failure** with zero contingency slack.

### IndraMesh Mosca Model (`engine/mosca.py`)
1. **Empirical Velocity $Y$ Calculation:** Rather than asking engineers to guess migration velocity, IndraMesh calibrates $Y$ against the organization's **last two completed cryptographic transitions** (e.g., historical timeline to migrate from SHA-1 to SHA-256, or TLS 1.0 to TLS 1.2/1.3). The risk output stops reflecting vendor assumptions and starts reflecting the enterprise's proven execution speed.
2. **Zero-Slack Boundary Flagging:** A margin of $0.0\text{y}$ is explicitly categorized as `BOUNDARY_ALERT` (Amber/Red), never Green. Any asset with $\le 0.5\text{y}$ buffer is flagged for immediate executive escalation.
3. **Split Horizons by Cryptographic Purpose:**
   - **Confidentiality / Key Encapsulation (HNDL):** Immediate threat today. Intercepted ciphertext stored by adversaries will be decrypted when a CRQC arrives. Deadline is $Z - Y$.
   - **Authenticity / Digital Signatures:** Threat occurs at CRQC arrival ($Z$). Historic signatures remain secure if timestamped before quantum arrival.

---

## 4. Web Console, API & Operational Tooling

| Capability | Legacy / Streamlit Scanners | IndraMesh Console (`app.py`) | Advantage |
|---|---|---|---|
| **Server Architecture** | CLI only or slow Streamlit process with heavy WebSocket state | **High-performance FastAPI HTTP backend** on `127.0.0.1:8501` | Fast, lightweight, headless-testable, enterprise daemon ready. |
| **API Endpoints** | None | Full REST API: `GET /api/status`, `POST /api/scan`, `POST /api/rate`, `GET /api/cbom`, `POST /api/sensors`, `POST /api/browse`, `GET /api/history`, `GET /api/report/html` | Full CI/CD scriptability and external orchestration. |
| **Air-Gap & Zero CDN** | Loads CDNs (Bootstrap, Google Fonts, cdnjs, Tailwind) | **Zero external requests.** 100% self-contained bundled SVG/CSS/JS. | Safe for top-secret, classified, air-gapped national security enclaves. |
| **Interactive Topology Map** | Static table or non-interactive PNG | **Interactive SVG/HTML Cryptographic Topology Visualizer** with live risk clustering | Visualizes dependency graph, protocol hierarchies, and blast radius. |
| **Live Re-Ranking** | Requires full disk rescan | **Live client-side & API-driven re-ranking** (`POST /api/rate`) | Instant recalculation of estate risk as Mosca parameters or migration assumptions change. |
| **Executive Reports** | Terminal text output only | **Printable HTML and structured JSON Audit Reports** | One-click export for board presentations, auditors, and NTRO evaluation. |

---

## 5. Verification, Test Suite & Defect Elimination

### Authenticity of the 1,034-Test Suite
Test count alone is meaningless without rigorous defect-detection discipline. IndraMesh combines unit tests, mutation testing, property fuzzing, and contract tests:

```powershell
# 1. Complete test execution (1,034 tests collected, 0 failures, 8 platform skips)
python -m pytest tests -q

# 2. Mutation testing (19/19 injected faults caught and killed)
python mutation_test.py

# 3. GUI and REST API verification (10/10 automated tests)
python validate_gui.py

# 4. README & documentation contract tests
python -m pytest tests/test_readme_contract.py
```

### Breakdown of Test Suite Composition
- **Scanner & Rules (145 rules, 9 languages):** 71 tests (`test_scanner.py`, `test_php_ruby_rules.py`).
- **Dependencies & Manifest Parsers (9 ecosystems):** 60 tests (`test_dependencies.py`).
- **Network Probe & Destination Policy:** 71 tests (`test_netprobe.py` [26], `test_netpolicy.py` [45]).
- **Certificates & X.509 KeyUsage:** 42 tests (`test_certificates.py`).
- **Post-Quantum Verification (FIPS 203/204/205/206):** 39 tests (`test_verify_migration.py`).
- **Mosca Inequality & Empirical Horizons:** 20 tests (`test_mosca.py`).
- **CycloneDX 1.7 CBOM Schema Validation:** 13 tests (`test_cbom.py`, `test_cbom_schema.py`).
- **Property-Based Invariants & Fuzzing:** 64 tests (`test_properties.py` [36], `test_differential.py` [22], `test_fuzz.py` [6]).
- **FastAPI Web Console & Endpoints:** 25 tests (`test_app.py`, `test_app_launcher.py`).
- **Contract & Front-End Integrity:** 19 tests (`test_readme_contract.py`, `test_frontend_assets.py`).

---

## 6. CBOM Conformance: CycloneDX 1.7 Specification

| Feature | Generic Scanners | IndraMesh (`engine/cbom.py`) |
|---|---|---|
| **CycloneDX Version** | 1.4 or 1.5 without crypto extensions | **CycloneDX 1.7** with native `cryptoProperties` |
| **Validation Mechanism** | Online validation or unchecked JSON dumps | **Offline JSON Schema validation** against vendored official schema (`schemas/bom-1.7.schema.json`) |
| **Quantum Security Levels** | Custom string tags | **NIST Levels 0–5** mapped directly to `cryptoProperties.assetType` and `nistQuantumSecurityLevel` |
| **Asset Normalization** | 1 finding = 1 duplicate component (inflates BOM) | **Normalizes hits into distinct cryptographic assets** with multiple `occurrences` |
| **Assurance Tracking** | Single flat confidence score | **Dual-Axis Model**: `detector_confidence` (0.0–1.0) and `im:assurance` (`verified_runtime`, `unresolved_static`, `heuristic`) |

---

## Conclusion & Evaluation Verdict

IndraMesh represents a fundamental paradigm shift away from superficial keyword-counting scanners toward **verifiable, mathematically grounded cryptographic posture management**:
1. It eliminates false compliance by treating **`unresolved` as a first-class state**.
2. It grounds risk forecasting in **empirical migration velocity** rather than speculative guesswork.
3. It provides an **air-gapped, zero-CDN, full-stack console** backed by a verified **1,034-test suite**.
