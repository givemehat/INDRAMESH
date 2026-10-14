# IndraMesh vs Conventional State-of-the-Art ACDI — Evidence-Based Architectural Comparison

**Scope:** Architectural, empirical, and operational evaluation of **IndraMesh (v2.4 PQC)** against the **Conventional Reference ACDI Architecture** (the leading state-of-the-art AST-driven CBOM scanner) following IndraMesh's **1,000+ test suite milestone (1,034 passing tests, 0 regressions)**.

**Naming Convention:**
Throughout this document, the leading peer project is referred to objectively by its architectural archetype: the **Conventional Reference ACDI Scanner** (or *Reference Implementation*). Neither project is obscured, and all comparative claims cite concrete source files, passing test suites, or published specifications.

**Evidence Standards:**
- Every IndraMesh capability is verified by source files (`engine/*.py`, `app.py`, `cli.py`), dedicated pytest suites, and automated verification scripts.
- Every claim regarding the Conventional Reference Architecture is cited directly from its published design documentation and codebase specifications.
- Areas where IndraMesh leads, where the tools are tied, and where the Reference Architecture maintains an advantage are stated with equal candour and technical rigour.

---

## 1. Executive Scorecard: Ahead, Tied, and Behind

| Evaluation Area | Status | Key Differentiator | Evidence / Source |
|---|---|---|---|
| **Test Verification & Defect Elimination** | **IndraMesh Ahead** | **1,034 passing tests** (1,042 collected) + **100% mutation test kill rate** (19/19) + Hypothesis fuzzing vs. 664 unit/regression tests. | `mutation_test.py`, `tests/test_properties.py`, `tests/test_differential.py` |
| **Discovery Accuracy & Resolution** | **IndraMesh Ahead** | **Runtime Resolution vs. Unresolved State** as a first-class CBOM citizen. Resolves dynamic provider/TLS negotiation instead of counting misleading static call sites. | `engine/purpose.py`, `engine/cbom.py`, Section 2 of this guide |
| **Mosca Risk Modeling** | **IndraMesh Ahead** | **Empirical Velocity $Y$** derived from real enterprise migration history (SHA-1, TLS 1.0) + **Zero-Slack ($0.0\text{y}$) Boundary Flagging**. Naive tools misreport $0.0\text{y}$ margin as green/safe. | `engine/mosca.py`, `tests/test_mosca.py` |
| **Language Coverage & Detection Rules** | **IndraMesh Ahead** | **145 rules across 9 full languages** (Python, Java, Go, Rust, C/C++, JS/TS, C#, PHP, Ruby) with comment blanking & offset preservation. | `engine/scanner.py:35-180`, `tests/test_scanner.py` |
| **Interactive Topology & Dynamic Re-Ranking** | **IndraMesh Ahead** | Dynamic sub-second estate re-ranking (`POST /api/rate`) + interactive SVG/HTML cryptographic topology visualizer. | `engine/graph.py`, `app.py`, `validate_gui.py` |
| **X.509 Certificate Sensor** | **Tied** | Both feature deep ASN.1 / DER / PEM parsing for KeyUsage, ExtendedKeyUsage, and PQC hybrid certificates. | `engine/certificates.py`, `tests/test_certificates.py` (42 tests) |
| **Live Network TLS/SSH Sensor** | **Tied** | Both feature native, opt-in TLS 1.2/1.3 and SSH probing with strict SSRF/DNS rebinding destination policies. | `engine/netprobe.py` (26 tests), `engine/netpolicy.py` (45 tests) |
| **Served Air-Gapped Web Console & API** | **Tied** | Both run FastAPI on loopback with zero-CDN local asset bundling, strict bind guards, and REST APIs. | `app.py` (port 8501), `tests/test_app_launcher.py` |
| **Printable Audit Report Generation** | **Tied** | Both generate self-contained, offline printable HTML & JSON reports for compliance audits. | `GET /api/report/html`, `GET /api/report/download` |
| **CycloneDX 1.7 CBOM Conformance** | **Tied** | Both emit CycloneDX CBOMs with `cryptoProperties` validated offline against official JSON schemas. | `engine/cbom.py`, `schemas/bom-1.7.schema.json` |
| **Binary Symbol Analysis** | **Reference Ahead** | Reference architecture parses ELF symbol tables and version banners; IndraMesh uses binary strings, constants, and byte markers. | `engine/scanner.py:101-140` |
| **Risk Input Persistence Across Rescans** | **Reference Ahead** | Reference architecture stores operator overrides in SQLite across rescans; IndraMesh persists overrides in-memory per session. | Architectural comparison |
| **Packaged Submission Media Assets** | **Reference Ahead** | Reference architecture bundles pre-rendered MP4 walkthrough videos and PPTX slide decks; IndraMesh is code- and document-first. | Submission asset inventory |

---

## 2. Discovery Accuracy: Call Site Counting vs Runtime Resolution

### The "Call Site Counting" Fallacy
A core architectural debate in Automated Cryptographic Discovery and Inventory (ACDI) is how to report cryptographic usage. Conventional AST-driven tools focus on **call site extraction**: if an AST or regex pass discovers:
```java
Cipher c = Cipher.getInstance("TLS");
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
```
the conventional scanner marks `RSA-2048` or `TLS` as a closed, discovered finding and counts it toward its accuracy totals.

**Why this creates severe enterprise vulnerability:**
The cryptographic primitive in the source code is rarely the primitive that executes in production:
1. **Dynamic Negotiation:** A client code snippet calls `SSLContext.getInstance("TLS")`. What executes over the wire is determined by the server's cipher suite preferences, negotiated TLS 1.3 extensions, and the underlying OpenSSL provider.
2. **KMS & HSM Bindings:** A call to `kms.sign(keyId)` resolves to an asymmetric or symmetric algorithm determined at deployment time via IAM policy or hardware specs.
3. **Provider Ordering:** Java `Security.addProvider()` can route generic calls to a BouncyCastle PQC hybrid provider or a legacy hardware module.

A CBOM recording a static algorithm (e.g. `RSA-2048`) where the runtime code negotiates whatever the peer offers is **far worse than a gap**. Gaps get investigated by security engineers; false entries get ticked off as compliant, creating catastrophic exposure to Harvest Now, Decrypt Later (HNDL) attacks.

### IndraMesh Runtime Resolution Architecture
IndraMesh establishes **`unresolved` as a first-class CBOM state** (`engine/purpose.py`, `engine/cbom.py`):
- When source analysis encounters dynamic or ambiguous invocations, IndraMesh categorizes them under assurance `unresolved_static`.
- The CBOM explicitly records the item as an open question and specifies the exact requirement for resolution (e.g., *"Requires live TLS handshake probe or server configuration binding"*).
- Only when corroborated by runtime evidence (e.g., live network handshake via `engine/netprobe.py`) does the item graduate to `verified_runtime`.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ CONVENTIONAL AST SCANNER:                                                     │
│ Source AST Match ──► "Found RSA call!" ──► CBOM: [RSA-2048] (Ticked Off)      │
│                                                                               │
│ INDRAMESH ACCURACY ARCHITECTURE:                                              │
│ Source Match     ──► purpose.py        ──► Can concrete primitive be proven?  │
│                                                  │                            │
│                      ┌───────────────────────────┴───────────────┐            │
│                      ▼                                           ▼            │
│                [RESOLVED]                                  [UNRESOLVED]       │
│          Assurance: Proven Call                   Assurance: Ambiguous Spec   │
│          PQC Target Assigned                      Target: Manual Review Req   │
│          CBOM: Validated Asset                    CBOM: Explicit Gap State    │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Risk Modeling: Mosca's Inequality & Empirical Velocity $Y$

Both platforms implement Michele Mosca's theorem ($X + Y > Z$), which dictates that migration must begin before migration time ($X$) plus secrecy shelf-life ($Y$) exceeds the arrival of a Cryptographically Relevant Quantum Computer ($Z$).

### The Knife-Edge Failure Bug ($0.0\text{y}$ Margin)
In conventional implementations, margin is computed as:
$$\text{Margin} = Z - (X + Y)$$
When an asset has $X + Y = Z$, the margin evaluates to exactly $0.0\text{y}$.
- **Conventional Flaw:** Naive scanners evaluate `margin >= 0` as a pass, painting the dashboard green. An executive receiving that screenshot assumes the asset is safe, when mathematically it sits on the knife-edge boundary of failure with zero contingency buffer.
- **IndraMesh Boundary Flagging (`engine/mosca.py`):** IndraMesh explicitly tags a $0.0\text{y}$ margin as `BOUNDARY_ALERT` (Amber/Red). Any asset with $\le 0.5\text{y}$ buffer is flagged for immediate executive escalation.

### Empirical Velocity $Y$ vs Arbitrary Guesswork
- **Conventional Reference:** Models $Z$ as a triangular distribution over (earliest, likely, latest) years, but relies on static operator estimates for migration duration $X$ and secrecy shelf-life $Y$.
- **IndraMesh Innovation:** IndraMesh calibrates migration velocity empirically from the organization's **last two completed cryptographic transitions** (e.g., historical timelines to migrate from SHA-1 to SHA-256, or TLS 1.0 to TLS 1.2/1.3). This ensures the risk calculation stops reflecting arbitrary vendor assumptions and directly measures the organization's proven operational velocity.

---

## 4. Detailed Sensor-by-Sensor Comparison

### 4.1 Source Code Scanning
- **Conventional Reference:** Python AST analysis with parameter extraction (`key_size=1024`), plus curated rule packs for C/C++, C#, Go, Java, JS, PHP, Ruby. Swift and Rust handled only by basic language-agnostic rules.
- **IndraMesh:** **145 curated rules across 9 full languages** in `engine/scanner.py`, including first-class Rust crates (`ring`, `ed25519-dalek`, `rsa`, `pqcrypto`), PHP (`openssl_*`, `sodium_*`), Ruby (`OpenSSL::Cipher`, `OpenSSL::PKey`), Go, Java, C/C++, C#, Python, and JS/TS.
- **Comment Handling:** IndraMesh blanks comments and docstrings with byte-offset preservation (`scanner.py:240-270`), preventing documentation samples from triggering false alarms while keeping reported line numbers exact.
- **Verdict:** IndraMesh leads on total rule count (145), language breadth (9 full languages with first-class Rust), and comment blanking integrity.

### 4.2 Dependency Manifests
- **Conventional Reference:** 13 manifest formats reported in documentation.
- **IndraMesh:** **9 ecosystems** in `engine/dependencies.py`: pip (`requirements.txt`, `setup.py`), `pyproject.toml`, npm/yarn (`package.json`), go.mod, maven (`pom.xml`), cargo (`Cargo.toml`), rubygems (`Gemfile`), composer (`composer.json`), and dotnet (`*.csproj`).
- **Verdict:** Competitive parity across all major enterprise package management ecosystems, backed by 60 dedicated unit tests.

### 4.3 Live Network TLS & SSH Sensor
- **Conventional Reference:** Native TLS probing including hybrid PQC group negotiation (`X25519MLKEM768`).
- **IndraMesh:** Native, opt-in network probing in `engine/netprobe.py` and destination safety policy in `engine/netpolicy.py`. Wired into `cli.py --sensors network`, `cli_advanced.py`, and the FastAPI Web Console (`POST /api/sensors`).
- **Network Safety Policy:** Bounded timeout, loopback/private IP filtering, DNS rebinding guards, and SSRF prevention.
- **Verdict:** Tied. Both platforms provide fully integrated live network probing with cryptographic group negotiation.

### 4.4 Binary Analysis
- **Conventional Reference:** Parses ELF symbol tables, cryptographic constant matching, and version banners.
- **IndraMesh:** Uses binary printable string extraction, cryptographic magic constants, and version string matching (`engine/scanner.py:101-140`).
- **Verdict:** The Conventional Reference maintains an advantage in ELF symbol table parsing. IndraMesh provides platform-agnostic constant matching across ELF, PE, and Mach-O binaries.

### 4.5 Container Inspection
- **Conventional Reference:** OCI layout tar inspection with layer replay and whiteout handling (`.wh.`).
- **IndraMesh:** In-memory multi-layer tar archive scanner (`engine/scanner.py:449-525`) with strict path traversal prevention (anti-Zip Slip), member count limits (max 5,000 files), and decompression size ceilings (max 25 MB per member).
- **Verdict:** The Reference tool provides layer replay; IndraMesh prioritizes strict memory and containment safety without extracting untrusted archives to disk.

---

## 5. Web Console, API & Report Generation

| Architectural Component | Conventional Reference | IndraMesh Console (`app.py`) | Verdict |
|---|---|---|---|
| **Server Engine** | FastAPI on `127.0.0.1:8000` | FastAPI on `127.0.0.1:8501` | **Tied** (Production-grade ASGI) |
| **Air-Gap & CDN Assets** | Vanilla JS, 0 CDN assets | Bundled CSS/SVG/JS, 0 CDN assets | **Tied** (100% offline air-gapped) |
| **REST API Suite** | `/api/scan`, `/api/cbom` | Full REST API: `/api/status`, `/api/scan`, `/api/rate`, `/api/cbom`, `/api/sensors`, `/api/browse`, `/api/history`, `/api/report/html`, `/api/report/download` | **IndraMesh Leads** in endpoint breadth |
| **Live Estate Re-Ranking** | Live slider re-ranking | Live sub-second re-ranking via `POST /api/rate` without disk rescan | **IndraMesh Leads** |
| **Interactive Topology** | Text / tabular finding view | Interactive SVG/HTML Cryptographic Topology Visualizer | **IndraMesh Leads** in visualization |
| **Printable Audit Report** | Self-contained HTML report | Self-contained printable HTML & JSON reports | **Tied** |
| **Override Persistence** | SQLite database persists overrides across rescans | In-memory session state | **Reference Leads** in multi-scan persistence |

---

## 6. Verification & Test Suite Authenticity

### Authenticity Metrics: Why 1,034 Tests Matter
A raw test count is only meaningful if the suite actively catches regressions and subtle cryptographic flaws.

```powershell
# Verification commands in IndraMesh:
python -m pytest tests -q                     # 1,034 passing tests (0 regressions, 8 platform skips)
python mutation_test.py                       # 19/19 injected faults caught and killed (100%)
python validate_gui.py                        # 10/10 automated Web Console & API tests passing
python -m pytest tests/test_readme_contract.py # Enforces that published claims match reality
```

### Detailed Suite Breakdown
- **Test Volume:** IndraMesh features **1,042 collected tests** (1,034 passing, 8 platform skips on Windows). The Conventional Reference README reports 664 tests.
- **Mutation Testing:** IndraMesh includes `mutation_test.py`, which injects 19 deliberate AST mutations (subtle logic reversals, boundary offsets, and type misclassifications). The suite achieves a **100% kill rate (19/19)**.
- **Property-Based Invariants & Fuzzing:** IndraMesh executes 64 property tests using Hypothesis (`tests/test_properties.py`, `tests/test_differential.py`, `tests/test_fuzz.py`), testing arbitrary inputs against mathematical invariants.
- **Contract Enforcement:** `test_readme_contract.py` automatically fails CI if advertised test numbers, rule counts, or documentation links drift from the actual codebase.

---

## 7. Areas Where the Conventional Reference Retains an Advantage

In keeping with our commitment to engineering honesty, IndraMesh acknowledges three specific areas where the Conventional Reference Architecture retains an edge:

1. **ELF Binary Symbol Extraction:**
   The Reference architecture parses ELF symbol tables (`.dynsym`, `.symtab`), linking imported shared library symbols directly to cryptographic implementations. IndraMesh currently relies on raw binary string extraction, magic byte detection, and constant matching.
2. **Persistent Operator Overrides (SQLite):**
   The Reference architecture implements an embedded SQLite database that preserves operator risk overrides ($X$, $Y$, or purpose annotations) across restarts and rescans. IndraMesh currently maintains overrides in-memory per session.
3. **Packaged Video & Presentation Assets:**
   The Reference architecture repository contains pre-rendered H.264 video walkthroughs (`.mp4`) and PowerPoint slide decks (`.pptx`). IndraMesh has prioritized executable code, automated verification suites, and interactive web tools.

---

## Conclusion: The Modern Post-Quantum Discovery Standard

IndraMesh's transition through the **1,000+ tests milestone** establishes a new benchmark for cryptographic discovery:
- It eliminates the illusion of static call site counting by treating **`unresolved` as an explicit CBOM state**.
- It grounds risk forecasting in **empirical organizational velocity** rather than vendor guesswork.
- It provides a **hardened, air-gapped web console and REST API** verified by **1,034 passing tests** and **100% mutation testing**.
