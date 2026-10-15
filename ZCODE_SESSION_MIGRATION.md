# ZCode Session Migration Dossier: ECDAT / IndraMesh

This document contains the complete context migrated from Cline Desktop (`session_1791761408123_ne548`) to ZCode for high stability, uninterrupted workflow, and enterprise hardening.

---

## 1. Project Summary & Status
* **Workspace Path**: `C:\Users\Public\Downloads\chrome downloads\post quantom sih\ECDAT`
* **Project Name**: ECDAT (Enterprise Cryptographic Discovery & Assessment Tool) / IndraMesh
* **Architecture Highlights**:
  - `engine/scanner.py`: Hybrid Regex + ML AST scanner detecting cryptographic algorithms, certificate parameters, and protocol implementations.
  - `engine/cbom.py`: CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) generator with RFC 10024 hybrid PQC markers.
  - `engine/mosca.py`: Risk scoring engine implementing Mosca's Theorem ($X + Y > Z$) with NIST IR 8547 policy deadlines (deprecated 2030, disallowed 2035).
  - `engine/coverage_reconcile.py`: Asset inventory control reconciliation report (scanned, inaccessible, unknown, out-of-scope).
  - `server.py` & `app.py`: FastAPI server with token authentication, healthcheck endpoints, and interactive UI visualizer.

---

## 2. Test Suite & Verification Milestone
* **Test Count**: **1,044 passing tests**.
* **Test Runner**:
  - Standard pytest: `pytest -q` (now enabled via `pythonpath = .` in `pytest.ini`).
  - Per-file floor validator: `python run_tests_by_file.py`
* **Recent Hardening Fixes Applied**:
  1. Fixed `pytest.ini` by adding `pythonpath = .` so pytest executes reliably from any directory or IDE without module import errors.
  2. Fixed thin coverage in `tests/test_integration.py` by adding `test_coverage_manifest_reconcile_integration` (lifting integration tests to 10/10, surpassing the floor).

---

## 3. Active Goal & Loop Instructions
The user has established an ongoing autonomous improvement loop (`/goal`):
1. **Loop Sequence**:
   - **Research**: Examine next cryptographic or enterprise enhancement opportunities (PQC algorithms, CycloneDX 1.6 spec compliance, performance).
   - **Upgrade**: Implement clean, well-typed code changes.
   - **Verify**: Run `python run_tests_by_file.py` and ensure zero test regressions.
   - **Commit**: Commit clean milestones using conventional commit format (`hardening(enterprise-loopX): ...`).
2. **Current Loop Target**:
   - Maintain full test coverage across all modules.
   - Keep integration and schema validation at enterprise grade.

---

## 4. OpenCode & ZCode Connection Details
* **ZCode Bridge**: Running on `http://127.0.0.1:4097/v1`
* **OpenCode Engine**: Running on `http://127.0.0.1:4096`
* **ZCode Model Configuration**:
  - Provider: `opencode-zen-chat`
  - Base URL: `http://127.0.0.1:4097/v1`
  - Recommended Free Models: `opencode/longcat-2.5-preview-free`, `opencode/space-bunny-free`, `opencode/nemotron-3.5-lightning-free`.
