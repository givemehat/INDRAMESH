# IndraMesh vs Conventional ACDI & Static Scanners — Evidence-Based Comparison Table

Scope: IndraMesh architecture and sensor suite versus conventional static discovery scanners.

**Evidence rules used here.** Every IndraMesh claim cites a file (and a test where one exists).
Every competitor claim quotes their README. Anything I could not verify from the material in
this repository is marked **unknown** — including several places where *not* knowing is
unfavourable to us. Read the `unknown` rows as open questions, not as wins.

**A warning about the headline numbers.** Their accuracy figures (precision 1.000, recall 1.000,
F1 1.000) and ours (precision 1.00/0.90, recall 0.22/0.11) **are not comparable and must never be
placed in the same column.** They say so themselves:

> "Both corpora are synthetic and were written by this project's developers; the two results are
> separate, non-comparable experiments. Real-world enterprise accuracy has not been measured."
> — competitor README L97–99

> "**Precision is excellent. Recall is poor, and we published that ourselves.** … Anyone who
> quotes a recall number from this repository should quote it **with these numbers**"
> — `docs/HAND-160-summary.md` L36–41

They score higher on a corpus they wrote. We score lower on corpora we did not. Neither number
is a claim about real code. That is the whole honest story of this row.

---

## 1. Sensors / evidence classes

| Sensor | Better | By how much | Evidence |
|---|---|---|---|
| Source (Python) | **unknown** | — | They claim "Python by its real AST … AST resolves parameters (`key_size=1024`)" (L210). We use **regex only** — `engine/scanner.py:35-98` is a `RULES` table of compiled regexes, and `ast_depth` comes from the optional PyTorch model, not from `ast`. We emit no `key_size=`-style parameter extraction. Their claim is unverified from here; our regex-only design is verified from `engine/scanner.py`. |
| Source (other languages) | **They** | 1 pack each | We: C/C++/C#/Go/Java/JS/TS/Rust in `SOURCE_EXTENSIONS` (`scanner.py:21`), matched by the same regex table — no per-language packs. They: "curated rule packs for C/C++, C#, Go, Java, JavaScript, PHP, Ruby" + "Rust and Swift files are recognised and scanned, but only by the four language-agnostic rules" (L210). They are ahead on PHP and Ruby, for which we have no rules at all, and on per-language tuning. |
| Dependency manifests | **They** | 4 parsers | We: `PARSERS` has **9** entries — pip, pyproject, npm, gomod, maven, cargo, gem, composer, dotnet (`engine/dependencies.py:793-803`). They: "13 manifest formats" (L31, L211). Granularity of "format" is undefined in their README, so the true gap is 4 parsers and **unknown** in absolute terms. |
| Binary | **They**, decisively | Whole technique | We: `BINARY_MARKERS` (`scanner.py:101-110`) does printable-string regex over raw bytes. No ELF symbol table, no constant matching, no version-banner parsing. They: "ELF symbol tables, cryptographic constant matching, version banners … Symbols are strong; raw strings are weak" (L212). They state the limit themselves: "Binary analysis is ELF only" (L105); "Mach-O and PE binaries … are still string-matched" (L586-587). |
| Certificates | **Tie** | — | We have `engine/certificates.py` (75 KB, `tests/test_certificates.py`, 42 tests) behind `cli_certificates.py`. They: "X.509, PEM/DER, private key material, including PQC certificates … Parsed, not guessed" (L213), with 10 labelled certificate cases at F1 1.000 (L656). Both exist; neither independently verified here. |
| Configuration | **Tie** | — | We: `CONFIG_FILENAMES = openssl.cnf, openssl.conf, java.security, nginx.conf, httpd.conf, ssh_config, sshd_config, web.xml` plus 2 config rules (`scanner.py:25-26, 92-97`). They: "nginx, Apache, sshd, OpenSSL, Java security policy" (L214). Same list. |
| Container images | **They**, decisively | 5 named features | We: `CONTAINER_EXTENSIONS = .tar, .tar.gz, .tgz`, plain layer scan, no layer replay (`scanner.py:24, 449-525`). They: OCI layout directory, OCI layout tar, `docker save`; gzip/bzip2/xz; "**zstd layers are named and refused**, not silently reported as empty"; "**Layers are replayed in order**, with `.wh.` and `.wh..wh..opq` whiteouts applied"; "An archive holding more than one image is **refused until one is named**"; per-member vetting with "member count, per-file size, total uncompressed bytes, nesting depth and wall clock … bounded" (L573-611). Every one of those is absent from `scanner.py`. |
| Network / TLS | **Unreachable for us** | — | `engine/netprobe.py` (45 KB) and `engine/netpolicy.py` (44 KB) exist and are committed, with 26 + 45 tests. **No entry point calls them.** `grep` over `cli.py`, `cli_advanced.py`, `cli_certificates.py`, `app.py` returns zero references to `netprobe`. They: "Live TLS probing, including hybrid PQC group negotiation … Ground truth for what is negotiated" (L215), reachable from the console and the API. We wrote the sensor and shipped no button. |

## 2. Detection technique

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Parsing vs pattern matching | **They** | Whole class of defect | Our scanner is regex plus comment blanking (`scanner.py:228-258`). They use "Python AST analysis" plus rule packs. Their benchmark found seven defects "none visible by inspection" (L676), including `TLSv1` matching inside `TLSv1.2` and `DES` matching inside `DES-CBC3` — exactly the bug class a regex table invites. Our `IM-CFG-LEGACY-001` regex is `\b(3DES|DES-CBC3|RC4|NULL-SHA|EXPORT)\b` (`scanner.py:97`), correct only because `3DES` is hand-listed ahead of `DES-CBC3`. |
| Comment handling | **Us** | — | We blank comments and Python docstrings before matching, preserving byte offsets so reported line numbers stay correct (`scanner.py:228-258`, regression-tested). Not claimed in their README. A genuine advantage of ours. |
| Recall on third-party code | **unknown — do not claim it** | — | Their paramiko figure: "**12 distinct cryptographic assets across 70 files in 1.3s**" (L495). Ours on the same pinned commit: 27 TP / 3 FP / 30 predicted (`benchmark/RESULTS.md`). Different units — assets vs `(file, line)` hits — and neither README reconciles them. **unknown.** |

## 3. CBOM conformance

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Spec versions | **They** | 1 version | We: `SPEC_VERSION = "1.7"` only (`engine/cbom.py:35`), no switch. They: "CycloneDX 1.6 (ECMA-424) with `cryptoProperties`" as the **default**, 1.7 supported, and "1.7 is a real implementation, not a relabelled 1.6" (L256, L720-726). |
| 1.7-specific fields | **They** | 3 fields | Checked against our own vendored `schemas/bom-1.7.schema.json`: `algorithmProperties.curve` carries `"deprecated": true`, and `ellipticCurve` / `algorithmFamily` exist beside it. We emit **only the deprecated `curve`** (`engine/cbom.py:291-292`); we never emit `ellipticCurve` or `algorithmFamily`. They use all three and "**omit** `algorithmFamily` … when the purpose is unresolved" (L721-726). |
| Validation | **They**, narrowly | Checksum + CI gate on both versions | We do validate: `validate_cbom.py` against a vendored schema, 4 real schema tests in `tests/test_cbom_schema.py` (I ran them: 4 passed), and a CI step that is not `\|\| true` (`.github/workflows/tests.yml`). Two deficits: the schema is not checksum-verified on load — their words, "a validator you can quietly modify is not a validator" (L713-714), apply to us; and our emitter has no internal validator, so only the fixture shapes are ever checked. They report structural and official checks **separately**, and "A run where official validation could not happen reports `checked: false` — never a pass" (L706-708). Ours exits 2 from a script — honest, but not surfaced in the product. |
| Detection evidence in the standard field | **They** | — | We emit `evidence.occurrences` only and put confidence in a vendor property `im:detector_confidence` (`engine/cbom.py:342-344`). They: "detection evidence in `evidence.occurrences` and per-finding confidence in `evidence.identity`" (L256-257) — the standard location. |
| Asset normalisation | **They** | Whole concept | We emit one component per *finding*, so one algorithm seen 800 times is 800 components. They: "Raw detector hits are **normalised into distinct cryptographic assets**, so one algorithm seen 800 times is one migration item with 800 call sites" (L148-150), with "purpose and assurance … part of an asset's identity" (L187-188). A consumer of our CBOM gets an inventory, not an asset graph. |
| Corroboration / correlation | **They** | Whole module | They have `app/engine/correlate.py` with an explicit list of what correlation may never do (L623-633). We have `engine/graph.py` at 2.2 KB and nothing else. |
| Certificate assets in the CBOM | **They** | — | We have a certificate sensor but no `cryptoProperties.assetType: "certificate"` emitter; certificates become ordinary algorithm components. `engine/cbom.py` has no certificate branch. |


## 4. Risk model

| Item | Better | By how much | Evidence |
|---|---|---|---|
| X + Y > Z | **Tie** | — | Both implement it. Ours: `engine/mosca.py:232-333`. Theirs: `app/engine/risk.py` (L1047). |
| Z as a distribution | **They**, clearly | Whole concept | Ours is three fixed presets and a three-point sensitivity band: `Z_PRESETS = {aggressive:5, gri_midpoint:10, conservative:15}` (`mosca.py:65-72`). They model Z as "a triangular distribution over (earliest, likely, latest) … reported as a probability alongside the exposure at the median" (L240-243), caught their own mode-vs-median bug, and "compute and report both" now (L806-810). Our Z labels are also internally inconsistent — see Finding 3 of the companion review. |
| Split horizon by purpose | **Tie** | — | We do this well: `PRIMITIVE_HORIZON` plus `hndl_exposed` only for confidentiality (`mosca.py:42-56, 275`). They do it with a four-row table including a "Retroactive? Yes / No / Gradually / Assumed yes" column (L794-799). Equivalent. |
| Risk-input provenance | **They** | Whole concept | They tag every input `observed` / `derived` / `operator` / `default` because "a score built from four guesses and one built from four reviewed values look identical unless the tool says which is which" (L766-775), with overrides that "survive a restart and a rescan" (L776-782). We have `x_reason` / `y_reason` strings (`mosca.py:324-329`) — a weaker version of the same idea — but **no persistence and no overrides at all**; there is no SQLite anywhere in this repository. |
| Unresolved-purpose handling | **Tie** | — | Ours declines to name a target (`recommender.py:227-245`). Theirs: "the recommender returns 'manual review required' instead of a plausible replacement" (L531-532). Both correct; both cite the same insight — ours cites theirs. |

## 5. Purpose and assurance model

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Concept | **Tie** | — | Theirs is the origin of ours — `engine/purpose.py:3-10` quotes them and credits them. Both have the four assurance states with near-identical wording. |
| Implementation depth | **They** | — | They resolve purpose from `RSA_sign`, `rsa.EncryptOAEP`, `Signature.getInstance` (L834-840) and fixed seven purpose defects the benchmark found (L689-691). We resolve from a flat needle list (`purpose.py:36-49`) with no class-agnostic `RSA_sign` / `rsa.EncryptOAEP` equivalents and no corpus coverage for purpose at all. **Our purpose-resolution accuracy is unmeasured — unknown.** |
| Published in the CBOM | **Tie** | — | They export `cryptoFunctions` and `detection:assurance` (L858-859); we export `im:assurance` and `cryptoFunctions` (`engine/cbom.py:322-324`). |

## 6. Post-migration verification

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Existence | **They**, by integration | — | We have `engine/verify_migration.py` with 39 tests and correct Kyber/Dilithium/SPHINCS+ handling — genuinely good work, and they name us as the model (L28-30). But it is reachable only from `cli_advanced.py`. They verify PQC from inside the product: the certificate sensor reads PQC certificates, the network sensor enumerates negotiated groups, and scan history tracks readiness over time. |


## 7. GUI

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Console exists | **Tie** | — | `app.py`, 53 KB, Streamlit, 7 roles (`app.py:66-71`). Theirs: 1,200 hand-written lines of vanilla JS, zero dependencies (L541-545). |
| Served console + API | **They** | Whole deployment model | They run FastAPI on 127.0.0.1:8000 with an API, and every HTTP route the console calls is under test (L484). We have no HTTP server; Streamlit serves the app itself. For a projector demo theirs is more portable; ours depends on Streamlit being installed. |
| Front-end dependencies | **They**, narrowly | — | "vanilla JavaScript with no build step, no framework and no CDN", aimed at air-gapped use (L541-545). We depend on Streamlit, which is heavy, but also ship no CDN. Comparable. |
| Live re-ranking of the estate | **They** | — | "The console lets you drag those three years and re-rank the entire estate live" (L242-243). We expose X/Y overrides in the sidebar but cannot re-rank the estate against Z live (`app.py:844-852`). |
| Evidence drill-down | **Tie** | — | Theirs: "Every finding opens onto its evidence — file, line, technique, confidence, assurance grade, and the exposure arithmetic … with each input labelled by where its value came from" (L275-277). Ours renders a per-finding drawer with the same fields. Genuinely competitive. |

## 8. Report export

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Printable report | **They** | Whole artefact | They ship a self-contained offline HTML report, printable to PDF, in which "every asset — not the top fifteen — carries a six-step traced chain", and where "A partial scan says so at the top, with the reasons" (L743-752). **We have no report generator.** Our only exports are JSON via `st.download_button` (`app.py:164`). For a SIH submission this is a visible gap. |

## 9. Tests

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Raw count | **They** (nominally) | 71 collected items | I ran the suite: **819 passed, 8 skipped** (`pytest tests -q`). Their README says **664 tests** (L466). Ours is 533 `def test_` functions across 21 files. **Neither number is a quality measure** — our own summary says "a test count is not evidence of correctness" (`docs/HAND-160-summary.md` L20). Do not put these two numbers side by side in a deck without that caveat. |
| Suite composition | **They**, more balanced | — | Their per-file table (L468-484): 91 security, 70 assessment, 61 detection-correctness, 61 standards/reporting, 43 container, 38 knowledge, 32 container-security, 30 risk, 29 normalize, 29 benchmark-regressions. Ours: 60 dependencies, 45 netpolicy, 42 certificates, 39 verify_migration, 36 properties, 26 netprobe, 22 differential, 21 mutation-kills, 20 competitive-upgrades, 20 mosca, 19 recommender, 17 scanner, 17 gui_helpers, 13 cbom. **We have no dedicated risk-model suite to match their 70-test `test_assessment.py`** — our 20 `test_mosca.py` tests are the thinnest area relative to how load-bearing `mosca.py` is. |
| Defect-detection evidence | **Us** | Unique | `mutation_test.py` injects 19 deliberate defects and requires the suite to kill them; wired into CI (`.github/workflows/tests.yml`, "Mutation-test the engine"). Their nearest equivalent is `test_benchmark_regressions.py`, "One test per defect the benchmark found" (L480) — real, and not the same claim. A genuine unmatched advantage. |
| Property / fuzz / differential | **Us** | Unique | `tests/test_properties.py` (36), `test_differential.py` (22), `test_fuzz.py` (6). No counterpart claimed in their README. |
| Skipped tests | **Us (disclosed)** | — | 8 skips, and `pytest.ini` deselects `slow` and says so in the file. Honest, and better than silence. |


## 10. Accuracy evidence

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Any measured accuracy at all | **Tie** | — | Both measure and both publish the caveat. This row is a tie and we should say so plainly. |
| Corpus independence | **Us** | Whole category | Theirs: "a synthetic corpus written by the same person who wrote the detectors … It measures this corpus and nothing else" (L426-429). Ours: two **externally cloned, SHA-pinned third-party** corpora — CryptoAPI-Bench `e6b6b50f`, paramiko `142f593e` — with the caveat that "the line-level ground truth is hand-annotated by the author of this harness" (`benchmark/RESULTS.md`). We are honest that our *labels* are ours; they are honest that their *fixtures* are theirs. Ours is the harder evidence. |
| Reproducible from a fresh clone | **They** | Decisive | Their corpus, harness and results are **committed** (L1053: "benchmark/ — labelled corpus, accuracy harness and committed results"). Ours: `.gitignore` excludes `benchmark/corpora/` — the corpora are re-fetched over the network. A judge who clones our repo cannot reproduce our accuracy number without network access. |
| Reported precision | **They** | 0.90 → 1.00 | Ours 1.00 (46/46) cryptoapi_bench, 0.90 (27/30) paramiko (`docs/HAND-160-summary.md` L31-33). Theirs 1.000. **Not comparable** — different corpora. |
| Reported recall | **unknown** | — | Ours 0.22 / 0.11 on external corpora. Theirs 1.000 on their own. **Not comparable, and neither project has measured the other's setting.** Marked unknown deliberately; do not put these in one table. |
| Corpus labelling discipline | **They**, narrowly | — | They relabelled three false positives as correct detections **and wrote the reason and the score effect into `benchmark/manifest.json`'s changelog**, stating "Labels were never changed in the other direction" (L403-411). We publish raw counts beside every ratio and state "The rule table is a curated set of patterns; it finds what it was written to find" (`docs/HAND-160-summary.md` L38-39). Both disclose; theirs is more auditable. |
| What measuring found | **Tie** | — | They list seven detector defects the benchmark caught (L676-693). We list 21 across mutation and property/fuzz testing (`docs/HAND-160-summary.md` L45-57). Comparable honesty, different instruments. |

## 11. Security posture

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Filesystem containment | **Tie** | — | Ours: `engine/fspolicy.py` — `check_root`, `resolve_within`, `is_credential_store` — applied in `scanner.py:560-577`, `dependencies.py:983-998`, `verify_migration.py:499-513`. Theirs: `app/fspolicy.py` (L896-904), including the concrete `config.py → ~/.ssh/id_rsa` incident that motivated it. Same design; both found it independently. |
| Network destination policy | **They**, on documentation | 4 named mechanisms | Ours: `engine/netpolicy.py` (44 KB, 45 tests) exists; I have not read it line by line and will not characterise it beyond "exists and is tested". Theirs is documented in detail: address-by-address resolution, connecting to the vetted literal, refusal of `2130706433` / `::ffff:127.0.0.1` / `2002:7f00:1::1`, refusal of a name resolving to both public and internal, and four bounded env vars (L870-894). **Their documentation of the posture beats ours because ours documents nothing.** |
| Access control on the console | **They** | Whole feature | "Bound to loopback with no token, the console is open … Set `CD_TOKEN` and every `/api` route requires it. **Bind anywhere else without a token and the server refuses to start**" (L906-913), with 91 tests behind it (L471). **UPDATE:** we now have half of that half -- `app.py` defaults to `127.0.0.1` and refuses a non-loopback bind unless `--allow-unauthenticated-public` is passed (`tests/test_app_launcher.py`), where previously it silently bound `0.0.0.0`. We still have **no token and no per-route auth**, so the row stays theirs. |
| Evidence redaction | **They** | — | "One was a leak: a hardcoded secret the scanner found was exported verbatim into the CBOM … Evidence is now redacted" (L736-739). Our rules cannot match a hardcoded secret, so we do not leak one — but we do not detect one either, and we have no equivalent of their 91-test security suite. |
| Scan bounds | **They** | 4 bounds we lack | We bound manifest size (8 MB), binary read (64 MB) and container member size (25 MB). They bound wall clock, directory entries walked, concurrent scans and files read, and "When a bound is reached the scan **ends cleanly and says so**" (L920-931). **We have no wall-clock and no file-count bound**: a scan of a large tree has no ceiling. This one goes to them. |
| Container archive safety | **They** | Decisive | `scanner.py:475-522` reads each member and never checks its name. We do not vet archive members, do not count refusals, and have no decompression-bomb bound. Harmless today only because we never extract to disk — but a traversal member is counted as a normal file rather than refused and counted. |
| Air-gap claim | **unknown (ours unverified)** | — | They assert "It runs **fully air-gapped**. There are no outbound network requests, no CDN assets and no telemetry" (L160-163), and it is structurally plausible. We have a torch dependency and `benchmark/run_benchmark.py` clones from the network. **We make no air-gap claim and I cannot verify one either way — unknown.** |


## 12. CI

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Matrix | **They** | 2 extra versions | They: "runs the suite on Python 3.11, 3.12 and 3.13, then runs a separate smoke job that scans this repository, emits a CBOM and **fails the build if the document does not conform** to CycloneDX 1.6" (L502-506). Ours: `.github/workflows/tests.yml` pins **3.11 only** with no self-scan smoke job, and the separate `indramesh_scan.yml` gates on `--fail-on CRITICAL` but then swallows the exit with `\|\| echo "::warning::"`. **Our scan job cannot fail the build.** |
| What CI proves | **Tie** | — | We additionally run mutation testing and a per-file coverage report; they run benchmark regressions. Different instruments, both real. |

## 13. Submission assets

I enumerated the repository tree. Result: **0** `.pptx`, **0** `.pdf`, **0** `.mp4`, **0** `.png`,
**0** files under any `submission/` directory.

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Deck | **They** | Total | Theirs: six-slide deck (`.pptx` + PDF, "6 pages, vector text, verified"), built from the official template (L1068-1069). We have none. |
| Films | **They** | Total | 3:09 full and 1:26 short, 1920×1080 H.264, caption-led, captions burned in and also written as SRT (L1070-1071). They explain *why* there is no narration (L113-116), which is itself submission craft. We have none. |
| Screenshots | **They** | Total | "genuine captures of the running console", reproducible with `submission/build/capture_screens.py` (L262-267, L1075). We have none. |
| One-command demo | **They** | Total | `run.py --demo` builds fixtures, scans, and is "deliberately pointed at one endpoint the destination policy refuses, so the scan finishes **PARTIAL** with its reason recorded" (L326-349). We have `dummy_target/` and `examples/` — a weaker equivalent. |
| Architecture diagram with editable source | **They** | Total | `docs/architecture/architecture.mmd` plus SVG and PNG exports, "One source, two palettes, so the two cannot disagree about what the system does" (L167-171). We have `docs/` prose only. |
| Written project report | **They** | Total | `Report/` — "project report and design history" (L1061). We have `docs/CODE_REVIEW.md` and `docs/HAND-160-*.md`: good engineering writing, not a submission report. |
| Q&A sheet / quotable figures | **They** | Total | `presenter/` includes "the figures that may be quoted" (L1073). We have no equivalent — and given the findings in the companion review, writing one today would be **harmful** to us. |

## 14. Known-limitations disclosure

| Item | Better | By how much | Evidence |
|---|---|---|---|
| Honest limitations surface | **They** | Decisive | Their "Known limitations" section (L960-1018) runs ~60 lines and includes things that hurt them: "Not independently audited", "SHA-1-signed certificates are classified but not corpus-tested", "The command-line entry point is source-only", "Most risk inputs start as unreviewed defaults". `docs/HAND-160-summary.md` is 77 lines and candid about recall, but there is no single limitations page a judge can be handed. |


---

# Top 5 gaps where THEY beat US

Ordered by how much each costs us in a judging session, not by engineering effort.

### 1. We ship sensors no entry point can reach, and a CLI that runs one sensor

They win because their product is seven *reachable* sensors; ours is three reachable ones plus two
orphans. `cli.py` imports only `scanner`, `mosca`, `recommender`, `cbom`. `cli_advanced.py` adds
dependencies and migration verification. `cli_certificates.py` adds certificates.
**`engine/netprobe.py` (45 KB, 26 tests) and `engine/netpolicy.py` (44 KB, 45 tests) are imported
by nothing** — `grep -n "netprobe" *.py` returns zero hits outside the module's own tests. A live
handshake is the one evidence class that can settle `purpose` and prove a migration, which is
exactly what `engine/purpose.py` and `engine/verify_migration.py` say they cannot do alone. They
name the same limitation for their own CLI and answer it by shipping the console (L364-369,
L978-980). We have the sensor and not the path.

**Close it:** `cli.py::main` — add `--sensors source,dependency,certificate,container,network`;
`app.py::run_scan` — call the network probe under `netpolicy` and merge findings with
`evidence_class="negotiated"`. **Highest value in the list, because the code already exists.**

### 2. Recall on real code, and a benchmark a judge can reproduce

They win because they publish precision 1.000 / recall 1.000 / F1 1.000 with a per-scanner
breakdown (L650-658); we publish precision 1.00/0.90 and recall **0.22/0.11** and say so
ourselves. Ours is the more honest measurement and the worse number. Worse, `benchmark/corpora/`
is git-ignored, so a judge who clones our repo **cannot reproduce our own numbers** without
network access, while their corpus, harness and results are all committed (L1053).

**Close it:** `engine/scanner.py::RULES` is the lever — the benchmark already names the misses
(ECDH 0/30, RSA 1/37, AES 1/27 on paramiko, per `docs/HAND-160-summary.md` L38-39). Add rules
for those three families first. Secondarily, `benchmark/run_benchmark.py` should gain an
`--offline` mode that prints the committed `results.json` and labels it as the committed run, so
a published number can never be confused with a fresh measurement.

### 3. Asset normalisation and cross-sensor correlation

They win because they normalise hits into distinct cryptographic assets so "one algorithm seen 800
times is one migration item with 800 call sites — not 800 findings" (L148-150), and they correlate
across sensors with an explicit list of what correlation may never do (L613-636). We emit one CBOM
component per finding and have a 2.2 KB `engine/graph.py`. A judge who opens both CBOMs sees an
inventory versus an asset graph, and the inventory is the weaker artefact.

**Close it:** `engine/cbom.py::generate_cbom` — key components on
`(algorithm, primitive, resolved purpose, assurance)` and carry every additional hit as another
`evidence.occurrences` entry, instead of `ref = f"crypto-asset-{idx}"` per finding. `engine/graph.py`
then becomes the correlation point rather than a leaf.


### 4. Console, report, persistence, access control

They win because they have a served console, a self-contained printable HTML report where every
asset carries a six-step traced chain and a partial scan says so at the top (L743-752), SQLite
persistence with **operator overrides that survive a rescan** (L766-782), and a token guard that
**refuses to start** when bound off-loopback without one (L906-913). We have a Streamlit app, JSON
downloads, and no persistence, no overrides, no auth and no report.

**Close it:** `app.py` — (a) a `st.download_button` emitting a self-contained HTML report built from
the records `app.py::rate_findings` already produces; (b) persist X/Y overrides keyed on
`(name, primitive, file)` via stdlib `sqlite3` and re-apply on rescan; (c) refuse to serve unless
`INDRAMESH_TOKEN` is set or the bind address is loopback. (b) is also the fix for the missing
risk-input provenance in §4.

### 5. Submission assets, and a limitations page that would survive a judge

They win because they ship a verified six-page deck, two films, script-reproducible screenshots, an
architecture diagram with editable source, a presenter script and a Q&A sheet. We ship none of
these.

**Close it:** not a code change — but it must not be written until the review findings are fixed,
because three of them (CBOM `curve` deprecation, the Z-label contradiction, the fabricated
`dl_confidence`) are exactly what a CBOM-conformance question in a Q&A session finds in thirty
seconds. Ship a `docs/LIMITATIONS.md` modelled on theirs, including the recall numbers.

---

# Where WE are better — stated with the same scepticism

- **Mutation testing in CI.** `mutation_test.py`, 19 injected defects, required to reach 100%.
  Unmatched in their README. They have regression tests per defect, which is good and is not the
  same claim.
- **Property / fuzz / differential suites.** `test_properties.py` (36), `test_differential.py` (22),
  `test_fuzz.py` (6). No counterpart claimed.
- **External, SHA-pinned corpora.** CryptoAPI-Bench and paramiko are third-party. Their corpus is
  self-authored and they say so. Ours is the more honest measurement even though the number is worse.
- **Comment and docstring blanking with offset preservation** (`scanner.py:228-258`). Not claimed by
  them; a real false-positive class, and the mirror image of the `TLSv1`-inside-`TLSv1.2` defect
  they found in their own logic.
- **Concept provenance.** `engine/purpose.py:3-10` credits their observation explicitly. That is to
  their credit and should stay credited.

# Things the competitor says about themselves that we should adopt verbatim in tone

- "A score of 1.000 is a statement about the corpus, not the tool" (L430-431).
- "A check that silently did not run is worse than one that failed" (L707-708).
- "the reason and the effect on the score written into `benchmark/manifest.json`'s changelog, so
  the change is auditable rather than invisible" (L405-408).
- "Not independently audited … they have not been reviewed by a cryptographer" (L1016-1018).
  A limitations section that admits this is stronger than a README that implies the tool is finished.

