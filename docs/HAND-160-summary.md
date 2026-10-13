# HAND-160 — what changed, and what is still not true

Task: close the gaps found in the competitive analysis, prove the work, and reach the one claim
no competitor can make.

## Headline

| measure | before | after |
|---|---|---|
| tests passing | 145 | **819** (+674) |
| mutation score | 57.9% (11/19) | **100% (19/19)** |
| real defects found by testing | — | **24** (8 mutation + 13 property/fuzz + 3 UI/schema) |
| external accuracy benchmark | none | **precision + recall on 2 published corpora** |
| evidence classes covered | 3 | **5** (+ dependency, + negotiated) |

## The three claims no competitor can make

**1. Mutation-tested, not just test-counted.** `mutation_test.py` injects 19 deliberate defects
into isolated repo copies and re-runs the full suite. Score: 57.9% → 78.9% → **100%**.
The competitor has 664 tests; a test count is not evidence of correctness. This is.

**2. Measured accuracy on a published external corpus.** `benchmark/RESULTS.md` — CryptoAPI-Bench
(pinned `e6b6b50f`) plus paramiko (pinned `142f593e`). The competitor's own README says their
figures come from "a synthetic corpus written by [the author]".

**3. A scanner that is safe to point at an untrusted tree.** `engine/fspolicy.py`: symlink
containment, credential-store refusal, no code execution, every skip recorded.

## What the benchmark actually says — read this before quoting any number

```
cryptoapi_bench   precision 1.00 (46/46)   recall 0.22 (46/210)
paramiko          precision 0.90 (27/30)   recall 0.11 (27/240)
```

**Precision is excellent. Recall is poor, and we published that ourselves.**

The per-primitive breakdown in `benchmark/RESULTS.md` shows where: ECDH 0/30, RSA 1/37, AES 1/27
in paramiko. The rule table is a curated set of patterns; it finds what it was written to find.

Anyone who quotes a recall number from this repository should quote it **with these numbers**, not
a better-looking subset. Claiming high recall here would be the exact self-contradiction we
criticise competitors for.

## The 21 real defects found by testing

8 by mutation testing (`docs/` in the commit message of `e776f3f`), 13 by property/differential/
fuzz testing (`docs/HAND-160-property-bugs.md`). The most serious:

| defect | consequence |
|---|---|
| Truncated container image crashed the whole scan | one corrupt `.tar` destroyed every other finding in the tree |
| Report showed `x_y: 21.2` beside `z: 21.2` and claimed RISK | float error; the reader's arithmetic disagreed with our verdict |
| `dependencyType` is not a CycloneDX 1.7 field | any finding without a `file` produced an invalid document |
| Single-file scans skipped dedup and coverage finalisation | `scanners_run` empty while findings were returned |
| Comment stripping absent | a Javadoc block mentioning `KeyPairGenerator.getInstance("RSA")` was an RSA finding |
| Symlink escape read files outside the scan root | arbitrary file read |

## Honest position

Enterprise cryptographic discovery requires both precision and transparent limits. What we have:
a measured defect-detection rate (mutation testing), an external accuracy measurement, and a strict containment boundary.
The next real gain is recall — extending the rule table against the per-primitive misses the
benchmark already identified. That is measured, prioritised work, not guesswork.

## Reproducing everything

```bash
python -m pytest tests -q          # 819 passing, 8 skipped
python mutation_test.py            # 19 mutants, expects 100% killed
python benchmark/run_benchmark.py  # external accuracy
python -c "import app"             # GUI imports without a server
streamlit run app.py               # the console
```
