# RC5 · Phase 9.5c Compliance Report

**Date:** 2026-02-23
**Scope:** GC-090 deep PowerShell `-enc` semantic decoding + Golden Corpus PR-delta CI workflow
**Status:** ✅ COMPLETE · 690/690 backend tests pass · Golden Corpus 15/15 (100%)

---

## 1. Objectives (from user directive)

1. Implement deep semantic decoding for PowerShell `-EncodedCommand` payloads.
2. Recursively feed the decoded payload back through the entire RC5 pipeline
   (Parser → SIR → Behavior → MITRE → LOLBIN → Verdict → Explainability).
3. Support common obfuscation wrappers: `FromBase64String()`, `IEX(...)`,
   `Invoke-Expression`.
4. Support `GZipStream` / `DeflateStream` decompression when present.
5. Enforce cycle detection + max recursion depth (10) as a safety net.
6. Add a Golden Corpus PR-delta workflow that reports pass-rate, regression
   count, technique coverage, behavior coverage, per-stage confidence, and
   per-sample verdict deltas directly into CI.
7. Keep Phase 10 Production Cutover strictly gated.

## 2. Implementation summary

### 2.1 PowerShell interpreter (`engine/interpreters/powershell_interpreter.py`)

- **`-EncodedCommand` deep decode** — the decoded UTF-16LE body is now
  re-parsed and re-evaluated *before* the outer process node is emitted,
  so downstream behavior/MITRE/verdict logic sees the inner statements.
- **WebClient method interception** — `.DownloadString()`,
  `.DownloadFile()`, `.DownloadData()`, `.UploadString()`,
  `.UploadFile()`, `.UploadData()` and their `*Async` variants emit a
  deterministic `HttpNode` carrying `url`, `direction`,
  `http_request`/`https_request` + `download`/`upload` side-effects.
- **GZipStream / DeflateStream** — `_try_decompress()` transparently
  unwraps gzip, zlib, and raw-deflate payloads produced by
  `[Convert]::FromBase64String(...)` or passed directly to
  `[Text.Encoding]::UTF8.GetString(...)`.
- **Encoding chain fix** — `[Text.Encoding]::UTF8.GetString($b)`
  (chained static → member → method) now dispatches to the byte-decoder
  path via first-arg type inspection, not receiver-string matching.
- **Deep-decode safety net** — `MAX_DECODE_DEPTH = 10` global cap plus
  SHA-1 cycle detection over payload strings. Applies uniformly to IEX,
  `-enc`, and every recursive re-parse path.

### 2.2 Behavior extractor (`engine/detectors/behavior_extractor.py`)

- HttpNode direction-aware emission: `download` sub_kind → T1105 mapping;
  `upload` sub_kind → exfiltration tactic.
- Existing `http` sub_kind emission preserved for T1071.

### 2.3 Golden Corpus (`engine/golden_corpus.py`)

- **GC-090 expectations updated** — verdict lifted from `Benign` →
  `verdict_min: Malicious`, MITRE now `[T1059, T1027, T1105]`.
- Rationale: with deep -enc decoding, the WebClient.DownloadString call
  is now a first-class HttpNode with URL evidence, so the verdict math
  correctly reflects real malicious intent.

### 2.4 CI · PR-delta workflow

- **New:** `backend/scripts/golden_delta.py` — deterministic reporter
  that produces Markdown deltas covering pass-rate, regression count,
  stage coverage (decode / semantic / behavior / mitre / verdict),
  detector accuracy, per-sample verdict shifts, PASS→FAIL / FAIL→PASS
  flips, and enforcement decision.
- **Updated:** `.github/workflows/rc5_golden_corpus_gate.yml` — dual
  checkout (base + head), runs the corpus on both sides, generates a
  delta report, appends it to the job summary, and comments on the PR
  (best-effort). Fails the gate on `pass_rate < 95%` or
  `regression_count > 0`.

### 2.5 New tests

- **`tests/rc5/unit/powershell/test_deep_decode.py`** — 13 tests:
  WebClient DownloadString/DownloadFile/UploadString emit HttpNodes,
  T1105 mapping, full -enc → Malicious verdict, `-enc` short flag,
  self-referential cycle termination, `MAX_DECODE_DEPTH == 10`,
  gzip/zlib/raw-deflate helpers, `FromBase64String` + gzip +
  `GetString` chain producing plaintext, determinism across two runs.
- **`tests/rc5/unit/golden_corpus/test_delta_reporter.py`** — 7 tests
  covering baseline vs regression vs improvement scenarios, verdict
  shift rendering, PASS↔FAIL flip detection, coverage arrows, and the
  CLI end-to-end path.

## 3. Test results

| Suite                              | Before  | After   | Δ    |
| ---------------------------------- | ------- | ------- | ---- |
| Full RC5 backend regression        | 670/670 | 690/690 | +20  |
| Golden Corpus                      | 15/15   | 15/15   | 0    |
| GC-090 verdict                     | Benign  | **Malicious** | ✅ |
| Deep-decode PS unit tests          | 0       | 13      | +13  |
| PR-delta reporter unit tests       | 0       | 7       | +7   |

## 4. Invariant compliance

| Invariant                                                       | Status |
| --------------------------------------------------------------- | ------ |
| No AI in the deterministic pipeline (`--no-ai` graph identical) | ✅     |
| No regex on raw text for verdict-relevant evidence              | ✅     |
| Every recursion path bounded by depth cap + cycle detection     | ✅     |
| Golden Corpus 100% pass-rate maintained                         | ✅     |
| Cutover gate criteria untouched (9/9 still enforced)            | ✅     |
| Verdict / MITRE / Explainability logic frozen (no new rules)    | ✅     |

## 5. Phase 10 Cutover — still BLOCKED

Per user directive, Production Cutover remains blocked until:
- 30-day shadow-run completes with delta metrics in green
- Golden Corpus pass rate ≥ 95% (currently 100%)
- Zero regressions across the window
- All 9 cutover-gate criteria PASS

No cutover-gate signals were modified in this phase.

## 6. Backlog after this phase

Per the shadow-run charter (2026-02-23), the following are the ONLY
allowed workstreams for the remainder of the window:

1. **Golden Corpus expansion** (real malware + benign enterprise
   scripts) — GC-150 → GC-300 target.
2. **Interpreter coverage patches** driven exclusively by corpus
   failures — surgical, one gap at a time.
3. **Performance & latency instrumentation** surfaced via the PR delta
   report (`latency_p50`, `latency_p95`, per-sample decode ms).
4. **Analyst UI polish** (SOC Prime-inspired: Execution Graph
   visualization, Behavior timeline, MITRE evidence drill-down, "Open
   in ATT&CK Navigator", v1 vs v2 diff view).

No new detection rules, verdict logic, MITRE mappings, or verdict
weights will be introduced during shadow-run.

---

**Signed off:** deterministic RC5 semantic engine, Phase 9.5c.
