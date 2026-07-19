# NivXRay — Sprint Roadmap (v1.6.0 · Deterministic-First Pivot)

**Locked direction (from `Ideas_updated.docx` · Feb 2026)**: The deterministic
engine is the product. AI is an **opt-in analyst assistant**, never the
core decoder. Everything must work offline.


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
