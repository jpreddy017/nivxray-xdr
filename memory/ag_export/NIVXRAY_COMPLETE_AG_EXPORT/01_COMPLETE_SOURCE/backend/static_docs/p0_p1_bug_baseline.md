# NivXRay · P0/P1 Bug Baseline (Pre-Migration)
_Date: 2026-08-09 · Author: E1 · Applies to: git HEAD `52007cbd`_

> **Purpose**: ADR-004 Amendment A1 requires a known-good behavioral baseline BEFORE Verdict Engine migration begins. This document captures every P0/P1 defect currently observable on HEAD, so post-migration parity tests can distinguish `preserved / fixed / introduced` outcomes.

> **Scope**: Correctness bugs, security risks, freezes/hangs, workspace UX defects, provenance losses observed during this session. Not an exhaustive audit — a defect-hunt pass focused on user-visible issues.

---

## P0 · Correctness / Security / Blockers

### P0-01 · SSRF on URL acquisition
- **Where**: `services/ida/acquisition.py` — `httpx.get(url, follow_redirects=True)`
- **Risk**: User-supplied URL can point at `169.254.169.254` (cloud metadata), RFC1918 IPs, or `localhost:8001`
- **Evidence**: No allow-list, no IP resolution + block, no host filter observed
- **Fix effort**: 4 hours (resolve-then-verify + block private IP ranges)
- **Regression test needed**: `test_ssrf_blocked.py` — assert 400/403 for metadata IP / 127.0.0.1 / RFC1918
- **Blocks migration?** No, but MUST be fixed before any customer exposure

### P0-02 · 3 verdict engines produce potentially divergent verdicts
- **Where**: `services/uaie/orchestrator.py`, `nivxforge/investigation/verdict_engine.py`, `backend/v2/verdict/engine.py`
- **Evidence**: Verification grep §Q1 (see ADR-004)
- **Risk**: Same input may produce different verdicts depending on which endpoint is called. Deterministic-first claim is compromised.
- **Fix effort**: This IS ADR-004 migration step 1
- **Regression test needed**: `test_verdict_engine_parity.py` — same 20 corpus inputs through all 3 engines, snapshot outputs, diff. This test becomes the migration gate.

### P0-03 · Original 360° audit contained ~8 false "NOT IMPLEMENTED" claims
- **Where**: `memory/CURRENT_STATE_AUDIT.md` (v1)
- **Status**: RESOLVED via reconciliation. Superseded by `CURRENT_STATE_AUDIT_RECONCILIATION.md`.
- **Note**: Kept here so future agents don't re-inherit the wrong baseline.

---

## P1 · High-severity but not blocking

### P1-01 · Workspace freeze / Page Unresponsive dialog on 7 KB+ inputs
- **Where**: `frontend/src/pages/WorkspacePage.jsx` (3,982 LOC monolith)
- **Root cause chain**:
  - `autoInvestigate()` fires `/die/understand` + `/die/analyze` + `/die/narrate` in parallel with `/decode/chain`
  - 3-4 promise chains resolve within ~100 ms
  - React 18 cannot auto-batch across async boundaries
  - Each setState re-reconciles the 3,982-line JSX tree
  - Combined reconciliation > 15 s → Chrome fires "Page Unresponsive"
- **Mitigations shipped this session**:
  - SSE stream coalescing (`WorkspacePage.jsx::runAnalysis` — 200 ms flush window, `startTransition`)
  - Auto-chain detection routes multi-layer inputs directly to `/decode/chain`, skipping the 3 parallel calls
  - Workspace-level error boundary catches component crashes
  - Global `window.error` + `unhandledrejection` handlers prevent uncaught throws from blanking the tab
- **Remaining gap**: The paste itself can still produce a ~3.6 s long task from React reconciling a 7 KB controlled textarea. Not a freeze (well below 15 s) but still slow.
- **Real fix**: Migration step 10 (WorkspacePage.jsx split). Deferred by design because it must ride on a stable API surface.
- **Regression test needed**: Playwright test that pastes 7 KB blob, clicks AUTO INVESTIGATE, asserts no `longtask > 15000 ms`.

### P1-02 · Defanged IOCs not extracted at top-level
- **Where**: `services/artifact_splitter.py::split_artifacts` (or wherever IOC extraction happens for article body)
- **Evidence**: The Sophos article's `149[.]28[.]81[.]19` (defanged) appears 3× in reader comments; top-level IOC extractor returned 0 IPs. Only the chain decoder's `peeled_iocs` surfaced the C2 IP.
- **Impact**: Any DFIR blog post with defanged IPs is under-extracted at the top-level IOC panel
- **Fix effort**: ~2 hours (refang `[.]` → `.` and `hxxp` → `http` before regex extraction)
- **Regression test needed**: `test_defanged_ioc_extraction.py`

### P1-03 · `v2/investigation/pipeline` (canonical) not wired to workspace
- **Where**: `frontend/src/pages/WorkspacePage.jsx::autoInvestigate`
- **Evidence**: Verification grep §Q2 — WorkspacePage calls `/api/decode/*` and `/api/v2/analyze/report` only. No route through `v2/investigation/pipeline`.
- **Impact**: The "canonical" pipeline picked in ADR-004 is not on the user path. Every workspace investigation still runs through legacy paths.
- **Fix**: This IS migration step 3.

### P1-04 · Trajectory canvas reads from BKB projection, not evidence graph
- **Where**: `frontend/src/components/investigation/TrajectoryDiagram.jsx` ← consumes clusters from `routers/cases.py:343` ← `services/ice/correlate::enrich_clusters_in_place`
- **Impact**: The canonical evidence graph (`engine/evidence_graph.py`) is not visible in the analyst's primary visualization
- **Fix**: This IS migration step 4.

### P1-05 · `%COMSPEC%` and `start /b /min` wrappers were dropping commands until today
- **Status**: FIXED this session (canonicalizer + `_HEAD_START` regex + `_consider` 32 KB cap)
- **Regression test added**: `tests/test_url_classifier_powershell_bug.py` (13 tests locking the fix)
- **Keep**: yes — this is the "known good" behavior to preserve during migration

### P1-06 · `cmd /c foo bar baz` was collapsing to `cmd /c foo` (single-token inner)
- **Where**: `services/canonicalizer/__init__.py` line 236 (before fix)
- **Status**: FIXED this session
- **Regression test needed**: `test_canonicalizer_multi_token_inner.py` (does not yet exist explicitly)

### P1-07 · `\bpowershell\b` regex matched URL path substring, misclassifying URLs
- **Where**: `services/die/input_understanding.py`
- **Status**: FIXED this session
- **Regression test**: `tests/test_url_classifier_powershell_bug.py` (shipped)

### P1-08 · `-EncodedCommand` payload decoded but not surfaced in analyst text
- **Where**: `services/ida/artifact_router.py::investigate_artifact` (before fix)
- **Status**: FIXED this session — `recovered_payload` + `decode_stages` + `peeled_iocs` now rendered in Command Analysis panel

### P1-09 · `AutoHotkey stager` false positive from base64 substring
- **Where**: `services/ida/behaviors.py::classify_command` (line 295)
- **Root cause**: `"ahk" in h` matched base64 substring when head was the entire wrapped command
- **Status**: FIXED this session (tightened to `\b(?:autohotkey|ahk)(?:\.exe|_l)?\b`)
- **Regression test needed**: `test_ahk_false_positive.py`

### P1-10 · Sophos community URL (Imperva-protected) acquisition fails
- **Where**: `services/ida/acquisition.py`
- **Status**: FIXED this session — Wayback Machine fallback added; Playwright given real Chromium UA
- **Regression test needed**: `test_wayback_fallback.py` (mock httpx returning tiny anti-bot page)

---

## P2 · Medium-severity (deferred, but documented)

- 89 memory/*.md files — curation debt, blocks fast fork onboarding
- 34 frontend pages — audit + delete unused
- No structured logging / no Prometheus metrics
- No PDF report export UI wired (backend module exists — `engine/report_pdf.py`)
- No BKB admin UI
- No audit log of analyst actions
- Multiple provenance modules coexist (Amendment A2 review pending)
- Golden corpus fragmented across 3 locations

---

## Baseline snapshot required BEFORE migration step 1

The following behavioral snapshots must be captured (using vendor corpus) and committed to the repo as "before" state:

1. **Verdict snapshot** — verdict + confidence + top techniques for each of the 20 pinned Tier-1 corpus reports. Saved as `backend/corpus/vendor/v1/reports/baseline_verdicts.json`.
2. **Chain decode snapshot** — for each PowerShell-encoded corpus entry, the full 4-stage output (stage names + byte counts + peeled_iocs). Saved as `backend/corpus/vendor/v1/reports/baseline_chain_decodes.json`.
3. **BKB projection snapshot** — for each canonical behavior, the full technique/tactic list. Saved as `backend/corpus/vendor/v1/reports/baseline_bkb_projections.json`.
4. **IOC extraction snapshot** — full IOC set (grouped by type) for each corpus entry. Saved as `backend/corpus/vendor/v1/reports/baseline_iocs.json`.

Effort: ~2-3 days to build the harness + capture. Post-migration these become the parity gates for every step.

---

## Test files that MUST exist before ADR-004 migration step 1 begins

| Test | Path | Status |
|---|---|---|
| Verdict parity (3-way) | `backend/tests/test_verdict_engine_parity.py` | **MISSING — create** |
| Defanged IOC extraction | `backend/tests/test_defanged_ioc_extraction.py` | **MISSING — create** |
| Canonicalizer multi-token inner | `backend/tests/test_canonicalizer_multi_token_inner.py` | **MISSING — create** |
| AHK false positive | `backend/tests/test_ahk_false_positive.py` | **MISSING — create** |
| Wayback fallback | `backend/tests/test_wayback_fallback.py` | **MISSING — create** |
| SSRF blocked | `backend/tests/test_ssrf_blocked.py` | **MISSING — create** |
| URL vs PowerShell classifier | `backend/tests/test_url_classifier_powershell_bug.py` | ✅ EXISTS (13 tests) |
| BKB CI gate | `backend/tests/test_bkb_ci_gate.py` | ✅ EXISTS |
| Quality dashboard floors | `backend/tests/test_quality_dashboard.py` | ✅ EXISTS |

---

## Recommendation

Complete Step 0 (P0/P1 bug baseline) in this order:

1. **Fix P0-01 (SSRF)** — 4 hours. Non-negotiable before any customer-facing test.
2. **Capture 4 baseline snapshots** — 2-3 days. These are the parity gates.
3. **Create the 6 missing regression tests** — 1-2 days. These lock the fixes already shipped this session.
4. **Fix P1-02 (defanged IOC)** — 2 hours. Low-effort correctness improvement.

Then and only then start ADR-004 migration step 1 (Verdict Engine).

Estimated Step 0 duration: **3-5 working days**.

_End of P0/P1 Bug Baseline._
