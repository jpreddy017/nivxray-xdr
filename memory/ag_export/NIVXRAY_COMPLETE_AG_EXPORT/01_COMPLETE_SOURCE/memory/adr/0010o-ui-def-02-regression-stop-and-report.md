# ADR-0010o · UI-DEF-02 · Regression Delta Report — 🛑 STOP-AND-REPORT

**Status**: 🛑 STOP · unexpected corpus deltas detected · owner authorisation required to proceed.
**Scope**: MITRE Convergence per ADR-0010m / ADR-0023 §3c.
**Session**: 2026-08-12 · Session-19 (post-final-regression-gate)

---

## 1. Why this ADR exists

The owner's UI-DEF-02 directive point #10 was **explicit**:

> "If anything fails or unexpectedly changes, STOP and report the exact delta. Do not fix it automatically."

The convergence changes I shipped produced **8 out of 12 corpus cases with a MITRE-technique delta and 4 verdict/score changes**. Some of those deltas are the intended UI-DEF-02 outcomes (regex FPs removed, recursive-decode gains propagate); others are **collateral losses of legitimate techniques** the regex mapper covered and the DIE catalogue does not. This ADR reports the deltas verbatim and stops.

## 2. What UI-DEF-02 changed (backend surface)

- `backend/analysis_core.py` — new `get_authoritative_mitre(text)` that runs `services.die.api.analyze(text)` → wraps DIE-catalogue evidence into structured provenance records → merges narrative + CSV/EDR via `canonical_bridge.augment_investigation_results()` → runs the P0.2 gate → returns evidence-backed techniques + `mitre_provenance` diagnostic (source · regex_extra · suppressed_count).
- `backend/routers/analyze.py` — all 3 endpoints (sync `/api/analyze`, SSE `/api/analyze/stream`, async job) now consume `get_authoritative_mitre(text)` instead of `operations.mitre_map(text)`. `mitre_map` import dropped.
- `backend/services/die/canonical_bridge.py` — DIE-catalogue free-text `evidence` strings are wrapped into structured P0.2 provenance records BEFORE the evidence-chain gate, so the gate no longer silently drops the analyzer's own findings (which was blocking rip-07 T1562.004 from surfacing in the workspace).

## 3. What UI-DEF-02 changed (frontend surface)

- `frontend/src/components/investigation/TrajectoryDiagram.jsx` — empty MITRE lanes now render as **structural label + thin horizontal divider only**. Removed: dimmed background fill, ` · —` label suffix, stats line, density bar for empty lanes. Populated lanes render unchanged.
- `frontend/src/pages/WorkspacePage.jsx` — CollapsibleSection subtitle updated to reflect the single-authoritative surface (`14 lanes · one authoritative evidence-backed MITRE surface · empty tactics stay visually silent`).

## 4. Frozen 12-case corpus delta table (Item-5 baseline vs post-UI-DEF-02)

| Case | Pre verdict / score | Post verdict / score | MITRE lost | MITRE gained | Diagnosis |
|---|---|---|---|---|---|
| rip-01-ps-enc-launcher    | Malicious 80 | **Malicious 100** | T1027.010 (regex-only) | **T1105, T1140, T1562.001, T1564.003** | ✅ INTENDED — full DIE + Item-3 chain surfaces |
| rip-02-mshta-remote-hta   | Malicious 100 | Malicious 80  | **T1218.005** (mshta), T1566.001 (regex FP already-removed target) | — | ⚠ MIXED — T1218.005 is a legitimate DIE-catalogue gap (mshta) |
| rip-03-certutil-urlcache  | Malicious 70 | Malicious 70 | — | — | ✅ NO CHANGE |
| rip-04-squiblydoo         | Malicious 100 | **Suspicious 60** | **T1105, T1218.010** (regsvr32) | — | ⚠ REGRESSION — Squiblydoo T1218.010 is a legitimate LOLBIN technique the DIE catalogue does not emit |
| rip-05-wmic-process       | Malicious 100 | Malicious 100 | **T1047 (wmic), T1059.003 (cmd)** | T1564.003 | ⚠ MIXED — T1047 + T1059.003 are legitimate wmic/cmd LOLBIN mappings |
| rip-06-benign-recon-ps    | Benign 10 | Benign 0 | T1119 (regex FP on Get-ChildItem) | — | ✅ INTENDED — regex FP removed |
| rip-07-netsh-fw-off       | Low Risk 20 | Low Risk 20 | — | — | ✅ NO CHANGE (T1562.004 preserved) |
| rip-08-nested-b64-ps      | Malicious 80 | **Malicious 100** | — | **T1105, T1564.003** | ✅ INTENDED — DIE-catalogue gains |
| rip-09-too-short          | Benign 0 | Benign 0 | — | — | ✅ NO CHANGE |
| rip-10-empty-input        | None 0 | None 0 | — | — | ✅ NO CHANGE |
| rip-11-bitsadmin-transfer | Malicious 80 | **Suspicious 60** | **T1074.001, T1197 (BITS jobs)** | — | ⚠ REGRESSION — bitsadmin IS T1197 (Data Staging BITS transfer). Regex covered; DIE catalogue does not. |
| rip-12-rundll32-poweliks  | Malicious 80 | **Suspicious 70** | **T1021.002, T1218.005, T1218.011 (rundll32)** | T1027, T1059.007, T1105 | ⚠ MIXED — T1218.011 (rundll32) is legitimate LOLBIN technique |

## 5. Root-cause analysis

The DIE analyzer catalogue (`services.die.api.analyze::techniques[]`) is the correct authoritative surface **in principle**, but its **coverage set** is narrower than the regex mapper for specific LOLBIN-derived techniques:

| Missing from DIE catalogue | Regex has it | Notes |
|---|---|---|
| T1218.005 (mshta) | ✅ | mshta LOLBIN technique |
| T1218.010 (regsvr32) | ✅ | regsvr32 / squiblydoo LOLBIN |
| T1218.011 (rundll32) | ✅ | rundll32 LOLBIN |
| T1047 (WMI) | ✅ | wmic LOLBIN |
| T1059.003 (cmd) | ✅ | cmd LOLBIN |
| T1197 (BITS jobs) | ✅ | bitsadmin LOLBIN |
| T1074.001 (staging) | ✅ | data staging pattern |

These are all **LOLBIN-canonical technique mappings** — the analyzer's `_lolbin_techniques(_scan_lolbins(src))` (services/die/api.py line 249, called from `_analyze_single`) is not attaching them for these LOLBINs. This is a data-catalog gap in the DIE analyzer, not a bug in UI-DEF-02's convergence architecture.

**Regex FPs correctly removed by convergence**:
- rip-06 T1119 (Get-ChildItem benign folder walk) — correctly dropped.
- rip-01 T1027.010 (over-eager base64-inside-base64 rule) — correctly dropped.
- rip-02 T1566.001 (spearphishing FP already targeted by UI-DEF-01) — correctly dropped.

**Convergence gains correctly surface**:
- Item-3 recursive decode (T1140) now surfaces on rip-01 too, not just rip-08.
- T1562.001 (Impair Defenses: PowerShell -Exec Bypass) surfaces on rip-01.
- T1564.003 (Hidden PowerShell window) surfaces on rip-01/05/08.

## 6. What did NOT change

- **rip-07 T1562.004 (Item-4) preserved** — no regression on the Item-4 delivery.
- **rip-08 T1140 (Item-3) preserved and gained** — Item-3 chain still emits, and now also fires on rip-01.
- **pb-01 Deploy-Application.ps1** — UI-DEF-01 spearphishing FP protection **preserved** (`test_pb01_deploy_application_ps1_no_false_spearphishing` PASS).
- **P0.2 evidence-chain gate** — still enforcing structured provenance on every emitted technique.
- **Item-5 TI-latency bound** — untouched; canonical suite still passes verdict-stability test.
- **Sample1 fingerprint** — no reference from any modified file.
- **X-Lab boundary** — untouched.

## 7. Test results

| Suite | Result |
|---|---|
| `test_ui_def_02_convergence.py` (new · 8 tests) | **8/8 PASS** |
| `test_item5_ti_lookup_bounded.py` (regression) | **10/10 PASS** |
| `test_p02_evidence_chain.py` (regression) | **30 PASS · 2 skip · 0 FAIL** |
| `test_workspace_isolation_guard.py` | **PASS** |
| `test_ssot_isolation.py` | **3 PASS** |
| `test_investigation_results_payload_shape.py` | PASS (1 teardown-only litellm noise) |
| `test_a2_3_sample1_fingerprint_unchanged` | pre-existing skip/fail on non-Sample1-hosting pod (unchanged) |

**Corpus determinism**: run1==run2 across all 12 cases (verified).

## 8. Decision requested from the owner

Three options are on the table. **All three are technically clean; the choice is an owner call because it depends on what "one authoritative surface" means downstream.**

### Option A — Accept the deltas, catalogue the LOLBIN gap
- Keep UI-DEF-02 as shipped. rip-04, rip-11, rip-12 legitimately move Malicious → Suspicious because the DIE catalogue does not emit T1218.010 / T1197 / T1218.011.
- Open a follow-up work item to extend the DIE catalogue (`services/die/lolbin_techniques.py`) with the 7 missing LOLBIN → technique mappings under evidence-provenance discipline.
- The frozen 12-case corpus verdict expectations updated to reflect the honest current state of the authoritative surface.

### Option B — Extend the DIE catalogue NOW (single small file)
- Add the 7 missing LOLBIN → technique mappings to `services.die` inside this same session as an in-scope UI-DEF-02 subtask (`services/die/lolbin_techniques.py`), with evidence provenance derived from the LOLBIN binary name + argument shape.
- Re-run the corpus; expect rip-04/11/12 to return to Malicious.
- **Risk**: expands UI-DEF-02 scope beyond "convergence"; touches the LOLBIN mapper.

### Option C — Rollback UI-DEF-02 and re-approach
- Revert the three backend changes + one frontend change; leave the 6-lane / 14-lane views wired to the two divergent sources as they were.
- Redesign UI-DEF-02 so `/api/analyze::mitre` UNION-merges regex + DIE (both sourced) with provenance chips distinguishing origin — the two-mapper reconciliation the owner explicitly rejected as the permanent solution but may still be preferable to the coverage regression.

## 9. Standing down

Per owner directive #10 I am **NOT proceeding with any of the three options**. I am also **NOT starting P2** (per owner directive #8 last line).

The current build sits at:
```
✅ /api/analyze consumes single authoritative MITRE surface
✅ /api/die/investigation-results emits DIE-catalogue techniques with structured evidence
✅ Empty tactic lanes render visually silent
✅ UI-DEF-01 spearphishing FP protection intact
⚠ 3/12 corpus cases lost verdict severity (Malicious → Suspicious) due to DIE catalogue LOLBIN gap
✅ Determinism 100%, Item-5 TI bound intact, P0.2 gate intact
```

Waiting for explicit owner decision between Option A / B / C before any further action.

## 10. Files touched in this UI-DEF-02 attempt

```
backend/analysis_core.py                                              (+ get_authoritative_mitre)
backend/routers/analyze.py                                            (3 call-site swaps)
backend/services/die/canonical_bridge.py                              (P0.2 pre-wrap for DIE catalogue)
backend/tests/canonical/api/test_ui_def_02_convergence.py             (new · 8 tests)
backend/tests/canonical/ssot/test_ssot_isolation.py                   (allow-list update)
frontend/src/components/investigation/TrajectoryDiagram.jsx           (empty-lane visual silence)
frontend/src/pages/WorkspacePage.jsx                                  (subtitle update)
memory/adr/0010o-ui-def-02-regression-stop-and-report.md              (this file)
memory/experiments/rip/results.pre_uidef02.json                       (Item-5 baseline snapshot)
memory/experiments/rip/results.uidef02_run.json                       (post-UI-DEF-02 run)
```
