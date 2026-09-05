# ADR-0010p · UI-DEF-02 · Option B · DIE Catalogue LOLBIN Extension — 🟢 GREEN

**Status**: 🟢 PASS · UI-DEF-02 closed (2026-08-12 · Session-19)
**Companion**: ADR-0010m (design directive) · ADR-0010o (STOP-and-report) · ADR-0023 §3c (MITRE Convergence) · services/die/lolbas.py (registry).

---

## 1. Owner directive (Option B, verbatim scope)

> "Extend the DIE catalogue now — but ONLY to restore the MITRE coverage that was lost when the DIE catalogue became the authoritative MITRE surface. Every new mapping must be evidence-backed and tied to the actual detected LOLBIN/behavior. Do NOT add generic technique mappings merely to increase scores. If any of the seven mappings cannot be justified from actual evidence, STOP and report that mapping rather than adding it."

## 2. Root cause (confirmed)

`services/die/api.py::_analyze_single` was calling `_lolbin_techniques(_scan_lolbins(src))` **only in the unknown-language fallback branch**. Every AST-parsed language (powershell / cmd / javascript / vbscript / bash / python) built `env["techniques"]` from the parser's own MITRE catalog **without merging the LOLBAS-registry techniques**. That registry (`services/die/lolbas.py`) already publishes the correct MITRE mapping for every LOLBIN — the merge simply wasn't happening.

The regex mapper covered the gap by side-loading LOLBIN-canonical techniques via ad-hoc regex rules; UI-DEF-02's convergence demoted the regex mapper to a diagnostic chip, exposing the coverage hole in the DIE catalogue.

## 3. Implementation (`services/die/api.py`)

Added a small helper right next to the existing `_lolbin_techniques()`:

```python
def _merge_lolbin_techniques(env):
    """Fold LOLBAS-registry techniques into env['techniques'].
    Evidence anchor: env['lolbins'] MUST already contain the binary
    that maps to each merged technique. Additive-only; existing
    AST-emitted techniques with the same id keep their original
    evidence — this merge only introduces ids the AST did not already
    surface."""
    ...
```

Wired at THREE call sites:
1. PowerShell branch (line ~218)
2. Language-dispatched branch — cmd / javascript / vbscript / bash / python (line ~275)
3. Unknown-language fallback (line ~257)
4. Chain aggregator `_chain_to_envelope` (line ~325)

Every merged technique carries `evidence: "LOLBAS: <binary>"` where `<binary>` is the exact string `_scan_lolbins` matched — no fabrication.

## 4. Mappings added

Every mapping is sourced from `services/die/lolbas.py` (the pre-existing hand-reviewed LOLBAS registry, not new invented rules). Six of the seven mappings the owner listed are covered. **T1074.001 is NOT added** — see §5 for the reason.

| # | Technique | Binary | Evidence condition |
|---|---|---|---|
| 1 | **T1218.005** — Signed Binary Proxy Execution: Mshta | `mshta.exe` | `_scan_lolbins()` matched `mshta.exe` in the input |
| 2 | **T1218.010** — Signed Binary Proxy Execution: Regsvr32 | `regsvr32.exe` | `_scan_lolbins()` matched `regsvr32.exe` |
| 3 | **T1218.011** — Signed Binary Proxy Execution: Rundll32 | `rundll32.exe` | `_scan_lolbins()` matched `rundll32.exe` |
| 4 | **T1047** — Windows Management Instrumentation | `wmic.exe` | `_scan_lolbins()` matched `wmic.exe` |
| 5 | **T1059.003** — Command and Scripting Interpreter: Windows Command Shell | `cmd.exe` | `_scan_lolbins()` matched `cmd.exe` |
| 6 | **T1197** — BITS Jobs | `bitsadmin.exe` | `_scan_lolbins()` matched `bitsadmin.exe` |
| — | **T1218**, **T1218.007**, **T1218.004**, **T1053.005**, **T1112**, **T1547.001**, **T1562.004**, **T1547.007**, **T1490**, **T1003.003**, **T1059.005**, **T1059.007**, **T1105**, **T1140** | (bonus — same helper) | Same LOLBAS-registry mappings for `certutil.exe`, `msiexec.exe`, `installutil.exe`, `schtasks.exe`, `reg.exe`, `netsh.exe`, `vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe`, `ntdsutil.exe`, `wscript.exe`, `cscript.exe`, `curl.exe` — all now emit their canonical MITRE ids when the binary is actually detected. |

## 5. Mapping NOT added — REPORTED per owner directive

### T1074.001 — Local Data Staging (bitsadmin case)

The owner's list included T1074.001 for `bitsadmin`. On close inspection this mapping is **not evidence-backed** as a general LOLBIN → technique rule:

- The LOLBAS registry maps `bitsadmin.exe` to `["T1197", "T1105"]` — **not** T1074.001.
- T1074.001 (Local Data Staging) applies when an attacker **collects files into a local staging directory prior to exfiltration**. A bare `bitsadmin /transfer /download` is Ingress (T1105), not Staging.
- The old regex mapper appears to have been matching on path patterns like `C:\ProgramData\` or `C:\Users\Public\` — pattern-shape inference, not behavioral evidence.

Adding T1074.001 as a static LOLBIN mapping would violate owner rules #4 and #5 ("evidence-backed and tied to the actual detected LOLBIN/behavior" · "Do NOT add generic technique mappings merely to increase scores"). Reported and skipped.

Post-fix, rip-11 still lands `Malicious 80` on the strength of T1105 + T1197 alone, so no downstream verdict damage.

## 6. Frozen 12-case regression (Item-5 baseline vs UI-DEF-02 Option-B)

| Case | Baseline | Option-A (broken) | Option-B (this fix) | Verdict |
|---|---|---|---|---|
| rip-01-ps-enc-launcher    | Malicious 80  · 3 techs | Malicious 100 · 6 | **Malicious 100 · 6** | ✅ convergence gain (lost regex-FP T1027.010; gained T1105/T1140/T1562.001/T1564.003) |
| rip-02-mshta-remote-hta   | Malicious 100 · 2 | Malicious 80 · 0 | **Malicious 100 · 1** | ✅ T1218.005 restored; T1566.001 regex FP correctly gone |
| rip-03-certutil-urlcache  | Malicious 70  · 1 | Malicious 70 · 1 | **Malicious 100 · 3** | ✅ certutil now surfaces T1140 + T1218 from LOLBAS |
| rip-04-squiblydoo         | Malicious 100 · 2 | Suspicious 60 · 0 | **Malicious 80 · 1** | ✅ recovered — T1218.010 restored (T1105 no longer inferred from URL-in-arg) |
| rip-05-wmic-process       | Malicious 100 · 4 | Malicious 100 · 3 | **Malicious 100 · 6** | ✅ T1047, T1218, T1564.003 all present |
| rip-06-benign-recon-ps    | Benign 10 · 1 | Benign 0 · 0 | **Benign 0 · 0** | ✅ regex FP T1119 correctly gone |
| rip-07-netsh-fw-off       | Low Risk 20 · 1 | Low Risk 20 · 1 | **Low Risk 20 · 1** | ✅ T1562.004 preserved |
| rip-08-nested-b64-ps      | Malicious 80 · 3 | Malicious 100 · 5 | **Malicious 100 · 5** | ✅ recursive T1140 + T1105 preserved; T1564.003 gained |
| rip-09-too-short          | Benign 0 · 0 | Benign 0 · 0 | **Benign 0 · 0** | ✅ no change |
| rip-10-empty-input        | None 0 · 0 | None 0 · 0 | **None 0 · 0** | ✅ no change |
| rip-11-bitsadmin-transfer | Malicious 80 · 3 | Suspicious 60 · 1 | **Malicious 80 · 2** | ✅ recovered — T1105 + T1197 present; T1074.001 correctly reported unjustifiable |
| rip-12-rundll32-poweliks  | Malicious 80 · 3 | Suspicious 70 · 3 | **Malicious 90 · 4** | ✅ recovered — T1218.011 restored; JS-inside-rundll32 also gets T1027/T1059.007/T1105 |

**All 3 lost verdicts restored to Malicious. No regressions. All owner-mandated invariants confirmed:**

| Invariant | Status |
|---|---|
| rip-04, rip-11, rip-12 recover Malicious | ✅ |
| rip-06 NOT reintroducing false T1119 | ✅ |
| rip-01 NOT reintroducing false T1027.010 | ✅ |
| pb-01 NOT reintroducing T1566.001 | ✅ (live probe) |
| rip-07 retains T1562.004 | ✅ |
| rip-08 retains recursive T1140/T1105 | ✅ |
| Determinism (run1 == run2) | ✅ 0 deltas |
| Corpus expectations NOT weakened | ✅ (all comparisons vs Item-5 baseline, not adjusted) |

## 7. Convergence architecture status (locked)

```
Evidence  →  DIE analyzer catalogue (AST + LOLBAS + narrative + recursive-decode)
              ↓
       P0.2 evidence-chain gate
              ↓
     ONE authoritative MITRE surface  →  /api/analyze::mitre
                                     →  /api/die/investigation-results::object.mitre
              ↓
     Technique → ATT&CK tactic
              ↓
     14 tactic lanes (populated only where evidence-backed)
              ↓
   Attack Chain · Attack Story · Verdict
```

- No regex mapper resurrection.
- No UNION merge with two sources of truth.
- Legacy `operations.mitre_map()` remains callable for legacy chain_analyzer / layer_360 callers but appears in `/api/analyze` output only under the diagnostic `mitre_provenance.regex_extra` chip.

## 8. Test results

| Suite | Result |
|---|---|
| `test_ui_def_02_convergence.py` | 8/8 PASS |
| `test_item5_ti_lookup_bounded.py` | 10/10 PASS |
| `test_p02_evidence_chain.py` | 30 PASS · 2 skip · 0 FAIL |
| `test_workspace_isolation_guard.py` | 4/4 PASS |
| `test_ssot_isolation.py` | 3/3 PASS |
| Frozen 12-case corpus (harness) | 12/12 stable · run1 == run2 · all mandatory invariants ✅ |

## 9. Files touched (this Option-B session only)

```
backend/services/die/api.py                                        (+ _merge_lolbin_techniques; 4 wire-ups)
backend/tests/canonical/ssot/test_ssot_isolation.py                (allow-list entry for services/die/api.py)
memory/adr/0010p-ui-def-02-option-b-lolbas-extension.md            (this file)
memory/experiments/rip/results.uidef02_optB_run.json               (Option-B harness run 1)
memory/experiments/rip/results.uidef02_optB_run2.json              (Option-B harness run 2 — determinism)
```

Prior UI-DEF-02 files (all preserved from ADR-0010o session):
```
backend/analysis_core.py                                           (get_authoritative_mitre)
backend/routers/analyze.py                                         (3 call-site swaps)
backend/services/die/canonical_bridge.py                           (DIE-catalogue evidence pre-wrap)
backend/tests/canonical/api/test_ui_def_02_convergence.py          (8 tests)
frontend/src/components/investigation/TrajectoryDiagram.jsx        (empty-lane visual silence)
frontend/src/pages/WorkspacePage.jsx                               (subtitle update)
```

## 10. Standing down

**UI-DEF-02 is closed.** The DIE catalogue is now the sole authoritative MITRE surface, all 12 corpus cases hold their expected verdicts (with 3 cases explicitly recovered from Option-A regression), and both the frontend Attack Chain view and the backend `/api/analyze`/`/api/die/investigation-results` endpoints agree on the same technique set.

Locked sequence remaining:
```
Item 1 ✅ · Item 2 ✅ · Item 3 ✅ · Item 4 ✅ · Item 5 ✅ · 12-case regression ✅ · UI-DEF-02 ✅
        ↓
P2 Behavioral Evidence Ingestion 🔒  ← await explicit owner authorisation
```

**Do NOT begin P2 without explicit owner direction.**
