# NivXForge EDR · Path Reconciliation (6 Discrepancies from Gate 0)

> **Gate 0.5 · Read-only.** No code changed. No git ops.

## §1 · Discrepancy Ledger (evidence-anchored)

| ID | Documented path (Handoff) | Actual path on `feature/rc2` | Implementation status (live) | Correct canonical path | Doc correction required? | Code change required? |
|---|---|---|---|---|---|---|
| PD-1 | `backend/security_state/contracts.py` | **DOES NOT EXIST** — no `backend/security_state/` directory at all | Security-State FSM lives inline in **`backend/routers/rc5_entities.py` + `backend/routers/rc5_diag.py`**; supporting library in `backend/services/security_state/` (if present — grep also negative) → real anchor is `rc5_entities.py`. IMPLEMENTED_AND_WORKING. | `backend/routers/rc5_entities.py` (+ `rc5_diag.py`) | YES — Handoff, Code Map, and Truth Audit rows #23 must be updated | **NO** code change. Optional refactor `rc5_entities → services/security_state/` is out of scope and would violate the "no reasoning-engine change" rule during Phase 1 |
| PD-2 | `backend/security_state/detection_bridge.py` | **DOES NOT EXIST** | Detection-to-state promotion is coded inside `backend/routers/verdict_stage2.py` + `backend/services/verdict_stage2/*` + rc5 routers | inline in existing routers (no dedicated bridge file) | YES — Handoff Code Map must be corrected | **NO** |
| PD-3 | `backend/run_content_truth_audit.py` (referenced as authoritative verification) | **DOES NOT EXIST** | No introspection endpoint returns "615" either | either ship the script OR add `GET /api/xdr/detection/inventory` (recommended) | YES — Handoff and Reference docs must be corrected to point at whichever mechanism is chosen | Phase 0.5 code change: **YES** — new introspection endpoint OR script |
| PD-4 | `backend/verify_decoder_truth_e2e.py` (referenced as authoritative verification) | **DOES NOT EXIST** | 59 = 45 top + 14 family modules — verifiable via filesystem but no runtime endpoint | either ship the script OR add `GET /api/decode/registry/inventory` (recommended) | YES — same as PD-3 | Phase 0.5 code change: **YES** — new introspection endpoint OR script |
| PD-5 | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` (referenced by Code Map and Truth Audit) | **DOES NOT EXIST** | Real Evidence Explorer at `/app/frontend/src/pages/EvidenceExplorerPage.jsx` (main SPA). Companion investigation UI at `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`. Both IMPLEMENTED_AND_WORKING. | `/app/frontend/src/pages/EvidenceExplorerPage.jsx` for main SPA; the companion path may exist in a fork not currently on `feature/rc2` | YES — 4 references across Code Map, Truth Audit, UI Map, Attack-Chain doc | **NO** code change (UI is frozen) |
| PD-6 | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | **DOES NOT EXIST** | Real workspace at `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx`. Companion v2-style at `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`. Both IMPLEMENTED_AND_WORKING. | `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx` for main SPA | YES — Code Map + Truth Audit + UI Map | **NO** code change (UI is frozen) |

## §2 · Cross-file audit — where each discrepancy appears in the handoff

- **PD-1 / PD-2:** `EMERGENT_HANDOFF_README.md §F`, `NIVXFORGE_EDR_EMERGENT_HANDOFF.md §6 (table)`, `NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md §2 rows (Authoritative Security State)`, `NIVXFORGE_EDR_TRUTH_AUDIT.md §23`, `NIVXFORGE_EDR_RESPONSE_INTEGRATION_CONTRACT.md §3 row (Security State Intervention)`.
- **PD-3 / PD-4:** `EMERGENT_HANDOFF_README.md §C, §K1`, `NIVXFORGE_EDR_EMERGENT_HANDOFF.md §2, §25 acceptance criteria`, `HANDOFF_SCOPE_AND_BOUNDARIES.md §1.1`.
- **PD-5 / PD-6:** `NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md §2 rows (Evidence Explorer & Investigation Workspace)`, `NIVXFORGE_EDR_TRUTH_AUDIT.md §22, §15, §Findings-1, §Findings-2`, `NIVXFORGE_EDR_UI_INTEGRATION_MAP.md`.

## §3 · Do-not rules honoured

- ✅ No production code, tests, configs, UI modified.
- ✅ No git ops.
- ✅ Existing engines untouched.
- ✅ Reconciliation actions listed for owner approval.

## §4 · Recommended owner actions (before Phase 1)

1. **Publish an addendum** `NIVXFORGE_EDR_HANDOFF_PATH_ADDENDUM.md` inside the handoff package that overrides the six paths above.
2. **Approve Phase 0.5 code changes** for PD-3 and PD-4 (introspection endpoints — see §5.3 of `NIVXRAY_CONTENT_DECODER_TRUTH_RECONCILIATION.md`).
3. **Accept `NO CODE CHANGE`** for PD-1, PD-2, PD-5, PD-6. Reuse existing paths; do NOT create phantom modules.

## END · path reconciliation delivered · read-only
