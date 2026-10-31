# NivXRay · Current-State Truth Contract v2 (Gate 0.5 · new snapshot · NOT an amendment)

> **This is a NEW artifact, not an edit of v1.** The immutable Truth Contract v1 at commit **`d3f7a0a000892131abc9a32ee97009338dd38d79`** is preserved unchanged as the historical anchor.
> **Scope of v2:** record post-Gate-0.5 branch observations, resolve the 6 path discrepancies, register the two decoder trees, hold the 615-object claim at `UNVERIFIED_ON_CURRENT_BRANCH`, and index the two new introspection endpoints.
> **Governing rule (owner directive):** do not overwrite historical truth. Do not manufacture cardinalities. Runtime + code evidence remains authoritative over documentation.

---

## §1 · Provenance chain

| Snapshot | Commit / Location | Status | Purpose |
|---|---|---|---|
| Truth Contract v1 (immutable historical) | `d3f7a0a000892131abc9a32ee97009338dd38d79` — `docs/truth-contract/{NIVXRAY_CURRENT_STATE_TRUTH.md,NIVXRAY_CURRENT_STATE.json}` | **FROZEN — DO NOT MODIFY** | historical baseline for Antigravity |
| Truth Contract v2 (this file) | `/app/memory/edr_review/NIVXRAY_CURRENT_STATE_TRUTH_V2.md` (staged) · will land at `docs/truth-contract/v2/` after Save-to-Github | LIVE | branch-observation superset + reconciliation |

---

## §2 · Content Fabric — dual-perspective truth (do NOT collapse)

- **Historical AG audit claim (Handoff package):** `615-Object Content Fabric` (100% verified, active-certified, split as `600 active + 15 synthetic`).
- **Current branch filesystem evidence:** `backend/detection_content/` has **51 Python infrastructure modules** (`__init__.py` excluded) and **zero rule YAML/JSON/SIGMA files**. `backend/detection_content/corpus/` and `backend/detection_content/yara_engine.py` are **MISSING_FROM_BRANCH**.
- **Live runtime (Mongo) evidence on this pod:**
  - `detection_content` collection: 1 doc
  - `xdr_detection_rules`: 93 docs
  - `xdr_correlation_rules`: 5 docs
  - `xdr_capability_contracts`: 339 docs
  - `xdr_engines`: 339 docs
  - **None equals 615; no combination equals 615.**
- **v1 (immutable) claim about content fabric:** did not name a cardinality. v1 recorded the registry framework as IMPLEMENTED_AND_WORKING; count deliberately unstated.
- **v2 classification per owner rule:** `content_fabric_cardinality_claim_615 = UNVERIFIED_ON_CURRENT_BRANCH`. The registry framework itself is IMPLEMENTED_AND_WORKING.
- **Truth endpoint:** `GET /api/xdr/detection/inventory` (Gate 0.5 · new · RBAC-gated) reports the above in machine-readable form.

## §3 · Decoder trees — TWO cooperating trees (do NOT collapse)

Owner-required distinction preserved (per Gate 0.5 letter):

| Facet | Value | Source of truth |
|---|---|---|
| A · Verified decoder modules on current branch | **59** = 45 top-level + 14 family | filesystem of `backend/decoders/` |
| B · EDR Truth Audit claim | "48 logical + 14 family = 62" (implied) OR "59" in Handoff README | Handoff docs (drift-of-3 vs filesystem) |
| C · DDO codec-family count | **7** (`base64_codec`, `compression`, `crypto`, `encoding`, `powershell_encoded_command`, `transform`, `xor_brute`) | v1 Truth Contract |
| D · DDO signature count | **14** (regex-line-count heuristic; canonical per v1) | `services/decoder/orchestrator.py` |
| E · Malware-family profilers | 14 (Cobalt Strike, Emotet, Formbook, …) | `backend/decoders/families/` |

**Runtime architecture fact recorded in v2:** the pod imports from BOTH trees. `server.py` imports `from decoders import …` for 40+ legacy modules AND uses `services/decoder/orchestrator.py` DDO. The v1 phrase "single authoritative Universal Decoder runtime" is **BRANCH_DIVERGENCE** — v2 supersedes with "dual cooperating decoder trees, both IMPLEMENTED_AND_WORKING". This does NOT modify v1; v2 records the new observation.

- **Truth endpoint:** `GET /api/decode/registry/inventory` (Gate 0.5 · new · RBAC-gated).

## §4 · Path reconciliation (six discrepancies from Gate 0)

| ID | Doc-referenced path | Reality | v2 resolution |
|---|---|---|---|
| PD-1 | `backend/security_state/contracts.py` | MISSING | Real anchor = `backend/routers/rc5_entities.py` (+ `rc5_diag.py`). Doc-only correction. No code rename authorized. |
| PD-2 | `backend/security_state/detection_bridge.py` | MISSING | Inline in `routers/verdict_stage2.py` + rc5. Doc-only correction. |
| PD-3 | `backend/run_content_truth_audit.py` | MISSING | Superseded by `GET /api/xdr/detection/inventory`. |
| PD-4 | `backend/verify_decoder_truth_e2e.py` | MISSING | Superseded by `GET /api/decode/registry/inventory`. |
| PD-5 | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | MISSING | Real anchor = `/app/frontend/src/pages/EvidenceExplorerPage.jsx` (main SPA). Handoff addendum required. UI freeze applies. |
| PD-6 | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | MISSING | Real anchor = `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx`. Handoff addendum required. UI freeze applies. |

## §5 · AD-03 provisional-approval note (owner asked for confirmation)

Owner authorized reuse of `rc5_entities.py` as the Security-State module **provided** it is architecturally the correct owner. Emergent's read of the code:

- `backend/routers/rc5_entities.py` (verified live) implements the FSM states, transitions, and enforcement APIs. It is the sole reachable route surface for the FSM.
- No competing module claims Security-State ownership. `backend/services/security_state/` does NOT exist. Grep for `class SecurityState` / `SECURITY_STATE` / `AUTHORITATIVE_SECURITY_STATE` returned zero hits outside rc5.
- Coupling concerns: `verdict_stage2.py` and `rc5_entities.py` are decoupled — rc5 exposes reads; verdict consumes them via HTTP or import. No semantic duplication observed.

**Emergent's confirmation:** rc5 IS the correct existing owner of Security-State FSM. **No semantic coupling or duplicate ownership detected.** AD-03 is safe to lift from provisional to full approval on this evidence.

## §6 · Gate 0.5 code changes actually landed (authorised only)

| Change | File(s) | Nature | Regression? |
|---|---|---|---|
| Add truth-inventory router | `backend/routers/truth_inventory.py` (NEW) | additive, read-only, RBAC-gated | none — new file only |
| Wire router into app | `backend/server.py` (+3 lines after existing `xdr_detection_content` include) | additive | none — 87/87 observability + decoder-harness tests pass |
| Add P0-D adversarial test suite | `backend/tests/edr/test_cross_tenant.py` + `backend/tests/edr/__init__.py` | test-only | 12/12 pass |
| Docs | this file + Gate 0.5 reconciliation MDs | doc-only | n/a |

**Regression protection audit:**
- `pytest tests/observability_tests tests/decoder_harness tests/corpus -q` → **163 passed + 1 intentional mal-20 FN**. Matches baseline (v1 Truth Contract).
- `pytest tests/edr` → **12/12 pass** (new).
- Content Fabric untouched: `backend/detection_content/**` unchanged.
- Decoders untouched: `backend/decoders/**`, `backend/services/decoder/**` unchanged.
- Reasoning engines untouched: `backend/routers/verdict_stage2.py`, `backend/routers/rc5_entities.py`, `backend/routers/rc5_diag.py`, `backend/reasoning/**`, `backend/services/verdict_stage2/**`, `backend/services/ikg/**` unchanged.
- UI untouched: `frontend/**`, `apps/nivxray-xdr/**` unchanged.
- Live smoke: `/api/health`, `/api/metrics`, `/api/openapi.json`, `/api/xdr/detection/inventory` (new, RBAC-gated), `/api/decode/registry/inventory` (new, RBAC-gated) all return 200/expected.

## §7 · Owner-directed rules honoured

- ✅ Immutable `d3f7a0a000892131abc9a32ee97009338dd38d79` **untouched**.
- ✅ v2 is a NEW snapshot, not an amendment.
- ✅ 615 recorded as `UNVERIFIED_ON_CURRENT_BRANCH`.
- ✅ Decoder split (A / B / C / D / E) preserved in truth endpoint output.
- ✅ Truth endpoints RBAC-gated (`Depends(get_current_user)`).
- ✅ No Phase 1 EDR implementation.
- ✅ No sensor / no telemetry stream / no FIM / no network / no response drivers / no sandbox / no UBAE / no EDR UI.
- ✅ No git operations from the agent.

## §8 · What v2 does NOT do

- v2 does NOT modify v1.
- v2 does NOT introduce Phase 1 code.
- v2 does NOT declare a canonical 615 count.
- v2 does NOT rename `rc5_entities.py`.
- v2 does NOT touch the UI.

## END · Truth Contract v2 delivered · read-only · awaiting owner review
