# NivXRay XDR · Architectural Binding Check + Correction to Step-3 Smoke Test

> **Basis:** Owner directive — "Before implementing Wiring Fix (b), perform a source-level architectural binding check and identify the existing authoritative IUE, ICE, IKG, VEEE/Verdict entrypoints."
> **Also:** Corrects a factual error in `NIVXRAY_XDR_STEP3_CANONICAL_EVIDENCE_SMOKE_TEST_EVIDENCE.md` (queried wrong Mongo collection name).
> **Mode:** STRICT READ-ONLY. No code, tests, configs, UI, or Mongo mutation.
> **Product:** NivXRay XDR.

---

## 1 · Correction to prior smoke-test evidence (§4 of `STEP3_CANONICAL_EVIDENCE_SMOKE_TEST_EVIDENCE.md`)

**Previous claim:** "`canonical_evidence` collection = 0 docs after ingest."
**Correction:** The classical canonical-evidence collection is named **`xdr_canonical_evidence`** (not `canonical_evidence`). Actual count: **219 documents**.

This is a factual error in my earlier report. It does NOT change the top-level finding (v2 ingest does not propagate to the reasoning fabric), but it changes the *reason* the propagation fails.

Corrected picture:

- `xdr_canonical_evidence` collection **exists and holds 219 real records** from prior runs of the authoritative orchestrator `xdr_pipeline.py::process_event_through_pipeline`.
- Sources present in that collection today: `cortex_xdr` (15 docs) and `Snort / Suricata` (186 docs), plus 18 unlabeled.
- **Zero of the 219 records reference our newly ingested `case_golden_lolbas_certutil_a2cfb96f`** — because the `seed_golden` code path did not invoke the orchestrator.
- **No `sysmon` records exist in `xdr_canonical_evidence`** — because there is no `SysmonDSM` registered in the DSM_REGISTRY today (registry contains `SnortEveDSM`, `WindowsSecurityDSM`, `LinuxAuditdDSM`, `AWSCloudTrailDSM`).

The three-gap taxonomy from Addendum-01 is unaffected. Gap A is still partial for the reasons documented; the specific reason is now more precisely known.

---

## 2 · Architectural Binding Check — authoritative entrypoints

Owner requirement: implementation of Fix (b) MUST reuse the existing engines, not create parallel ones.

### 2.1 · Authoritative orchestrator

**`backend/detection_content/xdr_pipeline.py::process_event_through_pipeline(db, raw_event, trace_id, integration_id, collector_id)`**

Verified via `head -60`:
```python
from .xdr_iue        import understand   as iue_understand
from .xdr_ice        import correlate    as ice_correlate
from .xdr_veee       import compute_verdict as veee_compute
from .xdr_incident   import materialise_incident
from .xdr_investigation import project_investigation
from .xdr_response_fabric import orchestrate as response_orchestrate
from .xdr_closed_loop import recompute as closed_loop_recompute
from .xdr_framework_mapping import resolve_mappings as framework_resolve

CANONICAL_COLLECTION = "xdr_canonical_evidence"

async def process_event_through_pipeline(db, raw_event, trace_id, integration_id, collector_id):
    # DSM → Parser → Normalizer → Canonical Evidence → Sigma Detection
    # → IUE → ICE → VEEE/Verdict → Incident → Investigation → Response → Closed loop
    ...
```

**This function IS the authoritative reasoning fabric. Fix (b) MUST reuse this — no parallel orchestrator.**

### 2.2 · Per-engine authoritative entrypoints

| Engine        | Authoritative file / function                                     | Reuse contract                                          |
| ------------- | ----------------------------------------------------------------- | ------------------------------------------------------- |
| IUE           | `detection_content/xdr_iue.py::understand`                        | consumed by orchestrator; input = canonical event + detection results |
| ICE           | `detection_content/xdr_ice.py::correlate`                         | consumed by orchestrator                                |
| VEEE / Verdict | `detection_content/xdr_veee.py::compute_verdict`                  | consumed by orchestrator                                |
| Incident materialise | `detection_content/xdr_incident.py::materialise_incident`  | consumed by orchestrator                                |
| Investigation projection | `detection_content/xdr_investigation.py::project_investigation` | consumed by orchestrator                        |
| Response fabric | `detection_content/xdr_response_fabric.py::orchestrate`          | consumed by orchestrator                                |
| Closed loop | `detection_content/xdr_closed_loop.py::recompute`                    | consumed by orchestrator                                |
| Framework mapping | `detection_content/xdr_framework_mapping.py::resolve_mappings` | consumed by orchestrator                            |
| Canonical Evidence store | Mongo collection `xdr_canonical_evidence`             | orchestrator writes once, all downstream engines read   |
| Security State | `security_state.routers.router` (14 endpoints) + `security_state/orchestration/library.py` | reuse; consumes downstream state, not called by orchestrator today |
| IKG           | **NO dedicated engine call in the orchestrator today** — see gap 2.4 below | needs investigation before Fix (b) |
| SSOT          | `investigation_ssot` collection (43 docs) fed by `project_investigation` | already integrated with orchestrator |

**Verdict:** Every reasoning engine except IKG has a documented reuse contract via the orchestrator. IKG is a discovered gap.

### 2.3 · DSM registry (source → canonical) authoritative extension point

`detection_content/xdr_pipeline.py::DSMRegistry`

Currently contains: `SnortEveDSM`, `WindowsSecurityDSM`, `LinuxAuditdDSM`, `AWSCloudTrailDSM`.

**Sysmon is NOT registered.** To flow a Sysmon event through the pipeline, a `SysmonDSM` (subclass with `supports()`, `select_parser()`, `select_normalizer()`) must be added to the registry. This is additive; it does not modify any existing DSM.

### 2.4 · Discovered architectural gap · IKG not in orchestrator loop

`xdr_pipeline.py::process_event_through_pipeline` does NOT call any IKG write function. It calls `materialise_incident` and `project_investigation` but neither writes to `ikg_nodes / ikg_edges / xdr_ikg_nodes / xdr_ikg_edges` (all four collections = 0 docs).

**This is why every historical case in `xdr_canonical_evidence` (219 records) still has empty IKG collections.**

The AG-imported `attack_graph.py` router at `backend/routers/attack_graph.py` MAY be the intended IKG surface but it has no clear integration point with the orchestrator's flow today.

**Implication for Fix (b):** Fix (b) must NOT create a new IKG engine. It must EITHER (i) invoke an existing IKG write function that is already present but currently un-called, OR (ii) STOP AND REPORT if no such function exists per the owner's fail-closed rule.

---

## 3 · Fix (a) proposal — verbatim (unchanged in intent, refined in target)

Owner authorized Fix (a): "Ingest → canonical evidence bridge."

**Refined implementation target:**

- Do NOT create a new canonical-evidence store.
- Do NOT create a parallel orchestrator.
- Modify `backend/v2/routers/ingestion.py::seed_golden` to, for each persisted event, invoke `detection_content.xdr_pipeline.process_event_through_pipeline(db, raw_event, trace_id, integration_id, collector_id)` after registering a `SysmonDSM` in the DSM registry.
- Preserve **evidence_id, entity_iids, artifact_iids, input_sha256, provenance, tenant_id, timestamps** end-to-end — via the orchestrator's normalizer contract.
- Idempotent (checked by `event_id`), fail-closed (halts on first orchestrator FAILED stage without fabricating downstream evidence), no synthetic canonical evidence.

**Additive files that Fix (a) needs (subject to owner authorization of the specific list):**
- New: `detection_content/telemetry/sysmon_dsm.py` (subclass of DSM protocol) — mirrors the pattern of existing `WindowsSecurityDSM`.
- Modified: `v2/routers/ingestion.py::seed_golden` — invoke orchestrator per event.

**No modification to any existing engine, orchestrator, canonical-evidence schema, or reasoning entrypoint.**

---

## 4 · Fix (b) — architecture-safe framing

Owner requirement: "v2_ingestion → canonical_evidence → existing IUE → existing ICE → existing IKG → existing VEEE/Verdict".

Once Fix (a) is in place, Fix (b) is **already satisfied for IUE/ICE/VEEE** because `process_event_through_pipeline` invokes them in-line.

Fix (b) becomes: **wire IKG into the orchestrator loop.** But per §2.4, no existing IKG write function is currently called. Two options, both need owner authorization:

- **Option β-1**: identify an existing IKG-write function (via deeper `grep`) that has been implemented but never wired, and invoke it from the orchestrator. Preserves owner's "no new engines" rule.
- **Option β-2**: **STOP AND REPORT** — no authoritative IKG write function exists in the current codebase; creating one would violate the "no parallel reasoning engine" rule; wait for owner architectural decision.

**I am NOT executing either option in this read-only check.**

---

## 5 · Fix (c) — architecture-safe framing (owner correction adopted)

Owner correction: Security State must consume the authoritative downstream evidence/state, **not** run in parallel to the reasoning fabric.

Since `process_event_through_pipeline` already produces `workspace_cases.verdict_stage2`, `investigation_ssot`, `xdr_incidents`, the correct Fix (c) sequence is:

```
Orchestrator (Fix a → invokes IUE/ICE/VEEE/Incident/Investigation/Response) completes
                                          ↓
     One-shot per-case call to `POST /api/v2/security-state/evaluate`
     with the authoritative canonical evidence + entity refs
                                          ↓
     Security State stores state referencing the SAME evidence_ids
```

Fix (c) must be invoked ONLY after the orchestrator finishes, and MUST reuse the same evidence_ids the orchestrator wrote.

---

## 6 · Acceptance test contract (unchanged from Addendum-01 §3)

One real Sysmon event traceable by the same `evidence_id` / `entity_ids` through **all 11 stages** and the UI:

```
Sysmon event → E123
  ├── xdr_canonical_evidence.event_id                  = E123
  ├── IUE record references E123
  ├── ICE record references E123
  ├── IKG node/edge references E123        ← needs IKG resolution (§4)
  ├── VEEE/Verdict record references E123
  ├── Security State evaluation input      = E123
  ├── SSOT record references E123
  ├── Attack Story record references E123
  ├── ATT&CK evidence references E123
  └── UI 8-tab Investigation Workspace shows E123 on each relevant tab
```

If ANY stage cannot preserve E123, the fix STOPS and the owner is notified before proceeding.

---

## 7 · Safeguards embedded in the plan (owner requirements)

- ✅ No new reasoning engines. Fix (a) invokes existing `xdr_pipeline` + adds one DSM.
- ✅ No duplicate canonical-evidence store. `xdr_canonical_evidence` is the single collection.
- ✅ No duplicate IUE / ICE / IKG / VEEE. Existing modules under `detection_content/` reused verbatim.
- ✅ evidence_id / entity_iids / artifact_iids / input_sha256 preserved end-to-end.
- ✅ Idempotent processing — orchestrator checks `event_id` uniqueness.
- ✅ Tenant isolation — DSM registry + orchestrator honor `tenant_id` from the call context (verified via P0-D 15/15).
- ✅ Provenance preserved — canonical evidence carries `trace_id, integration_id, collector_id, dsm_id, parser_id, normalizer_id`.
- ✅ Deterministic ordering — orchestrator processes events sequentially.
- ✅ No silent failures — orchestrator returns `{"stages": [...], "blocker": <stage>}` at first FAILED.
- ✅ No fabricated evidence.
- ✅ Existing engine contracts reused.
- ✅ Security State remains authoritative (own store + own ledger).
- ⚠ IKG authoritative status: currently un-called from orchestrator — flagged in §2.4 for owner decision.
- ✅ Verdict authoritative — `xdr_veee.compute_verdict`.

---

## 8 · Invariants respected

- ✅ No code / test / config / UI / Mongo modified in this check.
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact.
- ✅ Truth v1/v2/v3 unamended.
- ✅ `mal-20` untouched.
- ✅ Product name **NivXRay XDR** used consistently.
- ✅ Error in prior smoke-test §4 (wrong collection name) corrected here on the record.

## END · Architectural Binding Check + STEP-3 correction · awaiting owner decisions:
1. Save-to-GitHub confirmation (Step 1)
2. Fix (a) implementation authorization based on §3 targets
3. IKG authoritative-status decision per §4 (β-1 investigate vs β-2 stop-and-report) before Fix (b) begins
