# §19 — BEHAVIOR / ML / INVESTIGATION READINESS INVENTORY

**NOTHING IN THIS DOCUMENT WAS ACTIVATED.** No router imports `edr_behavior`, `edr_ml` or
`edr_investigation` at the end of this phase, exactly as at the start. This is an inventory
produced so the next phase can be planned on evidence, and it deliberately stops short of a
design.

Verified by import-graph inspection at the phase HEAD:

```
grep -rl "edr_behavior|edr_ml" backend/routers/   -> (empty)
non-test importers of edr_behavior -> edr_ml/*, edr_trajectory/artifacts_overlay.py (unmounted)
non-test importers of edr_ml       -> edr_investigation/builder.py
non-test importers of edr_investigation -> (none)
```

---

## BEHAVIOR ENGINE — `backend/edr_behavior/**` (16 modules)

| | |
|---|---|
| INPUT_CONTRACT | `edr_behavior.contracts.EvidenceRecord` — a normalized observation. The §d adapter now produces an equivalent normalized row (`edr_trajectory.contracts.event`), so an adapter between the two is a mapping, not a new ingestion path. |
| OUTPUT_CONTRACT | Behavior findings from `engine`/`matcher` against `rules`, with `suppression` and `replay`. The shape is NOT the production finding shape: E1's durable detection authority is `edr_plane.fabric.contracts.Finding` (`finding_id`, `rule_id`, `evidence_refs[]`, `attck[]`, `attck_basis`, `severity`, `detection_source`). |
| REQUIRED_E1_HOOK | `edr_plane/canonical_bridge.py` — the single place where a canonical observation already reaches `edr_plane.findings_intake.record_endpoint_detection`. Behavior must emit through THAT intake so one detection authority stays authoritative. |
| TENANT_BOUNDARY | Not established. The engine has its own store with no `TENANT_PARTITIONED_STORES` declaration and no `require_tenant` equivalent. This must be settled BEFORE activation, not after. |
| STORAGE | `edr_behavior/store.py`, its own collection, not registered in `ENDPOINT_KEYED_STORES`. Consequence: a behavior finding is not addressable by the one endpoint resolver, so it cannot be joined to a trajectory row by the exact-reference rule this phase established. |
| FAILURE_MODE | Unproven. The trajectory now degrades truthfully when the findings authority is unavailable (`E1_FINDINGS_AUTHORITY_UNAVAILABLE`); a behavior engine wired into the ingest path needs the same property or a rule outage becomes silent data loss. |
| TEST_STATUS | Own unit tests exist and pass inside the suite. No production-path test, no tenant-isolation test, no real-evidence test. |
| REAL_EVIDENCE_PROOF_STATUS | NONE. |
| NEXT_SAFE_INTEGRATION_STEP | Declare the tenant partition and the endpoint-keyed fields for its store, then emit through `findings_intake` behind a default-off flag, SHADOW ONLY (write findings, present nothing). Prove tenant isolation and idempotent replay before any UI reads it. |

## ML ENGINE — `backend/edr_ml/**` (pipeline, features, baseline, models, signals, metrics, safe)

| | |
|---|---|
| INPUT_CONTRACT | `edr_ml/pipeline.py` consumes `edr_behavior.contracts.EvidenceRecord`, so ML is DOWNSTREAM OF BEHAVIOR. It cannot be activated before the behavior boundary is settled. |
| OUTPUT_CONTRACT | A decision dict (`{"engine": "edr_ml", "model_id", "detail"}`) read by `edr_investigation/builder.py:166`. Not a `Finding`; carries no `evidence_refs`, therefore not joinable to a trajectory row today. |
| REQUIRED_E1_HOOK | None exists. There is no scheduled job, no API and no durable decision store in production. |
| TENANT_BOUNDARY | Not established. Baselines are per-model, not per-customer; a baseline trained across customers would be a cross-tenant inference channel. This is the single most important unresolved question for ML. |
| STORAGE | Own decision store, unregistered. |
| FAILURE_MODE | `edr_ml/safe.py` exists; its guarantees are not proven against the production path. |
| TEST_STATUS | Unit tests only. |
| REAL_EVIDENCE_PROOF_STATUS | NONE. |
| NEXT_SAFE_INTEGRATION_STEP | Settle per-customer baseline isolation on paper and get owner agreement, because it is a data-boundary decision and not an implementation detail. Then score in shadow and publish a metrics-only surface. A model score must never reach an analyst as a verdict — the §12 rule applies: an ML signal is not a detection and a detection is not a verdict. |

## INVESTIGATION / HYPOTHESIS ENGINE — `backend/edr_investigation/{builder,causal,ti,contracts}.py`

| | |
|---|---|
| INPUT_CONTRACT | Findings + ML decisions + its own TI surface (`edr_investigation/ti.py`), which is SEPARATE from production TI (`routers/threat_intel.py`, `services/ioc_intelligence/**`). Two TI notions must not both reach an analyst. |
| OUTPUT_CONTRACT | A hypothesis/narrative object. No durable store, no route. |
| REQUIRED_E1_HOOK | None. Also depends on the §d lineage the trajectory now produces (`edr_trajectory/lineage.py` proven causality), which is a better causal source than `edr_investigation/causal.py` because it is built from evidence identity rather than heuristics. |
| TENANT_BOUNDARY | Not established. |
| STORAGE | None. |
| FAILURE_MODE | Undefined. A hypothesis engine that cannot say "I do not know" is the highest-risk surface of the three. |
| TEST_STATUS | Unit tests only. |
| REAL_EVIDENCE_PROOF_STATUS | NONE. |
| NEXT_SAFE_INTEGRATION_STEP | Last of the three. It should consume the §d lineage and the durable findings rather than its own causal and TI modules, and every claim it renders needs the same basis/authority field the trajectory contract now carries. |

---

## ORDER IMPLIED BY THE DEPENDENCIES (not a plan, an observation)

```
Behavior  (settles the tenant boundary + the findings intake contract)
   └── ML            (consumes Behavior's EvidenceRecord; needs per-customer baselines)
        └── Investigation  (consumes findings + ML + lineage; needs a truthful "unknown")
```

Each of the three needs a tenant boundary declared before activation. That is the same decision
three times, and it is an owner-level data-boundary decision rather than an implementation one.
