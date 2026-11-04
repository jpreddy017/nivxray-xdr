# CAT-08 · Verdict / Risk / Prioritisation (+ AG Security State)

> STRICT READ-ONLY deep-dive. Also carries the **Security State** row folded in from the prior taxonomy (master §B reconciliation).

## 1 · PRE-AG baseline (proven — and AG never touched it)

| Artifact | Evidence | Status |
|---|---|---|
| **VEEE — Verdict & Evidence Evaluation Engine** | `backend/detection_content/xdr_veee.py`, 110 lines, present at `5d67934e`, **NOT in the AG diff** | IMPLEMENTED, 100% PRE-AG |
| Verdict projection | `backend/verdict_projection.py` | IMPLEMENTED, PRE-AG |
| Stage-2 verdict API | `/api/verdict/stage2/{compute,auto-compute,status}` | IMPLEMENTED, PRE-AG |
| Verdict profiles | `/api/v2/verdict/profiles` | IMPLEMENTED, PRE-AG |
| Case verdicts + aggregate | `/api/v2/cases/{id}/verdicts`, `/verdicts/aggregate` | IMPLEMENTED, PRE-AG |
| Analyst verdict correction loop | `/api/corrections/*` (10 paths), `backend/analyst_corrections.py` | IMPLEMENTED, PRE-AG |
| Verdict shadow observation | `verdict_shadow_observations` (280 docs), `/api/telemetry/verdict-inputs` | IMPLEMENTED, PRE-AG |

### Documented determinism contract (verbatim, `xdr_veee.py:5-18`)

```
Detection = capability match (a rule fired).
IUE       = understanding of the evidence (entities, severity_hint).
ICE       = correlation evidence.
VEEE      = *combined* deterministic verdict projection.

Determinism (§3): Same canonical + IUE + ICE inputs → byte-identical verdict.
No clock reads, no random, no LLM.
```

### Scoring is fully open (`xdr_veee.py:30-46`)

| Contributor | Weight |
|---|---|
| Detection rule fired | 45 |
| Each ICE correlation match (capped at 3) | 20 |
| Severity CRITICAL / HIGH / MEDIUM / LOW / INFO | 35 / 25 / 15 / 5 / 0 |
| Max score | 100 |

| Band | Label |
|---|---|
| ≥80 | `MALICIOUS` |
| ≥55 | `SUSPICIOUS` |
| ≥25 | `LIKELY_BENIGN` |
| ≥0 | `INCONCLUSIVE` |

Honest-state clause (`:15-18`): *"`reason` never falls back to a generic template — if there is zero evidence, we say so."*

## 2 · AG delta — the entire Security State plane (100% AG)

`backend/security_state/` — **81 files, all `A` at `95b1c82a`**, zero PRE-AG presence:

| Sub-plane | Files |
|---|---|
`model/security_state.py` | canonical security-state model |
`reachability/engine.py` | what an adversary can still reach |
`counterfactual/engine.py` | what would have happened otherwise |
`impact/engine.py` | blast-radius |
`intervention/optimizer.py` | optimal intervention selection |
`causal/engine.py` | causal reasoning |
`capability/engine.py` | adversary capability inference |
`progression/engine.py` | attack progression |
`attack_state/machine.py` | attack state machine |
`ledger/ledger.py` | immutable state ledger |
`orchestration/{engine,library,models}.py` | orchestration |
`hydration/{case_hydrator,provenance}.py` | case hydration + provenance (IKG **readers**) |
`persistence/{models,repository}.py` | persistence |
`response_safety/{safety_gate,verification}.py` | pre/post response safety (see CAT-16) |
`adapters/ssot_adapter.py`, `detection_bridge.py`, `contracts.py`, `benchmarks/benchmark.py` | integration |
`routers/router.py` | **14 endpoints**, mounted at `backend/server.py:352-353` |

Mount evidence, `backend/server.py:348-353`:
```python
# 14 endpoints backed by the full AG security_state package (attack-state …
from security_state.routers.router import router as security_state_router
app.include_router(security_state_router)
```

Live endpoints (`security_state/routers/router.py`):
```
POST /evaluate                              :131
GET  /{case_id}                             :204
GET  /{case_id}/history                     :230
GET  /{case_id}/transitions                 :242
GET  /{case_id}/causality                   :250
GET  /{case_id}/capabilities                :262
GET  /{case_id}/reachability                :282
POST /{case_id}/counterfactual              :298
POST /{case_id}/interventions/plan          :317
POST /{case_id}/response/verify             :338
GET  /{case_id}/ledger                      :365
GET  /streaming/status                      :383
GET  /{case_id}/provenance                  :402
POST /{case_id}/interventions/stage         :417
```
Exposed publicly as `/api/v2/security-state/*` (14 live paths confirmed in the OpenAPI surface).

## 3 · Current state (live)

**RUNTIME-PROVEN:** VEEE is invoked in the canonical pipeline at `xdr_pipeline.py:297` `verdict = veee_compute(canonical, detection, iue, ice)`; the stage emits `label`, `score`, `engine_id`, `reason` (`:298-302`).

`GET /api/v2/security-state/streaming/status` → `422 {"type":"missing","loc":["query","tenant_id"]}` — i.e. **mounted, reachable, and tenant-scoped by contract**. Not a failure; it is proof of tenant enforcement at the signature level.

Runtime volumes: `security_states` **3** · `xdr_verdict_inputs` 5 · `verdict_shadow_observations` 280 · `xdr_recommendations` 688.

| Dimension | Verdict (VEEE) | Verdict (Security State) |
|---|---|---|
| Implemented | ✅ | ✅ 81 files |
| Registered | ✅ | ✅ 14 endpoints mounted |
| Executed | ✅ | ⚠️ 3 state docs |
| Runtime-proven | ✅ | 🟡 reachable; correctness untested |
| Production-ready | 🟡 | 🔴 thin runtime, near-invisible in the operator console |

## 4 · Industry benchmark

| Vendor | Verdict / prioritisation |
|---|---|
| **Microsoft Defender XDR** | Defender Queue Assistant — **ML score 0-100** from severity + asset criticality + MITRE techniques + attack-disruption signals |
| **Splunk ES** | **Risk-based alerting** — cumulative risk score per entity in the risk index; finding groups trigger on risk-score or MITRE-tactic-count thresholds |
| **SentinelOne** | Purple AI emits **TP / FP / Unknown** with an auditable evidence chain |
| **Cisco XDR** | Agentic AI TP/FP determination; **asset value feeds incident priority** |
| **Cortex XDR** | Analytics-engine severity on ABIOCs |
| **CrowdStrike** | Detection severity + Threat Graph context |
| **Trellix** | Insights prioritises by sector/geography relevance |
| **All of them** | 🔴 **None document reachability, counterfactual, impact or intervention-optimisation reasoning.** |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No entity-level risk score (RBA analogue)** | **P1** | VEEE scores **events/incidents**, not entities. Splunk's risk index and MS's asset-criticality input are both entity-centric. NivXRay has `xdr_cve_assets` (24) and no join to verdict |
| **Asset criticality not an input to scoring** | P1 | `xdr_veee.py:30-45` weights = detection + correlation + severity only. Asset data exists (`xdr_cve_assets`, `xdr_cve_exposures` 16) and is unused |
| Verdict cannot self-improve | P2 | 280 shadow observations + a full corrections API exist; VEEE is deterministic by design so there is **no learning path** — this is an accepted trade-off, not a defect. Record it as a deliberate architectural stance |
| Security State runtime is thin | **P1** | 81 files, 14 endpoints, **3** state docs. Implemented ≠ operated |
| Security State invisible to analysts | P2 | only surfaced by `frontend/src/v2/pages/SecurityStateTab.jsx` in the **frozen** main SPA, not in the active `apps/nivxray-xdr/` console |
| `mal-20` false negative | P2 | **DELIBERATELY UNTOUCHED** per standing owner directive. Recorded, not investigated |

## 6 · Where NivXRay is ABOVE parity — protect this

1. **Deterministic, fully-published verdict maths.** Weights, caps and bands are in source (`xdr_veee.py:30-46`) and byte-reproducible. Every benchmarked vendor's score is opaque ML. For regulated buyers and for the Honest-State contract this is a **stronger** position, not a weaker one.
2. **Security State.** Reachability + counterfactual + impact + intervention optimisation + immutable ledger is a capability class **no benchmarked vendor ships**. It is the single clearest differentiator found in this audit — and it is currently almost unused (3 docs) and almost unseen (frozen SPA only).

## 7 · UNKNOWN

- U-08.1 — Security-State engine correctness (master U-8). 81 files implemented and mounted; correctness requires execution.
- U-08.2 — Whether the 3 `security_states` docs were produced by the Stage-3 replay or by live evaluation. `NIVXRAY_XDR_STAGE3_SECURITY_STATE_REPLAY_EVIDENCE.md` suggests replay; not confirmed here.
- U-08.3 — `mal-20` root cause — out of scope by directive.
