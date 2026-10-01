# CAT-16 · Playbooks / Automation / Response / Approvals / Verification

> STRICT READ-ONLY deep-dive. This is the **closed-loop** category: rule → finding → automation rule → response policy → playbook → approval → action → verification → closure.

## 1 · PRE-AG baseline (proven — the response *fabric* is original NivXRay)

| Artifact | Evidence at `5d67934e` | Status |
|---|---|---|
| Action registry | `backend/detection_content/xdr_action_registry.py` | IMPLEMENTED |
| Response fabric | `xdr_response_fabric.py` | IMPLEMENTED |
| Response strategy | `xdr_response_strategy.py` | IMPLEMENTED |
| Response decision | `xdr_response_decision.py` | IMPLEMENTED |
| Response executor | `xdr_response_executor.py` | IMPLEMENTED |
| Mitigation intelligence | `xdr_mitigation_intelligence.py`, `routers/mitigations_evidence_driven.py` | IMPLEMENTED |
| Recommendation synthesis | `xdr_recommendation_synthesis.py` | IMPLEMENTED |
| Closed loop | `xdr_closed_loop.py` | IMPLEMENTED |
| Closure classification | `xdr_closure_classification.py` | IMPLEMENTED |
| Response evidence router | `routers/xdr_response_evidence.py` (`prefix="/xdr"`, 3 routes) | IMPLEMENTED |
| Response alias | `routers/response_alias.py` → `/api/response/{actions,{incident_id},{incident_id}/recompute}` | IMPLEMENTED |
| Credential vault | `xdr_credential_vault.py`, `/api/xdr/secrets/*` | IMPLEMENTED |
| Webhooks | `/api/xdr/webhooks` + 5 sub-paths | IMPLEMENTED |
| UI | `XdrPlaybooksPage.jsx`, `XdrPlaybookDesignerPage.jsx`, `XdrAutomationRulesPage.jsx`, `XdrAutomationRuleEditorPage.jsx`, `XdrApprovalsPage.jsx` | IMPLEMENTED (all PRE-AG) |

## 2 · AG delta

| Added | Purpose |
|---|---|
`security_state/response_safety/safety_gate.py` | **pre-action safety gate** |
`security_state/response_safety/verification.py` | **post-action verification** |
`security_state/intervention/optimizer.py` | optimal intervention selection |
`security_state/orchestration/{engine,library,models}.py` | orchestration |
`detection_content/corpus/mapping_response_corpus.py`, `translation/mapping_translator.py` | response-mapping content |
Live endpoints (`security_state/routers/router.py`) | `POST /{case_id}/interventions/plan` (`:317`), `POST /{case_id}/interventions/stage` (`:417`), `POST /{case_id}/response/verify` (`:338`) |

**AG's contribution here is the safety/verification/optimisation layer — genuinely differentiating (see §6).**

## 3 · Current state (live)

### 3.1 · Action registry — RUNTIME-PROVEN, and honestly incomplete

`GET /api/response/actions` (live, authenticated):

```json
{"summary":{"total":13,"capability_available":5,
  "by_domain":{"endpoint":7,"network":1,"intel":5},
  "by_risk":{"CRITICAL":1,"HIGH":4,"MEDIUM":2,"LOW":6},
  "honesty_note":"capability_available is derived from the current environment at each call.
    Actions without a configured integration remain in the registry so decision engine + UI
    can honestly report 'capability unavailable'."}}
```

| Action | Domain | Available |
|---|---|---|
`IOC_ADD_WATCHLIST` | intel | ✅ |
`OSINT_ENRICH_IP` / `_URL` / `_DOMAIN` / `_HASH` | intel | ✅ (4) |
`ENDPOINT_ISOLATE` | endpoint | ❌ |
`ENDPOINT_RELEASE_ISOLATION` | endpoint | ❌ |
`COLLECT_FORENSIC_SNAPSHOT` | endpoint | ❌ |
`APPLICATION_ALLOW_LIST_ADD` | endpoint | ❌ |
`PROCESS_EXCLUSION_ADD` | endpoint | ❌ |
`PATH_EXCLUSION_ADD` | endpoint | ❌ |
`THREAT_EXCLUSION_ADD` | endpoint | ❌ |
`IP_BLOCK` | network | ❌ |

**The 5 available actions are all intel/enrichment. Every containment action is unavailable.** So NivXRay can currently *enrich* and *watchlist*, but cannot *contain*.

### 3.2 · Runtime volumes

`xdr_response_executions` **183** · `xdr_response_timeline` **535** · `xdr_response_evidence` 2 · `xdr_response_audit` 2 · `xdr_recommendations` 688.

### 3.3 · The three missing API surfaces

| Missing surface | Evidence |
|---|---|
| **Playbook execution** | 733 live paths; `playbook` matches only `/api/admin/playbooks/{playbook_id}/votes` and `/api/admin/content-supply-chain/incidents/{id}/playbooks`. **No `POST /playbooks/{id}/run`.** `XdrPlaybookDesignerPage.jsx` has no execution endpoint |
| **Approvals queue** | `approv` matches only `/api/corrections/{corr_id}/approve`, `/api/learner/approve/{payload_id}`, `/api/learner/approved` — all unrelated to response. `XdrApprovalsPage.jsx` has **no approvals API**. The nearest real gate is AG's `POST /api/v2/security-state/{case_id}/interventions/stage` |
| **Automation rules** | `automation` matches only `/api/docs/automation/*` (documentation tooling). `XdrAutomationRulesPage.jsx` + `XdrAutomationRuleEditorPage.jsx` have **no automation-rule API** |

| Dimension | Verdict |
|---|---|
| Implemented | 🟡 registry + strategy + decision + executor + safety + verification |
| Registered | 🟡 12 response paths; **0 playbook-execution, 0 approvals, 0 automation-rule paths** |
| Executed | ✅ 183 executions, 535 timeline records |
| Runtime-proven | 🟡 for intel actions; 🔴 for containment |
| Production-ready | 🔴 |

## 4 · Industry benchmark

| Vendor | Automation / response |
|---|---|
| **CrowdStrike Fusion SOAR** | No-code visual builder + Foundry-programmatic; triggers on platform events / schedule / on-demand; native actions, RTR script execution, HTTP actions, Foundry functions; **CEL conditional branching + sequential/concurrent loops**; execution history + KPI dashboard |
| **Cisco XDR** | Workflows (parent) + **Atomic Actions** (reusable); **Automation Exchange** (Cisco-managed / verified / community); Automation Rules triggered by incident creation / schedule / webhook; playbooks in 4 NIST 800-61r2 phases; **25 custom playbooks per org** |
| **Splunk ES/SOAR** | Automation rules pair detections with ES-type playbooks (Configure > Splunk SOAR); **FIFO** prioritisation; **one automation rule per detection**; detections must be enabled |
| **Microsoft Defender XDR** | AIR (Automated Investigation & Remediation); **automatic attack disruption** — time-limited, incident-scoped isolation/account-disable, monitored in the Activities tab and queryable via `DisruptionAndResponseEvents` |
| **SentinelOne** | Singularity **Hyperautomation** — governed, policy-driven response actions |
| **Trellix** | **TAuR/FSO** — API-based response triggered by correlation rules or manually |
| **Cortex XDR** | Agent-level prevention rules terminate causality chains |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No playbook execution API** | **P1** | Designer UI exists with nothing to call. The whole SOAR value proposition is unreachable |
| **No approvals queue API** | **P1** | `XdrApprovalsPage.jsx` unbacked; AG's `safety_gate.py` is the *engine* with no *queue* |
| **No automation-rule API** | **P1** | Two editor pages unbacked. Splunk's "one rule per detection, FIFO" and Cisco's "trigger on creation/schedule/webhook" are the models |
| **No containment capability** | **P1** | 8/13 actions unavailable; all containment actions among them. Blocked by CAT-12/CAT-13 (no integration configured) |
| No DAG / branching / loops | P2 | CrowdStrike's CEL branching + loops is the benchmark. Do not build the engine before the execution API exists |
| No response rollback | P2 | `ENDPOINT_RELEASE_ISOLATION` exists as the inverse action; no generic rollback |
| Playbook count unverifiable | — | master U-5: 22 playbooks claimed in prior audits; **no playbook collection in Mongo, no execution API**. Claim marked UNKNOWN |

## 6 · Where NivXRay is ABOVE parity — protect this

1. **`response_safety/verification.py` + `POST /{case_id}/response/verify`.** Explicit, engine-backed **post-response verification** — "did the action actually achieve the intended state change?". Every benchmarked vendor logs action *success*; none documents a verification *engine*.
2. **`intervention/optimizer.py` + `interventions/plan`.** Optimal intervention *selection* rather than static playbook branching. No benchmarked vendor documents this.
3. **`capability_available` + `honesty_note` on the action registry.** Vendors hide unavailable actions; NivXRay shows them and says why. This is the honest-state contract expressed in the response plane, and it prevents an analyst from believing a containment exists when it does not.

## 7 · UNKNOWN

- U-16.1 — Playbook count (master U-5).
- U-16.2 — What the 183 `xdr_response_executions` actually executed. Given only 5 intel actions are available, most are presumably enrichment; **not confirmed**.
- U-16.3 — Whether `safety_gate.py` is invoked on any live path today, or only from `interventions/stage`. Requires execution.
