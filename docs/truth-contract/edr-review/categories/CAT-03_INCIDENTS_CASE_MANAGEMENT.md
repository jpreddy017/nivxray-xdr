# CAT-03 · Incidents / Case Management

> STRICT READ-ONLY deep-dive. **Framing:** the incident queue is an *experience*; the incident *record* is the plane.

## 1 · PRE-AG baseline (proven, and substantial)

| Artifact | Evidence at `5d67934e` | Status |
|---|---|---|
| Incident router | `backend/routers/incidents.py` | IMPLEMENTED |
| Incident materialisation engine | `backend/detection_content/xdr_incident.py` | IMPLEMENTED |
| Closure classification | `backend/detection_content/xdr_closure_classification.py` | IMPLEMENTED |
| Closed loop | `backend/detection_content/xdr_closed_loop.py` | IMPLEMENTED |
| Executive summary | `backend/detection_content/xdr_executive_summary.py` | IMPLEMENTED |
| Framework mapping | `backend/detection_content/xdr_framework_mapping.py` | IMPLEMENTED |
| Threat family | `backend/detection_content/xdr_threat_family.py` | IMPLEMENTED |
| Bulk ops | `backend/routers/xdr_queue_ops.py` → `/api/xdr/incidents/bulk/{assign,state}` | IMPLEMENTED |
| Analyst annotations | `backend/detection_content/xdr_analyst_annotations.py` | IMPLEMENTED |
| Incident summary / threat model routers | `routers/incident_summary.py`, `routers/incident_threat_model.py` | IMPLEMENTED |

**All PRE-AG.** None of these files appear in the AG import diff.

## 2 · AG delta

**NONE on the incident plane itself.** AG modified `xdr_pipeline.py` (which *calls* `materialise_incident`) and `xdr_ice.py`/`xdr_iue.py` (which feed it), but did not add or replace any incident router, model or engine.

## 3 · Current state (live)

**30 incident-scoped API paths.** Full lifecycle surface is present:

```
/api/incidents                                  list
/api/incidents/{id}                             record
/api/incidents/{id}/state                       lifecycle transition
/api/incidents/{id}/assignee                    ownership
/api/incidents/{id}/summary                     narrative
/api/incidents/{id}/understanding               IUE projection
/api/incidents/{id}/attack-graph                graph
/api/incidents/{id}/attack-story                narrative chain
/api/incidents/{id}/attack-evidence             evidence
/api/incidents/{id}/investigation               investigation projection
/api/incidents/{id}/investigation/findings      findings
/api/incidents/{id}/investigation/executions    executions
/api/incidents/{id}/threat-model
/api/incidents/{id}/operations
/api/incidents/{id}/report, /report/blocks, /report/blocks/{id}/suppress, /report/pdf
/api/incidents/{id}/intelligence/overlays (+ per-field + history)
/api/incidents/{id}/inspector/{kind}/{ref_id}
/api/xdr/incidents/{id}/response-executions
/api/xdr/incidents/bulk/{assign,state}
/api/narration/incident/{id}/{attack-story,cross-lane-story,executive-summary,report-narration,r46-overlay-summary}
```

### Runtime volumes (live Mongo)

| Collection | Docs | Interpretation |
|---|---|---|
| `workspace_cases` | **484** | legacy analyst-facing case store |
| `v2_cases` | **35** | v2 case model |
| `xdr_incidents` | **1** | canonical-pipeline incident output |
| `xdr_incident_promotion_audit` | 2 | promotion attempts recorded |
| `xdr_investigations` | 151 | investigation projections |
| `xdr_investigation_findings` | 1,099 | |
| `xdr_investigation_activity` | 6,223 | |
| `xdr_analyst_annotations` | 31 | |
| `xdr_report_blocks` | 9 | |
| `xdr_closure_classification` | — | no dedicated collection observed |

`GET /api/v2/cases` (live, authenticated) returns e.g.:
```json
{"id":"case_golden_powershell_encoded_3fa120c2","name":"Golden · Encoded PowerShell",
 "tags":["ingested","phase4"],"status":"open","created_by":"ingestion-pipeline",
 "event_count":0,"entity_count":0}
```

| Dimension | Verdict |
|---|---|
| Implemented | ✅ (broad, PRE-AG) |
| Registered | ✅ 30 live paths |
| Executed | ✅ |
| Runtime-proven | 🟡 — cases exist and are readable, but `event_count`/`entity_count` are **0** and `v2_case_events`/`v2_case_entities` collections are **empty** |
| Production-ready | 🔴 — **three parallel case stores** |

## 4 · Industry benchmark

| Vendor | Case-management model |
|---|---|
| **Microsoft Defender XDR** | Single unified incident aggregating alerts + automated investigations; Activities tab records disruption actions; incidents queryable in advanced hunting |
| **Cisco XDR** | Incident Manager with **playbook-guided lifecycle** in 4 NIST 800-61r2 phases (Identification / Containment / Eradication / Recovery); up to 25 custom playbooks per org |
| **Cortex XDR** | Issues → incidents, Causality view + Timeline per incident |
| **CrowdStrike** | Detections and incidents as distinct triggerable entities in Fusion SOAR |
| **SentinelOne** | Storyline-backed incidents; Purple AI emits TP/FP/Unknown verdict with auditable evidence chain |
| **Splunk ES** | Findings → finding groups → investigation; hard caps: **100 findings per investigation**, 50 contributing events aggregated per group |
| **Trellix** | Investigation guides that dynamically adapt to the case |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **Three parallel case stores** (`workspace_cases` 484 / `v2_cases` 35 / `xdr_incidents` 1) | **P0** | Master §G DEV-3. Every incident KPI is unfalsifiable until one store is authoritative |
| Case sub-collections empty | **P1** | `v2_case_events`, `v2_case_entities`, `v2_case_behaviors`, `v2_case_relationships`, `v2_case_reports`, `v2_audit_log` = **all 0 docs** |
| No alert→incident aggregation | **P0** (inherited) | CAT-02 |
| No SLA / aging plane | P1 | `XdrShell.jsx:76` `sla-aging … disabled: true` |
| No incident merge/split/link | P2 | 0 live paths for merge/link between incidents |
| Lifecycle phases not modelled as a guided playbook | P2 | Cisco's NIST-phase model is the benchmark; NivXRay has `state` transitions but no phase guidance. `xdr_closure_classification.py` is the nearest existing asset |

## 6 · UNKNOWN

- U-03.1 — Which case store the owner intends as SSOT. A **decision**, not a discoverable fact.
- U-03.2 — Whether the 484 `workspace_cases` are historically valid or accumulated test data. Not determinable read-only.
- U-03.3 — Closure-loop runtime volume (master U-4): `xdr_closed_loop.py` exists, no collection isolates closure events.
