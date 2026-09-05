# NivXRay XDR · Pre-AG Baseline + Industry XDR Capability Audit · MASTER CONSOLIDATED AUDIT

> **Mode:** STRICT READ-ONLY. Zero application code, config, DB state, UI, engine, detection-content, decoder, Security-State or production behaviour was modified during this audit. Only Markdown artifacts were created.
> **Product:** NivXRay XDR.
> **Audit date:** 2026-09-05.
> **Branch audited:** `feature/rc2-alignment` @ `869f7336b3f6d1db1f9623e126984029066419a9` (2026-09-05T09:41:43Z).
> **Rule:** NO EVIDENCE → NO CLAIM. AG-created code is never used to inflate the PRE-AG baseline. Anything not provable is marked `UNKNOWN`.
> **Owner framing rule (adopted):** MSS Dashboard, Incidents and Analyst Workspace are **experiences over the XDR planes**, not the architecture. Detection, correlation, intelligence, telemetry, hunting, response/playbooks and administration are audited as **independent planes**. The 8-tab Investigation Workspace is *not* the XDR.

Companion artifacts:

| Artifact | Purpose |
|---|---|
| `categories/CAT-01 … CAT-17_*.md` | 17 per-category deep-dive evidence reports |
| `NIVXRAY_XDR_ARCHITECTURE_COVERAGE_MATRIX.json` | machine-readable coverage matrix (prior master audit) |
| `NIVXRAY_XDR_AG_VS_GIT_COMPLETE_BUILD_VERIFICATION.md` | AG-vs-Git file-level reconciliation (prior session) |

---

# A · PRE-AG BOUNDARY — EXACT SHA AND PROOF

## A.1 · Candidate commits considered

| # | SHA | Date (UTC) | Subject | `--shortstat` | Verdict |
|---|---|---|---|---|---|
| 1 | `975223dc717cd2ec62e5ecfac7455ee82ff46ab8` | 2026-09-05T06:09:22 | `## Master AG Export · Read-Only Reconciliation COMPLETE` | 4715 files, +1,241,309 | **NOT the product boundary** — 4712/4715 files land under `memory/ag_export/` (reference material only), 1 under `memory/edr_review/`, 1 under `docs/truth-contract/`, 1 under `backend/docs/`. **Zero executable product code.** |
| 2 | `7fe9fcd8…`, `2db4e3fc…`, `06b56144…`, `5d67934e…` | 06:17 → 06:48 | Branch-alignment / UI-review docs | 7 / 2 / 1 / 6 files | Docs + `.tok` only. No product code. |
| 3 | **`95b1c82a9aaeb0024814fd08cc509818d77367d1`** | **2026-09-05T07:32:44** | `## AG Complete Baseline Integration · Stage 1 + Stage 2 · DELIVERED` | **367 files, +94,326 / −215** | **THIS IS THE AG PRODUCT-CODE BOUNDARY** |
| 4 | `3517827e…` | 07:50:01 | `## AG Baseline Integration + UI Honest-State Repair …` | 8 files, +207/−25 | AG **follow-up**, not the boundary |

## A.2 · Selected boundary

```
PRE-AG BASELINE COMMIT (last commit containing zero AG product code)
    SHA     : 5d67934e4cfb879c8cc69d42ab48878040cf793d
    DATE    : 2026-09-05T06:48:11+00:00
    SUBJECT : ## UI Review Gate · PASS WITH CHANGES

AG IMPORT COMMIT (first commit containing AG product code)
    SHA     : 95b1c82a9aaeb0024814fd08cc509818d77367d1
    PARENT  : 5d67934e4cfb879c8cc69d42ab48878040cf793d
    DATE    : 2026-09-05T07:32:44+00:00
    AUTHOR  : emergent-agent-e1
```

**CONFIDENCE: HIGH.** Proof chain, each item independently verifiable:

1. **Parent linkage proven** — `git log -1 --format=%P 95b1c82a` → `5d67934e…`. Single parent, linear history, no merge.
2. **Diff characteristics prove a bulk import, not organic work** — 172 files `A`(dded) vs 24 `M`(odified) inside `backend/ apps/ frontend/`; two brand-new package trees appear whole: `backend/security_state/` (**81 files, all `A`**) and `backend/detection_content/{corpus,translation,library,canonical_ir,deduplication,validation_framework,telemetry}/` (**60 files, overwhelmingly `A`**).
3. **The AG export itself is separately traceable** — the AG source-of-truth landed one commit-group earlier at `975223dc` into `memory/ag_export/NIVXRAY_COMPLETE_AG_EXPORT` + `memory/ag_export/ag.zip` (4,716 files present on disk today). The import commit `95b1c82a` therefore has a *provable upstream*, which is what distinguishes it from an ordinary large commit.
4. **The stated 335/358-file figure was NOT trusted.** Measured reality: `95b1c82a` = 367 files total, of which **196 are product code** (`backend/ apps/ frontend/`) and the remainder are docs/handoff/test-report artifacts. The prior framework's "335 imports + 51 conflict-resolutions = 386" figure is **not reproducible from git** and is superseded by the measured numbers in §A.3.
5. **Code-tree equivalence of the two candidate anchors proven** — `git diff --name-only 06b56144 5d67934e | grep -v '\.md$'` → **0 files**. The previously-published anchor `06b56144` and the anchor selected here (`5d67934e`) have **byte-identical non-Markdown trees**, so no previously-published PRE-AG claim is invalidated by this correction; the anchor is merely tightened to the true last-pre-AG commit.
6. **No later AG code injections** — every commit in `3517827e..HEAD` touching `backend/` or `apps/` was inspected. Only four product files change after the AG follow-up: `backend/v2/routers/cases.py` (`a073cd6f`), and `backend/detection_content/telemetry/sysmon_dsm.py`, `xdr_pipeline.py`, `backend/v2/ingestion/metrics.py`, `backend/v2/routers/ingestion.py` (`869f7336`). These are **Emergent-authored session work**, not AG imports, and are tagged `POST-AG-EMERGENT` throughout this audit.

## A.3 · Measured AG product-code delta (authoritative, replaces prior counts)

| Scope | Added | Modified |
|---|---|---|
| `backend/security_state/**` | **81** | 0 |
| `backend/detection_content/**` | **~54** | 6 (`contract_registry.py`, `rule_binding.py`, `sigma_strict.py`, `xdr_ice.py`, `xdr_iue.py`, `xdr_pipeline.py`) |
| `backend/tests/**` | 29 | 5 (fixtures/report JSON) |
| `apps/nivxray-xdr/**` | 3 pages (`XdrEvidenceExplorerPage`, `XdrInvestigationWorkspacePage`, `XdrInvestigationsListPage`) | 3 (`App.jsx`, `XdrShell.jsx`, `RecordHeader.jsx`) |
| `frontend/src/**` | 1 (`v2/pages/SecurityStateTab.jsx`) | 0 |
| `backend/` misc | 4 audit runners, `verify_decoder_truth_e2e.py`, `services/analyzers/security_controls.py`, `services/artifact_intelligence/analyzers/{archive,shellcode}.py`, `v2/investigation/shadow_hook.py` | `server.py`, `engine/models.py`, `rc22_adapter.py`, `routers/xdr_correlation.py`, 3 decoders, 3 services |
| **TOTAL product code** | **172 A** | **24 M** |

## A.4 · CORRECTION to a previously published claim

> Prior framework §1 stated: *"120 routers imported at PRE-AG anchor; 129 on current branch → 9 net-new routers came from AG."*

**This is FALSE and is hereby corrected.** `diff <(git ls-tree -r --name-only 5d67934e -- backend/routers) <(git ls-tree -r --name-only HEAD -- backend/routers)` → **empty**. **Zero** router files in `backend/routers/` were added, removed or renamed by AG. AG contributed exactly **one** new router *module*, outside that directory: `backend/security_state/routers/router.py` (14 endpoints), mounted at `backend/server.py:352-353`.

---

# B · 17-CATEGORY MASTER CAPABILITY MATRIX

Status vocabulary (applied uniformly):
`IMPLEMENTED` code exists · `REGISTERED` reachable via a mounted route/registry · `EXECUTED` observed to run · `RUNTIME-PROVEN` observed producing correct output on live data this session · `PARTIAL` · `SCAFFOLD` (shape without behaviour) · `NOT IMPLEMENTED` · `UNKNOWN`.

| # | Category | PRE-AG status | AG delta | Current status | Runtime-proven this session | Industry gap |
|---|---|---|---|---|---|---|
| 1 | MSS / XDR Dashboard | IMPLEMENTED (`routers/xdr_mss.py`, `routers/xdr_dashboard.py`) | none | REGISTERED + RUNTIME-PROVEN | ✅ `/api/xdr/mss/kpis`, `/api/xdr/dashboard/tiles` returned live tile counts | MEDIUM — no exec/board reporting, no coverage posture |
| 2 | Alerts & alert triage | **NOT IMPLEMENTED — no alert object exists** | none | **NOT IMPLEMENTED** | n/a — `0` API paths match `alert` in 733 live paths | **CRITICAL** — every benchmarked vendor has an alert tier |
| 3 | Incidents / case management | IMPLEMENTED (`routers/incidents.py` + 30 sub-routes) | none | REGISTERED + PARTIAL | ✅ 1 doc in `xdr_incidents`, 484 in `workspace_cases` | HIGH — two parallel case stores |
| 4 | Investigation / Analyst Workspace | IMPLEMENTED (main-SPA `AnalystWorkspacePage.jsx`) | **AG-added 8-tab `XdrInvestigationWorkspacePage.jsx`** | PARTIAL · **two coexisting workspaces** | ✅ workspace UI renders honest empty states | MEDIUM |
| 5 | Detection Engineering | IMPLEMENTED (`sigma.py`, `xdr_detection_content.py`, 98 rules, 4,300 versions) | **10 corpus modules, 13 translators, `canonical_ir/`, `validation_framework/`, `library/`, `deduplication/`, `yara_engine.py`** | REGISTERED + PARTIAL | ✅ `/api/xdr/detection/status`, `/inventory` | MEDIUM — no rule test harness in UI, no BIOC/XQL analogue |
| 6 | Correlation / attack chaining | IMPLEMENTED (`xdr_ice.py`, `xdr_attack_chain_graph.py`) | `xdr_ice.py` **modified**; `correlation_library.py` added | REGISTERED + RUNTIME-PROVEN | ✅ `/api/xdr/correlation/status` → 10 rules, 6 matches, 13 operators implemented | HIGH — no cross-domain correlation (single telemetry domain live) |
| 7 | Security Intelligence / IUE | IMPLEMENTED (`xdr_iue.py`, `services/iue/`) | `xdr_iue.py` modified | REGISTERED + EXECUTED | ✅ 219 docs in `xdr_iue_understanding` | MEDIUM |
| 8 | Verdict / risk / prioritisation | IMPLEMENTED (`xdr_veee.py`, deterministic) | none | REGISTERED + RUNTIME-PROVEN | ✅ `/api/verdict/stage2/*`; VEEE weights at `xdr_veee.py:30-45` | HIGH — **no entity-level risk score / RBA analogue** |
| 9 | Threat hunting / query plane | **NOT IMPLEMENTED as a plane** — only `/api/investigation/{case_id}/hunting` (query *suggestions*) | none | **PARTIAL / SCAFFOLD** | ✅ route exists; ❌ no executable query language | **CRITICAL** — no KQL/XQL/SPL analogue |
| 10 | Entity 360 | PARTIAL (`layer_360.py` module; no entity API) | none | **PARTIAL** — 0 entity-centric API paths | ❌ `v2_case_entities` = **0 docs** | **CRITICAL** |
| 11 | Threat Intelligence / IOC / MITRE / YARA | IMPLEMENTED and strong (25+ TI paths, `mitre_catalogue/`, LOLBAS 11,196 primitives, 1,894 sync runs) | none | REGISTERED + RUNTIME-PROVEN | ✅ 1,094 framework mappings, 172 intelligence observations | **LOW — NivXRay is at or above parity here** |
| 12 | Telemetry / data sources / integrations | PARTIAL — 16 declared kinds, **0 configured data sources** | +3 DSMs (Windows-Security, Linux-Auditd, AWS-CloudTrail) | **PARTIAL** | ✅ `/api/xdr/data-sources` → `count: 0`; `/telemetry-health` → all `never_connected` | **CRITICAL** |
| 13 | EDR / endpoint | PARTIAL — `routers/edr.py` is an explicit **read-only projection** over `workspace_cases` | +`sysmon_dsm.py` (POST-AG-EMERGENT) | **PARTIAL / PROJECTION** | ✅ 4 `/api/edr/*` routes | **CRITICAL** — no agent, no live endpoint telemetry |
| 14 | NDR / network | PARTIAL — `SnortEveDSM` in pipeline only | none | **PARTIAL** | ✅ DSM registered at `xdr_pipeline.py:29-48` | **CRITICAL** — 0 network API paths |
| 15 | Email / identity / cloud / SaaS | **NOT IMPLEMENTED** (identity/cloud DSMs exist but 0 API paths) | +`aws_cloudtrail_dsm.py` (cloud DSM) | **NOT IMPLEMENTED** at plane level | ❌ 0 paths match email/identity/cloud/saas | **CRITICAL** |
| 16 | Playbooks / automation / response / approvals / verification | PARTIAL — 13 canonical actions, `response_alias.py`, `xdr_response_*` engines | +`security_state/response_safety/{safety_gate,verification}.py`, `orchestration/` | **PARTIAL** | ✅ `/api/response/actions` → 13 actions, **5 capability_available**, honest note | HIGH — no DAG playbook engine, no approvals queue API |
| 17 | Administration / governance / tenancy / auditability | IMPLEMENTED and strong (RBAC 20 routes, audit log 6,465 docs + verify, vault 33,004 audit docs, secrets, API keys, webhooks) | +Security-State tenant-isolation tests | REGISTERED + RUNTIME-PROVEN | ✅ `xdr_audit_log` 6,465 · `xdr_vault_audit` 33,004 · `/api/xdr/audit-log/verify` exists | **LOW — near parity** |

**Reconciliation with the prior 17-category list:** the earlier framework used a different taxonomy (which included *Security State*, *UBAE*, *Sandbox*, *Multi-tenancy*, *Unified UI* as standalone rows). The owner's final instruction list is authoritative and is used above. The dropped rows are folded in and still audited: **Security State** → CAT-08 §AG delta + CAT-16; **UBAE/UEBA** → CAT-07 §gap (`NOT IMPLEMENTED`, no runtime, PRE-AG *and* AG); **Sandbox** → CAT-13 §gap (`NOT IMPLEMENTED`, infrastructure-gated); **Multi-tenancy** → CAT-17; **Unified UI** → CAT-04.

---

# C · PRE-AG vs AG CAPABILITY SEPARATION MATRIX

| Capability | Existed PRE-AG (`5d67934e`)? | Evidence | AG contribution |
|---|---|---|---|
| Canonical pipeline orchestrator | **YES** | `backend/detection_content/xdr_pipeline.py` first added `fc33871c` (2026-08-31), *5 days before AG* | AG **modified** it (Stage-2), did not create it |
| IUE (understanding) | **YES** | `xdr_iue.py` added `fc33871c` 2026-08-31 | modified only |
| ICE (correlation) | **YES** | `xdr_ice.py` added `fc33871c` 2026-08-31 | modified only |
| VEEE (verdict) | **YES** | `xdr_veee.py` present at `5d67934e`; **untouched by AG** | none |
| Incident materialisation | **YES** | `xdr_incident.py` at `5d67934e` | none |
| Investigation projection | **YES** | `xdr_investigation.py` at `5d67934e` | none |
| Vendor adapters (Cortex, Falcon, MDE, S1) | **YES** | 5 `xdr_*_vendor_adapter.py` at `5d67934e` | none |
| Response fabric / strategy / executor / decision | **YES** | 4 `xdr_response_*.py` at `5d67934e` | none |
| Attack-chain graph | **YES** | `xdr_attack_chain_graph.py` at `5d67934e` | none |
| MSS dashboard + tiles | **YES** | `routers/xdr_mss.py`, `routers/xdr_dashboard.py` at `5d67934e` | none |
| RBAC / audit log / vault / secrets / API keys | **YES** | `routers/xdr_rbac.py`, `xdr_audit_log.py`, `xdr_credential_vault.py` at `5d67934e` | none |
| Standalone XDR shell app | **YES** | `apps/nivxray-xdr/` created `fcbcaed1` 2026-08-29 | AG added 3 pages onto it |
| **Security State (reachability, counterfactual, impact, intervention, causal, capability, progression, ledger, orchestration, hydration, response-safety, verification, attack-state)** | **NO** | entire `backend/security_state/` = 81 files, all `A` at `95b1c82a` | **100% AG** |
| Detection corpus (10 corpora) | **NO** | `detection_content/corpus/*` all `A` at `95b1c82a` | **100% AG** |
| Content translators (13: Sigma/KQL/SPL/EQL/YARA/IOC/behavioral/anomaly/correlation/hunting/mapping) | **NO** | `detection_content/translation/*` all `A` | **100% AG** |
| Canonical IR (rule intermediate representation + evaluator) | **NO** | `detection_content/canonical_ir/*` all `A` | **100% AG** |
| Content validation framework (gates/tiers/lifecycle/binding-bridge) | **NO** | `detection_content/validation_framework/*` all `A` | **100% AG** |
| Content deduplication (engine + fingerprint) | **NO** | `detection_content/deduplication/*` all `A` | **100% AG** |
| Enterprise rule library / registry | **NO** | `detection_content/library/*` all `A` | **100% AG** |
| Telemetry DSMs: Windows-Security, Linux-Auditd, AWS-CloudTrail | **NO** | `detection_content/telemetry/*` all `A` | **100% AG** |
| YARA runtime engine | **NO** | `detection_content/yara_engine.py` `A` | **100% AG** |
| Sysmon DSM | **NO** | `telemetry/sysmon_dsm.py` added `869f7336` | **POST-AG-EMERGENT** (neither PRE-AG nor AG) |

**Honest conclusion on the PRE-AG baseline:** the PRE-AG NivXRay XDR already owned the **entire reasoning spine** (pipeline → IUE → ICE → VEEE → incident → investigation), the **operations planes** (MSS, incidents, RBAC, audit, vault, response fabric) and **industry-leading threat-intelligence depth**. AG contributed **breadth**: detection-content manufacturing/validation, multi-format translation, three telemetry DSMs, and one wholly new reasoning plane (**Security State**). AG contributed **no** dashboard, incident, verdict, response, TI, RBAC or audit capability.

---

# D · END-TO-END EXECUTION-PATH TRUTH MATRIX

Traced path: `POST /api/v2/ingestion/golden/{dataset_id}` → `backend/v2/routers/ingestion.py` → `detection_content.xdr_pipeline.process_event_through_pipeline` (`xdr_pipeline.py:224`).

| # | Stage | Code evidence (file:line) | Status | Runtime-proven? |
|---|---|---|---|---|
| 1 | SOURCE TELEMETRY | golden datasets via `/api/v2/ingestion/golden/{id}`; `/api/xdr/ingest/telemetry` | **PARTIAL** | ✅ synthetic/golden only. **No live source.** `/api/xdr/data-sources` → `count: 0` |
| 2 | COLLECTOR / ADAPTER | `routers/xdr_collectors.py`, `xdr_collector_landing.py` (33 collector paths); `xdr_collectors` = 110 docs | **IMPLEMENTED, not connected** | ❌ `/api/xdr/collector/telemetry-health` → rest/webhook/syslog all `never_connected`, `instances: 0` |
| 3 | PARSER / DSM | `xdr_pipeline.py:29-74` (`SnortEveDSM` + `DSMRegistry`); `telemetry/registry.py:14-39` (`TelemetryDSMRegistry`) | **IMPLEMENTED** | ✅ `dsm` stage returns `EXECUTED` with `dsm_id/vendor/product` |
| 4 | NORMALIZATION | `xdr_pipeline.py:126` `SnortNormalizer`; `dsm.select_normalizer()` at `:254` | **IMPLEMENTED** | ✅ `normalizer` stage `EXECUTED` |
| 5 | CANONICAL EVIDENCE | `xdr_pipeline.py:258-263` → single write to `CANONICAL_COLLECTION` | **IMPLEMENTED** | ✅ **222 docs in `xdr_canonical_evidence`**, 280 in `xdr_canonical_events` |
| 6 | DETECTION | `xdr_pipeline.py:179` `evaluate_detection`, `:185-199` delegates to `library.REGISTRY.evaluate_event` | **IMPLEMENTED** | ✅ `detection` stage `EXECUTED`; 98 rules / 4,300 versions in Mongo |
| 7 | CORRELATION (ICE) | `xdr_pipeline.py:290` `await ice_correlate(...)` | **IMPLEMENTED** | ✅ 21 docs `xdr_correlation_matches`, 11 `xdr_correlation_state`; `/status` → 13/13 operators implemented |
| 8 | IUE / ANALYSIS | `xdr_pipeline.py:279` `iue_understand(canonical, detection)` | **IMPLEMENTED** | ✅ 219 docs `xdr_iue_understanding` |
| 9 | IKG (on-read graph) | **no IKG writer in the pipeline**; readers in `security_state/hydration/provenance.py`, `reachability/engine.py` | **PARTIAL — read-side only** | ⚠️ `xdr_evidence_graph_edges` = **10 docs** only |
| 10 | VEEE / VERDICT | `xdr_pipeline.py:297` `veee_compute(...)`; weights `xdr_veee.py:30-45`; bands `:41-46` | **IMPLEMENTED, deterministic** | ✅ `verdict` stage `EXECUTED` with `label/score/reason` |
| 11 | INCIDENT | `xdr_pipeline.py:305` `materialise_incident(...)`, gated (`NOT_CREATED` + reason when gate fails) | **IMPLEMENTED** | ⚠️ only **1 doc** in `xdr_incidents` (vs 484 `workspace_cases`) |
| 12 | INVESTIGATION | `xdr_pipeline.py:325` `project_investigation(...)` — projection, no second engine | **IMPLEMENTED** | ✅ 151 `xdr_investigations`, 1,099 findings, 6,223 activity docs |
| 13 | PLAYBOOK / POLICY | `xdr_response_strategy.py`, `xdr_response_decision.py`; 22 playbooks claimed in prior audits | **PARTIAL** | ⚠️ **no playbook execution API** in 733 live paths (only `/api/admin/playbooks/{id}/votes`, `/api/admin/content-supply-chain/incidents/{id}/playbooks`) |
| 14 | APPROVAL | `security_state/response_safety/safety_gate.py`; `/api/v2/security-state/{case_id}/interventions/stage` (`router.py:417`) | **PARTIAL / SCAFFOLD** | ❌ no approvals-queue API; only 3 `approve` paths, all unrelated (corrections/learner) |
| 15 | RESPONSE | `/api/response/actions`, `/api/response/{incident_id}`; `xdr_response_executor.py` | **PARTIAL** | ✅ 13 actions registered, **5 `capability_available`**; 183 `xdr_response_executions`, 535 timeline docs. **0** isolate/contain/quarantine API paths |
| 16 | VERIFICATION | `security_state/response_safety/verification.py`; `/api/v2/security-state/{case_id}/response/verify` (`router.py:338`) | **IMPLEMENTED (AG)** | ⚠️ 2 docs `xdr_response_evidence`, 2 `xdr_response_audit` |
| 17 | CLOSURE | `xdr_closure_classification.py`; `/api/incidents/{id}/state`, `/api/xdr/incidents/bulk/state` | **IMPLEMENTED** | ⚠️ `xdr_closed_loop.py` present; closure runtime volume UNKNOWN |

**Honest end-to-end verdict:** stages **3 → 12 are runtime-proven** on golden/synthetic telemetry. Stages **1–2 are the hard break** (no live source, no connected collector). Stages **13–15 are partial**, **14 is effectively scaffold**, and **9 (IKG) has no write path in the canonical pipeline**. The claim "NivXRay XDR is end-to-end" is therefore **TRUE only for synthetic ingestion**, and is **FALSE for production telemetry**.

---

# E · INDUSTRY PARITY MATRIX

Legend: 🟢 at/above parity · 🟡 partial · 🔴 absent · ⚪ UNKNOWN.

| Capability | MS Defender XDR | Cisco XDR | Cortex XDR | CrowdStrike | SentinelOne | Splunk ES/SOAR | Trellix | **NivXRay XDR** |
|---|---|---|---|---|---|---|---|---|
| Unified incident queue | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 two stores (`workspace_cases` 484 / `xdr_incidents` 1) |
| Alert tier feeding incidents | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (findings) | ✅ | 🔴 **no alert object at all** |
| ML/AI incident prioritisation | ✅ Queue Assistant 0-100 | ✅ Agentic AI | ✅ Analytics BIOC | ✅ | ✅ Purple AI Agentic Investigation | ✅ RBA risk score | ✅ Trellix Wise | 🟡 deterministic VEEE 0-100 (by design, no ML) |
| Executable hunting query language | ✅ KQL, 30-day raw | ✅ | ✅ XQL | ✅ | ✅ | ✅ SPL | ✅ | 🔴 **none** |
| Causality / attack-chain stitching | ✅ | ✅ attack graph | ✅ CID/CGO | ✅ Threat Graph | ✅ Storyline | ✅ finding groups | ✅ Wise graphs | 🟡 `xdr_attack_chain_graph.py` + 10 graph edges |
| Cross-domain correlation (EP+NW+ID+Email+Cloud) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ 1,000+ sources | 🔴 **one live domain** |
| Custom detection authoring | ✅ | ✅ | ✅ BIOC/XQL | ✅ | ✅ | ✅ | ✅ | 🟢 98 rules, 4,300 versions, 13 translators, IR + validation gates |
| Detection content lifecycle/validation gates | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟢 **above parity** (`validation_framework/{gates,tiers,lifecycle}`) |
| Threat intelligence depth (IOC/MITRE/LOLBAS/YARA) | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | 🟢 **at/above parity** — 11,196 LOLBAS primitives, 1,094 framework mappings, 1,894 TI sync runs |
| Entity 360 / entity-centric investigation | ✅ | ✅ Asset Insights | ✅ | ✅ | ✅ | ✅ | ✅ | 🔴 0 entity API paths, `v2_case_entities` = 0 |
| Automated attack disruption | ✅ time-limited, incident-scoped | 🟡 | ✅ agent-level chain kill | ✅ | ✅ autonomous | 🟡 | ✅ TAuR | 🔴 no isolate/contain/quarantine endpoint |
| DAG/no-code playbook designer | ✅ AIR | ✅ Workflows + Atomic Actions, 25 custom | ✅ | ✅ Fusion SOAR (CEL, loops) | ✅ Hyperautomation | ✅ | ✅ | 🟡 designer page exists; **no execution API** |
| Approval gating on response | 🟡 | ✅ | 🟡 | ✅ | ✅ governed | ✅ | ✅ | 🟡 safety-gate code, **no approvals queue** |
| Post-response verification | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟢 **explicit engine** (`response_safety/verification.py`) — differentiator |
| Counterfactual / reachability / intervention reasoning | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🟢 **AG Security State — no benchmarked vendor has this** |
| Immutable, verifiable audit trail | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟢 6,465 audit + 33,004 vault-audit docs + `/audit-log/verify` |
| Multi-tenancy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 tenant param present, 0 `tenant` API paths ⚪ |
| Endpoint agent / live response | ✅ | 🟡 | ✅ | ✅ RTR | ✅ | 🔴 | ✅ | 🔴 none — `routers/edr.py` is a *projection*, self-documented at `edr.py:1-14` |
| Sandbox / detonation | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | 🔴 not implemented |
| UEBA / behavioural baselining | ✅ | ✅ | ✅ ABIOC | ✅ | ✅ | ✅ | ✅ | 🔴 not implemented (target in both PRE-AG and AG) |
| Data retention plane / security data lake | ✅ 30d raw | ✅ | ✅ Native Data Lake | ✅ LogScale | ✅ 365d | ✅ | ✅ | 🔴 SDL tab disabled in `XdrShell.jsx:195` |

---

# F · ARCHITECTURE COMPARISON (structural, not feature-count)

| Dimension | Industry norm | NivXRay XDR | Assessment |
|---|---|---|---|
| Ingest model | Massive multi-source connector fleet feeding a data lake, then detect | DSM → Parser → Normalizer → **single canonical write** → reason | **Architecturally cleaner**, but starved: 0 connected sources |
| Detection→incident tiering | source alert → normalised alert → correlated incident | detection match → **incident directly** (no alert tier) | **Deviation.** Loses per-alert triage, tuning telemetry, FP feedback loop |
| Verdict | ML/risk-score, often opaque | deterministic weighted projection, byte-identical for identical inputs (`xdr_veee.py:11-18`) | **Differentiator** (explainability) at the cost of adaptivity |
| Investigation | analyst-driven query + graph | **projection over existing evidence** — explicitly "no second engine" (`xdr_pipeline.py:322-324`) | **Differentiator**: single source of truth, no divergent reasoning |
| Hunting | first-class query language over retained raw data | none; only per-case query *suggestions* | **Deviation.** No retained-telemetry plane to hunt over |
| Response | orchestrated, agent-backed, approval-gated | registry of 13 actions with honest `capability_available` (5/13) | **Honest but unarmed** |
| Novel plane | — | **Security State**: reachability, counterfactual, impact, intervention optimisation, causal, progression, capability, ledger | **No benchmarked vendor ships this.** Genuine differentiator |
| Honesty posture | vendors interpolate/estimate | NO EVIDENCE → NO CLAIM enforced in API payloads (e.g. `count_source: "live"`, `honesty_note` on `/api/response/actions`) | **Unique. Preserve at all cost.** |

---

# G · CRITICAL ARCHITECTURAL DEVIATIONS

| ID | Deviation | Evidence | Severity |
|---|---|---|---|
| **DEV-1** | **No alert tier.** Detection fires → incident materialisation is attempted directly. | `xdr_pipeline.py:266-311`; `0` of 733 live API paths contain `alert` | **P0** |
| **DEV-2** | **Two DSM registries.** `xdr_pipeline.DSMRegistry` (`:51-74`) hard-codes `SnortEveDSM` then *try-imports* the telemetry package; `telemetry/registry.TelemetryDSMRegistry` (`:14-39`) is a second, independent registry with its own `register_dsm()`. Registration in one is invisible to the other. | both files | **P0** — silent capability loss; `except Exception: pass` at `xdr_pipeline.py:59,65` hides DSM load failures |
| **DEV-3** | **Two case stores.** `workspace_cases` (484) is the analyst-facing legacy store; `xdr_incidents` (1) is the canonical pipeline output; `v2_cases` (35) is a third. | Mongo counts | **P0** |
| **DEV-4** | **No IKG write path in the canonical pipeline.** IKG is consumed by Security State but nothing in `process_event_through_pipeline` writes graph edges. | `xdr_pipeline.py:224-330`; `xdr_evidence_graph_edges` = 10 | **P1** |
| **DEV-5** | **Empty v2 case sub-collections.** `v2_case_events`, `v2_case_entities`, `v2_case_behaviors`, `v2_case_relationships`, `v2_case_reports`, `v2_audit_log`, `v2_enrichment_cache` are **all 0 docs**, yet `/api/v2/cases` returns 35 cases with `event_count: 0, entity_count: 0`. | live `/api/v2/cases` response | **P1** — honest, but the v2 case model is unpopulated |
| **DEV-6** | **`threat_hunting` RBAC permission with no route behind it.** | `routers/xdr_rbac.py:157,211,230` vs 0 hunting routes | **P2** — registration without capability |
| **DEV-7** | **Response actions declared but 8/13 have no capability.** | `/api/response/actions` → `capability_available: 5` of 13 | **P1** (honest; not a bug) |

---

# H · MISSING / PARTIAL CAPABILITY INVENTORY

**MISSING (no code path):** alert object & triage · executable hunting query language · retained-telemetry / security-data-lake plane · entity-360 API · endpoint agent & live response · sandbox/detonation · UEBA/UBAE runtime · NDR API plane · email XDR · identity XDR · cloud/SaaS XDR planes · isolate/contain/quarantine execution · approvals queue · playbook execution API · entity risk scoring (RBA analogue).

**PARTIAL:** collectors (implemented, 0 connected) · DSM coverage (5 DSMs vs 16 declared source kinds) · IKG (read-only) · incident lifecycle (split stores) · response (5/13 capable) · multi-tenancy (param-level, no API) · Security State (implemented + mounted, thin runtime — `security_states` = 3 docs) · Analyst Workspace (two coexisting consoles).

**AT/ABOVE PARITY (do not "improve" without cause):** threat intelligence & IOC/MITRE/LOLBAS/YARA depth · detection-content lifecycle & validation gates · deterministic explainable verdict · audit trail & vault auditability · post-response verification engine · Security-State counterfactual/reachability reasoning.

---

# I · P0/P1/P2 ROADMAP RECOMMENDATIONS

> Gated by the owner's rule: **not recommended merely because a leader has it.** Each item below is justified by an evidence-backed NivXRay gap, not by vendor envy.

**P0 — the baseline is architecturally blocked without these**
1. **Unify the DSM registry (DEV-2).** One registry, explicit registration, **fail loud** instead of `except Exception: pass`. Justification: silent DSM loss invalidates every telemetry-coverage claim. Smallest possible change; no new engine.
2. **Connect one real telemetry source end-to-end (Gap B).** Justification: stages 1–2 are the only break in an otherwise runtime-proven 3→12 chain. One real source converts the whole spine from "synthetic-proven" to "production-proven".
3. **Decide the case-store single source of truth (DEV-3).** Justification: 484 vs 1 vs 35 makes every incident metric unfalsifiable. This is a *decision*, then a migration — not a new capability.

**P1 — required for credible XDR positioning**
4. **Introduce an alert tier (DEV-1).** Detection → Alert → (correlation) → Incident. Justification: without it there is no per-detection triage, no FP feedback, no rule-tuning telemetry — and the existing 98 rules / 4,300 versions cannot be measured.
5. **IKG write path inside the canonical pipeline (DEV-4).** Justification: Security State already *reads* IKG; the graph it reasons over is currently 10 edges.
6. **Entity-360 read API over canonical evidence.** Justification: `v2_case_entities` is empty and IUE already extracts entities (`xdr_pipeline.py:279-287`) — this is a projection, not a new engine.
7. **Playbook execution + approvals queue API.** Justification: `safety_gate.py` and `verification.py` exist and are unreachable from an operator surface.

**P2 — differentiator amplification & parity fill**
8. **Hunting plane** (needs a retention decision first — do **not** build a query language before there is retained telemetry to query).
9. **UBAE/UEBA runtime** (explicit target in both PRE-AG and AG; needs baselining data, which needs P0-2).
10. **Sandbox** (infrastructure-gated; unchanged).
11. **Retire the duplicate Analyst Workspace** (Stage 11 feature-parity migration).
12. **Surface Security State in the operator console.** Justification: it is the single capability no benchmarked vendor ships, and it is currently near-invisible in the UI (`security_states` = 3 docs).

---

# J · EXPLICIT `UNKNOWN` LIST

| # | Unknown | Why it cannot be resolved read-only |
|---|---|---|
| U-1 | Whether the "615 active-certified content objects" claim is real | `/api/xdr/detection/inventory` itself labels it `historical_ag_audit_claim` and does not reproduce it. Mongo shows 98 rules / 339 capability contracts / 339 engines. **Not manufactured here.** |
| U-2 | Decoder count | Prior reconciliation documents disagree; not re-derived in this audit (out of scope, and would require execution) |
| U-3 | Multi-tenancy enforcement depth | `tenant_id` is a required query param on `/api/v2/security-state/streaming/status`, but 0 API paths contain `tenant`. Isolation tests exist (`tests/edr/test_security_state_isolation.py`, `test_phase2_1_tenant_isolation.py`) but were **not executed** (read-only) |
| U-4 | Closure-loop runtime volume | `xdr_closed_loop.py` exists; no collection isolates closure events |
| U-5 | Real playbook count (22 claimed) | No playbook collection observed in Mongo; no execution API. Claim not verifiable |
| U-6 | Whether the 3 AG-added UI pages fully replace main-SPA equivalents | Requires interactive parity testing, which is implementation/QA, not audit |
| U-7 | `mal-20` false-negative root cause | **Deliberately untouched** per standing owner directive |
| U-8 | Security-State engine correctness | 81 files implemented and mounted; `security_states` = 3 docs. Correctness would require execution |

---

# K · AUDIT LIMITATIONS AND CONFIDENCE LEVELS

| Area | Method | Confidence |
|---|---|---|
| PRE-AG boundary SHA | git metadata + parent linkage + diff characteristics + tree-equivalence proof | **HIGH** |
| AG product-code delta counts | `git diff --name-status 95b1c82a^ 95b1c82a` | **HIGH** |
| API surface (733 paths) | live `GET /api/openapi.json` from the preview URL | **HIGH** |
| Mongo runtime volumes | direct `count_documents({})` on the live DB | **HIGH** |
| Pipeline stage wiring | direct source read of `xdr_pipeline.py:224-330` | **HIGH** |
| Runtime proof of dashboard/correlation/detection/verdict/response | authenticated live `curl` against the preview URL | **HIGH** for the endpoints listed in §D; **not** a functional-correctness proof |
| Industry benchmarks | primary vendor documentation retrieved 2026-09-05 (learn.microsoft.com, docs-cortex.paloaltonetworks.com, developer.crowdstrike.com, sentinelone.com, help.splunk.com, docs.xdr.security.cisco.com, trellix.com) | **HIGH** for documented capability existence; **LOW** for effectiveness/quality comparison — never claimed |
| Engine functional correctness (IUE/ICE/VEEE/Security State) | **NOT TESTED** — execution is outside a read-only audit | **N/A** |
| UI functional parity | **NOT TESTED** | **N/A** |

**Declared limitations:** (a) no test suite was executed, so "runtime-proven" means *observed producing output*, never *observed producing correct output*; (b) the preview environment is not production, so telemetry-connectivity findings describe the preview only; (c) capability comparison is capability-existence only — no vendor bake-off, no effectiveness ranking, no proprietary UI cloning; (d) two prior published claims are corrected in §A.2 (#4) and §A.4 and no other prior artifact was edited.

---

## END · Consolidated Master Audit · 17 category deep-dives in `./categories/` · STRICT READ-ONLY · zero application changes
