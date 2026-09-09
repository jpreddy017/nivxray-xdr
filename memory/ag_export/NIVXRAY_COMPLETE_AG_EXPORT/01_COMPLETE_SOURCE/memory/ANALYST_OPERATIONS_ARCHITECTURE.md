# NivXRay Analyst Operations — Phase 0 Architecture Audit

**Status**  ·  Phase 0 · Inventory & Contract Mapping · read-only
**Locked**  ·  Owner directive 2026-02-31
**Rule**    ·  No UI code, no engine changes, no duplicate engines until
              Phase 0 gate passes.

---

## 0 · Locked pillar & principle

    NivXRay XDR
       │
       ├── ANALYST OPERATIONS   ← NEW pillar (this workstream)
       │      Dashboard · Queues · Case · Response · Closure · Report
       │
       ├── INVESTIGATION        ← canonical projections
       │      Evidence · Process Tree · ATT&CK · Attack Story ·
       │      Network · IOCs · Correlation · Scenario Intelligence
       │
       └── ENGINE FABRIC        ← reusable analytical services
              IDA · IUE · UAIE · VEEE · DIE · ICE ·
              IEDDE · UIL · Interpreter · Recipe · Recursive ·
              Artifact Intelligence · PE · Behavioral · Fingerprint ·
              IOC Intelligence · CEM · Provenance · SSOT ·
              KB · MITRE · LOLBAS · Sigma · TI · OSINT ·
              Evidence-Driven Mitigation

**Absolute rule** — the new Analyst Operations layer **orchestrates**
these engines.  It never re-implements them, never renames them, never
collapses their boundaries, and never bypasses them with LLM output.

Retiring an analyst-facing panel (IUE / UAIE Catalog / Verdict-Stage-2
UI) is **not** removal of the underlying engine.

---

## 1 · Engine fabric inventory (backend/services)

Every path below is verified to exist in `/app/backend/services/`.

### 1.1 Investigation & analytical engines

| Engine | Path | Purpose | Contract entry-points |
|---|---|---|---|
| **IDA** — Input & Data Acquisition | `services/ida/` | Ingest + classify + route artifacts | `acquisition.py`, `artifact_router.py`, `artifact_splitter.py`, `input_classifier.py`, `behavior_registry.py`, `behaviors.py`, `report_extractors.py`, `url_intent.py` |
| **IUE** — Input Understanding Engine | `services/iue/` | Normalize raw evidence, run lane parsers, emit understanding rows | `intake.py`, `understanding.py`, `aggregator.py`, `recurse.py`, `timeline.py`, `collectors/` (file/log/url), `parsers/` (csv/json/xml/ndjson/acquired_url/artifact), `normalizers/field_map.py`, `lanes/` (file/url), `_prov.py`, `observability.py`, `failure.py`, `tenancy.py`, `security.py` |
| **UAIE** — Universal Artifact Intelligence Engine | `services/uaie/` | Multi-stage artifact analysis + plugin orchestration | `orchestrator.py`, `planner.py`, `planner_v2.py`, `recognizer.py`, `capability.py`, `capability_adapter.py`, `capability_profiles.py`, `evidence.py`, `provenance.py`, `ledger.py`, `lifecycle.py`, `contract.py`, `retirement_ledger.py`, `ssot_projector.py`, `legacy_ssot_adapter.py`, `transformer_op_adapter.py`, `discovery_report.py`, `adapters/` (commandline/docx/eml/html/json/pdf/plain_text/url/zip_archive), `plugins/` (43 plugins — see §1.6), `qa.py`, `termination.py` |
| **VEEE** — Verdict / Evidence Extraction Engine | `services/veee/` | Evidence extraction, image classification, OCR, summary | `evidence_extractor.py`, `image_classifier.py`, `image_discovery.py`, `line_joiner.py`, `ocr_engine.py`, `summary.py` |
| **DIE** — Decoder / Intent Engine | `services/die/` | Multi-language AST + intent + narrative + LOLBAS + MITRE chain | `api.py`, `input_understanding.py`, `intent.py`, `chain.py`, `mitre_evidence_chain.py`, `narrative.py`, `analyst_narrative.py`, `canonical_narrative_enrichment.py`, `behavior_explainer.py`, `investigation_results.py`, `timeline_projection.py`, `powershell_ast.py`, `bash_ast.py`, `cmd_ast.py`, `python_ast.py`, `javascript_ast.py`, `vbscript_ast.py`, `csv_edr_analyzer.py`, `archive_recovery.py`, `recursive_decode.py`, `ioc_semantic.py`, `query_hunt.py`, `lolbas.py`, `canonical.py`, `canonical_bridge.py`, `confidence.py`, `input_health.py`, `preprocessor/`, `dkp/` |
| **ICE** — Investigation Correlation Engine | `services/ice/` | Correlate observations across evidence | `correlate.py` |

### 1.2 Decoding / command intelligence

| Engine | Path | Purpose |
|---|---|---|
| **IEDDE** — Iterative Evidence-Driven Decode Engine | (invoked via `services/die/recursive_decode.py` + `services/uaie/plugins/`) | Recursive layered decode |
| **UIL** — Universal Input Language | `services/uil/` | Canonical input classification + preprocessing | `canonical_entry.py`, `canonical_session.py`, `classifier.py`, `mixed.py`, `preprocess.py` |
| **Interpreter Identifier** | `services/interpreter_identifier.py` | Detect executing interpreter (PowerShell / CMD / bash / python) |
| **Recipe Planner** | `services/recipe_planner.py` | Plan decode recipe |
| **Recursive Child Pipeline** | `services/recursive_child_pipeline.py` | Recurse into decoded children |

### 1.3 Artifact / malware intelligence

| Engine | Path | Purpose |
|---|---|---|
| **Artifact Intelligence** | `services/artifact_intelligence/analyzers/` | `elf.py`, `office.py`, `pdf.py`, `pe.py` |
| **PE Analyzer** | `services/pe_analyzer.py` (+ UAIE plugin `pe_analyzer`) | PE structural analysis |
| **Behavioral** | `services/behavioral/evtx_reader.py`, `sysmon_adapter.py` | EDR/EVTX/Sysmon behavior extraction |
| **Attack Fingerprint** | `services/attack_fingerprint.py` | Family / campaign fingerprinting |
| **Technique Detector** | `services/technique_detector.py` | ATT&CK technique mapping |
| **IOC Intelligence** | `services/ioc_intelligence/` | `engine.py`, `consensus.py`, `cache.py`, `health.py`, `schema.py`, `providers/` (`virustotal_abuseipdb.py`, `hybrid_analysis.py`, `malwarebazaar.py`, `threatfox.py`, `urlhaus.py`, `urlscan.py`) |

### 1.4 Analytical governance

| Engine | Path | Purpose |
|---|---|---|
| **CEM** — Canonical Evidence Model | `services/cem.py` | Evidence typing |
| **Confidence & Provenance** | `services/confidence_provenance.py` + `services/uaie/provenance.py` + `services/iue/_prov.py` + `services/registry/provenance.py` | Every result carries source + confidence |
| **SSOT** | `services/ssot_store.py` + `services/uaie/ssot_projector.py` + `services/uaie/legacy_ssot_adapter.py` | Single source of truth for engine outputs |
| **XDR Observation Contract** | `services/xdr_observation_contract.py` | Canonical OBSERVATION schema |
| **Canonical Evidence Recovery** | `services/canonical_evidence_recovery.py` | Recover CEM rows from historical incidents |
| **Registry** | `services/registry/` | `iue_projection.py`, `provenance.py`, `router.py` |

### 1.5 Knowledge / threat intelligence

| Layer | Path |
|---|---|
| **Knowledge Base** | `services/knowledge/behavior_registry.py`, `backend/routers/kb.py`, `services/reasoning/behavior_extractor.py` |
| **MITRE ATT&CK** | `services/die/mitre_evidence_chain.py`, `services/ida/projections/mitre.py`, `services/diagnostics/mitre_consistency.py`, `backend/routers/mitre_heatmap.py` |
| **LOLBAS** | `backend/lolbas.py`, `backend/lolbas_chain.py`, `services/die/lolbas.py`, `backend/routers/xdr_lolbas.py`, `backend/routers/lolbas_export.py` |
| **Sigma** | `backend/sigma_generator.py`, `backend/sigma_export.py`, `backend/routers/sigma.py` |
| **Threat Intelligence** | `backend/routers/threat_intel.py`, `threat_intel_enrich.py`, `threat_intel_rss.py`, `taxii.py`, `backend/ti_feed_sync.py`, `backend/feeds.py`, `backend/routers/public_feeds.py` |
| **OSINT** | `backend/osint.py` |
| **Evidence-Driven Mitigation** | `services/mitigation/evidence_driven/`, `backend/routers/mitigations_evidence_driven.py`, `backend/routers/mitigations.py` |
| **SOC-100** | `backend/data/soc100_scenarios.json` (100 · locked), `backend/routers/xdr_scenarios.py`, `backend/tests/test_xdr_scenarios.py` |

### 1.6 UAIE plugin registry (43 plugins)

Anti-fabrication note — the UAIE plugin set is authoritative and must be
reused by Analyst Operations rather than reproduced:

```
analyzer_magic_byte_retyper · base64_bare · base64_frombase64string ·
crypto_aes_cbc · crypto_rc4 · crypto_shape_detector ·
cs_beacon_config_parser · extractor_binary_configuration ·
family_universal_recognizer · gzip_inflate · op_crypto_api_annotator ·
op_ps_encodedcommand_multilayer · op_ps_hex_csv_inline ·
op_ps_normalize · op_ps_reverse_regex_swap · op_ps_reverse_string ·
op_ps_semantic_mini · op_ps_xor_inline_key · op_rc4_inline_decrypt ·
pe_analyzer · pe_dotnet_recognizer · pe_extractor ·
powershell_encoded_command · promoter_configuration_iocs ·
ps_alias_normalizer · ps_backtick_normalizer · ps_hex_escape ·
ps_reconstruct · repair_base64_strip_html_entities ·
repair_base64_surgical · shellcode_analyzer · shellcode_string_scan ·
transformer_byte_array_xor_loop · validator_base64_text ·
validator_gzip_bytes · validator_pe_bytes · validator_shellcode_bytes ·
xor_brute · zlib_inflate
```

### 1.7 XDR-native investigation layer (already present)

| Component | Path |
|---|---|
| Correlation | `services/correlation_engine.py`, `backend/routers/xdr_correlation.py`, `backend/routers/correlations.py` |
| Process Tree | `backend/chain_analyzer.py`, `backend/routers/process_tree.py`, `apps/nivxray-xdr/src/xdr/investigation/ProcessTreePanel.jsx` |
| ATT&CK Chain | `apps/nivxray-xdr/src/xdr/investigation/AttackChainPanel.jsx`, `services/ida/projections/kill_chain.py` |
| Attack Story | `services/die/narrative.py`, `services/die/analyst_narrative.py`, `services/die/canonical_narrative_enrichment.py` |
| Verdict Stage 2 | `services/verdict_stage2/engine.py`, `model.py`, `rules.py`, `fingerprint.py`, `inputs.py`, `backend/routers/verdict_stage2.py` |
| Scenario Intelligence | `backend/data/soc100_scenarios.json` (100), `backend/routers/xdr_scenarios.py` |
| Evidence-First workspace | `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` |
| Selection Context | `apps/nivxray-xdr/src/xdr/investigation/WorkspaceSelectionContext.jsx` |
| Report shell | `apps/nivxray-xdr/src/xdr/investigation/InvestigationReportShell.jsx` |

---

## 2 · Current API surface (Mongo-backed, `/api/*`)

Verified in `backend/routers/`.  Each row lists the HTTP contract that
Analyst Operations MUST reuse.

### 2.1 Incidents (case metadata)

| Method | Path | Router | Notes |
|---|---|---|---|
| GET | `/api/incidents` | `incidents.py:493` | scoped to `user_email`, only cases with `name` |
| GET | `/api/incidents/{id}` | `incidents.py:520` | `_project_detail` — trimmed doc |
| PATCH | `/api/incidents/{id}/state` | `incidents.py:537` | lifecycle transition (new / in_progress / on_hold / resolved / closed) |
| PATCH | `/api/incidents/{id}/assignee` | `incidents.py:580` | ownership |
| GET | `/api/incidents/{id}/summary` | `incident_summary.py:156` | canonical summary projection |
| GET | `/api/incidents/{id}/response-executions` | `xdr_response_evidence.py:191` | response action history |

### 2.2 Cases (analyst working set)

| Method | Path | Router | Notes |
|---|---|---|---|
| POST | `/api/cases/save` | `cases.py:44` | persist working investigation |
| GET | `/api/cases` | `cases.py:288` | list saved cases |
| GET | `/api/cases/{id}` | `cases.py:310` | detail |
| DELETE | `/api/cases/{id}` | `cases.py:421` | remove |
| GET | `/api/cases/{id}/sigma` | `cases.py:430` | Sigma export |
| GET | `/api/cases/{id}/yara` | `cases.py:468` | YARA export |
| POST | `/api/cases/{id}/reinvestigate` | `cases.py:507` | re-run engines |
| POST | `/api/cases/reinvestigate-broken` | `cases.py:578` | bulk repair |

### 2.3 Investigations (workspace working set)

| Method | Path | Router |
|---|---|---|
| GET | `/api/investigations` · `/recent` · `/lookup` · `/{iid}/timeline` · `/{iid}/note` · `/{iid}` (delete) | `investigations.py` |
| POST | `/api/workspace/investigation` (create) | `workspace_investigation.py:189` |
| GET | `/api/workspace/investigation` (list) | 218 |
| GET | `/api/workspace/investigation/{case_id}` | 241 |
| GET | `/api/workspace/investigation/{case_id}/workspace` | 302 |
| PUT | `/api/workspace/investigation/{case_id}/workspace` | 308 |
| POST | `/api/workspace/investigation/{case_id}/state/transition` | 350 |
| GET | `/api/workspace/investigation/{case_id}/state` | 380 |
| DELETE | `/api/workspace/investigation/{case_id}` | 396 |

### 2.4 Engine execution endpoints

| Engine | Route |
|---|---|
| Verdict Stage 2 | GET `/api/verdict-stage2/status` · POST `/compute` · POST `/auto-compute` |
| IUE lanes | `iue_lane_a` · `iue_lane_b` · `iue_lane_c` · `iue_timeline` routers |
| Auto-Investigate | POST `/api/auto-investigate` · POST `/api/auto-investigate/jobs` · GET `/jobs/{job_id}` |
| Correlations | GET `/api/xdr/correlation/status` · `/rules` · `/matches` · POST `/signals` · `/replay` · CRUD `/rules` |
| Enrichment | GET/POST `/api/enrichment/config` · POST `/enrichment/ioc` · `/bulk` · GET `/classify` |
| Response evidence | POST `/api/xdr/response-evidence` · GET `/{execution_id}` |
| Behavioral | via `behavioral.py` router |
| Behavior provenance | via `behavior_provenance.py` |
| Behavior registry | via `behavior_registry.py` |
| DIE | via `die.py` router |
| IEDDE | via `iedde.py` router |
| UAIE | `uaie.py` + retired `uaie_catalog.py` UI (engine intact) |
| UIL | via `uil.py` |
| Analyze | via `analyze.py` |
| IOC Intelligence | via `ioc_intelligence.py` |
| KB / Sigma / Threat Intel / TAXII / LOLBAS | `kb.py` · `sigma.py` · `threat_intel*.py` · `taxii.py` · `lolbas_export.py` |
| MITRE heatmap | `mitre_heatmap.py` |
| Reports | `reports.py` + `report_writer.py` |
| Mitigations | `mitigations.py` + `mitigations_evidence_driven.py` |
| Chain | `chain.py` (process chain analyzer) |
| Process tree | `process_tree.py` |
| Coverage metrics | `coverage_metrics.py` |
| Timeline | `timeline.py` |
| Activity | `activity.py:27` |
| Ops / Health | `ops.py` · `platform_health.py` |
| Analyst corrections | `analyst_corrections.py` · `analyst_v2.py` |
| XDR RBAC | `xdr_rbac.py` (`/permissions`, `/roles`, `/users`, `/groups`, `/simulate`) |
| XDR Rule Studio | `xdr_rule_studio.py` |
| XDR Audit Log | `xdr_audit_log.py` |
| XDR Detection Content | `xdr_detection_content.py` |
| XDR Collectors / Data Sources / API keys / Secrets / Webhooks | `xdr_collectors.py` · `xdr_data_sources.py` · `xdr_api_keys.py` · `xdr_secrets.py` · `xdr_webhooks.py` |
| XDR Ingest | `xdr_ingest.py` |
| XDR CVE | `xdr_cve.py` |
| XDR Scenarios | `xdr_scenarios.py` (100 SOC scenarios) |
| XDR Response Evidence | `xdr_response_evidence.py` |
| XDR Correlation | `xdr_correlation.py` |

---

## 3 · Data model — Mongo collections referenced today

| Collection | Owner | Purpose |
|---|---|---|
| `incidents` | `incidents.py`, `incident_summary.py`, `cases.py`, `workspace_investigation.py`, `verdict_stage2/engine.py` | primary case document · carries `verdict_stage2`, `incident_state`, `incident_assignee`, `iocs`, `evidence`, `techniques` |
| `workspace_cases` | `workspace_investigation.py` | analyst working state |
| `xdr_correlation_matches` / `xdr_correlation_rules` | `xdr_correlation.py` | correlation state |
| `response_executions` | `xdr_response_evidence.py` | response history |
| `xdr_audit_log` | `xdr_audit_log.py` | immutable audit |
| `xdr_rbac_*` | `xdr_rbac.py` | roles / users / groups |
| `xdr_observations` | to be created by Phase-4 Process Genealogy (previously Task E) | canonical OBSERVATION objects |
| `iocs` | `threat_intel.py` | IOC store |
| `ssot_store` | `services/ssot_store.py` | canonical engine outputs |

---

## 4 · Contract map — ENGINE → INPUT → OUTPUT → CONSUMER

    Detection / Telemetry
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  IDA  · input classifier + acquisition                       │
    │        in:  raw evidence, URLs, artifacts                    │
    │        out: classified input, artifact envelope              │
    │  consumer → IUE, UAIE, VEEE                                  │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  IUE  · normalize + parse lanes                              │
    │        in:  classified input                                 │
    │        out: understanding rows, timeline, provenance         │
    │  consumer → UAIE, DIE, VEEE, correlation                     │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  UAIE · plugin orchestration (43 plugins)                    │
    │        in:  understanding rows                               │
    │        out: artifact evidence, decoded payloads, provenance  │
    │  consumer → DIE, VEEE, ICE                                   │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  DIE  · decoding + intent + narrative                        │
    │        in:  understanding rows + artifact evidence           │
    │        out: intent, chain, mitre_evidence_chain, narrative   │
    │  consumer → VEEE, ICE, Attack Story                          │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  VEEE · evidence extraction / OCR / image / summary          │
    │        in:  understanding + intent                           │
    │        out: canonical evidence rows                          │
    │  consumer → ICE, Verdict Stage 2, Report                     │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  ICE  · correlate observations                               │
    │        in:  evidence + observations                          │
    │        out: correlation graph edges, IKG updates             │
    │  consumer → Verdict Stage 2, Attack Story, Report            │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  Verdict Stage 2 · deterministic risk / verdict              │
    │        in:  evidence + observations + correlation            │
    │        out: verdict, confidence, provenance                  │
    │  consumer → Incident.verdict_stage2, Attack Story, Report,   │
    │             Dashboard tiles, Queues                          │
    └─────────────────────────────────────────────────────────────┘
             │
             ▼
    Attack Story · SOC-100 pivots · Recommendations · Report

Additionally:

    UIL / Interpreter / Recipe / Recursive Child
       └── called by UAIE + DIE when the input demands it
    IEDDE
       └── recursive decode iteration inside DIE / UAIE
    Artifact Intelligence · PE · Behavioral · Fingerprint · Technique · IOC
       └── called by UAIE plugins + IUE lanes
    CEM · Confidence & Provenance · SSOT
       └── enforced by every engine on output rows
    KB · MITRE · LOLBAS · Sigma · TI · OSINT · SOC-100
       └── enrichment inputs, never fabricated evidence
    Evidence-Driven Mitigation
       └── produces Recommendations from canonical evidence + verdict

---

## 5 · Frontend XDR route inventory

| Route | Component | State |
|---|---|---|
| `/xdr` → redirect | | |
| `/xdr/incidents` | `XdrIncidentsPage.jsx` | list + `?mine=1` · `?technique=T####` filters (no tiles / lenses yet) |
| `/xdr/incidents/:id` | `XdrIncidentDetailPage.jsx` | tabs = overview / investigation / activity / response · sub-tabs in Investigation |
| `/xdr/incidents/:id/domain/:domainKey` | `XdrIncidentDomainPage.jsx` | domain deep-links |
| `/xdr/endpoints/:device/trajectory` | `XdrDeviceTrajectoryPage.jsx` | device trajectory |
| `/xdr/intelligence/threat` · `iocs` · `command` · `malware` | `XdrReservedPage` | reserved placeholders |
| `/xdr/intelligence/mitre` | `XdrMitreHeatmap.jsx` | MITRE coverage |
| `/xdr/intelligence/kb` · `/xdr/kb` | `XdrKbPage.jsx` | Knowledge Base |
| `/xdr/respond/playbooks` · `/:id` | `XdrPlaybooksPage.jsx`, `XdrPlaybookDesignerPage.jsx` | playbooks |
| `/xdr/respond/automation-rules` · `/:id` | `XdrAutomationRulesPage.jsx`, `XdrAutomationRuleEditorPage.jsx` | automation |
| `/xdr/respond/approvals` | `XdrApprovalsPage.jsx` | approval queue |
| `/xdr/evidence/:executionId` | `XdrEvidenceRefPage.jsx` | evidence deep-link |
| `/xdr/detections` · `/:id` · `/detect/tuning/:ruleId` | `XdrDetectionsPage.jsx`, `XdrDetectionRuleEditorPage.jsx`, `XdrRuleTuningPage.jsx` | detection content |
| `/xdr/docs` | `XdrDocsPage.jsx` | docs |
| `/xdr/exposure` | `XdrExposurePage.jsx` | exposure surface |
| `/xdr/dashboard` | *(not routed — `XdrDashboardPage.jsx` exists but unrouted)* | **GAP — Phase 1 lands here** |

Existing incident detail sub-tabs on the Investigation lens:
`overview / investigation / activity / response` (`XdrIncidentDetailPage.jsx`).

`InvestigationReportShell.jsx` renders **Executive Summary + Coverage +
Section availability**, all preview-only.  It is honest — never
fabricates content.

---

## 6 · What is missing (Analyst Operations layer)

Gaps discovered through this inventory:

1. **No routed dashboard.** `XdrDashboardPage.jsx` exists but no route
   points at it, and it has no lens tiles yet.
2. **No operational lenses on `/xdr/incidents`.**  Only `?mine=1` and
   `?technique=T` filters exist.  Missing: Critical / High Priority /
   High Fidelity / Unassigned / In Progress / Customer Response / On
   Hold / SLA / Aging / Recently Created / Recently Updated.
3. **No SLA / aging fields on the `incidents` collection.**  Priority,
   severity, on-hold-reason, on-hold-until, customer-engaged flags are
   not persisted.
4. **No `xdr_observations` collection.**  Was Task E in the old queue —
   subsumed by Phase 4 in the new plan.
5. **No engine-execution ledger for a given incident.**  Provenance
   exists per engine (`_prov.py`, `provenance.py`, `ledger.py`) but
   there is no single `GET /api/incidents/{id}/engine-executions`
   endpoint that answers "which engines ran, with what input, with what
   output, at what confidence".
6. **No engine-orchestration entry-point** that says: "for this
   incident, run the correct engines for the correct evidence" and
   emits provenance-tagged results.  `auto_investigate.py` and
   `verdict_stage2/auto-compute` are the closest components; both need
   an orchestration wrapper.
7. **No enrichment router for hosts / users / processes / files /
   certificates** — only IOC enrichment (`enrichment/ioc`).
8. **No Executive Summary / Technical Summary / Supporting Evidence /
   Recommendations generators** — sections are stubbed in
   `InvestigationReportShell.jsx` awaiting Phase 5.
9. **No Closure Readiness computation.**  Closure fields are not
   modelled.
10. **No Related-Records graph endpoint** unifying parent / child /
    duplicate / related incidents.
11. **No dedicated Attachments router.**
12. **Notes exist under `/api/investigations/{iid}/note` but are not
    surfaced separately from system activity in the UI.**
13. **`activity.py` router exists but is inventory-only** — no
    per-incident immutable activity feed endpoint yet.

---

## 7 · Locked implementation plan (updated queue)

The previous `B → E → C → A → F → D` queue is superseded.  New locked
order:

```
Phase 0 · Architecture Audit (this document)                 ← DONE
Phase 1 · Operations Dashboard (routed, lens tiles)
Phase 2 · Incident Queues (operational lenses + filters)
Phase 3 · Incident Record + Lifecycle + Ownership
Phase 4 · Auto-Investigation Orchestration
              wires IDA→IUE→UAIE→DIE→VEEE→ICE→Verdict + Process
              Genealogy (was Task E) + Correlation into per-incident
              engine-execution ledger.  Emits canonical OBSERVATION
              rows into xdr_observations.
Phase 5 · Executive Summary · Technical Summary ·
              Supporting Evidence · Recommendations
              (uses Attack Story from DIE narrative + Verdict Stage 2 +
              Evidence-Driven Mitigation + SOC-100 pivots)
Phase 6 · Enrichment · Telemetry navigation · OSINT · TI
Phase 7 · Activity · Notes · Related Records · Attachments
Phase 8 · Response integration
Phase 9 · Closure + Closure Readiness
Phase 10 · Final evidence-backed Report
```

**Anti-fabrication invariants — enforced at every phase:**

- Scenario knowledge (SOC-100) ≠ Incident evidence ≠ Detection ≠ Verdict
- Recommendation ≠ Executed action (state: RECOMMENDED / PENDING / EXECUTED / FAILED / NOT_APPLICABLE / UNKNOWN)
- System-generated ≠ Analyst-authored (both stored, both audited)
- Missing engine result ≠ Empty result ("engine unavailable" is honest)
- Evidence is immutable; analyst annotations sit alongside, never overwrite
- OBSERVED / CORRELATED / INFERRED / RECOMMENDED / EXECUTED / UNKNOWN classifications preserved on every claim

**Engine-fabric preservation:**

- IDA / IUE / UAIE / VEEE / DIE / ICE / IEDDE / UIL / Interpreter /
  Recipe / Recursive Child / Artifact Intelligence / PE / Behavioral /
  Fingerprint / Technique Detector / IOC Intelligence / CEM /
  Provenance / SSOT / KB / MITRE / LOLBAS / Sigma / TI / OSINT /
  Evidence-Driven Mitigation — all remain reusable, none rewritten.

---

## 8 · Phase 0 completion — deliverable status

| Item | Status |
|---|---|
| Engine inventory | ✅ §1 |
| API contract map | ✅ §2 |
| Data model map | ✅ §3 |
| ENGINE → INPUT → OUTPUT → CONSUMER map | ✅ §4 |
| Frontend surface inventory | ✅ §5 |
| Gap identification | ✅ §6 |
| Locked implementation plan | ✅ §7 |

**Phase 0 gate — PASS.**  Ready to plan Phase 1 (Operations Dashboard)
under owner approval.  No implementation code written until Phase 1
scope is signed off.
