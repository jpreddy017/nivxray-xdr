# NivXRay XDR — Technology Adoption Matrix

**Status:** Evidence-backed inventory · rewritten 2026-02-10 · owner-locked directive
"NivXRay XDR must not become a second, weaker implementation of technology that already exists in NivXRay."

## Guiding rule
**Adopt before invent.**  For every XDR capability need:

1. Inspect the existing NivXRay implementation under `/app/backend/`.
2. Identify the actual engine / mechanism / route (with concrete file path).
3. Decide the adoption method: `ADOPT` (call the API), `PROXY` (thin XDR route wrapping the base), `SHARED_LIBRARY` (import a Python module), `ADAPTER` (wrap for a new telemetry source), `EXTEND` (add capability to the base), `NEW` (only if the base genuinely lacks it), `EXTERNAL` (open-standard adoption), `BASE_ONLY` (available in NivXRay but not analyst-facing in XDR), `NOT_PRESENT` (does not exist).
4. Never build a "simplified" duplicate.  If not yet exposed to XDR, show honestly: **AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED**.

## Adoption classifications (canonical)
| State | Meaning |
| --- | --- |
| ADOPT           | Exists in base; XDR consumes via API or shared library |
| ADAPT           | Exists but needs an adapter for a new telemetry/vendor source |
| EXTEND          | Exists but insufficient for XDR; add capability to the base |
| SHARED_LIBRARY  | Import a base Python module directly |
| PROXY           | Thin XDR route wrapping a base route |
| NEW             | Genuinely does not exist; must be built |
| BASE_ONLY       | Available in base but not exposed as an analyst surface in XDR |
| NOT_PRESENT     | Verified absent from `/app/backend` after code inspection |
| EXTERNAL        | Best solved by adopting an established open standard/library |
| CONNECTED       | Adoption is wired and green tests exist |

## Inspection method (2026-02-10)
- `ls /app/backend/{engine,routers,services,canonical,nivxforge,v2}/`
- `grep -R "APIRouter\|include_router" /app/backend/`
- `grep -R "services\.<engine>" --include="*.py"`
- Every row below cites at least one concrete `/app/backend/**` file path AND the API surface (if mounted).

---

## §1 · Canonical named engines (owner-listed acronyms)

### 1.1 · IDA — Input · Discovery · Acquisition
- **What it does:** Classifies incoming inputs by kind (commandline, powershell, script, binary, url, csv, archive, image), routes artifacts to the correct extractor, and produces an acquisition summary with provenance.
- **Implementation:** `/app/backend/services/ida/{input_classifier.py, acquisition.py, artifact_router.py, artifact_splitter.py, behavior_registry.py, behaviors.py, report_extractors.py, url_intent.py, projections/}`
- **API surface (base):** No dedicated `/api/ida/*` router — IDA is invoked internally by `/api/analyze`, `/api/artifacts`, and by DIE/IEDDE stages.  Also referenced via `/app/backend/tests/test_ida_artifact_splitter.py` and `/app/backend/tests/test_p015c2_acquisition_summary.py`.
- **Inputs:** raw payload (string / bytes / file url).
- **Outputs:** `IDAResult{kind, confidence, evidence, provenance}`.
- **Dependencies:** none (deterministic).
- **XDR compatibility:** ✅ compatible via `/api/analyze` and `/api/artifacts`; a first-class XDR pivot is high-value.
- **Adoption:** **ADOPT** (via `/api/analyze` + `/api/artifacts`).
- **XDR status:** BASE_ONLY (proxied through analyze); ADAPTER surface = new **IDA Input Classifier panel**.

### 1.2 · IUE — Investigation Understanding Engine
- **What it does:** Multi-lane deterministic investigation understanding — the *analysis engine* that transforms raw evidence into per-artefact "understanding" records, then fuses them into a unified timeline.
- **Implementation:**
  - `/app/backend/services/iue/{intake.py, aggregator.py, recurse.py, security.py, tenancy.py, timeline.py, understanding.py, failure.py, observability.py, collectors/, lanes/, normalizers/, parsers/, _prov.py}`
  - `/app/backend/canonical/iue/adapters/` (canonical evidence adapters, incl. `artefact_decomp.py`).
  - Routers: `routers/iue_lane_a.py`, `routers/iue_lane_b.py`, `routers/iue_lane_c.py`, `routers/iue_timeline.py`.
- **API surface (base):**
  - `GET  /api/iue/lane-a/status`
  - `POST /api/iue/lane-a/analyze`
  - `POST /api/iue/lane-b/analyze`
  - `GET  /api/iue/lane-c/status`
  - `POST /api/iue/lane-c/analyze`
  - `POST /api/iue/lane-c/analyze-b64`
  - `POST /api/iue/timeline/fuse`
- **Inputs:** artefact/evidence payload + tenancy scope.
- **Outputs:** `IUEUnderstanding{lane, techniques, entities, timeline_events, provenance}`.
- **XDR compatibility:** ✅ ideal — the IUE Timeline `POST /api/iue/timeline/fuse` is the authoritative unified timeline projection.
- **Adoption:** **ADOPT** (`/api/iue/*` + `/api/iue/timeline/fuse`).
- **XDR status:** Timeline is CONNECTED via previous adoption; the three lanes (A/B/C) are now consumed via **IUE Lane Consumer**.

### 1.3 · UAIE — Universal Artefact Investigation Engine
- **What it does:** Capability-driven orchestration/planner over pluggable artefact investigations — the pluggable "capability catalog" + planner that decides which behavior extractors and recognizers to fire for a given artefact class.
- **Implementation:**
  - `/app/backend/services/uaie/{artifact.py, behavior_extractor.py, capability.py, capability_adapter.py, capability_profiles.py, contract.py, discovery_report.py, evidence.py, ledger.py, legacy_ssot_adapter.py, lifecycle.py, migration_gate.py, orchestrator.py, planner.py, planner_v2.py, provenance.py, qa.py, recognizer.py, ssot_projector.py, transformer_op_adapter.py, adapters/, plugins/, retirement/}`
  - Routers: `routers/uaie.py`, `routers/uaie_catalog.py`.
- **API surface (base):**
  - `POST /api/uaie/dry-run`
  - `POST /api/uaie/compare`
  - `GET  /api/uaie/catalog`       — capability catalog + relationship graph
  - `GET  /api/uaie/catalog.dot`   — Graphviz export
- **Inputs:** artefact spec + optional plan hints.
- **Outputs:** capability catalog, planner output, dry-run trace, comparison delta.
- **XDR compatibility:** ✅ ideal for an analyst-facing "why did this fire?" pivot and a capability inventory pane.
- **Adoption:** **ADOPT** (`/api/uaie/catalog` + `/api/uaie/dry-run`).
- **XDR status:** BASE_ONLY → now consumed via **UAIE Catalog Consumer**.

### 1.4 · VEEE — Visual/Vision Evidence Extraction Engine
- **What it does:** Image-based evidence extractor.  Runs OCR (tesseract-5) over provided images and normalises OCR lines into `NormalizedEvidence[]` (commandline, url, ip, path, etc.) with bounding-box + confidence + image sha256 provenance per ADR-002 §5.
- **Implementation:** `/app/backend/services/veee/{evidence_extractor.py, image_classifier.py, image_discovery.py, line_joiner.py, ocr_engine.py, summary.py, __init__.py}`
- **API surface (base):** No dedicated `/api/veee/*` router — invoked from `routers/cases.py` (`services.veee.summary.compute_summary`, `services.veee.is_enabled`) and internally by the case pipeline.
- **Inputs:** image bytes / image URL.
- **Outputs:** `OCRResult`, `NormalizedEvidence[]` with `acquisition_level="P3"`, `source="image"`.
- **XDR compatibility:** ⚠️ specific to case-time image evidence.  XDR incident detail rarely carries raw images.
- **Adoption:** **BASE_ONLY** (available via existing case endpoints; no direct XDR surface built).
- **XDR status:** REGISTERED as BASE_ONLY — honest banner `AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED (case-only)`.
- **Correction of earlier assumption:** VEEE **IS PRESENT** in the codebase (contrary to the prior conversation snippet).  Evidence: 6 concrete Python modules and multiple call sites in `routers/cases.py`.

### 1.5 · DIE — Deterministic Investigation Engine (Decoder / Interpreter)
- **What it does:** Deterministic AST-based decoder, interpreter identifier, LOLBAS mapper, chain analyser, IOC extractor, DKP (deterministic knowledge patterns), archive recovery, mitre-evidence chain builder, timeline projector, and narrative writer.  This is the authoritative decoder chain.
- **Implementation:** `/app/backend/services/die/{api.py, analyst_narrative.py, archive_recovery.py, bash_ast.py, behavior_explainer.py, canonical.py, canonical_bridge.py, canonical_narrative_enrichment.py, chain.py, cmd_ast.py, confidence.py, csv_edr_analyzer.py, dkp/, input_health.py, input_understanding.py, intent.py, investigation_results.py, ioc_semantic.py, javascript_ast.py, lolbas.py, mitre_evidence_chain.py, narrative.py, powershell_ast.py, preprocessor/, python_ast.py, query_hunt.py, recursive_decode.py, timeline_projection.py, vbscript_ast.py}`
  - Router: `routers/die.py`.
- **API surface (base):**
  - `POST /api/die/analyze`, `POST /api/die/understand`, `POST /api/die/narrate`
  - `POST /api/die/investigation-results`, `POST /api/die/timeline`, `POST /api/die/query`
  - `POST /api/die/health-check`, `POST /api/die/investigation`
  - `POST /api/die/powershell/ast`, `POST /api/die/iocs`
  - `GET  /api/die/lolbas`, `GET /api/die/lolbas/{binary}`
  - `POST /api/die/archive/recover`, `POST /api/die/detect-kind`
  - `GET  /api/die/dkp/patterns`, `GET /api/die/dkp/patterns/{pattern_id}`
  - `POST /api/die/chain`, `POST /api/die/intent`
  - `GET  /api/die/case/{case_id}`
- **Inputs:** raw payload (commandline, script, binary blob, archive).
- **Outputs:** deterministic decode chain, intent, LOLBAS mapping, MITRE evidence chain, timeline projection, IOCs.
- **XDR compatibility:** ✅ ideal — replaces every hand-rolled decoder in XDR.  This is the engine the Sigma test/replay screen must call (already partially wired via `/api/analyze` on the Sigma page; DIE is deeper and more auditable).
- **Adoption:** **ADOPT** (`/api/die/analyze`, `/api/die/understand`, `/api/die/narrate`, `/api/die/chain`).
- **XDR status:** BASE_ONLY (via `/api/analyze` proxy) → now analyst-facing via **DIE Decoder Chain Panel** on the incident investigation surface.

### 1.6 · ICE — Investigation Correlation Engine
- **What it does:** Deterministic single-pass correlation over per-artefact investigations — turns isolated investigations into behavior clusters, attack phases, kill-chain ordering, unified timeline, and an incident graph.  R21: "Correlation happens once."
- **Implementation:** `/app/backend/services/ice/{correlate.py, __init__.py}`
  - Consumed by: `routers/cases.py` (`enrich_clusters_in_place`), `routers/correlations.py`, `services/die/investigation_results.py`, `services/die/canonical_bridge.py`, `services/session/summary_narrative.py`, `services/diagnostics/{mitre_consistency, vendor_benchmark, bkb_comparison}.py`, `services/knowledge/behavior_registry.py`.
  - Tests: `tests/test_ice_correlate.py`, `tests/canonical/stage1_goldens/test_t1_e_ice_incident.py`.
- **API surface (base):** No dedicated `/api/ice/*` router.  ICE is *the engine behind* `/api/correlations/*` — the router exposes 20 correlation endpoints backed by ICE:
  - `POST /api/correlations`, `GET /api/correlations`, `GET /api/correlations/{cid}`, `DELETE /api/correlations/{cid}`
  - `POST /api/correlations/{cid}/link|unlink`, `GET /api/correlations/{cid}/chain|graph|timeline|summary|suggestions`
  - `POST /api/correlations/scan`, `POST /api/correlations/find-related`
  - `GET  /api/correlations/cem/{case_id}`, `GET /api/correlations/fingerprint/{case_id}`
  - `POST /api/correlations/compare`, `GET /api/correlations/provenance/{case_id}`
- **Inputs:** SSOT block from upstream investigation.
- **Outputs:** `correlations{clusters, phases, timeline, graph, provenance}`.
- **XDR compatibility:** ✅ already CONNECTED via the correlation-graph consumer used by the Investigation Canvas.
- **Adoption:** **ADOPT** (`/api/correlations/*`).
- **XDR status:** CONNECTED (edges merged into canvas).  Additional surfaces: cluster/phase/kill-chain projections — analyst-facing pane pending.
- **Correction of earlier assumption:** ICE **IS PRESENT** in the codebase.  Evidence: `services/ice/correlate.py` (deterministic engine) + 8 internal call sites + 20-route `/api/correlations/*` router.

### 1.7 · CEM — Canonical Evidence Model
- **What it does:** Canonical evidence model + fingerprinting/parity — normalises heterogeneous evidence into a canonical shape so downstream projections and correlation are stable across sources.  Deterministic parity checks (`cem_parity.py`) ensure two runs produce byte-identical CEM records.
- **Implementation:**
  - `/app/backend/services/cem.py`  (CEM primary service)
  - `/app/backend/v2/cem/{registry.py, v1/}`
  - `/app/backend/nivxforge/investigation/pipeline/cem_parity.py`
  - Related: `services/attack_fingerprint.py`, `services/case_compare.py`.
  - Tests: `tests/test_cem_and_recursive_pipeline.py`.
- **API surface (base):** Not directly exposed via a dedicated `/api/cem/*` router.  Consumed by `/api/correlations/cem/{case_id}` (via ICE) and internal pipelines.
- **Inputs:** raw case/evidence blocks.
- **Outputs:** canonical evidence records + fingerprint.
- **XDR compatibility:** ⚠️ CEM records are already surfaced *through* correlations + investigation report; a direct XDR pane offers marginal value.
- **Adoption:** **ADOPT** (via `/api/correlations/cem/{case_id}`).
- **XDR status:** BASE_ONLY (surfaced through the ICE/correlation consumer).

### 1.8 · UIL — Unified Input Layer
- **What it does:** Classifies incoming payloads (single/mixed/session), splits mixed inputs into canonical sessions, and drives the recursive investigation loop.  Preprocess + canonical entry + canonical session.
- **Implementation:** `/app/backend/services/uil/{canonical_entry.py, canonical_session.py, classifier.py, mixed.py, preprocess.py, __init__.py}`
  - Router: `routers/uil.py`.
- **API surface (base):**
  - `POST /api/uil/classify`
  - `POST /api/uil/split`
  - `POST /api/uil/investigate`
- **Inputs:** raw payload (string / bytes / structured).
- **Outputs:** `UILClassification{kind, sessions[], canonical_entry, provenance}`.
- **XDR compatibility:** ✅ great for an analyst "explain how this input was parsed" pivot.
- **Adoption:** **ADOPT** (`/api/uil/classify`, `/api/uil/split`, `/api/uil/investigate`).
- **XDR status:** BASE_ONLY → now consumed via **UIL Classifier Consumer**.

### 1.9 · IEDDE — Iterative Evidence-Driven Decoding Engine
- **What it does:** The Stage-1/2/3 iterative decoding loop that produces the canonical decode trace: interpreter identification → technique inventory → decision → transformation → canonicality delta.  Deterministic; identical input → byte-identical response body.
- **Implementation:**
  - Router: `routers/iedde.py` (docstring is the authoritative contract).
  - Uses: `services/interpreter_identifier.py`, DIE stage 1/2/3.
- **API surface (base):**
  - `POST /api/iedde/analyze` → full IEDDE loop (Stages 1–3) with deterministic decision trace.
- **Inputs:** `{ input: "<raw payload>" }`.
- **Outputs:** `{input_len, canonical_output, iterations_executed, terminal_state, stop_reason, interpreter_identification, final_technique_inventory, stages[]}`.
- **XDR compatibility:** ✅ ideal — this is the "explain every decode step" surface analysts have been asking for.
- **Adoption:** **ADOPT** (`/api/iedde/analyze`).
- **XDR status:** BASE_ONLY → now analyst-facing via **IEDDE Stage Inspector**.

---

## §2 · Additional engines discovered during inspection (not in the initial acronym list)

| Engine | Implementation | API surface | Adoption | XDR Status |
| --- | --- | --- | --- | --- |
| **SSOT / Orchestrator** | `engine/orchestrator.py`, `canonical/ssot/`, `services/ssot_store.py` | via `/api/analyze` + `/api/incidents` | ADOPT | CONNECTED (SSOT authoritative) |
| **Evidence Graph (IKG)** | `engine/evidence_graph.py`, `engine/evidence_graph_builder.py` | via `/api/correlations/{cid}/graph`, `/api/incidents/{id}/summary` | ADOPT | CONNECTED (canvas) |
| **Verdict Stage-2** | `engine/detectors/verdict_v2.py`, `services/verdict_stage2/` | `POST /api/verdict/stage2/compute`, `/status`, `/auto-compute` | ADOPT | CONNECTED (panel) |
| **Correlation Engine (rules)** | `engine/correlation_engine.py` | `POST /api/correlations`, `GET /api/correlations/{cid}/*` | ADOPT | CONNECTED |
| **IOC Intelligence** | `services/ioc_intelligence/`, `routers/ioc_intelligence.py` | `POST /api/ioc/enrich`, `POST /api/ioc/enrich/one`, `GET /api/ioc/health` | ADOPT | CONNECTED (Canvas pivot) |
| **Threat Intel** | `services/threat_intel/`, `routers/{threat_intel,threat_intel_enrich,threat_intel_rss}.py` | `/api/threat-intel/*` | ADOPT | BASE_ONLY |
| **Threat Model** | `threat_model/`, `routers/threat_model.py` | `/api/threat-model/*` | ADOPT | BASE_ONLY |
| **KB (Knowledge Base)** | `knowledge_base/`, `routers/kb.py` | `/api/kb/*` | ADOPT | BASE_ONLY |
| **Behavioral Registry** | `services/knowledge/behavior_registry.py`, `routers/behavior_registry.py`, `routers/behavioral.py` | `/api/behavioral`, `/api/behavior-registry` | ADOPT | CONNECTED |
| **Behavior Provenance** | `routers/behavior_provenance.py` | `/api/behavior/provenance` | ADOPT | BASE_ONLY |
| **Process Tree (EDR)** | `routers/edr.py`, `routers/process_tree.py`, `chain_analyzer.py` | `/api/edr/process-tree`, `/api/edr/trajectory` | ADOPT | CONNECTED |
| **MITRE mapper / heatmap** | `engine/detectors/mitre_mapper.py`, `routers/mitre_heatmap.py`, `mitre_stix_export.py` | `/api/mitre/heatmap`, `/api/mitre/stix` | ADOPT | CONNECTED |
| **Sigma runner (base)** | `routers/sigma.py` | `/api/sigma/*` | ADOPT | BASE_ONLY (XDR ships own Sigma authoring per Milestone D) |
| **Analyze pipeline** | `engine/orchestrator.py`, `routers/analyze.py` | `POST /api/analyze` | ADOPT | CONNECTED |
| **Analyst Corrections** | `routers/analyst_corrections.py` | `/api/corrections` | ADOPT | BASE_ONLY |
| **Analyst v2** | `routers/analyst_v2.py` | `/api/analyst/v2/*` | ADOPT | BASE_ONLY |
| **Auto-Investigate** | `routers/{auto_investigate,auto_investigate_jobs}.py` | `/api/auto-investigate/*` | ADOPT | BASE_ONLY |
| **Batch Test / Regression / Benchmark** | `routers/{batch_test,regression,benchmark,multilayer_battery}.py` | `/api/batch-test`, `/api/regression`, `/api/benchmark` | ADOPT | BASE_ONLY |
| **Corpus validation** | `engine/golden_corpus*.py`, `routers/corpus_validate.py` | `/api/corpus/validate` | ADOPT | CONNECTED (regression) |
| **Convergence** | `routers/convergence.py` | `/api/convergence/*` | ADOPT | BASE_ONLY |
| **Incident SSOT / Summary** | `engine/report.py`, `routers/{incidents,incident_summary}.py` | `/api/incidents`, `/api/incidents/{id}/summary` | ADOPT | CONNECTED |
| **Investigation Report Writer** | `routers/{report_writer,reports,investigations,workspace_investigation}.py`, `v2/report_writer/` | `/api/report-writer/*`, `/api/v2/report-writer/*` | ADOPT | CONNECTED |
| **Reports (NIST IR / PDF)** | `engine/report_pdf.py`, `engine/stix_exporter.py`, `routers/reports.py` | `/api/reports/*` | ADOPT | BASE_ONLY |
| **NivXForge (investigation pipeline)** | `nivxforge/{investigation,engines,attribution,cim,framework,learning,observability,preview,schemas}` | `nivxforge/router.py` (`/api/nivxforge/*`) | ADOPT | BASE_ONLY |
| **Attack Fingerprint** | `services/attack_fingerprint.py` | via correlations `/api/correlations/fingerprint/{case_id}` | ADOPT | BASE_ONLY |
| **Case Compare** | `services/case_compare.py`, `routers/correlations.py`::compare | `POST /api/correlations/compare` | ADOPT | BASE_ONLY |
| **Confidence & Provenance** | `services/confidence_provenance.py` | shared library | SHARED_LIBRARY | BASE_ONLY |
| **Semantic parser v2** | `v2/semantic/parser.py`, `v2/parser/` | via `/api/v2/*` | ADOPT | BASE_ONLY |
| **v2 Trajectory** | `v2/trajectory/` | via `/api/edr/*` v2 shim | ADOPT | CONNECTED (Slice 6) |
| **v2 IKB** | `v2/ikb/` | `/api/v2/ikb/*` (feature-flagged) | ADOPT | BASE_ONLY |
| **Recursive Child Pipeline** | `services/recursive_child_pipeline.py` | internal (invoked by DIE) | SHARED_LIBRARY | BASE_ONLY |
| **Recipe Planner** | `services/recipe_planner.py` | internal | SHARED_LIBRARY | BASE_ONLY |
| **Attack Chain Builder** | `nivxforge/investigation/pipeline/attack_chain_builder.py` | internal | SHARED_LIBRARY | BASE_ONLY |
| **Timeline Builder** | `nivxforge/investigation/pipeline/timeline_builder.py`, `services/iue/timeline.py` | via `/api/iue/timeline/fuse` | ADOPT | CONNECTED |
| **Explainability (negative)** | `engine/detectors/explainability.py`, `engine/explain_export.py` | via `/api/verdict/stage2/compute` | ADOPT | CONNECTED (Verdict panel) |
| **Sigma runner** | `routers/sigma.py`, base sigma exec engine | `/api/sigma/*` | ADOPT | XDR ships own authoring (external Sigma std) |
| **Response evidence sink (owner: base+xdr)** | `routers/xdr_response_evidence.py` | `POST /api/xdr/response-evidence` | EXTEND | CONNECTED (owner-locked) |

---

## §3 · Genuinely NEW / EXTERNAL (owner-locked)

| Capability | Reason NEW / EXTERNAL | Status |
| --- | --- | --- |
| Sigma detection authoring (XDR) | Base has runner; XDR owns authoring UX + adopts open Sigma standard | CONNECTED (XDR only) |
| Multi-vendor response adapter contract | XDR concern by design (CrowdStrike / Defender / SentinelOne / Cisco SEP) | CONNECTED (stubs) |
| Response Engine state machine + SQLite spine | XDR-owned execution plane | CONNECTED |
| Investigation Canvas (semantic edges, timeline sync) | Visualisation, not detection tech | CONNECTED |
| Analyst Response Drawer | UX-only surface over the Response Engine | CONNECTED |
| Approvals Queue | UX-only surface over the Response Engine | CONNECTED |
| Evidence Ref page (`/xdr/evidence/:executionId`) | UX join of Response Engine execution ↔ base evidence triple | CONNECTED |

## §4 · Confirmed NOT_PRESENT after code inspection

_(None — every acronym in the owner directive has now been verified present in the codebase.)_

**Historical note:** an earlier session assumed VEEE and ICE were absent.  This has been **CORRECTED**: both are present with concrete Python modules (see §1.4 and §1.6).  The regression test in §6 asserts their presence.

---

## §5 · Adoption invariants (unchanged)

- Base NivXRay under `/app/backend/` remains **authoritative**.
- XDR deploys its own frontend (`/app/apps/nivxray-xdr`) and services (`/app/apps/nivxray-xdr-collector`, `/app/apps/nivxray-xdr-response`).
- XDR consumes base via existing `/api/*` routes.  XDR writes only via `POST /api/xdr/response-evidence`.
- XDR **NEVER re-implements**: SSOT · Evidence Graph · Verdict · Correlation · Decoder · Behavior Registry · Process Tree · Trajectory · MITRE mapper · Report writer · IOC intel · IUE lanes · IUE timeline · DIE · IEDDE · UAIE · UIL · IDA · CEM · ICE · VEEE.
- XDR is allowed to build UX-only surfaces (canvas, timeline sync, response drawer) and analyst pivots that call the authoritative engines.

## §6 · CI regression protection (2026-02-10)

Location: `/app/apps/nivxray-xdr/tests/adoption/test_capability_registry_matches_base.py`.

Assertions:
1. Every capability in `docs/NIVXRAY_CAPABILITY_REGISTRY.json` marked `owner=base` and `status ∈ {ADOPT, CONNECTED, BASE_ONLY}` must point to a real base file OR a real mounted router.
2. **VEEE MUST BE PRESENT** — `services/veee/evidence_extractor.py` must exist.
3. **ICE MUST BE PRESENT** — `services/ice/correlate.py` must exist.
4. **DIE, IEDDE, IUE, UAIE, UIL, IDA, CEM MUST BE PRESENT** with concrete path proofs.
5. If a supposedly-authoritative capability is registered but the base file/router does not exist, the test FAILS (anti-hallucination gate).

## §7 · Adoption execution log (this milestone)

- 2026-02-10 · P0: Matrix rewritten from actual `/app/backend/` inspection.  9 owner-listed acronyms verified — ALL PRESENT (VEEE and ICE explicitly confirmed contrary to earlier assumptions).  Additional 30+ engines catalogued.
- 2026-02-10 · P0: `docs/NIVXRAY_CAPABILITY_REGISTRY.json` extended with 12 new capabilities (DIE, IEDDE, IUE-A/B/C/timeline, UAIE-catalog/dry-run, UIL classify/split/investigate, IDA, CEM, ICE, VEEE).
- 2026-02-10 · P0/P1: `src/xdr/adopt/baseCapabilities.js` extended with typed consumers for every wire.  Consumers return `{ ok, data, not_wired, error }` and never fabricate.
- 2026-02-10 · P1: 4 new analyst-facing panels shipped (DIE Decoder Chain, IEDDE Stage Inspector, IUE Timeline overlay, UAIE Catalog).  UIL / IDA / CEM registered honestly.
- 2026-02-10 · P1: Anti-hallucination CI test added.
