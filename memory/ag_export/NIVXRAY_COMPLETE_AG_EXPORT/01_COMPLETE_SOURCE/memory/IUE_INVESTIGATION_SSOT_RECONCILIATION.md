# IUE / INVESTIGATION SSOT RECONCILIATION — TRACK A · READ-ONLY

**Owner directive** (2026-08-10):
"Do NOT modify code. Do NOT fix routes. Do NOT consolidate IUEs.
Do NOT modify Verdict. Do NOT modify Wave 1. Do NOT start ADR-004
Step 2. Produce a read-only reconciliation…"

**Companion to**: `/app/memory/IUE_ARCHITECTURE_TRACE.md`

**Scope**: catalog every IUE-shaped module and every SSOT-shaped
object in the codebase; compare them on a capability matrix; answer
questions A–F.

**Not in scope**: recommending which one wins, or how to migrate.

---

## PART 1 — IUE-SHAPED MODULES

Five modules perform some part of the intended IUE responsibility.

### IUE-1 · `nivxforge/investigation/input_understanding.py`
_a.k.a. `nivxforge/investigation/universal_investigation_engine.py`_

| Aspect | Reality |
|---|---|
| **Purpose** | 17-category classifier for the incident text (cisco_xdr, crowdstrike, defender, sentinelone, qradar, splunk, sysmon_xml, windows_event, powershell, cmd, bash, base64, stix, yara, email_headers, ioc_list, json_generic, unknown) |
| **Input contract** | `str` (raw text) |
| **Output contract** | `dict` with `{type, label, confidence, fingerprints[], route, size_bytes, line_count}` |
| **Lifecycle position** | Post-hoc **metadata stamp** placed on `cio.metadata["input_understanding"]` after the pipeline has already run |
| **Consumers** | UI topbar badge; analyst prose ("I received a Cisco XDR incident…"). `route` field is emitted but never consumed. |
| **Persisted?** | Only as a JSON field on the `CIO` doc if the case is saved |
| **Authoritative or projection?** | Projection — decisions have already been made by the time it runs |
| **What it uniquely knows** | 17-way vendor + payload category taxonomy |
| **Represents arbitrary input types?** | Text only. Cannot classify binary formats (PDF, DOCX, PE, ZIP, EVTX, PCAP, images). |
| **Produces a plan?** | ❌ No |
| **Produces intent?** | ❌ No |
| **Produces confidence matrix?** | Emits a single `confidence` float, not a matrix |
| **Dynamic routing?** | Static dict `_ROUTE_BY_TYPE`; never consulted |

---

### IUE-2 · `services/die/input_understanding.py` (761 LOC)

| Aspect | Reality |
|---|---|
| **Purpose** | Full "profile + intent + plan + executor" implementation. Docstring: *"The IUE is the FIRST thing every Workspace paste passes through… WHAT did the analyst give me? WHAT am I going to do with it?"* |
| **Input contract** | `str` (raw text), optional `execute: bool` |
| **Output contract** | `InputUnderstanding` dataclass with: `input_type, label, confidence, reasoning[], contents{ContentSummary}, decode_required, decode_reason, decode_layers[DecodeLayerPlan], next_engine, next_engine_reason, plan[PlanStep], confidence_matrix{ConfidenceMatrix}, execution_trace[PlanStep], hero_sentence, engines_selected[], engines_skipped[], pipeline_flow[]` |
| **Lifecycle position** | **First stage** on `/api/die/*`, `/api/sessions/investigate`, `/api/uil/investigate`. On those routes it runs before any decoder / analyzer. |
| **Consumers** | `services/die/investigation_results.render()` (produces `Canonical` SSOT); Workspace `IUE Panel`, `AnalystNarrativePanel`, `InvestigationBrainPanel` |
| **Persisted?** | Serialised into `Canonical.understanding` and case docs when saved |
| **Authoritative or projection?** | **Authoritative** on the routes that actually consume it |
| **What it uniquely knows** | Deterministic **PlanStep** list ("classify → understand → decode_1 → decode_2 → extract → stages → die → dkp → intent → story → report"), `ConfidenceMatrix{input_classification, decode_path, language_detection, estimated_recovery}`, `engines_selected/skipped`, `pipeline_flow`, and an `_execute_plan()` executor that actually runs the plan step-by-step |
| **Represents arbitrary input types?** | 21 types incl. `pe_file, rtf_document, office_ole, pdf_document, gzip_blob, registry_export, windows_event_log, sysmon_log, process_tree, vendor_json, vendor_report_text, url_only`. **Still text-oriented; binary detection uses magic-string heuristics on the string prefix.** Does not natively accept `bytes`. |
| **Produces a plan?** | ✅ Yes — `List[PlanStep]` |
| **Produces intent?** | Attack Intent added downstream by `services/die/intent.py` (via `classify_intent_from_analyze`), invoked by the executor step `id="intent"` |
| **Produces confidence matrix?** | ✅ Yes — `ConfidenceMatrix` (4 axes) |
| **Dynamic routing?** | ✅ Yes — `_next_engine()` picks the engine for the input type; the plan builder tailors steps to the type. **However, this routing is only honoured by the `services/die/investigation_results.render()` executor — not by the FastAPI router layer**, so Workspace Save/Reinvestigate never triggers it. |

---

### IUE-3 · `v2/investigation/iu/engine.py` + `v2/investigation/iu/detectors/*`

| Aspect | Reality |
|---|---|
| **Purpose** | Multi-artefact detector: given text, emit a **primary type + embedded types + capability dispatch list** |
| **Input contract** | `str` |
| **Output contract** | `ArtefactClassification{primary_type: ArtefactType, embedded: List[ArtefactType], confidence: int, evidence: List[Evidence], dispatch: List[Capability], determinism_hash: str}` |
| **Lifecycle position** | Called by `v2/investigation/graph/builder.py` when it needs to annotate evidence nodes with `source="input_understanding.<name>"` |
| **Consumers** | `v2/investigation/graph/builder.py` |
| **Persisted?** | Result travels into the `EvidenceGraph` (part of the pydantic `CIO` in `nivxforge/investigation/models.py`) |
| **Authoritative or projection?** | Projection — a graph-annotation helper |
| **What it uniquely knows** | Per-language semantic detectors (powershell_script, command_line, bash, python, vbscript, javascript). Emits `Capability.DECODER`, `Capability.IOC`, etc. — i.e. dispatch hints. |
| **Represents arbitrary input types?** | 6 language types; no vendor formats, no binary formats |
| **Produces a plan?** | ❌ No (only `dispatch: List[Capability]` — a set of capabilities, not an ordered plan) |
| **Produces intent?** | ❌ No |
| **Produces confidence matrix?** | Single `confidence` int |
| **Dynamic routing?** | Emits capability dispatch list; the actual dispatcher lives in `v2/investigation/graph/builder.py` |

---

### IUE-4 · `services/uil/classifier.py` (302 LOC)

| Aspect | Reality |
|---|---|
| **Purpose** | "Universal Input Layer" — classify **bytes or text (plus optional filename)** into a canonical `InputKind` |
| **Input contract** | `Union[bytes, str]`, `filename: Optional[str]` |
| **Output contract** | `InputKind` enum (33 values) via `classify(payload, filename)`; `NormalizedInput{text, ready, reason, metadata}` via `normalize()`; `List[Fragment]` via `split_mixed()` |
| **Lifecycle position** | Front door for `/api/uil/classify`, `/api/uil/split`, `/api/uil/investigate`. `/api/uil/investigate` **delegates to IUE-2** (`services/die/investigation_results.render()`) after normalising |
| **Consumers** | `/api/uil/*` router only |
| **Persisted?** | Not directly |
| **Authoritative or projection?** | Authoritative for `/api/uil/*` routes only |
| **What it uniquely knows** | **Only IUE that natively handles bytes**. Detects binary formats via magic bytes: PE, ELF, MACHO, APK, PDF, DOCX, PPTX, XLSX, ZIP, 7Z, RAR, ISO, EVTX, PCAP, image formats, email (EML/MSG). Also detects mixed inputs and can split them. |
| **Represents arbitrary input types?** | 33 kinds — the **only classifier that spans text + binary + rich formats** in one taxonomy |
| **Produces a plan?** | ❌ No — only classification + normalisation + optional splitting |
| **Produces intent?** | ❌ No |
| **Produces confidence matrix?** | ❌ No — a single classification decision |
| **Dynamic routing?** | Implicit: `ready`/`not-ready` gate. Not-ready inputs return a pending envelope; ready inputs are handed off to IUE-2 |

---

### IUE-5 · `services/ida/input_classifier.py` (referenced but not viewed)

| Aspect | Reality |
|---|---|
| **Purpose** | IDA · Intelligent Document Analyzer — classifies whether the input is an artefact needing decomposition (per module docstring in `services/die/investigation_results.py`: "The IUE remains the classifier of record; IDA contributes a deterministic artifact decomposition + IDA verdict on top.") |
| **Input contract** | Text + optional URL context (per `services/ida/acquisition.py`) |
| **Output contract** | `ida_class`, `confidence`, `reasoning` (populates `Canonical.ida`, `Canonical.artifacts`, `Canonical.artifact_summary`) |
| **Lifecycle position** | Called by IUE-2's executor (`services/die/investigation_results.render()`) after IUE-2 has classified |
| **Consumers** | `services/die/investigation_results.render()` |
| **Authoritative or projection?** | Projection — a downstream refinement of IUE-2's decision |
| **What it uniquely knows** | Deterministic **artefact decomposition** — splits a paste into typed sub-artefacts (URLs, PowerShell, base64 blobs, etc.) with an "IDA verdict" |
| **Represents arbitrary input types?** | Text-oriented; delegates URL fetching to `services/ida/acquisition.py` |

### Bonus · `services/die/input_health.py`

The pre-IUE **Input Health Check** from the intended diagram is implemented here (Structural corruption, oversized, malformed Base64, control-char ratio, etc.). Only reachable via `POST /api/die/health-check`; not called from Workspace Save / Reinvestigate / Docs Re-Investigate / Auto-Investigate.

---

## PART 2 — SSOT-SHAPED OBJECTS

Five objects claim (in docstring or by structure) to be "the single source of truth".

### SSOT-A · `v2/investigation/model.py::InvestigationModel`

| Aspect | Reality |
|---|---|
| **Purpose** | Docstring: *"The single source of truth for every downstream stage."* Phase-1 buckets model. |
| **Input contract** | Built by `build_model(raw, mdr_events, fis, osint, url_buckets)` inside the MDR pipeline |
| **Output contract** | Python dataclass with 9 buckets: `incident{IncidentMetadata}, assets{AssetContext}, processes[ProcessChain], files[FileEvent], network[NetworkEvent], registry[RegistryEvent], auth[AuthEvent], ti[TIItem], history[HistoricalItem], raw_events[dict], raw_text: str, coverage: dict` |
| **Lifecycle position** | Built ~85% of the way through `v2/jobs/pipeline.py::run_investigation_with_progress`, AFTER command detection, decoding, OSINT, quality scoring |
| **Consumers** | `v2/investigation/narrative.py::compose`, `v2/investigation/report.py::compose_report`, `v2/verdict/canonical_input.py::from_investigation_model` (Wave 1 shadow input) |
| **Persisted?** | Serialised as `result["investigation_model"]` on the MDR pipeline response; **not persisted by `POST /api/cases/save` today** |
| **Authoritative or projection?** | Authoritative on `/api/v2/auto-investigate` and (via L1 fix) `/api/documents/{id}/re-investigate` |
| **What it uniquely knows** | Explicit MITRE-like activity buckets (`processes, files, network, registry, auth`), threat-intel hits, historical-context items, per-bucket coverage rollup |
| **Represents arbitrary input types?** | Anything that can be flattened into MDR-style events. **Struggles with**: unstructured DOCX/PDF prose (no event schema), single-command pastes (no host/user context), pure binaries (no telemetry to normalise) |

---

### SSOT-B · `services/die/canonical.py::Canonical`

| Aspect | Reality |
|---|---|
| **Purpose** | Docstring: *"The Canonical Investigation Object is the single source of truth every Workspace surface must consume. Once emitted by the IUE, no UI panel, engine, filter, export, or API endpoint is allowed to re-parse the raw input."* — Rule R11 |
| **Input contract** | Built by `services/die/investigation_results.render()` from `input_health + IUE-2 + preprocessor + DIE analyze + IDA + ICE + intent` |
| **Output contract** | 21 fields: `metadata, input, health, profiling, understanding, plan[], commands[], iocs, lolbas, mitre, dkp, artifacts[], artifact_summary, ida, preprocessor, intent, confidence, engines_selected, engines_skipped` |
| **Lifecycle position** | End-product of `/api/die/investigation-results` and `/api/die/investigation` — projects the full IUE-2 pipeline into one object |
| **Consumers** | `WorkspacePage.jsx` line 1869 (`/die/investigation-results`); `routers/sessions.py` `session_investigate`; `routers/uil.py` `uil_investigate` |
| **Persisted?** | Persisted into `investigation_ssot` collection and inline on `workspace_cases.ssot` when the analyst hits Save Case (see `cases.py::save_case`); however the current Save Case bypass means it's populated from `decode_smart` output, not from `render()` |
| **Authoritative or projection?** | **Authoritative** on `/api/die/*` and `/api/sessions/investigate` and `/api/uil/investigate` |
| **What it uniquely knows** | IUE-2 outputs: `understanding, plan, engines_selected, engines_skipped, confidence signals`. Also holds the artifact decomposition (`artifacts, artifact_summary, ida`). Explicit `plan` field. |
| **Represents arbitrary input types?** | Text/paste focused. Not designed for `bytes`; no explicit `raw_events` bucket like SSOT-A. Artifacts field can hold sub-inputs (via IDA). |

---

### SSOT-C · `nivxforge/investigation/models.py::CIO` (a.k.a. **ADR-0014 CIO**)

| Aspect | Reality |
|---|---|
| **Purpose** | Docstring: *"The CIO is the single product of the Investigation Engine. It is backed by an Evidence Graph and carries a stream of ReasoningSteps recording every decision the engine made."* ADR-0014 §1.1 principles 1, 2, 6, 7, 8. |
| **Input contract** | Built by `nivxforge/investigation/builder.py::build_cio(fact_substrate)` from `nivxforge/cim/fact_substrate::from_analysis_result(result, input_text, source_endpoint)` |
| **Output contract** | Pydantic model with: `schema_version, cio_id, created_at, source{CIOSource}, input_text, input_kind, artifacts[], decode_chain[], evidence_graph{EvidenceGraph}, reasoning_steps[ReasoningStep], confidence, verdict, timeline[], summary, recommendations[], reports, metadata, truth` |
| **Lifecycle position** | Built inside `decode_smart` and `auto_investigate` AFTER the pipeline has already run — i.e. as a projection over `result` |
| **Consumers** | `WorkspacePage.jsx` (verdict card, IOC panel, MITRE, Evidence Graph, Truth Model views); `v2/verdict/shadow.py::compute_shadow` (Wave 1 shadow input via CIO metadata → InvestigationModel projection) |
| **Persisted?** | Yes — inline on `workspace_cases.ssot.investigation_object` (or dereferenced via `ssot_ref` from `investigation_ssot` collection) |
| **Authoritative or projection?** | **Both**: authoritative for Workspace UI (Evidence Graph, verdict, truth, timeline, summary, reports); **projection** for the shadow verdict pipeline (via `_cio_to_investigation_model()` in `v2/verdict/shadow.py`) |
| **What it uniquely knows** | The **EvidenceGraph** (nodes + typed edges) — the only SSOT with a graph representation. ReasoningStep stream (7 use-cases: replay, debug, explain, audit, training, LLM context, analyst-facing rationale). Investigation Truth Model (§1.1.20 — Observation → Finding → Hypothesis → Validation → Decision → Recommendation). Placeholder `verdict, summary, reports` fields designed to be populated by later "slices" (B/C/D/F). |
| **Represents arbitrary input types?** | `input_kind: str` field is intentionally free-form (§1.1.8 "input-agnostic principle"); `artifacts[]` can carry any type; but no per-type schema. Whether it can represent a specific type depends on whether an EvidenceGraph builder + fact_substrate exist for it. Today: text/JSON telemetry is supported; PDF/DOCX/binary requires the caller to have already extracted text (which is what the L1 fix does). |

---

### SSOT-D · `nivxforge/core/cio.py::CIO` (a.k.a. **North Star CIO / Phase 0**)

| Aspect | Reality |
|---|---|
| **Purpose** | Docstring: *"NORTH_STAR §3. The append-only shape every future NivXForge engine will read and write. Phase 0 defines the shape and the append-only invariant. **It does NOT populate any field.**"* |
| **Input contract** | `append(field, engine, payload)` — provenance-mandatory per-entry |
| **Output contract** | Pydantic model with 15 append-only buckets: `input, artifacts, decode_layers, evidence, iocs, behavior, mitre, malware, campaign, threat_intel, knowledge_graph, recommendations, confidence, telemetry, report` |
| **Lifecycle position** | Aspirational. **Not on any production execution path today.** |
| **Consumers** | Tests only |
| **Persisted?** | ❌ No |
| **Authoritative or projection?** | Neither — placeholder |
| **What it uniquely knows** | **Append-only invariant with mandatory `Provenance{engine, at}` on every entry**. Behavior + malware + campaign buckets don't appear in the other SSOTs. |
| **Represents arbitrary input types?** | Structurally yes — the `input` bucket is `List[CIOEntry]` where payload is arbitrary — but no engine actually writes to it. |

---

### SSOT-E · `l2_investigation/schemas.py::EvidenceBundle`

| Aspect | Reality |
|---|---|
| **Purpose** | Input contract for the L4 Analyst Workspace L2 services. Per docstring: *"A bundle is evidence, not presentation. It contains only what L1 Evidence Services return from the deterministic L0 platform."* |
| **Input contract** | Constructed from a `ConvergenceCertificate` + evidence primitives (IocEvidence, CapabilityEvidence, MitreEvidence, TransformationEvidence, SampleMetadata) |
| **Output contract** | Frozen dataclass with: `case_id, certificate, canonical_output, transformations, iocs, capabilities, mitre, sample, fingerprint (sha256)` |
| **Lifecycle position** | Feeds `l2_investigation/services/*` (attack_story, capability_explorer, detection_rules, executive_summary, hunting_queries, ioc_intelligence, threat_assessment, workspace_bundle). Persisted through `l1_evidence/case_store.CaseStore` |
| **Consumers** | Every `L2` service; `routers/workspace_investigation.py` (POST `/api/investigation`) |
| **Persisted?** | Yes — Mongo `investigation_cases` collection |
| **Authoritative or projection?** | Authoritative for the L4 Analyst Workspace path — but that path is bundle-in-bundle-out; it never runs the investigation itself |
| **What it uniquely knows** | Fingerprint-based determinism (sha256 of canonical JSON); "Capability" vocabulary (`PERSISTENCE.REG_RUN`, etc.) with confidence buckets; explicit per-iteration transformation provenance; `SampleMetadata{family, technique, variant, sample_id}` — malware taxonomy fields |
| **Represents arbitrary input types?** | Anything the L0 `workspace.convergence` engine can consume — historically CyberChef-style command inputs, base64 blobs, PowerShell. No native binary/document support at this layer. |

---

## PART 3 — CAPABILITY MATRIX

Legend:
- ✅ First-class field/support
- 🟡 Present but shallow / projection / requires external pre-processing
- ❌ Absent

| Capability | SSOT-A `InvestigationModel` | SSOT-B `Canonical` | SSOT-C `nivxforge CIO` (ADR-0014) | SSOT-D `North Star CIO` | SSOT-E `EvidenceBundle` |
|---|:-:|:-:|:-:|:-:|:-:|
| **Raw input preserved** | ✅ `raw_text` | ✅ `input.text` | ✅ `input_text` | 🟡 `input` list, unpopulated | ✅ `canonical_output` |
| **Artifacts (typed sub-inputs)** | ❌ | ✅ `artifacts[]` + `artifact_summary` (via IDA) | ✅ `artifacts[]` | ✅ `artifacts` append-only, unpopulated | ❌ |
| **Child artifacts (recursive)** | ❌ | 🟡 flat `artifacts[]` (IDA does one level) | ✅ EvidenceGraph edges can express recursion | 🟡 via `evidence` bucket | ❌ |
| **Process relationships** | ✅ `processes[ProcessChain]` (grandparent/parent/process/child) | ❌ (in `preprocessor.stages`) | ✅ EvidenceGraph nodes/edges | 🟡 `behavior` bucket | ❌ |
| **Network relationships** | ✅ `network[NetworkEvent]` (proto, direction, src/dst, port, url, dns) | 🟡 `iocs.urls/domains/ips` (no direction) | ✅ EvidenceGraph edges (IOC-type nodes) | 🟡 `iocs` bucket | 🟡 `iocs` (typed IocEvidence) |
| **Registry** | ✅ `registry[RegistryEvent]` (`is_persistence` flag) | 🟡 `iocs.registry` list | 🟡 EvidenceGraph node kind | 🟡 `evidence` bucket | ❌ |
| **Files** | ✅ `files[FileEvent]` (action, path, sha256/sha1/md5) | 🟡 `iocs.files/hashes` | 🟡 EvidenceGraph node kind | 🟡 `evidence` bucket | 🟡 `iocs` (typed) |
| **Authentication events** | ✅ `auth[AuthEvent]` | ❌ | 🟡 EvidenceGraph node kind | ❌ | ❌ |
| **Threat intelligence** | ✅ `ti[TIItem]` (kind, value, verdict, family, source) | 🟡 `metadata.osint`, `metadata.ti_hits` | ✅ `metadata.osint`; per-node `attrs.enrichment.providers` | ✅ `threat_intel` bucket, unpopulated | ❌ |
| **ATT&CK / MITRE** | 🟡 not first-class (via `ti[TIItem]` `detection_name`) | ✅ `mitre[]` | ✅ `evidence_graph` MITRE-kind nodes + `metadata.mitre` | ✅ `mitre` bucket, unpopulated | ✅ `mitre[MitreEvidence]` |
| **Capability vocabulary** | ❌ | ❌ (has `lolbas`) | ❌ | ❌ | ✅ `capabilities[CapabilityEvidence]` |
| **Verdict** | ❌ (produced downstream) | 🟡 via `confidence` + intent | ✅ `verdict` field (slice-C target) | ✅ `confidence` bucket | ❌ (produced by L2 service) |
| **Provenance (per-item)** | ❌ | 🟡 per-signal in `confidence.signals` | ✅ every EvidenceGraph node has `source` + ReasoningStep stream | ✅ **mandatory `Provenance{engine, at}`** on every entry | ✅ per-item `source_iteration` |
| **Timeline** | 🟡 via `raw_events` timestamps | ❌ | ✅ `timeline[]` (slice-B target) | ❌ | 🟡 derivable from `certificate` |
| **Attack story** | 🟡 via `history[]` + narrative composer | 🟡 via `preprocessor.stages` | ✅ `truth` field (slice-D) | 🟡 derivable | 🟡 produced by L2 `attack_story` service |
| **Recommendations** | ❌ (produced by downstream composer) | ❌ | ✅ `recommendations[]` | ✅ `recommendations` bucket, unpopulated | 🟡 produced by L2 service |
| **Executive summary** | ❌ (produced by downstream composer) | ❌ | ✅ `summary` field | ❌ | 🟡 produced by L2 `executive_summary` service |
| **Analyst investigation (per-stage reasoning)** | ❌ | ✅ `preprocessor.stages` with per-stage evidence | ✅ ReasoningStep stream (7 use-cases) | 🟡 via provenance | ❌ |
| **Recursive artifact discovery** | ❌ | 🟡 via IDA `artifacts[]` (one level) | ✅ EvidenceGraph supports N-level nesting | ✅ append-only decode_layers | ❌ |
| **Determinism fingerprint** | ❌ | ❌ | ❌ | ❌ | ✅ `fingerprint` (sha256) |
| **Append-only invariant** | ❌ | ❌ | ❌ (mutable) | ✅ enforced by API | ✅ frozen dataclass |
| **Persisted end-to-end** | ❌ (dropped after MDR run) | ✅ inline on `workspace_cases.ssot` | ✅ via `ssot_store` immutable store | ❌ | ✅ `investigation_cases` collection |

---

## PART 4 — ANSWERS TO OWNER QUESTIONS A – F

### A. Is one existing object clearly suitable as the canonical Investigation SSOT?

**No — none of the five, in its current form, is clearly suitable.**

Each has a critical gap when measured against the intended canonical
SSOT ("everything about the investigation, produced by IUE →
executors, consumed by every downstream surface").

### B. If yes, which one and why?

Not applicable — see A.

### C. If no, what information is missing from each candidate?

- **SSOT-A `InvestigationModel`**
  - No first-class MITRE bucket (MITRE arrives via `ti[].detection_name` or via the downstream report composer)
  - No verdict, no recommendations, no summary
  - No provenance / reasoning trail
  - No append-only / determinism invariant
  - No graph / recursive artifact discovery
  - No `plan` / `intent` / `understanding` — assumes upstream already knows the answer
  - **Structurally MDR-shaped**: struggles with pastes that aren't event-stream telemetry (single-command decodes, DOCX prose, binaries)

- **SSOT-B `Canonical`**
  - No first-class `verdict`, `recommendations`, `summary`, `timeline`, or `reports`
  - No evidence graph — flat lists only
  - No ReasoningStep stream
  - No native binary / bytes support
  - No append-only invariant
  - No MDR-shaped buckets (`processes/files/network/registry/auth`) — has them mixed into `preprocessor.stages`
  - `understanding` is populated by IUE-2; downstream engines therefore don't consume a stable schema, they consume `preprocessor.stages`

- **SSOT-C `nivxforge CIO` (ADR-0014)**
  - Slice-C `verdict`, Slice-D `summary/recommendations`, Slice-F `reports` are **placeholder fields** — schemas exist but the composers are not consolidated
  - `input_kind: str` is free-form — no unified type taxonomy
  - No MDR-shaped buckets (`processes/files/network/registry/auth`) — everything is graph nodes with soft `NodeKind`
  - No `plan` / `intent` field — IUE-2's plan output is not projected into this shape
  - Doesn't carry the analyst-visible engine plan / hero_sentence / pipeline_flow that IUE-2 emits
  - Wave 1 shadow **projects it back into `InvestigationModel`** to compute canonical verdict input → adds a lossy hop

- **SSOT-D `North Star CIO`**
  - **Zero engines populate it today**
  - Docstring is explicit: "It does NOT populate any field"
  - No timeline / verdict / summary fields
  - Has the append-only + provenance shape the other SSOTs lack — but no runtime

- **SSOT-E `EvidenceBundle`**
  - Built for the L4 Analyst Workspace, which is a downstream analyst view, not the ingestion path
  - No `plan` / `intent` / `understanding`
  - No native binary / document support
  - Assumes a `ConvergenceCertificate` already exists — i.e. the investigation has already happened; the bundle is a report *about* it, not the investigation itself
  - No graph / no reasoning steps / no timeline / no recommendations (those are produced by the L2 services on demand)

### D. Which existing IUE implementation is closest to the intended IUE?

**IUE-2 (`services/die/input_understanding.py`)** is closest by a
wide margin. It uniquely combines all four pillars of the intended
IUE:

| Intended IUE responsibility | IUE-1 (nivxforge) | IUE-2 (die) | IUE-3 (v2 detectors) | IUE-4 (uil) | IUE-5 (ida) |
|---|:-:|:-:|:-:|:-:|:-:|
| Profile input | ✅ | ✅ | ✅ | ✅ (native bytes) | 🟡 |
| Emit intent | ❌ | ✅ (via `intent` step) | ❌ | ❌ | ❌ |
| Emit deterministic plan | ❌ | ✅ (PlanStep list) | 🟡 (Capability list) | ❌ | ❌ |
| Confidence matrix | ❌ | ✅ (4 axes) | 🟡 (single int) | ❌ | 🟡 |
| Dynamic routing that is honoured downstream | ❌ | 🟡 (only on `/die/*` path) | 🟡 (via builder) | 🟡 (delegates to IUE-2) | ❌ |
| Executor that actually runs the plan | ❌ | ✅ | ❌ | ❌ | ❌ |
| Native bytes / binary support | ❌ | ❌ | ❌ | ✅ | ❌ |
| Vendor telemetry taxonomy | ✅ (17) | ✅ (21) | ❌ | 🟡 | ❌ |
| Multi-artefact / embedded artefacts | ❌ | 🟡 (via IDA) | ✅ | 🟡 (via mixed splitter) | ✅ |

**Best-of-breed observation** (informational, not a recommendation):
IUE-2's plan/executor/confidence-matrix + IUE-4's bytes/binary
classifier + IUE-3's multi-artefact evidence + IUE-5's artefact
decomposition covers all responsibilities. **No single existing IUE
implementation covers them all.**

### E. Which components should be considered analyzers/executors rather than IUE?

Based on their contracts (they receive an already-classified input and
produce enrichment on top), these are **executors, not IUE**:

- `services/die/api.py::analyze` (DIE semantic AST — PowerShell/CMD/Bash/JS/VBS/Python parsers) — **executor**
- `services/die/dkp/*` (Decoder Knowledge Pack pattern match) — **executor**
- `services/die/intent.py` (Attack Intent from analyze envelope) — **executor** (though named "classify_intent" it is a post-classification refinement)
- `services/die/chain.py` (chain analyzer) — **executor**
- `services/die/preprocessor/*` (stage extraction) — **executor**
- `services/die/archive_recovery.py` — **executor**
- `services/die/investigation_results.py::render` — **composer / SSOT emitter**, not IUE
- `services/ida/artifact_splitter.py`, `services/ida/artifact_router.py` — **executors** (given a class, split & route)
- `services/ida/acquisition.py` — **executor** (URL fetcher)
- `v2/investigation/graph/builder.py` — **executor / SSOT builder**
- `v2/investigation/iu/detectors/*` — **detectors** (individually), aggregated by IUE-3 into a **classifier** (borderline IUE responsibility, but its output is a Capability dispatch list, not a Plan)
- `v2/mdr/incident_parser.py` (`parse_events`, `build_timeline`, `compose_executive_summary`, `derive_recommendations`, `escalation_decision`) — **executors**
- `v2/verdict/canonical.py::score` — **executor** (verdict scoring)
- `v2/verdict/shadow.py::compute_shadow` — **observer / executor**
- `l2_investigation/services/*` (attack_story, capability_explorer, detection_rules, executive_summary, hunting_queries, ioc_intelligence, threat_assessment, workspace_bundle) — **executors on EvidenceBundle**
- `nivxforge/investigation/verdict_engine.py::refresh_verdict` — **executor**
- `nivxforge/investigation/osint_enricher.py::enrich_cio` — **executor**
- `nivxforge/investigation/recursive.py::recursively_investigate` — **executor** (iterative artefact investigator)
- `nivxforge/cim/fact_substrate.py::from_analysis_result` — **projection / adapter** (analysis_result → facts → CIO)

Genuine IUE candidates (in the strict sense of "first-stage
classifier + planner + intent + dynamic routing"):

- **IUE-2** — the strongest candidate
- **IUE-4** — the only one that handles bytes natively
- **IUE-3** — a multi-artefact detector that could plug into a larger IUE as its "detector fleet"
- **IUE-1** — an outer taxonomy stamp; behaves like a projection, not an IUE

### F. What must be true before Workspace routes can safely converge on one canonical investigation lifecycle?

Six preconditions:

1. **A single IUE contract is chosen** (or specified fresh) — one
   module answers `(input, filename?) → (InputHealth, InputProfile,
   Intent, ConfidenceMatrix, Plan, DispatchList)`. Until then, every
   entry point must decide which IUE to trust.

2. **A single SSOT shape is chosen** (or specified fresh) — one
   object holds `(input, understanding, plan, execution_trace,
   canonical_activity_buckets, evidence_graph, verdict, timeline,
   attack_story, recommendations, summary, provenance)`. This means
   picking one of A/B/C/D/E and extending it, or specifying a new
   one that supersedes them.

3. **A single execution model is chosen** — either:
   - (a) IUE emits a plan and a dispatcher iterates through it
     (IUE-2's model), OR
   - (b) IUE emits a dispatch list of capabilities and the executor
     resolves them in the right order (IUE-3's model).
   The current codebase does both; downstream engines depend on
   different guarantees.

4. **A single verdict input shape is chosen** — Wave 1 today runs
   `compute_shadow(cio)` on one path and
   `from_investigation_model(model)` on another. Both feed the same
   observation store. **This is a confounding variable in current
   Wave 1 data** and must be resolved before any consumer-switch
   decision is made — otherwise divergence attribution is meaningless.

5. **A migration provenance mechanism exists** — every consumer that
   reads today's SSOT (A, B, C, or E) needs a clear projection path
   from the canonical SSOT so it can keep working during migration.
   Today three of the five SSOTs have overlapping fields with
   different names (`iocs` in A/C/E has three different schemas),
   which means a wholesale switch would silently drop data.

6. **The `POST /api/cases/save` and `POST /api/cases/{id}/reinvestigate`
   persistence contracts are decided** — do they persist the full
   canonical SSOT (schema-versioned), or only a projection with a
   pointer? Today they persist a CIO snapshot (via `ssot_store`),
   which means changing the canonical SSOT would break historical
   case reload unless we keep the projection stable.

---

## PART 5 — WAVE 1 CONFOUND (called out explicitly, per §D observation)

The owner already flagged this in the prompt. The reconciliation
confirms it in code:

- `routers/auto_investigate.py:798-807` — computes shadow via
  `compute_shadow(_cio)` where `_cio` is SSOT-C
  (`nivxforge/investigation/models.py::CIO`).
- `v2/jobs/pipeline.py:679-720` — computes shadow via
  `from_investigation_model(model)` where `model` is SSOT-A
  (`v2/investigation/model.py::InvestigationModel`).
- `v2/verdict/shadow.py::_cio_to_investigation_model` — the SSOT-C
  path projects **back** into SSOT-A (partially, only what fits)
  before scoring.

**Consequence**: Wave 1 observations sample from two upstream shapes;
one of them takes a lossy hop back to the other; both write into the
same `verdict_shadow_observations` collection with no upstream-shape
label on the record. `divergence` telemetry cannot be attributed to
"scoring vs. impoverished input" without knowing which SSOT the
sample came from. **The owner's decision to pause Wave 1
interpretation until reconciliation is complete is technically
justified.**

The record shape does contain a `run_id` and the observation entry
includes the CIO/InvestigationModel-derived
`input_completeness{buckets_populated, completeness_pct}` — so
retrospective attribution IS possible once we label each record with
its source path (`from_cio` vs. `from_investigation_model`). That
labelling is not present today.

---

## PART 6 — INFORMATIONAL NOTE

Two governance documents in `/app/memory/` already exist and describe
the intended architecture at length:

- `IUE_ARCHITECTURE_V2.md` — the "IUE v2.0" spec that IUE-2 partially
  implements (Rule R11: "no consumer re-parses raw input"; Rule R9,
  R10, R11 in `WORKSPACE_ARCHITECTURE_RULES.md`)
- `NIVXRAY_ARCHITECTURE_V1.md` — R27 SSOT persistence, R28
  immutable store, R28.1 write-through migration

These describe **intended** state. The reconciliation above shows
that the codebase runs a partial implementation of each on parallel
routes rather than a converged one.

---

## STOP

Per directive: **no implementation-step proposals**. No changes made.
Awaiting owner decision on:
- which IUE contract to canonise (or whether to specify a new one)
- which SSOT shape to canonise (or whether to specify a new one)
- how to label Wave 1 observations by source path so existing data
  becomes interpretable

Read-only reconciliation ends here.
