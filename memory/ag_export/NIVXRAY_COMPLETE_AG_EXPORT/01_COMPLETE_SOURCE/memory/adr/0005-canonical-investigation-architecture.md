# ADR-005 · Canonical Investigation Architecture (DESIGN, READ-ONLY)

- **Status**: Proposed · awaiting owner approval
- **Date**: 2026-08-10
- **Author**: Emergent (Track A)
- **Supersedes (scope-wise)**: none — coexists with ADR-004
- **Complements**: `IUE_ARCHITECTURE_TRACE.md`, `IUE_INVESTIGATION_SSOT_RECONCILIATION.md`
- **Explicit non-goal**: no code changes, no route changes, no migrations, no scoring changes, no UI changes, no consumer switches, no Wave 1 modifications, no Engine A modifications, no ADR-004 Step 2 start.

This ADR **specifies requirements and boundaries**, not implementation.
No existing object is selected as "the winner" unless evidence in the
reconciliation report clearly supports it. The end of this document
lists the specific decisions that need OWNER approval before any
implementation step is proposed.

---

## 1. Context

The IUE trace and the reconciliation report established that:

- Five IUE-shaped modules exist in parallel; none is on the primary Workspace execution path in the strict "profile → intent → plan → dispatch" sense.
- Five SSOT-shaped objects exist in parallel; **no single one is clearly suitable as the canonical SSOT**.
- Wave 1 shadow observations sample from **two different SSOT source paths** without a source-path label — current n=2 data is architecturally contaminated.
- The Workspace user-visible bug (DOCX Save Case loses Attack Chain / Summaries) is a **symptom**, not the root cause. The root cause is architectural fragmentation.

Continuing ADR-004 (Verdict Engine consolidation) before resolving this fragmentation would decide *which verdict engine is canonical* before deciding *what canonical investigation data it consumes*. That is the wrong order.

## 2. Design principles (non-negotiable)

The canonical architecture MUST satisfy these principles. They are
input constraints for every choice below.

- **P1 · Single entry contract**. Every investigation, regardless of surface (Workspace paste, DOCX upload, URL, API, EDR/SIEM/OT push, future adapters), reaches the same canonical lifecycle.
- **P2 · Single SSOT**. Every downstream consumer (Verdict, Attack Story, Evidence Graph, MITRE, Recommendations, Analyst Summary, Executive Summary, Reports, Case Persistence, Wave-N shadow) reads from ONE canonical Investigation Object. No consumer re-parses raw input.
- **P3 · Provenance is mandatory**. Every fact, node, edge, verdict signal, or conclusion in the SSOT carries `who produced it (engine + version) + when + from which upstream evidence`. Analyst audit + explainability + replay + training-data extraction share this one mechanism.
- **P4 · Determinism**. Same input + same engines + same versions ⇒ byte-identical SSOT. Non-determinism (LLMs, network) is either forbidden inside the deterministic core, or gated behind an isolated "enrichment" boundary whose absence never changes the deterministic conclusion.
- **P5 · Input-agnostic**. The SSOT shape does not assume text vs. binary vs. telemetry vs. document. Type-specific structure lives in typed sub-shapes; the outer SSOT is uniform.
- **P6 · Additive migration**. New consumers/producers of the SSOT do not break old ones. Field additions are backwards-compatible; field removals require a schema-version bump.
- **P7 · Analyst-visible reasoning**. Every decision the engine made can be surfaced to the analyst (Rule R10). This is the same mechanism as P3 — a ReasoningStep stream.
- **P8 · Recursive by contract**. Child artefacts (a decoded PowerShell inside a base64 blob; a PE payload extracted from a DOCX; a URL fetched from an IOC list) enter the SAME lifecycle and produce nested nodes in the SAME SSOT. There is no "outer" investigation and "inner" investigation.

## 3. Canonical IUE contract (requirements)

### 3.1 Position and boundary

- IUE is the **first stage after Input Health**.
- IUE **classifies, profiles, plans, and dispatches**. It does **NOT** decode, extract, correlate, verdict, or render.
- IUE **hands off** an executable plan and a dispatch list to the Investigation Executor. Everything after IUE is downstream.

### 3.2 Contract

```
IUE.classify(RawInput, Context?)  ->  IUEDecision
```

Where `RawInput` accepts:
- `bytes` (primary, byte-safe)
- `str` (convenience)
- optional `filename`, `mime_hint`, `source_channel` (paste | upload | api | edr | siem | ot | url_acquire)

`IUEDecision` MUST contain:

| Field | Purpose |
|---|---|
| `input_health` | Result of the pre-IUE Input Health stage (structural corruption, oversized, malformed encoding, control-character ratio, password references, magic-byte anomalies) |
| `input_profile` | Canonical `InputProfile{primary_type, embedded_types[], input_kind, encoding, size, byte_signature, filename?}` — one taxonomy, not five |
| `intent` | Attack Intent (deterministic — from structural markers, NOT from decoded semantics). e.g. "vendor incident report", "encoded PowerShell stager", "IOC hunting list", "documented investigation report" |
| `capabilities` | Ordered list of capability tags the executor MUST run: `INPUT_HEALTH`, `DECODER`, `IOC_EXTRACTOR`, `VENDOR_NORMALISER`, `PROCESS_TREE`, `ARTIFACT_SPLIT`, `IDA_ACQUIRE`, `MITRE_MAP`, `ATTACK_CHAIN`, `THREAT_INTEL`, `SEMANTIC_AST`, `RECURSIVE_DISCOVERY`, etc. |
| `plan` | Ordered `List[PlanStep{engine, action, reason, required, expected_output_kind}]` — the executor's runbook |
| `confidence_matrix` | Named axes: `input_classification, decode_path, language_detection, estimated_recovery, artifact_completeness, telemetry_richness` |
| `dispatch_policy` | `strict_ordered` | `parallel_where_safe` | `dag` — how the executor may schedule the plan |
| `provenance` | Which IUE version emitted this; determinism hash of the decision |
| `next_engine_hint` | Human-readable one-liner for the analyst (equivalent to today's `hero_sentence`) |

### 3.3 Sub-classifier composition

The canonical IUE is a **composition** of sub-classifiers, not a single monolith:

- `InputHealth` — SHOULD run before classifiers; may set `blocking` flags.
- `BytesMagicClassifier` — detects binary types (PE / ELF / MACHO / PDF / DOCX / XLSX / ZIP / EVTX / PCAP / images / archives). Requires bytes-native input.
- `TextStructureClassifier` — JSON / XML / YAML / STIX / OpenIOC / YARA / Sigma / EML / registry-export / event-log / vendor-JSON / vendor-prose.
- `LanguageClassifier` — PowerShell / CMD / Bash / Python / JS / VBS / Batch (per-language AST hints).
- `MultiArtefactDetector` — identifies embedded artefacts (base64 inside PowerShell inside a `-EncodedCommand` inside a `wmic` wrapper, etc.).
- `IntentClassifier` — assigns an intent label from structural evidence alone.

Each sub-classifier emits `Evidence` (source, observation, confidence, rationale, meta). The composer aggregates them into `IUEDecision`.

### 3.4 IUE non-responsibilities (explicit)

IUE MUST NOT:
- Decode content (that is a downstream capability).
- Fetch URLs (that is an executor via `IDA_ACQUIRE`).
- Extract IOCs (that is a downstream capability).
- Map MITRE ATT&CK (that is a downstream capability).
- Compute a verdict.
- Emit prose ("analyst narrative") — only structured `next_engine_hint`.

### 3.5 Determinism guarantee

Same `(bytes | str | filename | mime_hint | source_channel)` tuple ⇒
identical `IUEDecision.determinism_hash`. Any non-deterministic
sub-signal (e.g. clock-derived) is forbidden inside IUE.

---

## 4. Canonical Investigation SSOT (requirements)

### 4.1 Minimum information the SSOT MUST represent

For every investigation, regardless of input type, the SSOT MUST hold:

| Bucket | Rationale |
|---|---|
| `id, created_at, schema_version, source{surface, endpoint, correlation_id, session_id?}` | Identity |
| `input_raw`: bytes-safe original + `filename?` + `mime_hint?` | P5 (input-agnostic), P4 (replay) |
| `input_profile` | Populated by IUE (§3.2) |
| `input_health` | Populated by pre-IUE health stage |
| `iue_decision` | Full `IUEDecision` — for replay and analyst-visible plan |
| `plan` | The plan actually executed (may differ from `iue_decision.plan` if steps were skipped) |
| `execution_trace[PlanStep]` | Per-step timings, status, engine identity |
| `artifacts[Artifact]` | Every typed artefact discovered — recursive (see §4.4) |
| `evidence_graph{nodes[], edges[]}` | Typed nodes + typed edges. Nodes cover: input, artifact, decoded_fragment, process, file, network_endpoint, url, domain, ip, hash, registry_key, auth_event, ti_hit, mitre_technique, capability, verdict_signal |
| `activity{processes[], files[], network[], registry[], auth[]}` | MDR-style typed activity buckets — projection over the evidence graph for consumers that want tabular access |
| `iocs{urls, ips, domains, hashes, files, registry, emails, user_agents}` | Projection over IOC-type evidence nodes |
| `threat_intel{hits[], sources[], enrichment_status}` | External + local TI attached to the relevant nodes |
| `attck{techniques[], tactics[], kill_chain[]}` | MITRE mapping — each technique carries the evidence node(s) that justify it |
| `attack_chain[Stage]` | Ordered stages with per-stage evidence and MITRE mapping |
| `attack_story` | Analyst-visible narrative sections (structured — not just prose) |
| `verdict{label, confidence, reason, contributors[], input_completeness}` | The single verdict object — populated by the Verdict Engine |
| `recommendations[Recommendation]` | Per-recommendation evidence pointers |
| `analyst_summary` | Structured, deterministic (not LLM) — with pointers into `evidence_graph` |
| `executive_summary` | Structured, deterministic — 5-question answer card |
| `reports{stix?, sigma?, yara?, navigator?, mdr?}` | Export projections; each is a pure function of the SSOT |
| `timeline[TimelineEvent]` | Ordered timeline — nodes tagged with `ts` roll up here |
| `reasoning_steps[ReasoningStep]` | Append-only per §3, §7 |
| `provenance{engine, version, at, upstream_evidence_ids[]}` | Every appended entry AND the SSOT itself carries this |
| `context{historical, prior_cases, same_host_recent, same_hash_recent}` | Historical context bucket |
| `metadata` | Free-form additive migration data |

### 4.2 Structural invariants

- **Append-only** — existing entries are never mutated or removed (Rule R11 spirit). Field-level updates go through provenance-bearing appends.
- **Every entry carries provenance** — the mechanism is uniform across all buckets.
- **Fingerprint-addressable** — canonical JSON has a stable sha256; used for immutable-store keys and Wave-N observation labelling.
- **Recursive by structural containment** — `artifacts[]` can contain child artefacts whose own `investigation` field is another SSOT-shaped sub-object OR a link (`ssot_ref`) into the immutable store.
- **Schema-versioned** — `schema_version` is a semver; consumers gate on major-version compatibility.

### 4.3 Projections vs. authoritative fields

The SSOT distinguishes **authoritative source** from **projections**:

- **Authoritative source**: `evidence_graph` + `reasoning_steps` + `iue_decision` + `execution_trace` + `input_raw`.
- **Projections**: `activity.*`, `iocs.*`, `attck.*`, `attack_chain`, `attack_story`, `analyst_summary`, `executive_summary`, `reports.*`, `timeline`, `verdict.contributors`.

Rule: **any projection MUST be a pure function of the authoritative source**. Rebuilding a projection from the authoritative source must yield byte-identical output. This is how migration compatibility is preserved.

### 4.4 Recursive artefacts

- A discovered artefact (decoded PowerShell inside base64 inside `-EncodedCommand`; PE payload inside DOCX; URL fetched → HTML page → embedded IOC list) is expressed as:

```
artifacts[]
  ├── Artifact{id, kind, ..., parent_evidence_id, investigation_ref?}
  │   └── (optional) investigation_ref → immutable_store[SSOT{...}]
  │        └── artifacts[]
  │            └── ...
```

- Rule: child SSOTs live in the same immutable store as top-level SSOTs. They are addressable by `ssot_ref`, versioned, and reusable.
- Rule: child SSOTs' `evidence_graph` nodes carry back-edges (`derived_from`, `parent_artifact_id`) so the top-level graph can traverse into children.
- Rule: `attack_chain`, `attck.techniques[]`, and `iocs.*` on the top-level SSOT MUST fold in children's contributions (with provenance pointing to the child SSOT).

---

## 5. Execution boundary — role assignment

The reconciliation showed today's codebase mixes IUE, executor, and
projector responsibilities in the same modules. The canonical
architecture separates them into six distinct roles:

| Role | Responsibility | Reads | Writes |
|---|---|---|---|
| **Health** | Pre-IUE structural check | `input_raw` | `input_health` |
| **IUE** | Classify, profile, intent, plan (§3) | `input_raw`, `input_health` | `iue_decision`, initial `plan` |
| **Executor** | Dispatch the plan; run capabilities; iterate for recursion | `iue_decision`, `plan` | `execution_trace`, `artifacts[]`, `evidence_graph`, `reasoning_steps` |
| **Analyzer/Decoder** | Per-capability workers (PowerShell AST, DKP, IDA split, base64 decode, PDF text-extract, PE static, DOCX text-extract, URL acquire, IOC extraction, MITRE map, semantic AST, correlation, TI lookup) | Sub-slice of SSOT relevant to the capability | Append to `evidence_graph`, `reasoning_steps`, `artifacts[]` |
| **Enricher** | External enrichment (OSINT, TI vendors, sandbox lookups) — isolated boundary (P4) | `iocs`, `evidence_graph` IOC nodes | Append to `threat_intel`, per-node `attrs.enrichment` |
| **Composer / Projector** | Compute projections (attack_chain, attack_story, analyst_summary, executive_summary, verdict, recommendations, reports, timeline, activity buckets, iocs projection) — pure functions of authoritative source | Authoritative source | Overwrite projection fields (marked as such) |

**Rule**: every module in the codebase MUST be classifiable into
exactly one of these six roles. Today's biggest problems come from
modules that straddle multiple roles (e.g. `decode_smart` acts as
Executor + IUE-stamper + Composer + Persister).

**Enricher isolation clause** (P4): the deterministic conclusion of
the investigation MUST be computable WITHOUT enrichers running.
Enricher outputs are attached to nodes; verdict input MAY promote
based on enrichment, but the promotion path is a labelled `contributor`
so removing enrichers yields a lower-confidence but still-valid SSOT.

---

## 6. Existing-object mapping against §4 requirements

None of the five existing SSOTs matches §4 in its current form. The
following table shows **the closest existing structural donor for
each required field**. This is a mapping study, not an endorsement.

| §4 required field | Closest donor(s) | Gap |
|---|---|---|
| `id, created_at, schema_version, source` | ADR-0014 CIO | none |
| `input_raw` | ADR-0014 CIO (text-only), EvidenceBundle (`canonical_output`) | bytes-native support missing |
| `input_profile` | Canonical (`understanding`) | needs unified taxonomy |
| `input_health` | services/die/input_health | not wired into any SSOT today |
| `iue_decision` | services/die/input_understanding.InputUnderstanding | needs to move into SSOT proper |
| `plan / execution_trace` | Canonical (`plan`), IUE-2 (`execution_trace`) | needs to be first-class SSOT fields |
| `artifacts[]` (recursive) | ADR-0014 CIO (flat `artifacts`), Canonical (flat `artifacts`) | neither supports recursion via `ssot_ref` |
| `evidence_graph` | ADR-0014 CIO | strong donor — but node/edge kinds need harmonising |
| `activity.processes` | InvestigationModel (`processes[ProcessChain]`) | strongest donor |
| `activity.files` | InvestigationModel (`files[FileEvent]`) | strongest donor |
| `activity.network` | InvestigationModel (`network[NetworkEvent]`) | strongest donor |
| `activity.registry` | InvestigationModel (`registry[RegistryEvent]`) | strongest donor |
| `activity.auth` | InvestigationModel (`auth[AuthEvent]`) | strongest donor |
| `iocs.*` projection | ADR-0014 CIO (`metadata.iocs`), Canonical (`iocs`) | needs unified schema |
| `threat_intel` | ADR-0014 CIO (`metadata.osint`, per-node enrichment) | strongest donor |
| `attck` | EvidenceBundle (`mitre[MitreEvidence]`), Canonical (`mitre`), ADR-0014 CIO (metadata.mitre) | EvidenceBundle has the strongest per-item schema |
| `attack_chain` | Today produced by MDR pipeline, DIE chain, and workspace-side syntheses (three sources) | no donor is authoritative |
| `attack_story` | L2 `attack_story` service (bundle-driven) | closest structured donor |
| `verdict` | ADR-0014 CIO (`verdict` placeholder), v2/verdict/canonical | placeholder + separate scorer |
| `recommendations` | ADR-0014 CIO (`recommendations`), MDR (`recommendations`) | duplicated |
| `analyst_summary` | ADR-0014 CIO (`summary`), MDR (`investigation_narrative`), DIE (`analyst_narrative`) | three parallel implementations |
| `executive_summary` | MDR (`executive_card`), ADR-0014 CIO (`summary`), L2 `executive_summary` service | three parallel implementations |
| `reports.*` | ADR-0014 CIO (`reports`), MDR (`investigation_report`), Sigma/YARA/STIX exporters | three parallel implementations |
| `timeline` | ADR-0014 CIO (`timeline`), MDR (`mdr_investigation.timeline`) | two parallel implementations |
| `reasoning_steps` | ADR-0014 CIO (only) | unique donor |
| `provenance` | North Star CIO (`Provenance` mandatory) + ADR-0014 CIO (per node) | best-of-both is required |
| `context` | InvestigationModel (`history[HistoricalItem]`) | strongest donor |
| `metadata` | all five have some form | trivial |

**Observation** (not a decision): the required canonical shape looks
most like a **union of ADR-0014 CIO's graph + reasoning + slice-C/D/F
targets + North Star CIO's provenance/append-only invariants + MDR's
`InvestigationModel` typed activity buckets + services/die IUE's
plan/execution_trace/confidence_matrix + EvidenceBundle's per-item
capability & MITRE schemas**. None of the five today provides this
union.

---

## 7. Entry-point convergence (target lifecycle)

Every entry point converges on ONE lifecycle:

```
[EntryAdapter] → InputHealth → IUE → Executor → SSOT → Consumers → Workspace
```

Per surface:

| Entry point | EntryAdapter role | Notes |
|---|---|---|
| Workspace paste (`/api/decode/smart`) | Normalise text; set `source_channel="workspace_paste"` | Today: runs its own pipeline + IUE stamp. Target: adapter-only. |
| Workspace Save Case (`/api/cases/save`) | Two modes: (a) persist an already-computed SSOT; (b) invoke lifecycle if the caller hasn't | Today: partially re-runs `decode_smart`. Target: never runs the lifecycle from `save`; the caller MUST supply an SSOT (or a hash that dereferences one). |
| Workspace Reinvestigate (`/api/cases/{id}/reinvestigate`) | Load raw input from case; enter lifecycle | Today: re-runs `decode_smart`. Target: run the canonical lifecycle. |
| Document Reinvestigate (`/api/documents/{id}/re-investigate`) | Extract bytes → text where needed; set `source_channel="document_reinvestigate"`; set `filename`, `mime_hint` | Today: L1 fix jumps to MDR pipeline. Target: enter IUE first (bytes-native), then dispatch — MDR-shaped capabilities are executor plugins. |
| Auto Investigate (`/api/v2/auto-investigate`) | Set `source_channel="auto_investigate"` | Today: MDR + post-hoc IUE stamp. Target: IUE first. |
| DIE (`/api/die/*`) | Same lifecycle; consumers render `Canonical`-shaped views by projection from SSOT | Today: IUE-2 drives whole pipeline via `render()`. Target: preserve behaviour but consume SSOT-of-record. |
| UIL (`/api/uil/*`) | Bytes-native entry adapter (leverages IUE-4's binary detection) → IUE | Today: classifies then delegates to IUE-2. Target: absorbed into the canonical IUE as its bytes classifier. |
| Future EDR / SIEM / OT adapters | Set `source_channel="edr" | "siem" | "ot"`; run vendor-normaliser executor first (Cisco/CrowdStrike/Defender/QRadar/SentinelOne/Splunk); IUE then classifies the normalised stream | Not built today. Adapter-only work. |
| L4 Analyst Workspace (`/api/investigation`) | Consumes SSOT — no lifecycle | Today: consumes `EvidenceBundle`. Target: `EvidenceBundle` becomes a projection of the canonical SSOT. |

**Rule**: no entry point may compute its own investigation. All entry
points differ ONLY in their EntryAdapter (bytes/text extraction, MIME
hints, source-channel labelling). Everything after the adapter is
shared.

---

## 8. Recursive investigation (target)

Recursive artifact discovery is a **first-class Executor capability**,
not an ad-hoc composition of other capabilities.

- Trigger: an executor step surfaces a new artefact node whose
  `artifact_kind` is investigable (base64 blob, PE bytes, URL,
  decoded PowerShell, extracted DOCX text, etc.).
- Action: `RECURSIVE_DISCOVERY` capability enqueues the child on the
  ArtifactQueue with a **budget** (max depth, max children, max wall time).
- Execution: the executor invokes the SAME `[Health → IUE → Executor]`
  pipeline on the child artefact, producing a **child SSOT**.
- Attachment: the child SSOT is stored in the immutable SSOT store
  and referenced from the parent's `artifacts[].investigation_ref`.
- Rollup: the parent's projections (`iocs.*`, `attck.*`, `attack_chain`,
  `verdict.contributors`, `timeline`) MUST fold in children's
  contributions with provenance edges pointing to the child SSOT.
- Termination: budgets are enforced; on exhaustion the parent's
  `execution_trace` records `status=budget_exhausted` per unvisited
  child. Never raises. Never truncates silently without an entry.

**Rule**: recursive investigation is a **structural** property of the
SSOT, not a compositional trick of a specific pipeline. Any
future capability may invoke it.

---

## 9. Downstream consumers (target contract)

Every consumer reads ONLY from the canonical SSOT — never from raw
input, never from another SSOT.

| Consumer | Reads from SSOT | Produces |
|---|---|---|
| Verdict Engine | `evidence_graph` + `activity.*` + `threat_intel` + `iue_decision.confidence_matrix` + `input_completeness` (rollup) | `verdict{label, confidence, reason, contributors[]}` — written back into the SSOT |
| Attack Chain | `evidence_graph` (process/file/network/registry chains) + `attck.techniques[]` | `attack_chain[Stage]` |
| Attack Story | `attack_chain` + `reasoning_steps` + `context.historical` | `attack_story` |
| Evidence Graph View | `evidence_graph` directly | UI projection only |
| MITRE Heatmap | `attck` | UI projection |
| Mitigation / Recommendations | `attck.techniques[]` + `iue_decision.intent` + `verdict` + `activity.*` | `recommendations[]` |
| Analyst Summary | Full SSOT (structured; deterministic) | `analyst_summary` |
| Executive Summary | `verdict` + `iue_decision.intent` + top-N `evidence_graph` + `context.historical` | `executive_summary` |
| Reports (STIX / Sigma / YARA / Navigator / MDR) | Full SSOT | `reports.*` |
| Timeline | `evidence_graph` node `ts` fields + `execution_trace` | `timeline[]` |
| Wave-N Shadow | Full SSOT (labelled `source_path`) | Observation entry with source-path label (§10) |
| Case Persistence | Full SSOT | Immutable-store entry + reference on `workspace_cases` |
| L4 Analyst Workspace | Full SSOT → projected into `EvidenceBundle` | `EvidenceBundle` becomes a projection |

**Rule**: no consumer parses raw input. No consumer synthesises its own
`attack_chain`, `attck` mapping, or `verdict` from raw text. If a
consumer needs data not present in the SSOT, the SSOT contract MUST be
extended (with provenance and schema-version bump), NOT worked around.

---

## 10. Wave 1 impact (architectural treatment — not a fix)

The reconciliation confirmed Wave 1 samples from two SSOT paths
without a source-path label. Under the canonical architecture:

- **Every Wave-N observation entry MUST carry** `source_ssot_shape`,
  `source_ssot_version`, `source_path` (e.g. `cio.compute_shadow`,
  `investigation_model.from_model`), and `input_completeness_by_bucket`.
- Records without these labels (the current `verdict_shadow_observations`)
  are **architecturally opaque** — they can still exist, but any
  aggregation across them MUST bucket by `source_path` and MUST NOT
  be treated as fungible.

**Owner decision required**: how to treat existing unlabelled Wave 1
observations. Two options (both architectural — neither implemented
today):

- **Option W1-A · Segment-and-continue**: keep existing observations
  in a `pre_ssot_reconciliation` segment; new observations after
  labelling go into a fresh segment. Aggregate the two separately.
  Existing n=2 remains useful only as directional signal within its
  own segment.
- **Option W1-B · Restart Wave 1**: retire existing observations;
  begin fresh Wave 1 once the source-path label lands. Loses n=2 but
  keeps analysis unambiguous.

Neither option requires code changes for this ADR. Both require the
observation-record schema to be extended (schema-version bump; per §6
this is backwards-compatible append).

---

## 11. What this ADR explicitly does NOT decide (owner scope)

The following decisions require OWNER approval before any
implementation step is proposed:

- **D1 · IUE canonisation**. Which of the four/five candidates
  becomes the canonical IUE? Sub-question: does the canonical IUE
  come from consolidating IUE-2 + IUE-3 + IUE-4 + IUE-5, or is it
  specified fresh with all four listed as reference implementations?
- **D2 · SSOT canonisation**. §4 defines the target contract. The
  reconciliation confirms none of the five existing objects match
  it. Sub-question: is the canonical SSOT
  (a) ADR-0014 CIO extended,
  (b) InvestigationModel extended,
  (c) a new object with existing ones as projections,
  (d) two-tier (a graph-based authoritative SSOT + a canonical
  projection for consumers)?
- **D3 · Provenance mechanism**. Adopt ADR-0014's ReasoningStep +
  per-node `source` for evidence-level provenance? Adopt North Star
  CIO's mandatory `Provenance` on every appended entry? Both?
- **D4 · Execution model**. IUE emits an ordered `plan` (IUE-2 model)
  vs. an unordered `dispatch: List[Capability]` (IUE-3 model)?
  Recommendation from analysis: emit both — `plan` for strict-ordered
  execution when required, `dispatch` for parallel-safe execution.
  Owner to confirm.
- **D5 · Entry-point convergence phasing**. Do we require all entry
  points to converge in one release, or is convergence phased with
  a shim (`cases.py::save_case` accepting either an SSOT or raw
  input during migration)?
- **D6 · Recursive-investigation store model**. Child SSOTs stored
  inline (nested JSON) vs. by reference (`ssot_ref` into immutable
  store)? Trade-off: inline is single-doc atomic; by-reference
  supports sharing (identical child artefacts across cases).
- **D7 · Wave 1 treatment**. W1-A (segment-and-continue) vs. W1-B
  (restart). Both require the observation-record schema extension
  called out in §10.
- **D8 · Enricher isolation**. Should enrichers be a separate
  role (§5) or a sub-role of Analyzer? Trade-off: separation makes
  determinism guarantee explicit; consolidation is simpler to
  implement. Recommendation: keep separate (matches P4).
- **D9 · Schema versioning strategy**. Semver on `schema_version`
  (major.minor.patch). Sub-question: is a major-version bump
  breaking for older workspace_cases (requiring migration), or is
  every major backwards-projectable from newer to older?
- **D10 · ADR-004 relationship**. Does ADR-005 SUPERSEDE ADR-004's
  Step 2+ (verdict engine consumer switch) until the canonical SSOT
  lands, or does ADR-004 continue in parallel on a "no consumer
  switch" freeze until ADR-005 D2 is decided?

---

## 12. Explicit non-goals of this ADR

This ADR is architecture-only. It does NOT:

- Modify any code, routes, migrations, scoring, UI, or consumer switches.
- Modify Wave 1 observation implementation, Engine A, or the canonical Verdict scoring.
- Start ADR-004 Step 2.
- Select a winning existing SSOT or IUE implementation.
- Propose an implementation plan, a migration plan, a timeline, or a resourcing plan.
- Prescribe naming (module names, class names, endpoint names).
- Prescribe storage layout (Mongo vs. Postgres vs. immutable store internals).
- Prescribe UI changes.

## 13. STOP — Decisions required from owner

Before any implementation step is proposed, the owner MUST decide
D1 through D10 (§11). Every subsequent ADR (ADR-006 through ADR-N)
depends on those decisions.

**Read-only design ends here. Awaiting owner review of ADR-005.**
