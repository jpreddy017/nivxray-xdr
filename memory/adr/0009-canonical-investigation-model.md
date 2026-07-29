# ADR-0009 — Canonical Investigation Model (CIM) & Investigation Workspace

- **Status:** **Accepted** (2026-02-28 · amended title + reframed scope) · implementation authorised
- **Amended title:** "Canonical Investigation View Model" → **Canonical Investigation Model (CIM) & Investigation Workspace**. `View Model` was UI-suggestive; the correct framing is *system of record*.
- **Sequencing amendment (2026-02-28):** Inserted **between ADR-0008 (done) and ADR-0007**. Rationale below.
- **Architectural amendments (2026-02-28, operator-directed):**
  1. **Dependency inverted** — CIM built from *canonical facts* (decoder chain outputs, IOC extractor output, reasoning outputs, TI enrichment), NOT from HTTP endpoint response envelopes. Endpoint responses are DERIVED from the CIM, not the other way around. Future parsers (email, Sysmon, PCAP, memory) plug into the same fact substrate without ever knowing about `/api/decode/smart` shape.
  2. **Evidence is a first-class object** with a stable ID, source, raw/normalized values, confidence, `supports`, and `contradicts` — not just a confidence tag on a field.
  3. **Unknowns are DETERMINISTICALLY generated** by rules over the fact substrate (missing process → "unknown parent"; missing network telemetry → "no network evidence"), never manually authored. Reproducible.
  4. **Every Assessment references supporting Evidence IDs.** Explainability by design: clicking any conclusion jumps to the evidence backing it.
  5. **One adaptive Investigate action, not two.** The `DECODE` and `AUTO INVESTIGATE` buttons collapse into a single `🔍 Investigate` action. The engine auto-detects input type and runs only the necessary modules (Normalize · Decode · Deobfuscate · IOC extract · TI · Behavior · Reasoning · ...). Decode becomes a *capability*, not a *feature* — surfaced as a section of the investigation ("Decode Chain") rather than a separate button. A new CIM field `stages_executed` gives analysts transparent visibility into which capabilities ran on this artifact.
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** Multiple independent evidence streams:
  - **UX architectural gap** — 2026-02-28 operator diagnostic + screenshot: NivXForge landing = input box + two buttons; no post-analysis workspace; missing destination for the investigation to land in.
  - **North Star exemplar** — hand-authored PhantomStealer investigation report (2026-02-28) demonstrates the target *shape* of an investigation as a structured, section-hierarchic object.
  - **Historical dual-surface defects** — P-VERDICT-DUAL-SURFACE (Cases 0002, 0006, 0013) + P-SHELLCODE-PRESENTATION-GAP (0002) + P-MITRE-DEDUP-MISS (0002).

## 1 · Problem (reframed — architectural, not UI)

The current architecture is:

```
Input → Engine → Output → UI
```

The engine is strong (Workspace 9.4/10, DECODE 9.7/10 per operator rating).
The layer *between engine and any consumer surface* is **missing**:

```
Input
  → Normalization
  → Decode / Correlation / TI
  → Reasoning
  → [MISSING: Canonical Investigation Model]
  → Workspace | NivXForge | Reports | API
```

Because there is no canonical representation, every surface (Workspace,
NivXForge, Reports, future API consumers) re-derives its own investigation
structure from raw endpoint outputs. This produces:

- Cross-surface divergence on the same case (Defects A/B/C from Case 0002).
- No post-analysis destination on NivXForge (the input-box-only landing).
- Reports and API cannot be added without each inventing its own shape.

## 2 · Decision

Introduce **one canonical investigation object** — the **Canonical
Investigation Model (CIM)** — as the *system of record* for every
investigation NivXRay produces. Every surface renders the same CIM;
no surface re-derives.

### 2.1 CIM object — top-level shape (v1)

```
Investigation                       # root
├── id                              # stable investigation identifier
├── case_id                         # optional link to workspace_cases row
├── created_at                      # UTC ISO8601
├── source                          # {surface, endpoint, correlation_id}
├── executive                       # analyst-facing headline (references Assessment IDs)
├── assessments                     # list of Assessment[] (each with stable id + evidence refs)
├── evidence                        # list of Evidence[] (first-class, stable ids EV-XXX)
├── timeline                        # ordered TimelineFact[] (each references Evidence IDs)
├── entities                        # list of Entity[] with stable ids (E-XXX)
├── relationships                   # list of Edge[] (entity → entity, kind, evidence refs)
├── threat_intel                    # TI summaries (references Evidence IDs)
├── attack                          # deduplicated ATT&CK techniques (each with evidence refs)
├── stages_executed                 # ORDERED list of AnalysisStage[] — which capabilities ran
│                                   # on this artifact (Normalize · Decode · Deobfuscate ·
│                                   # IOC-extract · TI · Behavior · MITRE · Reasoning · ...)
│                                   # provides adaptive-pipeline transparency for §2.5
├── decode_chain                    # ordered decoder-layer trace (was `layer_trace`)
│                                   # promoted to first-class CIM section — a *capability*,
│                                   # not a separate action button
├── unknowns                        # DETERMINISTICALLY generated data-gap list (§2.2)
├── recommendations                 # next-actions (references Evidence/Assessment IDs)
├── report                          # composed narrative (deferred to ADR-0010)
└── provenance                      # per-field source: engine · decoder · TI · analyst
```

Every top-level branch is a **section** — not a tab. Surfaces choose
their rendering (Workspace pages, NivXForge left-nav, Reports doc,
API JSON). Sections are the vocabulary.

### 2.1.a Evidence — first-class object

```
Evidence
├── id                     # stable "EV-001"..."EV-NNN" (dense, monotonic within an investigation)
├── type                   # ioc.ip | ioc.domain | ioc.url | ioc.hash | decoder.layer |
│                          # ti.provider_hit | mitre.technique | telemetry.process |
│                          # telemetry.network | telemetry.file | telemetry.registry |
│                          # analyst.correction | reasoning.inference
├── source                 # {producer: "decoder" | "extractor" | "ti_enrich" | "reasoning" | ...,
│                          #  producer_version, timestamp}
├── raw_value              # original bytes/text/struct as observed
├── normalized_value       # canonical form (e.g. lowercased domain, RFC-8949-friendly)
├── confidence             # "Confirmed" | "Strongly Inferred" | "Possible" | "Unknown"
├── supports               # list of Assessment.id — assessments this evidence backs
├── contradicts            # list of Assessment.id — assessments this evidence weakens
└── context_snippet        # up to 120 chars around the observation (reuses ADR-0008 §2 Stage 3)
```

### 2.1.b Assessment — every conclusion is traceable

```
Assessment
├── id                     # stable "A-001"..."A-NNN"
├── statement              # short human-readable conclusion ("PhantomStealer identified")
├── kind                   # verdict | family | category | behavior | attribution | risk
├── confidence             # "Confirmed" | "Strongly Inferred" | "Possible" | "Unknown"
├── evidence               # NON-EMPTY list of Evidence.id refs — REQUIRED for every Assessment
└── rationale              # why the referenced evidence supports the statement
```

**Governance rule (merge-gate):** `len(assessment.evidence) >= 1` for every
Assessment in every CIM. A CIM with an unsupported Assessment fails the
composer's validator and the endpoint returns 500 with a governance
error rather than surfacing a conclusion without backing. Explainability
by design.

### 2.1.c AnalysisStage — adaptive-pipeline transparency

```
AnalysisStage
├── name                   # "normalize" | "decode" | "deobfuscate" | "ioc_extract" |
│                          # "ti_enrich" | "behavior" | "mitre_map" | "reasoning" |
│                          # "pe_static" | "office_parse" | "pdf_parse" | "url_analyze" |
│                          # "sysmon_parse" | "email_parse" | "sigma_match" | "yara_match"
├── status                 # "ran" | "skipped" | "failed"
├── reason                 # optional — why skipped/failed (e.g. "input not b64 encoded")
├── started_at             # UTC ISO8601
├── duration_ms            # int
└── evidence_produced      # list of Evidence.id — what this stage contributed
```

`stages_executed` gives analysts full transparency into which capabilities
ran on this artifact — the analyst sees `✓ Decode · ✓ IOC Extraction ·
skipped: PE Static (not a PE) · ✓ TI Enrich · ✓ Reasoning` in the UI.
That transparency is the tradeoff that makes "one adaptive Investigate
action" (§2.4) safe.

### 2.2 Deterministic Unknowns generator

Unknowns are **generated by rules over the fact substrate**, never
manually authored. Each rule is a pure function
`(facts) → Optional[Unknown]`:

```
IF   entities.processes is empty          → emit "parent process unknown"
IF   entities.commandlines is empty       → emit "execution command line unknown"
IF   telemetry.network is empty           → emit "no network telemetry"
IF   telemetry.memory is empty            → emit "memory evidence unavailable"
IF   entities.users is empty              → emit "user account unknown"
IF   telemetry.registry is empty          → emit "registry state unknown"
IF   telemetry.authentication is empty    → emit "authentication logs unavailable"
IF   evidence.timeline lacks (start, end) → emit "activity time window unknown"
IF   attack.initial_access is empty       → emit "initial access vector unknown"
IF   entities.files is empty              → emit "no file artifacts observed"
```

Rules live in `nivxforge/cim/unknowns.py`. New rules require a real-world
observation entry in `REAL_WORLD_LOG.md` (governance discipline).

### 2.3 Design rules (operator-directed 2026-02-28)

- **Section-driven, not tab-driven.** UIs may render sections as tabs,
  panels, doc chapters, or navigation entries — the CIM does not care.
- **One model, multiple views.** Workspace, NivXForge, Reports, and API
  all consume the same CIM. No surface transforms fields for its own
  layout beyond pure formatting.
- **Confirmed / strongly inferred / unknown discipline.** Every
  `evidence` and `assessment` field carries a `confidence` tag
  (Confirmed · Strongly Inferred · Possible · Unknown) as demonstrated
  in the North Star exemplar's Evidence Confidence Matrix.
- **Explicit unknowns.** The `unknowns` section is a first-class part
  of the CIM (not an afterthought); it turns unknown-unknowns into
  known-unknowns so analysts can plan next steps.
- **One adaptive Investigate action, not two.** The `DECODE` and
  `AUTO INVESTIGATE` buttons collapse into a single `🔍 Investigate`.
  The engine auto-detects input type (PowerShell · b64 · PE · Office
  · PDF · URL · Cisco XDR incident · Sysmon record · email · …) and
  runs only the necessary stages. The tradeoff — the analyst gives up
  explicit workflow control — is protected by mandatory transparency:
  the CIM's `stages_executed` field (§2.1.c) surfaces which capabilities
  ran, which were skipped and why, and how long each took. Decode
  becomes a *capability*, not a *feature*; the analyst still gets a
  full "Decode Chain" section in the investigation.

### 2.4 Component contracts (frontend)

- `<CIMSection kind="..." data={inv.section} />` — every section is one
  component. Sections receive their own CIM slice and MAY NOT read
  other slices except through the top-level `provenance` map.
- Sections MAY NOT re-compute derived fields (verdict / confidence /
  MITRE dedup / IOC dedup). Those are baked into the CIM by the
  composer (§2.6).
- Sections carry stable `data-testid` prefixes per section (e.g.,
  `cim-executive-*`, `cim-evidence-*`) for testing + parity assertions.

### 2.5 Rendering order & data ownership

Default rendering order (top-to-bottom in NivXForge Investigation
Workspace v1):

1. **Executive** — headline verdict, confidence, family, category,
   business impact, evidence quality. *(Data owner: Reasoning engine.)*
2. **Stages Executed** — adaptive-pipeline transparency strip
   (`✓ Decode · ✓ IOC Extract · skipped: PE Static · ✓ TI Enrich · …`).
   *(Data owner: composer + orchestrator.)*
3. **Assessments** — every conclusion with its evidence refs.
   *(Data owner: Reasoning engine + ADR-0007 verdict gate when live.)*
4. **Evidence** — evidence records with confidence tags. *(Data owner:
   Reasoning engine + decoders + TI enrichment.)*
5. **Timeline** — temporal facts. *(Data owner: Decoders + reasoning.)*
6. **Entities** — hosts/files/URLs/IPs/hashes with roles. *(Data owner:
   IOC extractor (ADR-0008) + TI enrichment.)*
7. **Relationships** — entity graph edges. *(Data owner: Reasoning.)*
8. **Threat Intel** — TI Shield layer summaries. *(Data owner: TI
   enrichment pipeline.)*
9. **ATT&CK** — deduplicated technique list with evidence refs.
10. **Decode Chain** — ordered decoder-layer trace. *(Data owner:
    decoder pipeline; formerly the DECODE action; now a section.)*
11. **Unknowns** — deterministically generated data-gap list.
    *(Data owner: `unknowns.py` rules.)*
12. **Recommendations** — analyst next-actions. *(Data owner: Reasoning.)*
13. **Report** — composed narrative sections (deferred until a later ADR
    adds the narrative composer; v1 emits raw section text).

### 2.6 Composer — INVERTED dependency

The composer consumes the **canonical fact substrate**, not HTTP
response envelopes. The dependency graph is:

```
Raw Input
     │
     ▼
Normalization ── (existing decoder pipeline)
     │
     ▼
Analysis ────── (deterministic engines · reasoning · TI enrichment)
     │
     ▼
Canonical Facts ─ (decoder chain outputs · IOC records · TI hits ·
     │             reasoning inferences · MITRE hits · telemetry records)
     ▼
CIM  ─────────── (compose.py assembles Assessments/Evidence/Entities/
     │             Relationships/Timeline/Unknowns from canonical facts)
     ▼
Endpoint Response  (adds `investigation` field additive on
                    /api/decode/smart and /api/v2/auto-investigate)
```

**Concrete implication for the existing codebase:** `compose.py` reads
from a new lightweight **`FactSubstrate`** dict-like adapter — an
in-process pass-through populated by the existing analysis pipeline
just before the endpoint packages its HTTP response. The composer never
imports from `routers/ops.py`; the composer never parses HTTP JSON. Any
future ingest surface (email parser, Sysmon parser, PCAP parser, memory
parser) can populate a `FactSubstrate` and get a CIM for free.

Composer module layout (`/app/backend/nivxforge/cim/`):

```
cim/
├── __init__.py
├── models.py           # Pydantic models: Investigation, Assessment,
│                       # Evidence, Entity, Relationship, TimelineFact,
│                       # Unknown, Recommendation, ThreatIntelHit,
│                       # AttackTechnique, ExecutiveSummary, Section*
├── fact_substrate.py   # FactSubstrate: pipeline → composer decoupling
├── compose.py          # from_facts(substrate) -> Investigation
├── unknowns.py         # deterministic unknown-generator rules (§2.2)
├── evidence.py         # Evidence-ID allocation + supports/contradicts
│                       # relationship validation
├── assessments.py      # Assessment-ID allocation + evidence-ref
│                       # non-empty merge-gate
└── validators.py       # CIM invariants (Assessment.evidence non-empty,
                        # Evidence.supports IDs exist, etc.)
```

Wire-in point (backend-only, additive):

```python
# routers/ops.py — after analysis pipeline populates its results, before response:
from nivxforge.cim import compose, fact_substrate
facts = fact_substrate.from_analysis_result(result)   # in-process, zero I/O
result["investigation"] = compose.from_facts(facts).model_dump()
```

No new HTTP routes. No changes to existing response fields. Existing
consumers (Workspace, current NivXForge InvestigatePage) continue
reading `iocs`, `verdict_card`, etc., unchanged.

## 3 · Scope (small on purpose)

**In scope for ADR-0009 v1:**

- CIM object schema (Pydantic model in `nivxforge/cim/models.py`).
- CIM composer for the existing `/api/decode/smart` + `/api/v2/auto-investigate` responses.
- Additive `investigation` field on both endpoints.
- Frontend `<CIMSection>` component contracts.
- NivXForge Investigation Workspace v1: sections 1-10 (§2.4). Section 11 (composed report) deferred to ADR-0010.
- Parity assertion: same case → identical CIM regardless of surface.

**Out of scope:**

- No changes to `iocs`, `verdict_card`, `mitre`, `ti_shield`, or any other existing response field.
- No new backend HTTP routes.
- No changes to verdict logic (ADR-0007 will land after this ADR and update the `assessment` section only).
- No narrative composer (deferred to ADR-0010).
- No pixel-perfect UI redesign — the point is the *object*, not the pixels.
- No changes to Workspace pages (Workspace can optionally begin consuming CIM in a later ADR).

## 4 · Sequencing amendment (2026-02-28)

**Old lock:** ADR-0008 → ADR-0007 → parity → Phase 2.
**New lock:** ADR-0008 (done) → **ADR-0009 (this)** → ADR-0007 → parity → Phase 2.

**Rationale for the amendment:**

- Two fresh independent evidence signals (North Star exemplar + UX
  architectural diagnostic + screenshot) in a 48-hour window.
- ADR-0007 improves *correctness*; ADR-0009 improves *how users consume
  correctness*. Currently the bottleneck is the missing destination for
  the investigation to land in — not verdict wrongness.
- ADR-0009 is a pure additive layer (no changes to existing fields);
  ADR-0007 will then update only the `assessment` section of the CIM,
  giving ADR-0007 a cleaner target than the current dual-surface state.

## 5 · Non-goals (explicit)

- **NOT** a UI redesign. Sections may look identical to today's cards.
- **NOT** a tab-based information architecture. Tabs are one possible surface rendering; sections are the vocabulary.
- **NOT** a big-bang migration. Workspace continues to read raw fields; only NivXForge and future consumers must go through the CIM.
- **NOT** an authoring surface. The CIM is read-only in v1; analyst corrections continue to flow through the existing `analyst_corrections` path.

## 6 · Exit Criteria (mandatory · all must be true)

1. **CIM object schema** defined as a Pydantic model with unit-test coverage on every top-level section.
2. **Composer** produces identical CIM for the same input regardless of which endpoint was hit (`/api/decode/smart` vs `/api/v2/auto-investigate`) — parity assertion.
3. **Additive contract:** existing response fields (`iocs`, `verdict_card`, `mitre`, `ti_shield`, `layer_trace`, `l3_metadata`, `output`, `confidence`, `analysis_mode`, `layer_iocs`, `reasoning`) remain byte-for-byte compatible on all corpus cases.
4. **Sections 1-10 render** on the NivXForge Investigation Workspace v1 for every Corpus v1 case (20 cases).
5. **`<CIMSection>` components** each have a `data-testid` prefix and a component unit test asserting the read-only contract (no re-derivation).
6. **Parity contract test** (`nivxforge/tests/test_parity_endpoints.py`) remains green; a new parity test asserts CIM equivalence across the two endpoints.
7. **Full Workspace regression suite** green.
8. **Full NivXForge regression suite** green.
9. **Zero performance regression** on `/api/decode/smart` — CIM composition adds ≤ 5% to end-to-end latency (Corpus v1 mean baseline).
10. **North Star traceability:** the PhantomStealer exemplar can be expressed as a CIM instance (schema fits the target shape).

Partial success is not "success" for this ADR.

## 7 · Related patterns

- **P-VERDICT-DUAL-SURFACE** (0002, 0006, 0013) — resolved by §2.2 "one model, multiple views".
- **P-SHELLCODE-PRESENTATION-GAP** (0002) — resolved by `entities` + `evidence` section owning the shellcode representation once (`preferred_view`).
- **P-MITRE-DEDUP-MISS** (0002) — resolved by `attack` section carrying a deduplicated technique list.
- **NORTH-STAR-INVESTIGATION-SHAPE** (2026-02-28 exemplar) — the CIM v1 schema is derived directly from this exemplar's structure.

## 8 · Registry impact

`CAPABILITY_REGISTRY.md` gains a row on Accepted → Implemented:

| Capability | ADR | Status | Evidence | Corpus | Regression | Non-regression | Component | Introduced In | Superseded By |
|---|---|---|---|---|---|---|---|---|---|
| Canonical Investigation Model (CIM) | ADR-0009 | **Accepted** (2026-02-28) | 0002, 0006, 0013 + North Star + UX diagnostic | v1 | see ADR §6 | Workspace suite + NivXForge suite + parity | Composer (backend) + `<CIMSection>` (frontend) | pending | — |
