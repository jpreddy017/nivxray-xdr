# ADR-0009 — Canonical Investigation Model (CIM) & Investigation Workspace

- **Status:** **Accepted** (2026-02-28 · amended title + reframed scope) · implementation authorised
- **Amended title:** "Canonical Investigation View Model" → **Canonical Investigation Model (CIM) & Investigation Workspace**. `View Model` was UI-suggestive; the correct framing is *system of record*.
- **Sequencing amendment (2026-02-28):** Inserted **between ADR-0008 (done) and ADR-0007**. Rationale below.
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
├── executive                       # analyst-facing headline (Verdict + summary)
├── assessment                      # verdict / confidence / severity / family
├── evidence                        # ordered list of evidence records
├── timeline                        # ordered list of temporal facts
├── entities                        # hosts / files / users / URLs / domains / IPs / hashes
├── relationships                   # entity → entity edges with kind + evidence refs
├── threat_intel                    # TI Shield layer summaries + external references
├── attack                          # MITRE ATT&CK techniques (deduplicated, evidence-linked)
├── unknowns                        # explicit list of what the data does NOT contain
├── recommendations                 # analyst next-actions (immediate + hunting)
├── report                          # composed narrative sections (executive, story, ...)
└── provenance                      # per-field source: engine · decoder · TI · analyst
```

Every top-level branch is a **section** — not a tab. Surfaces choose
their rendering (Workspace pages, NivXForge left-nav, Reports doc,
API JSON). Sections are the vocabulary.

### 2.2 Design rules (operator-directed 2026-02-28)

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

### 2.3 Component contracts (frontend)

- `<CIMSection kind="..." data={inv.section} />` — every section is one
  component. Sections receive their own CIM slice and MAY NOT read
  other slices except through the top-level `provenance` map.
- Sections MAY NOT re-compute derived fields (verdict / confidence /
  MITRE dedup / IOC dedup). Those are baked into the CIM by the
  composer (§2.5).
- Sections carry stable `data-testid` prefixes per section (e.g.,
  `cim-executive-*`, `cim-evidence-*`) for testing + parity assertions.

### 2.4 Rendering order & data ownership

Default rendering order (top-to-bottom in NivXForge Investigation
Workspace v1):

1. **Executive** — headline verdict, confidence, family, category,
   business impact, evidence quality. *(Data owner: Reasoning engine.)*
2. **Assessment** — expanded verdict card with per-criterion evidence.
   *(Data owner: Reasoning engine + ADR-0007 verdict gate when live.)*
3. **Evidence** — evidence records with confidence tags. *(Data owner:
   Reasoning engine + decoders + TI enrichment.)*
4. **Timeline** — temporal facts. *(Data owner: Decoders + reasoning.)*
5. **Entities** — hosts/files/URLs/IPs/hashes with roles. *(Data owner:
   IOC extractor (ADR-0008) + TI enrichment.)*
6. **Relationships** — entity graph edges. *(Data owner: Reasoning.)*
7. **Threat Intel** — TI Shield layer summaries. *(Data owner: TI
   enrichment pipeline.)*
8. **ATT&CK** — deduplicated technique list with evidence refs.
9. **Unknowns** — explicit data-gap list. *(Data owner: Reasoning.)*
10. **Recommendations** — analyst next-actions. *(Data owner: Reasoning.)*
11. **Report** — composed narrative sections (deferred until a later ADR
    adds the narrative composer; v1 emits raw section text).

### 2.5 Composer

A single backend module `nivxforge/cim/compose.py` (isolated namespace)
takes the union of `/api/decode/smart` and `/api/v2/auto-investigate`
responses for a case and produces the CIM. No new backend HTTP routes.
The composer is invoked from the existing endpoints' post-processing
step and returned in a new **additive** response field: `investigation`
(the CIM object). Response envelope stability is preserved for all
current consumers (Workspace continues to read `iocs`, `verdict_card`,
`mitre`, `ti_shield`, `layer_trace`, etc.).

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
