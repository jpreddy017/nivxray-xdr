# ADR-005 · Owner Decision Matrix (READ-ONLY)

- **Status**: Awaiting owner decision on D1–D10
- **Date**: 2026-08-10
- **Source of truth**: `/app/memory/adr/0005-canonical-investigation-architecture.md` (ADR-005)
- **Scope**: For each of the ten decisions surfaced by ADR-005 §11, present:
  1. Decision statement
  2. Alternatives (explicitly named in ADR-005 only)
  3. Evidence from ADR-005 that shaped the decision
  4. Benefits
  5. Risks
  6. Migration implications
  7. Reversibility
  8. Dependency on other decisions
  9. Recommended option
  10. Unresolved questions
- **Explicit non-goals**: no code changes, no implementation details invented beyond ADR-005, no Wave 1 modification, no ADR-004 modification, no naming, no timelines, no resourcing.
- **Governance principle honoured throughout** (owner-stated 2026-08-10, referenced as **INV-1** below):
  > *"No analyzer, decoder, verdict engine, report generator, or UI component becomes an alternative SSOT. They produce evidence or projections."*

---

## Cross-cutting invariants (constraints on every decision)

- **INV-1 · No alternative SSOTs**. See above.
- **INV-2 · Determinism** (ADR-005 P4). Enrichers isolated; non-deterministic signals never inside the deterministic core.
- **INV-3 · Provenance is mandatory** (ADR-005 P3). Every derivation carries `(engine, version, at, upstream_evidence_ids)`.
- **INV-4 · Append-only + additive migration** (ADR-005 P6, §4.2). Field additions never break existing consumers; field removals require a major schema-version bump.
- **INV-5 · Input-agnostic** (ADR-005 P5). SSOT and IUE contracts do not assume text vs. binary vs. telemetry vs. document.
- **INV-6 · Every module classifies into exactly one of six roles** (ADR-005 §5). Straddling is forbidden.

Every decision below must satisfy INV-1 through INV-6. Where a
recommended option is proposed, its compliance with the invariants is
noted.

---

## Blocking vs. deferrable

| Decision | Class | Rationale |
|---|---|---|
| **D1 · IUE canonisation** | **BLOCKING** | Downstream contract (IUEDecision) is required before any executor / consumer can be redesigned. |
| **D2 · SSOT canonisation** | **BLOCKING** | Every consumer's contract depends on this. Wave-N labelling depends on this. |
| **D3 · Provenance mechanism** | BLOCKING | Determines the mandatory shape of every appended entry — cannot be added retroactively. |
| **D4 · Execution model** | **BLOCKING** | Determines whether IUE emits `plan[]`, `dispatch[]`, or both. Consumers of `IUEDecision` depend on this. |
| **D5 · Entry-point convergence phasing** | Deferrable (until D1/D2/D4 settled) | Sequencing question — not a contract question. |
| **D6 · Recursive-investigation store model** | **BLOCKING** | Determines whether `artifacts[].investigation_ref` is inline JSON or `ssot_ref` into an immutable store. Persistence contract depends on this. |
| **D7 · Wave 1 treatment** | **BLOCKING for interpretation** (not for continued observation) | New Wave-N observations should not accumulate under an ambiguous shape; existing observations should not be mixed with new labelled ones. |
| **D8 · Enricher isolation** | Deferrable (recommended default: keep separate) | Refinement of ADR-005 §5 — doesn't block D1/D2 design but must be settled before executor implementation. |
| **D9 · Schema versioning strategy** | Deferrable (design-once, decide before first release) | Doesn't block internal design; blocks external contract publication. |
| **D10 · ADR-004 relationship** | BLOCKING for scheduling | Determines whether ADR-004 Step 2 proceeds in parallel on a freeze or waits for D2. |

Priority order for owner attention (per your instruction): **D1, D2, D4, D6, D7**, then D3, D8, D9, D10, then D5.

---

## D1 · IUE canonisation

### Decision statement
Which IUE implementation becomes the canonical IUE that produces `IUEDecision`? Is it a consolidation of existing modules, a fresh implementation, or a new specification with existing modules as reference implementations?

### Alternatives (from ADR-005 only)
- **D1-A**: Canonicalise **IUE-2** (`services/die/input_understanding.py`) — closest structural match. Extend it with:
  - bytes-native + binary-format detection from IUE-4 (`services/uil/classifier.py`)
  - multi-artefact detection from IUE-3 (`v2/investigation/iu/engine.py`)
  - artefact decomposition from IUE-5 (`services/ida/input_classifier.py`)
- **D1-B**: Canonicalise **IUE-4** (`services/uil/classifier.py`) — only bytes-native option — and lift the plan/executor/confidence-matrix from IUE-2 into it.
- **D1-C**: Author a **fresh canonical IUE** conforming to ADR-005 §3.2, listing IUE-2 / IUE-3 / IUE-4 / IUE-5 as reference implementations to be superseded.
- **D1-D**: Retain **all four** as sub-classifiers under a thin composer (per ADR-005 §3.3), formalise the composer as the canonical IUE.

### Evidence from ADR-005
- §3.3: IUE is explicitly designed as a **composition** of sub-classifiers (Health + BytesMagic + TextStructure + Language + MultiArtefact + Intent).
- §4 answers (via reconciliation): "No single existing IUE implementation covers all responsibilities."
- §6 mapping: `input_profile` closest donor is Canonical (`understanding`); `iue_decision` closest donor is IUE-2 (`InputUnderstanding`).
- Reconciliation §D answers: IUE-2 is closest, but lacks bytes/binary support (IUE-4), multi-artefact (IUE-3), and artefact decomposition (IUE-5).

### Benefits (of each)
- **D1-A**: preserves the largest working codebase (IUE-2 is 761 LOC); minimises rewrite.
- **D1-B**: byte-safety guaranteed from the beginning; IUE-4's `InputKind` covers 33 binary/rich types.
- **D1-C**: cleanest architectural contract; no legacy shape to work around.
- **D1-D**: no code deleted; composer is thin; every existing sub-classifier keeps its owner and tests.

### Risks (of each)
- **D1-A**: IUE-2 is not bytes-native; retrofitting bytes/binary may distort its plan/executor.
- **D1-B**: IUE-4 has no plan / no intent / no executor — lifting from IUE-2 doubles the surface being changed.
- **D1-C**: highest short-term cost; requires migrating three or four consumers.
- **D1-D**: requires a composer contract; risk of the composer inheriting divergences between sub-classifiers.

### Migration implications
- **D1-A**: existing IUE-2 callers (`/api/die/*`, `/api/sessions/*`, `/api/uil/*`) continue working. Two entry points still require adapter work (Workspace paste, Docs, Auto-Investigate).
- **D1-B**: existing IUE-4 callers (`/api/uil/*`) are unaffected; IUE-2 callers need a rewrite.
- **D1-C**: every current caller of IUE-1/2/3/4/5 needs an adapter or a rewrite.
- **D1-D**: existing callers of any sub-classifier may keep calling directly during transition; canonical IUE consumers call the composer.

### Reversibility
- All four options: reversible via a shim (each canonicalised shape is a superset of at least one existing shape). D1-C is the least reversible in practice because it introduces a shape no existing caller emits.

### Dependencies
- Depends on **D3** (provenance shape appears in `IUEDecision.provenance`).
- Depends on **D4** (`IUEDecision` includes `plan`, `dispatch_policy`, or both — set by D4).
- Blocks **D5** (entry-point adapters cannot be designed until IUE shape is known).

### Recommended option
**D1-D · Composer over existing sub-classifiers** — matches ADR-005 §3.3 explicitly. Rationale:
- Compliant with **INV-6** (each sub-classifier keeps its single responsibility; the composer's responsibility is composition, not classification).
- Zero-loss: preserves the strongest donor for each capability (IUE-2 plan+executor, IUE-3 multi-artefact evidence, IUE-4 bytes-native, IUE-5 artefact decomposition).
- Minimises rewrite while producing a canonical contract.
- Reversible: sub-classifiers keep their public APIs; the composer is additive.

### Unresolved questions
- Is the composer's tie-breaking rule deterministic and specified? (ADR-005 §3.3 mentions aggregation but not tie-breaking.)
- Does the composer emit its OWN `Evidence` entries, or only forward its sub-classifiers'?
- How does IUE-5's artefact decomposition (which iterates over the input) interact with recursion (§8)? Decomposition = shallow scan; recursion = deep executor pass. Their outputs must not overlap in the SSOT.

---

## D2 · SSOT canonisation

### Decision statement
Which object becomes the canonical Investigation SSOT? Sub-question: does the answer come from extending one existing SSOT, or specifying a new one with existing SSOTs as projections?

### Alternatives (from ADR-005 §11 D2)
- **D2-a**: **Extend ADR-0014 CIO** (`nivxforge/investigation/models.py`) to cover all §4 required buckets.
- **D2-b**: **Extend `InvestigationModel`** (`v2/investigation/model.py`) with graph, provenance, verdict, summary, reports, timeline, reasoning steps.
- **D2-c**: **New canonical SSOT**, with existing ones (CIO, Canonical, InvestigationModel, EvidenceBundle) treated as projections.
- **D2-d**: **Two-tier**: authoritative graph-based SSOT + canonical projection SSOT for consumers.

### Evidence from ADR-005
- §4 explicitly enumerates 25+ required buckets; §6 mapping shows no single existing object covers them.
- §6 concluding observation: "The required canonical shape looks most like a **union** of ADR-0014 CIO's graph + reasoning + slice-C/D/F targets + North Star CIO's provenance/append-only invariants + MDR's InvestigationModel typed activity buckets + services/die IUE's plan/execution_trace/confidence_matrix + EvidenceBundle's per-item capability & MITRE schemas. **None of the five today provides this union.**"
- Reconciliation §A: "No — none of the five, in its current form, is clearly suitable."
- Reconciliation §F: 6 preconditions, one of which is "A single SSOT shape is chosen (or specified fresh)".
- INV-1 (owner-stated): "No analyzer, decoder, verdict engine, report generator, or UI component becomes an alternative SSOT."

### Benefits (of each)
- **D2-a (extend CIO)**: preserves the strongest donor (evidence graph, reasoning steps, truth model, verdict placeholder). ~5 of 25 §4 fields already present.
- **D2-b (extend InvestigationModel)**: preserves MDR's typed activity buckets which no other SSOT has cleanly.
- **D2-c (new SSOT)**: matches the reconciliation's own answer to "which one?" (none). Every existing SSOT becomes a labelled projection.
- **D2-d (two-tier)**: separates *authoritative representation* (graph + reasoning) from *consumer-friendly representation* (typed buckets + projections). This mirrors ADR-005 §4.3's authoritative-vs-projection distinction as a **structural**, not just conceptual, split.

### Risks (of each)
- **D2-a**: ADR-0014 CIO's `verdict/summary/reports` are placeholder fields (slices B/C/D/F). Extending means implementing all four slices — hidden cost.
- **D2-a**: CIO has no MDR-shaped activity buckets. Adding them risks duplicating information also present in the evidence graph — violates INV-1 unless activity buckets are declared **projections**.
- **D2-b**: InvestigationModel has no graph, no reasoning steps, no verdict, no summary — extending means bolting on features that existing CIO consumers already have. High cost.
- **D2-b**: `raw_events: list[dict]` is a leaky bucket — everything unclassified lands there; incompatible with INV-1.
- **D2-c**: three or four existing consumers each need a projection layer. Consumer surface area is the highest of any option.
- **D2-d**: two objects to maintain; consumers must know which to read. Complexity risk.

### Migration implications
- **D2-a**: existing CIO consumers (`WorkspacePage.jsx`, verdict shadow via CIO path) continue reading. Activity-bucket consumers (verdict shadow via InvestigationModel path, MDR narrative, MDR report) need a projection.
- **D2-b**: existing MDR consumers continue reading. All CIO consumers (Workspace, verdict via CIO, truth model view) need a projection layer.
- **D2-c**: every current consumer needs a projection. Highest one-time cost; cleanest end state.
- **D2-d**: existing consumers continue reading their existing shape (which becomes the projection tier). Authoritative tier is new. Lowest disruption.

### Reversibility
- **D2-a / D2-b**: low reversibility once consumers depend on the extended shape.
- **D2-c**: high reversibility — projections can be regenerated from the authoritative source.
- **D2-d**: high reversibility — the authoritative tier can be swapped out if the projection contract is preserved.

### Dependencies
- Depends on **D3** (provenance shape becomes a required field on every append).
- Depends on **D6** (recursive store model — `artifacts[].investigation_ref` is inline vs. by-ref).
- Depends on **D9** (schema versioning strategy).
- Blocks every downstream consumer redesign (Verdict, Attack Story, Recommendations, Summaries, Reports).
- Blocks **D7** (Wave-N labelling needs `source_ssot_shape` — that presumes a canonical shape exists).
- Blocks **D10** (ADR-004 Step 2 requires knowing what canonical verdict input looks like).

### Recommended option
**D2-d · Two-tier: authoritative graph + canonical projection tier.**

Rationale:
- Directly implements ADR-005 §4.3's authoritative-vs-projection distinction as a **structural** boundary.
- Fully honours INV-1: projections cannot become alternative SSOTs because they are *defined* as pure functions of the authoritative tier (regenerable, discardable).
- The authoritative tier absorbs ADR-0014 CIO's `evidence_graph + reasoning_steps + provenance` — the reconciliation's strongest donor.
- The canonical projection tier absorbs InvestigationModel's typed activity buckets, EvidenceBundle's per-item MITRE/Capability schemas, and Canonical's plan/execution_trace — every existing consumer can keep its current shape as a labelled projection.
- Reversible: any tier can be swapped independently while the other's contract is preserved.
- Enables INV-4 (additive migration): new fields land as new projections; the authoritative tier grows monotonically.

**Alternative under consideration**: D2-c (new SSOT with existing as projections) is essentially D2-d without the tier separation — acceptable if the owner prefers a single-object canonical shape at the cost of losing the authoritative/projection boundary as a code-level invariant.

### Unresolved questions
- Where does the authoritative-tier storage live vs. the projection tier? (INV-4 requires backwards-compatibility; storage choice affects that.)
- Are projections **eagerly materialised** on write, or **computed on read**? Trade-off: eager write costs storage + write-latency but caches perfectly; lazy read costs CPU per request but keeps storage minimal and always in-sync.
- What is the projection catalog? (i.e. which existing SSOTs are declared as "projections of the canonical" and which are retired?)
- Does the projection tier itself need a schema version, or is it derived from the authoritative tier's version?

---

## D3 · Provenance mechanism

### Decision statement
Which mechanism enforces §P3 "provenance is mandatory"?

### Alternatives (from ADR-005 §11 D3)
- **D3-x**: Adopt ADR-0014 CIO's ReasoningStep stream + per-node `source` for evidence-level provenance.
- **D3-y**: Adopt North Star CIO's mandatory `Provenance{engine, at}` on every appended entry.
- **D3-z**: **Both** — ReasoningStep for decision-level provenance; Provenance envelope for entry-level provenance.

### Evidence from ADR-005
- §3 P3: "Every fact, node, edge, verdict signal, or conclusion in the SSOT carries `(engine + version) + when + which upstream evidence`."
- §4.2 invariant: "Every entry carries provenance — the mechanism is uniform across all buckets."
- §5 role table: Analyzer / Enricher / Composer all *append*; every append must carry provenance.
- §7 P7 (Analyst-visible reasoning): ReasoningStep is the substrate for replay + debug + explain + audit + training + LLM context + rationale — one mechanism, seven use cases.
- Reconciliation SSOT-D observation: North Star CIO uniquely enforces mandatory Provenance on every entry.

### Benefits
- **D3-x**: analyst-visible reasoning is a first-class stream; replay is straightforward.
- **D3-y**: uniform envelope on every entry across every bucket; the mechanism is trivial to audit.
- **D3-z**: covers both **decision-level** (why did we conclude X?) and **entry-level** (who wrote this artefact node?) — the two are distinct concerns.

### Risks
- **D3-x alone**: entries in `artifacts[]`, `iocs.*`, `activity.*` have no per-entry provenance unless the ReasoningStep back-links them. Search/audit by provenance becomes an indirection.
- **D3-y alone**: no decision stream — analyst cannot see WHY the engine made a conclusion; only WHAT engines wrote WHERE.
- **D3-z**: duplication risk — a reasoning step's `output_nodes[]` must reference entries whose Provenance is consistent with the ReasoningStep's engine.

### Migration implications
- **D3-x / D3-y**: existing SSOTs need a per-node provenance retrofit (CIO has per-node `source`; InvestigationModel and Canonical have none).
- **D3-z**: same retrofit + the ReasoningStep stream, which ADR-0014 CIO already has.

### Reversibility
- **D3-z**: fully reversible (either tier can be dropped independently).
- **D3-x / D3-y**: less reversible — removing one leaves gaps.

### Dependencies
- Blocks **D2** (provenance shape must be defined before the canonical SSOT can require it).
- No upstream dependencies.

### Recommended option
**D3-z · Both**. Rationale:
- Matches ADR-005 P3 and P7 (seven use-cases require both decision-level and entry-level provenance).
- Honours INV-3 uniformly (every entry has an envelope) AND INV-6 (Composer role explicitly writes reasoning steps).
- Consistency check is expressible: `ReasoningStep.output_nodes ⊆ entries whose Provenance.engine == ReasoningStep.rule owner`.

### Unresolved questions
- Is `engine` a string or a versioned identifier (`engine@vX.Y.Z`)?
- Is the ReasoningStep's `rule` identifier stable across engine upgrades, or does it change when the underlying logic changes?

---

## D4 · Execution model

### Decision statement
Does IUE emit an ordered `plan[]`, an unordered `dispatch: List[Capability]`, or both?

### Alternatives (from ADR-005 §11 D4)
- **D4-1**: **Plan-only** (IUE-2 model). Ordered `List[PlanStep]`; executor runs them in order.
- **D4-2**: **Dispatch-only** (IUE-3 model). Unordered `List[Capability]`; executor resolves order via a dependency graph.
- **D4-3**: **Both** (`plan[]` + `dispatch[]` + `dispatch_policy: strict_ordered | parallel_where_safe | dag`).

### Evidence from ADR-005
- §3.2 `IUEDecision` explicitly lists `plan`, `capabilities`, AND `dispatch_policy` as separate required fields — the design already anticipates D4-3.
- §11 D4 recommendation: *"emit both — plan for strict-ordered execution when required, dispatch for parallel-safe execution."*
- Reconciliation IUE-2 vs. IUE-3 capability matrix: IUE-2 emits plan; IUE-3 emits Capability dispatch; §D concludes neither alone is sufficient.

### Benefits
- **D4-1**: simplest to reason about; deterministic ordering.
- **D4-2**: enables parallelism where safe; smaller IUE (no ordering logic).
- **D4-3**: same IUE serves synchronous and DAG executors; policy field selects behaviour per case.

### Risks
- **D4-1**: sacrifices parallelism opportunities where safe; recursive-discovery iterations become sequential.
- **D4-2**: IUE cannot express hard-ordering constraints (e.g. Health MUST run before IUE — but at that point IUE hasn't started; and IUE MUST run before decoders — that's exactly what a plan expresses).
- **D4-3**: executor must implement three scheduling policies; test surface is larger.

### Migration implications
- **D4-1**: IUE-2 shape is preserved; IUE-3's dispatch list is retired.
- **D4-2**: IUE-2's plan is retired; every capability worker must be side-effect-declaring for the DAG scheduler.
- **D4-3**: both survive as first-class outputs; existing IUE-2 callers get `plan[]`; existing IUE-3 callers get `dispatch[]`.

### Reversibility
- **D4-3**: high — removing either field is an additive-migration removal (major version bump).
- **D4-1 / D4-2**: low — losing information.

### Dependencies
- Depends on **D1** (composition composer needs to know what to emit).
- Blocks executor design.

### Recommended option
**D4-3 · Both, with `dispatch_policy`** — matches ADR-005 §3.2 verbatim. Rationale:
- Non-lossy: preserves IUE-2's plan semantics AND IUE-3's dispatch semantics.
- Policy-selectable: `strict_ordered` matches today's synchronous Workspace behaviour; `parallel_where_safe` enables MDR's per-command parallelism; `dag` enables future recursive-discovery graphs.
- Honours INV-6 (executor is a distinct role; IUE only declares).

### Unresolved questions
- How does the policy interact with recursion budgets (§8)?
- Does `strict_ordered` allow the executor to skip a step whose predecessors declared it obsolete?
- Is the `dag` policy required in the first release, or can it be added later without breaking existing callers?

---

## D5 · Entry-point convergence phasing

### Decision statement
Are all entry points converged in one release, or is convergence phased with a compatibility shim?

### Alternatives (from ADR-005 §11 D5)
- **D5-α**: Converge all entry points in one release. Requires D1/D2/D3/D4/D6 settled first; big-bang cutover.
- **D5-β**: Phase entry points. A shim (`cases.py::save_case` accepting *either* an SSOT *or* raw input during migration) allows staged migration.

### Evidence from ADR-005
- §7 target lifecycle applies to all entry points identically after adapters.
- §11 D5: "Do we require all entry points to converge in one release, or is convergence phased with a shim?"
- Reconciliation §F: 6th precondition — "the `POST /api/cases/save` and `POST /api/cases/{id}/reinvestigate` persistence contracts are decided."

### Benefits
- **D5-α**: single canonical shape from day 1; no shim maintenance; determinism guarantee is easier to prove.
- **D5-β**: risk-limited rollout; every entry point can be validated against a golden case before switching; existing consumers keep working.

### Risks
- **D5-α**: any consumer failing to migrate blocks the release.
- **D5-β**: shim becomes permanent (a well-known anti-pattern); dual code paths for possibly months.

### Migration implications
- **D5-α**: coordinated migration; large PR surface.
- **D5-β**: incremental PRs; each entry point migrated independently.

### Reversibility
- **D5-β** is inherently more reversible (each phase can be rolled back independently).

### Dependencies
- Depends on D1, D2, D3, D4, D6 being settled.
- Doesn't block ADR-005 architecture itself.

### Recommended option
**Deferred**. Owner explicitly stated the priority is D1/D2/D4/D6/D7 — phasing can be decided AFTER those five are settled.

### Unresolved questions
- If D5-β: what is the shim's lifetime bound (release date, or a metric-driven retirement)?

---

## D6 · Recursive-investigation store model

### Decision statement
Are child SSOTs stored **inline** (nested JSON) or **by reference** (`ssot_ref` into an immutable store)?

### Alternatives (from ADR-005 §11 D6)
- **D6-i**: **Inline** — child SSOTs are nested JSON inside the parent's `artifacts[]`.
- **D6-r**: **By reference** — child SSOTs live in an immutable store; parent carries `ssot_ref`.
- **D6-h**: **Hybrid** — small children inline; large children by-ref; policy determines the threshold.

### Evidence from ADR-005
- §4.4: rule states "child SSOTs live in the same immutable store as top-level SSOTs. They are addressable by `ssot_ref`."
- §8 recursive-investigation: "the child SSOT is stored in the immutable SSOT store and referenced from the parent's `artifacts[].investigation_ref`."
- §11 D6 trade-off: "inline is single-doc atomic; by-reference supports sharing (identical child artefacts across cases)."
- Reconciliation SSOT-C: `nivxforge` already has an immutable `investigation_ssot` store with `ssot_ref` write-through (documented in `routers/cases.py::save_case`).

### Benefits
- **D6-i**: single-doc atomic reads; simpler persistence; predictable read latency.
- **D6-r**: enables **content sharing** — same base64 blob decoded once across cases; same URL fetched once. Enables the "training data" and "corpus" use-cases without duplication. Matches P4 replay guarantee.
- **D6-h**: pragmatic — small artefacts (a decoded IOC) inline; large artefacts (a fetched HTML page, a PE binary) by-ref.

### Risks
- **D6-i**: Mongo 16 MB doc limit is a hard ceiling; `cases.py::save_case` already has fallback logic to drop sub-fields when the doc exceeds 8 MB — this is a symptom of inline storage overflowing.
- **D6-r**: read amplification (parent read + N child reads); requires a cache or aggregation.
- **D6-h**: threshold policy becomes a source of subtle bugs (identical child stored inline in case A, by-ref in case B, breaks determinism-hash equality).

### Migration implications
- **D6-i**: retires the existing `investigation_ssot` immutable store (§SSOT-C infrastructure) — regression.
- **D6-r**: extends the existing store to be the canonical child location — natural evolution.
- **D6-h**: keeps both mechanisms with a policy switch — complexity.

### Reversibility
- **D6-i → D6-r**: possible (extract children into store; replace inline with ref).
- **D6-r → D6-i**: possible but destroys sharing.
- **D6-h**: reversible but expensive to unwind.

### Dependencies
- Depends on **D2** (recursive `artifacts[]` shape).
- Depends on **D9** (schema versioning — inline vs. by-ref changes the doc shape).
- Blocks **D5** (entry-point adapters need to know how to persist).

### Recommended option
**D6-r · By reference into the immutable SSOT store** — matches ADR-005 §4.4 and §8 verbatim. Rationale:
- ADR-005 already specifies by-reference as the target.
- The existing `investigation_ssot` store + `ssot_ref` write-through mechanism is a working starting point (per reconciliation SSOT-C).
- Enables sharing / dedup — foundational for future corpus-scale analysis.
- Honours INV-4 (additive migration: the store already exists; we're extending it).
- Honours INV-1 (children ARE SSOTs, not projections — they belong in the SSOT store).

**Fallback under consideration**: D6-h for the specific case where the child artefact is smaller than a threshold *AND* is unique to the case (fingerprint not shared) — this would be a performance optimisation, not a structural change, and can be decided later.

### Unresolved questions
- What is the immutable-store retention policy? (indefinite; per-tenant TTL; per-schema-version compaction?)
- How is a `ssot_ref` versioned when the child's schema version bumps but the parent's does not?
- Is the store content-addressed (sha256 of canonical JSON = key) or id-addressed (uuid = key)? Content-addressing enables dedup but changes the ref stability.

---

## D7 · Wave 1 treatment

### Decision statement
How are existing Wave 1 observations (recorded without source-path labels) treated once the labelling extension lands?

### Alternatives (from ADR-005 §10)
- **W1-A · Segment-and-continue**: keep existing observations in a `pre_ssot_reconciliation` segment; new observations after labelling go into a fresh segment. Aggregate the two separately.
- **W1-B · Restart**: retire existing observations; begin fresh Wave 1 once the labelling lands.

### Evidence from ADR-005
- §10: current Wave 1 samples from two SSOT paths without a source-path label; retrospective attribution is only possible if records are tagged, which they are not.
- §11 D7: "Both options require the observation-record schema to be extended (schema-version bump; per §6 this is backwards-compatible append)."
- Reconciliation Part 5 (Wave 1 Confound): observations write into the same `verdict_shadow_observations` collection with no upstream-shape label; `divergence` telemetry cannot be attributed to "scoring vs. impoverished input" without knowing which SSOT the sample came from.

### Benefits
- **W1-A**: preserves existing n=2 as **directional signal within its own segment**; enables historical comparison "did the labelled segment behave differently from the unlabelled?"
- **W1-B**: unambiguous going forward; no risk of accidentally aggregating across segments.

### Risks
- **W1-A**: aggregation-across-segment errors are hard to prevent; requires every consumer of the observation store to be segment-aware.
- **W1-B**: throws away Wave 1's already-collected data; requires the observation window to reset.

### Migration implications
- **W1-A**: schema extension only; existing records get a synthetic `segment=pre_ssot_reconciliation` on read (or a one-time backfill).
- **W1-B**: existing records are marked `retired=true` OR moved to an archival collection; queries default to non-retired.

### Reversibility
- **W1-A**: fully reversible (records are preserved).
- **W1-B**: not reversible if records are deleted; reversible if merely archived.

### Dependencies
- Depends on **D2** (source-path labels reference SSOT shapes chosen in D2).
- Blocks **D10** (ADR-004 Step 2 decision depends on labelled Wave 1 data; unlabelled data cannot inform it).
- Blocks any consumer-switch decision — observations without labels cannot justify a switch.

### Recommended option
**W1-A · Segment-and-continue**, but with two rules:
1. Existing unlabelled observations are frozen into the `pre_ssot_reconciliation` segment; **no new observations may be added to that segment**.
2. Any aggregation query MUST specify a segment; queries without a segment return an error, not a merged result.

Matches ADR-005 §10 verbatim; matches owner's stated preference. Rationale:
- Preserves whatever directional signal exists in the current n=2 (per reconciliation, "the record shape does contain a run_id and input_completeness ... so retrospective attribution IS possible once we label each record with its source path").
- Fresh segment behaves as a clean Wave 1 with proper labelling.
- Reversible: if the segment separation turns out to be uninformative, both segments can be re-analysed together with post-hoc labels once the source-path can be inferred.

### Unresolved questions
- Can the source-path of existing records be inferred post-hoc from the `run_id` (i.e. by cross-referencing which endpoint the run originated from)? If yes, this could allow retroactive labelling — but per reconciliation §5 the current data does not include enough context to do this reliably.
- What is the minimum n per segment before Wave 1 interpretation is authorised? Owner has already indicated n ≥ 30 per class was the target — but this pre-dated the segment-labelling discovery. Should the target be reset to n ≥ 30 per (class × source_path)?

---

## D8 · Enricher isolation

### Decision statement
Are enrichers a distinct role (§5) or a sub-role of Analyzer?

### Alternatives (from ADR-005 §11 D8)
- **D8-s**: **Separate role**. Enrichment is its own boundary; deterministic conclusion is computable without enrichers running.
- **D8-c**: **Consolidated as sub-role of Analyzer**. Simpler role model; determinism guarantee is a per-Analyzer property.

### Evidence from ADR-005
- §5 role table already lists Enricher as distinct from Analyzer.
- §5 enricher-isolation clause: "the deterministic conclusion of the investigation MUST be computable WITHOUT enrichers running."
- §11 D8 recommendation: "keep separate (matches P4)."
- INV-2 (determinism): enrichment is external, non-deterministic, and network-touching.

### Benefits
- **D8-s**: determinism guarantee is a **structural invariant** (enricher can be disabled entirely and the deterministic core still produces a valid SSOT).
- **D8-c**: fewer roles; simpler executor.

### Risks
- **D8-s**: role count is higher; every module must classify.
- **D8-c**: silently breaks determinism when an Analyzer starts calling external APIs; harder to audit.

### Recommended option
**D8-s · Separate role** — matches ADR-005 §5 and §11 D8. Honours INV-2. Enables INV-6 (each module classifies into exactly one role).

### Unresolved questions
- Where do **local** enrichment sources (bundled TI corpus, LOLBAS registry) sit — Analyzer or Enricher? By-network criterion they're Analyzer (no network); by external-source criterion they're Enricher. Recommendation: treat any lookup against a non-input-derived data source as Enricher, regardless of network — the determinism-preserving property is that removing the source degrades to a still-valid SSOT.

---

## D9 · Schema versioning strategy

### Decision statement
What is the schema-versioning contract, and is a major-version bump breaking for older workspace_cases?

### Alternatives (from ADR-005 §11 D9)
- **D9-back**: **Every major is backwards-projectable** from newer to older (older clients keep working; new fields are hidden).
- **D9-mig**: **Major bumps are breaking**; a migration script must run against existing cases.
- **D9-both**: **Semver with declared backwards-compat guarantee** per major (semver-compat matrix; some majors are back-projectable, some are not — declared per release).

### Evidence from ADR-005
- §4.2 invariant: "Schema-versioned — `schema_version` is a semver; consumers gate on major-version compatibility."
- §6 mapping already reveals differences across SSOTs' field naming (`iocs` in three shapes) — future SSOT evolution will hit similar issues.
- INV-4 (additive migration).

### Benefits
- **D9-back**: minimises client breakage; older UIs keep working.
- **D9-mig**: cleaner internal shape; no back-compat baggage.
- **D9-both**: pragmatic — most bumps back-projectable, occasional breaking major when needed.

### Risks
- **D9-back**: schema accumulates permanent legacy fields.
- **D9-mig**: every major bump risks data loss if migration is imperfect.
- **D9-both**: relies on discipline; requires explicit per-major declaration.

### Recommended option
**D9-both** with the discipline that **the default is D9-back** — a breaking major is authorised by an explicit ADR each time. This matches INV-4 (additive migration is the default; breaking is by exception).

### Unresolved questions
- Is `schema_version` a field on the canonical SSOT alone, or on the authoritative tier AND projection tier independently (per D2-d)?

---

## D10 · ADR-004 relationship

### Decision statement
Does ADR-005 SUPERSEDE ADR-004's Step 2+ until the canonical SSOT lands, or does ADR-004 continue in parallel under a freeze?

### Alternatives (from ADR-005 §11 D10)
- **D10-super**: **ADR-005 is a prerequisite to ADR-004 Step 2**. No consumer switch until D2 settled and labelled Wave 1 observations accumulate.
- **D10-par**: **ADR-004 continues in parallel** on a "no consumer switch" freeze; Wave 1 continues under the segment-and-continue policy (D7 W1-A).
- **D10-freeze**: **ADR-004 fully paused** — shadow attach code preserved but no further waves.

### Evidence from ADR-005
- §11 D10: "does ADR-005 supersede ADR-004's Step 2+ ... or does ADR-004 continue in parallel under a freeze until D2 is decided?"
- §10 (Wave 1 impact): "any consumer-switch decision" cannot be made from currently unlabelled data.
- Reconciliation §F precondition 4: "A single verdict input shape is chosen" — this is D2.

### Benefits
- **D10-super**: architectural coherence; no premature verdict consolidation.
- **D10-par**: preserves ADR-004's telemetry infrastructure and continues gathering (labelled) data.
- **D10-freeze**: minimum-work; nothing changes until D2 lands.

### Risks
- **D10-super**: loses ADR-004 momentum; observation data accumulates only after D2 lands.
- **D10-par**: risk of ADR-004 team pushing for a consumer switch before D2 is settled.
- **D10-freeze**: labelled Wave 1 data does not accumulate until ADR-004 is unfrozen.

### Recommended option
**D10-super with active data collection** — ADR-004 Step 2 (consumer switch) is explicitly gated on D2. However, **the shadow observation attach continues** under the segment-and-continue policy (D7 W1-A) so that once D2 lands, labelled Wave 1 data is already accumulating. This is the ADR-005 §11 D10 middle option, explicitly softened to preserve observational continuity.

### Unresolved questions
- Owner-stated preference: "ADR-005 becomes a prerequisite to ADR-004 Step 2, and likely changes the input side of the Verdict migration." The recommendation above matches. Explicit confirmation is required so ADR-004's owner does not proceed with Step 2 planning under the old assumption.

---

## Summary matrix (one-line recommendations)

| D | Statement | Recommended option | Class |
|---|---|---|---|
| **D1** | IUE canonisation | **D1-D · Composer over IUE-2/3/4/5 sub-classifiers** | BLOCKING |
| **D2** | SSOT canonisation | **D2-d · Two-tier (authoritative graph + canonical projection tier)** | BLOCKING |
| **D3** | Provenance mechanism | **D3-z · Both (ReasoningStep + Provenance envelope)** | BLOCKING |
| **D4** | Execution model | **D4-3 · Both plan[] + dispatch[] + policy** | BLOCKING |
| **D5** | Entry-point phasing | *Deferred until D1/D2/D3/D4/D6 settled* | Deferrable |
| **D6** | Recursive store | **D6-r · By reference into immutable SSOT store** | BLOCKING |
| **D7** | Wave 1 | **W1-A · Segment-and-continue with locked pre-segment** | BLOCKING (interpretation) |
| **D8** | Enricher isolation | **D8-s · Separate role** | Deferrable |
| **D9** | Schema versioning | **D9-both · Default back-projectable; ADR-required breaking majors** | Deferrable |
| **D10** | ADR-004 relationship | **D10-super with active data collection** | BLOCKING (scheduling) |

---

## STOP

Per directive: no implementation, no code changes, no route changes,
no Wave 1 modifications, no ADR-004 modifications. This matrix is
the permanent architectural record; owner decisions can be recorded
inline in this document (a new "Owner decision" line per D) so future
readers understand the WHY.

**Awaiting owner decisions on D1, D2, D3, D4, D6, D7, D10 (blocking)
before any implementation sequence design is proposed.**
