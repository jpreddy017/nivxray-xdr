# ADR-001 · Semantic Contract Freeze (behavior-centric architecture)

**Status:** Accepted · 2026-02-05
**Milestone:** P0.9 (following P0.8 architectural completion)

## Context

Through P0.3 → P0.8 the pipeline was refactored into a behavior-centric
architecture with a single deterministic semantic layer.  With P0.8 the
architecture was declared complete.  This ADR **freezes** the semantic
contracts so that operational maturity work (validation, coverage
metrics, UI, contracts) can proceed on a stable foundation and future
semantic changes require an explicit version bump.

## Frozen contracts

### 1. Behavior schema  (`services.ida.behaviors.Behavior`)
Framework-neutral; **must not** carry any framework-specific field.
```python
@dataclass(frozen=True)
class Behavior:
    behavior_type:  str
    label:          str
    source:         str          # command_classifier | malware_lookup | lolbas_lookup | cve_lookup | uaie_*
    source_ref:     str
    provenance:     str          # command_execution | malware_reference | lolbas_binary_reference | cve_reference
    confidence:     str          # deterministic (only value today)
    evidence:       Dict
    observed_at:    Dict         # optional references: artifact_id / entity_id / evidence_index / line
    # id is a computed sha1[:12] property; not stored
```
- Any change requires a new schema version and an entry in
  `test_ida_behavior_projections.py::test_behavior_minimal_field_set`.

### 2. Projection API  (`services.ida.projections.*`)
Every framework projection **must** expose:
- a static `BEHAVIOR_TO_<FRAMEWORK>` map  (private to projection layer)
- a `project_to_<framework>(behaviors)` function  (bulk API)
- a `<framework>_for(behavior_type)` accessor  (single-lookup public API)

Callers **must** use `project_to_*` / `*_for` — the raw maps are gated by
the P0.6 CI invariant.

### 3. Graph schema  (Provenance endpoint · `schema_version: 1.1`)
Response envelope:
```jsonc
{
  "schema_version": "1.1",
  "behaviors":      [PublicBehavior…],
  "verdict":        {severity, one_liner},
  "summary":        {kill_chain, impacts, mitre},
  "graph":          {"nodes": [...], "edges": [...]}
}
```
Graph node types (closed set): `evidence · behavior · mitre · kill_chain · impact · recommendation`.
Graph edge types (closed set): `produces · projects · supports`.
- Any new node/edge type requires a schema-version bump.
- Adding fields to existing node types is minor-version compatible.

### 4. Provenance vocabulary  (closed set)
- `command_execution`         — observed live command
- `malware_reference`         — named malware family identified
- `lolbas_binary_reference`   — LOLBAS binary observed as file_path artifact
- `cve_reference`             — CVE observed in evidence
- `tool_reference`            — RESERVED for future Tool-Mention Extractor
- `document_reference`        — RESERVED for future narrative extractors

Any new provenance kind requires this ADR to be updated.

### 5. Recommendation Rule input contract
Rules **may read only**:
- `c.behaviors`, `c.impacts`, `c.mitre_techniques`, `c.attack_posture`  (semantic layer)
- `c.ips`, `c.urls`, `c.domains`, `c.hashes`  (structured IOC bags)
- `c.reached_shellcode`, `c.detection_confidence`, `c.scope`  (case-level modifiers)

Rules **must NOT read**:
- `c.output_text`, `c.processes`, `c.commands`, `c.files`, `c.registry_keys`
  (raw evidence · enforced by the P0.7 AST invariant)

### 6. Producer / Consumer discipline
- **Behavior Producers** (e.g. `services.ida.behaviors.generate_behaviors`,
  `services.uaie.behavior_extractor.extract_behaviors`) may consume
  Evidence and emit Behaviors.  They must NOT import projection modules
  or the recommendation engine.
- **Behavior Consumers** (projections, recommendation engine, provenance
  endpoint, SSOT projector) may consume Behaviors but must NOT construct
  them from raw evidence.
- Producer-only invariant on `behavior_extractor.py` is enforced by
  `test_uaie_extractor_is_a_producer_never_a_consumer`.

## CI-enforced architectural invariants (permanent)

| # | Test | Purpose |
|---|---|---|
| 1 | `test_ci_invariant_no_framework_map_imports_outside_projections` | Framework maps only live in projection layer |
| 2 | `test_ci_invariant_no_rule_inspects_raw_evidence`                | Rules must consume the semantic layer |
| 3 | `test_uaie_extractor_is_a_producer_never_a_consumer`             | Producers must not consume projections/engine |
| 4 | `test_projector_does_not_call_behavior_generator`                | SSOT projector projects, never synthesizes |
| 5 | `test_behavior_has_no_framework_specific_fields`                 | Behavior stays framework-neutral |

## Migration policy

Any change to a frozen contract **must**:
1. Bump the affected schema version (Behavior schema version, graph
   schema version, provenance vocabulary version)
2. Update this ADR with the change rationale
3. Provide a migration path or explicit break notice in `PRD.md`
4. Extend or update the CI invariants when a new architectural boundary
   is introduced

## Non-frozen areas (operational · may evolve freely)

- Corpus manifest content (add / remove test cases at will)
- Coverage-report schema (`REPORT_SCHEMA_VERSION`) — still 1.0, may evolve
- Recommendation rule list (adding / removing individual rules)
- Behavior vocabulary — new `behavior_type` entries are additive and
  require only a new row in each projection module; no schema break
- MALWARE_FAMILY_TO_BEHAVIORS, LOLBAS_BINARY_TO_BEHAVIORS, CVE_TO_BEHAVIORS
  lookup content

## Rationale

Freezing these contracts converts the architecture from a *living* system
(prone to drift as new features are added) into a *stable* one (where
new features compose on the boundary without violating the semantic
layer).  The three AST-based CI invariants + this ADR give both
mechanical and documentary enforcement so future contributors don't need
to rediscover the architectural discipline.
