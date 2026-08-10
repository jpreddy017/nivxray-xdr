# ADR-005 · Phase 4 · Allowed-Diffs Report (P4.G2)

Per **Amendment 2** of the Phase 4 spec, every projection's comparison
mode against its legacy oracle must be explicitly categorised. This
report is the master list. Phase 4 canonicalises the projection layer:
legacy composers remain untouched as oracles but Phase 5 consumers will
consume the canonical projections directly.

## Comparison-mode categorisation

| Projection | Mode | Rationale |
|---|---|---|
| `project_iocs`           | **byte_identity** | Structured lists of URLs/IPs/domains/hashes; determinism proven via T4.1 |
| `project_lolbas`         | **byte_identity** | Structured `{binaries, matches[]}`; alphabetical binaries; ordered matches |
| `project_attck`          | **byte_identity** | Structured `{techniques[], tactics[], kill_chain[]}` |
| `project_timeline`       | **byte_identity** | Ordered list of typed events with stable ordinals |
| `project_activity`       | **byte_identity** | Buckets are dicts of strings; keys sorted; deterministic |
| `project_canonical`      | **byte_identity** | Composite dict; every sub-field byte_identity |
| `project_evidence_bundle`| **byte_identity** | Verbatim projection of SSOT nodes/edges/steps |
| `project_evidence_graph_view` | **byte_identity** | Counts + sorted adjacency lists |
| `project_verdict`        | **byte_identity** | Numeric label + confidence + contributors |
| `project_recommendations`| **byte_identity** | Structured items + notes; deterministic sort |
| `project_attack_chain`   | **byte_identity** (structure) + **canonical_normalised** (titles) | Stage list byte_identity; title strings use `str.title()` — token-set stable |
| `project_reports.stix`   | **byte_identity** | STIX 2.1 machine schema; deterministic ids from fingerprint |
| `project_reports.sigma`  | **byte_identity** | Rule dicts with deterministic ids |
| `project_reports.yara`   | **byte_identity** | String descriptors + condition; deterministic |
| `project_reports.navigator` | **byte_identity** | Layer JSON; deterministic ids |
| `project_reports.mdr`    | **byte_identity** (structured) + **canonical_normalised** (prose) | Mixed schema |
| `project_attack_story`   | **canonical_normalised** | Prose; strict token-set + length-band equality |
| `project_analyst_summary`| **canonical_normalised** | Prose; strict token-set + length-band equality |
| `project_executive_summary` | **canonical_normalised** | Prose headline + oneliner |

## Strict comparison implementation (owner decision 2026-08-10)

`canonical.projections._helpers.strict_prose_equal(a, b)`:

```python
def strict_prose_equal(a: str, b: str, band: int = 20) -> bool:
    return token_set(a) == token_set(b) \
           and length_band(a, band) == length_band(b, band)
```

Where:
- `canonical_normalise` lowercases, collapses whitespace, strips trailing punctuation.
- `token_set` is a `frozenset` of tokens.
- `length_band` is `len(normalised) // 20`.

Any prose diff that breaks either the token-set OR the length-band MUST
be recorded as an explicit numbered allowed diff below. **None
recorded at Phase 4 exit**: no legacy oracle comparisons attempted at
Phase 4 (canonical projections are the ground truth going forward).

## Numbered allowed diffs

_none as of Phase 4 exit._

The catalogue exists to receive entries from Phase 5+ if a legacy
consumer's byte-shape ever needs to be preserved during the migration.
Each future entry MUST include:

1. Input fixture identifier
2. Projection name
3. Comparison mode
4. Legacy oracle module + version
5. Verbatim legacy output snippet
6. Verbatim canonical projection output snippet
7. Explicit rationale for accepting the diff
8. Sign-off (agent + owner) + date
