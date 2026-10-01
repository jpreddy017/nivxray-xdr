# RC5 Phase 11.0 — Evidence Knowledge Graph Foundation · Compliance

**Date:** 2026-02
**Status:** ✅ Complete
**User-approved scope:** Infrastructure only, side-car, no verdict influence.

## Deliverables

| Artefact | Path | Purpose |
| --- | --- | --- |
| Data model | `/app/backend/engine/evidence_graph.py` | Node · Edge · Graph · deterministic IDs · serialization · integrity |
| Feature flag + metrics | `/app/backend/engine/evidence_graph_config.py` | `NIVX_EVIDENCE_GRAPH` · `NIVX_EVIDENCE_GRAPH_METRICS` · `EvidenceGraphMetrics` |
| Side-car builder | `/app/backend/engine/evidence_graph_builder.py` | Pure `ExecGraph → EvidenceGraph` mapping |
| Schema tests | `/app/backend/tests/rc5/unit/evidence_graph/test_schema.py` | 25 tests |
| Builder tests | `/app/backend/tests/rc5/unit/evidence_graph/test_sidecar_builder.py` | 28 tests |
| Roadmap | `/app/memory/RC5_EVIDENCE_GRAPH_ROADMAP.md` | Quality-gated Phase 11 plan |

## Test results

- **762 total tests passing** (up from 709 · +53 new)
- **2 xfail** — known coverage gaps (`$env:APPDATA + …` parser hang, `[Reflection.Assembly]::Load`) — unchanged, pre-existing.
- **Zero regressions** across the RC5 suite.
- **Golden Corpus:** unchanged (88/88 as before).

## Constraints honoured (user-approved)

- ✅ Verdicts unchanged.
- ✅ Scoring unchanged.
- ✅ Confidence unchanged.
- ✅ Explainability unchanged.
- ✅ `ExecGraph` remains authoritative.
- ✅ Evidence Knowledge Graph is observational only.
- ✅ Feature flag defaults to `off` — zero runtime overhead in production until explicitly enabled.
- ✅ Legacy `operations.py` untouched.
- ✅ `rc22_adapter._apply_obfuscation_only_cap` untouched.

## Design decisions

1. **Content-addressed IDs** — `sha256(kind|canonical_key)[:16]` yields
   deterministic, dedup-friendly node/edge IDs. Two detectors observing
   the same entity converge on the same node without coordination.
2. **Canonical key** — sorted keys, whitespace stripped, `casefold`
   applied to domain-like fields (`domain`, `host`, `scheme`, `extension`).
3. **Immutability by construction** — `frozen=True` on every model.
   Mutations return a *new* graph. Matches the discipline of `ExecGraph`.
4. **Nearest-process anchor** — side-effects are attributed to the
   transitive nearest `ProcessNode` ancestor, falling back to a synthetic
   `<root>` process. Prevents self-loops on the source node.
5. **Orphan warning, not error** — Phase 11.0 accepts orphaned nodes so
   the graph can be constructed incrementally by future detectors
   (Phase 11.1+). Orphans are reported as `[warn]` entries.
6. **Derivation DAG** — `dependsOn` + `derivedFrom` must form a DAG. Other
   edge kinds (e.g. `contacts`) are legitimately cyclic and excluded from
   the cycle check.

## Performance envelope (verified in test)

| Metric | Threshold | Actual (representative graph) |
| --- | --- | --- |
| Build time | < 50 ms | < 5 ms |
| Peak memory | < 1024 KB | < 100 KB |
| Integrity errors | 0 | 0 |

## Rollback

The feature is gated by `NIVX_EVIDENCE_GRAPH` (default `off`). Setting the
env var back to `off` — or removing it entirely — instantly disables the
side-car with zero code changes. Nothing in the request/response path
consumes the graph in Phase 11.0.

## Next: Phase 11.1 — Evidence Graph population

- Extend the mapping table in `evidence_graph_builder.py`.
- Every corpus sample must produce a non-trivial graph.
- Deterministic across three consecutive corpus runs.
- Zero hard integrity errors across the corpus.
