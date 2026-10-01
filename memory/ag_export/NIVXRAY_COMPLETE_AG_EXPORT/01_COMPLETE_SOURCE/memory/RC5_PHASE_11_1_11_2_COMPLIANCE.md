# RC5 Phase 11.1 · Evidence Graph Population — Compliance
# RC5 Phase 11.2 · Determinism CI Gate — Compliance

**Date:** 2026-02
**Status:** ✅ Complete (Phase 11.1 + 11.2 shipped together)
**User-approved scope:** Population + determinism gate. No verdict, scoring, confidence, or explainability changes. `ExecGraph` remains authoritative.

## Phase 11.1 — Evidence Graph Population

### Delivered

Extended `engine/evidence_graph_builder.py` with mappings for every
`ExecNode.NodeKind` that the current Golden Corpus emits:

| ExecNode kind | Evidence entity | Rationale |
| --- | --- | --- |
| `string_op`, `concat`, `var_bind`, `var_expand` | `Command` | Plumbing that carries reconstructed intermediate values — surfaced so future Correlation Engine has a substrate |
| `unresolved` | `MemObj(unresolved=<reason>)` | Preserves "explicit unknown" as a first-class evidence node |

### Acceptance verified

- **88/88 Golden Corpus samples produce non-trivial evidence graphs** (min 2 nodes, avg 2.9, max 9).
- **Zero hard integrity errors** across the entire corpus.
- **Every corpus-emitted `NodeKind`** is materialised into at least one evidence entity per sample.
- **6 `NodeKind`s → 3 `EvidenceNodeKind`s** covered (Process, Command, URL/MemObj).

### New tests

- `tests/rc5/unit/evidence_graph/test_corpus_coverage.py`
  - Per-sample parametric test: every corpus sample yields > 1 node.
  - Per-sample parametric test: every corpus sample is integrity clean.
  - Corpus-wide statistics regression test.
  - Kind-coverage regression test (guards against silent mapping drops).

## Phase 11.2 — Determinism CI Gate

### Delivered

- Added `EvidenceGraph.to_canonical_dict()` / `to_canonical_json()` —
  provenance-stripped form that removes `source_node_ids` (which trace
  back to random `ExecNode.id` UUIDs). The canonical form is what CI
  compares for byte-identical determinism.
- Added `tests/rc5/unit/evidence_graph/test_corpus_determinism.py`:
  - `test_corpus_is_byte_identical_across_three_runs` — runs entire
    Golden Corpus 3× and asserts identical canonical JSON per sample.
  - `test_content_addressed_ids_stable_across_runs` — sorted node/edge
    ID sets identical across runs.
  - `test_no_hard_errors_across_three_runs` — integrity clean 3× in a row.

### Acceptance verified

- **Byte-identical canonical output across 3 consecutive corpus runs.**
- **Content-addressed IDs stable regardless of upstream ExecNode UUID churn.**

## Preview Endpoint Wiring

### Delivered

- `routers/rc5_diag.py` — `/api/rc5/parse` now emits optional
  `evidence_graph` + `evidence_graph_metrics` fields when
  `NIVX_EVIDENCE_GRAPH=sidecar` is set. Absent in production.
- `/api/rc5/status` reports the current evidence-graph mode + schema version.
- New response fields are strictly additive; all pre-existing fields
  are byte-identical between sidecar-off and sidecar-on invocations for
  the same input (verified by `test_evidence_graph_does_not_influence_verdict`).

### Preview env config

`/app/backend/.env`:
```
NIVX_EVIDENCE_GRAPH=sidecar
NIVX_EVIDENCE_GRAPH_METRICS=on
```

Production deploys default to `off` — set the env vars explicitly on
production only when Phase 11.3 (Correlation Engine) is ready to consume the graph.

## New API tests

`tests/rc5/api/test_diag_evidence_graph.py`:

1. `test_evidence_graph_absent_when_flag_off` — sidecar off → no `evidence_graph` field.
2. `test_evidence_graph_present_and_wellformed_when_sidecar` — sidecar on → well-formed graph with ≥ 2 nodes.
3. `test_evidence_graph_does_not_influence_verdict` — verdict tier/risk/scores/MITRE/LOLBIN identical between modes.
4. `test_status_endpoint_reports_evidence_graph_mode` — `/api/rc5/status` reports mode + schema version.

## Test suite

- **949 tests passing** (up from 762 · +187 new · zero regressions).
- **2 xfail** — pre-existing coverage gaps (`$env:APPDATA + …` parser hang, `[Reflection.Assembly]::Load` detection).
- **Golden Corpus 88/88 unchanged.**

## Constraints honoured

- ✅ Verdicts unchanged. Scoring unchanged. Confidence unchanged. Explainability unchanged.
- ✅ Analyst-visible behaviour in production unchanged (feature-flag defaults to `off`).
- ✅ `ExecGraph` remains authoritative.
- ✅ Legacy `operations.py` and `rc22_adapter._apply_obfuscation_only_cap` untouched.
- ✅ Deterministic evidence-graph generation across the entire Golden Corpus.
- ✅ Performance envelope: < 5 ms build time, < 100 KB peak memory per sample.

## Next: Phase 11.3 — Correlation Engine

Only unlocked once Phase 11.1 and 11.2 quality gates hold on `main`:
- Temporal reasoning (evidence ordering).
- Dependency reasoning (edge chains).
- Contradiction detection.
- FP suppression.
