# ADR-005 · Phase 3 Specification — Canonical Executor

- **Status**: **AUTHORISED for implementation** (owner 2026-08-10)
- **Prerequisites**: Phase 1 CLOSED, Phase 2 CLOSED
- **Owner decisions carried in**: D4-3 (plan[] + dispatch[] + `dispatch_policy`), D6-r (recursive by reference), D8-s (Enricher separate role, INV-2 isolation)
- **Sample1 record**: **NEVER modified** (R-G1..R-G6, IX-1)

## Scope (owner-authorised, verbatim from Phase 2 review)

### Allowed in Phase 3
- Canonical `Executor` class + capability plug-in registry (D4-3).
- Capability plug-ins wrapping existing Analyzers as READ-ONLY adapters (no legacy file modified).
- Executor reads `IUEDecision.plan[]` (or `dispatch[]`) + `dispatch_policy`, invokes plug-ins, writes to `AuthoritativeSSOT` via `.append(...)` with mandatory Provenance.
- Enricher isolation (INV-2): the deterministic conclusion of the investigation must be computable WITHOUT Enrichers running.
- Recursive discovery capability (D6-r): child artefact enters the SAME lifecycle, produces a child SSOT, is stored by reference.
- Budget enforcement (`max_depth`, `max_children`, `max_wall_time_ms`); on exhaustion, `execution_trace` records `budget_exhausted` — never silent truncation.
- Determinism guarantee: same input + same registry ⇒ byte-identical authoritative SSOT.

### NOT allowed in Phase 3
- ❌ Any route change (no router file modified).
- ❌ Workspace UI or frontend changes.
- ❌ `routers/cases.py` modification.
- ❌ Engine A / Verdict changes.
- ❌ Wave 1 modification.
- ❌ Existing SSOT class changes.
- ❌ **Populating any projection field** (Phase 4 territory) — `assert_projections_empty()` must still pass on every executor output.
- ❌ Attack Story / MITRE-based recommendations / summaries / reports (those are projections; Phase 4).
- ❌ Consumer switch.
- ❌ Deleting/deprecating any existing IUE/analyzer/decoder.
- ❌ Sample1 modification.
- ❌ Phase 4 auto-start.

## Deliverables

```
backend/canonical/executor/
├── __init__.py                    Public API: Executor, register_capability, ExecutorBudget
├── executor.py                    Executor class (plan-driven + dispatch-list)
├── registry.py                    Capability plug-in registry
├── budget.py                      ExecutorBudget dataclass
└── capabilities/                  Per-capability read-only adapters
    ├── __init__.py                Auto-registers built-in capabilities
    ├── input_health.py            Records IUE-emitted health into SSOT
    ├── ioc_extractor.py           Deterministic regex-based IOC extraction to evidence_graph nodes
    ├── command_detect.py          Wraps v2/mdr/incident_parser command detection
    ├── mitre_map.py               Wraps existing MITRE mapping (evidence-graph nodes only; no projection)
    ├── archive_extract.py         DOCX/ZIP member extraction to artefacts[]
    ├── threat_intel.py            Enricher plug-in (INV-2 isolated); deterministic no-op unless enabled
    └── recursive_discovery.py     Recurses into artifacts[] via ssot_ref (D6-r)

backend/tests/canonical/executor/
├── test_executor_contract.py         T3.1  · Executor emits SSOT with mandatory Provenance
├── test_executor_plan_driven.py      T3.2  · plan[] strict_ordered
├── test_executor_dispatch.py         T3.3  · dispatch[] parallel_where_safe byte-identical to strict
├── test_executor_recursion.py        T3.4  · RECURSIVE_DISCOVERY produces child SSOTs by ref (D6-r)
├── test_executor_budget.py           T3.5  · max_depth / max_children enforced; budget_exhausted recorded
├── test_executor_enricher.py         T3.6  · deterministic conclusion computable without Enricher
├── test_executor_determinism.py      T3.7  · byte-identical SSOT across 20 replays
├── test_executor_isolation.py        T3.8  · no route/UI imports executor
└── test_executor_sample_acceptance.py  A3.1..A3.3
```

## Invariants Phase 3 must enforce at runtime

- **INV-1** — capability plug-ins ARE NOT SSOTs. Plug-ins may hold local scratchpad state but MUST write final facts to `AuthoritativeSSOT.append(...)`. Any plug-in returning a "dict-shaped alternate SSOT" fails contract test T3.1.
- **INV-2** — with `enrichers_enabled=False`, the executor must still produce a valid, deterministic SSOT. Verdict, Attack Story, recommendations are NOT computed in Phase 3, so INV-2 here is verified by "same authoritative SSOT with/without Enricher plug-in registered".
- **INV-3** — every appended entry carries mandatory Provenance (verified by SSOT invariant carried from Phase 2).
- **INV-4** — projection buckets remain empty (`assert_projections_empty()`).
- **INV-6** — every plug-in classified as exactly one of {Health, Analyzer, Enricher}. Executor rejects a plug-in that fails this classification test.

## Exit condition

1. All Phase 3 tests green (T3.1..T3.8 + A3.1..A3.3).
2. Sample.docx NEW-case acceptance: authoritative SSOT populated (evidence_graph nodes/edges, artifacts, execution_trace, reasoning_steps), projections empty, deterministic hash stable.
3. Sample1 fingerprint verified unchanged.
4. Combined Phase 1 + Phase 2 + Phase 3 test suite green.
5. Phase 3 report at `/app/memory/adr/0005-phase3-report.md`.
6. **STOP.** Await owner review before Phase 4.
