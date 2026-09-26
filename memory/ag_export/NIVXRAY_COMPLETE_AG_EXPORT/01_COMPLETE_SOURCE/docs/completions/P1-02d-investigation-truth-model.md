# Completion Record · P1-02d · Investigation Truth Model + Quality Benchmark

## Backlog IDs
- `P1-02d` · Investigation Truth Model (§1.1.20)
- `P1-02e` · Investigation Quality Benchmark (permanent CI regression)

## Objective
Establish the single canonical projection every downstream surface
consumes so Story, Executive Summary, Reports, Verdict, Timeline,
Ledger, Notebook, and Exports can never drift again. Anchor future
engine changes to a measurable benchmark so regressions surface at PR
time, not in production.

## Investigation Truth Model — Six Canonical Layers

    Observation → Finding → Hypothesis → Validation → Decision → Recommendation

- **Observation** — raw fact recovered from the input (one per non-
  synthetic evidence-graph node). Carries `source_node_ids` for full
  traceability.
- **Finding** — curated conclusion from ≥ 1 observations. Severity
  mapped from the verdict-engine evidence class. Also emits a
  dedicated finding per synthetic behaviour signal (topology,
  temporal, entity, mitigating, shellcode).
- **Hypothesis** — deterministic derivation from CIO metadata:
  * `H-SHELLCODE` (validated when shellcode reached)
  * `H-LOLBAS-DOWNLOADER` (validated when LOLBAS/IEX/BITS attack-chain
    kinds fire)
  * `H-C2` (validated when confirmed-malicious IOCs or known-C2 layers
    fire)
  * `H-GENERIC` fallback so every non-Undetermined verdict yields ≥ 1
    hypothesis.
- **Validation** — pairs each hypothesis with its supporting +
  counter-evidence finding ids, tags the escalation rule that fired
  (if any).
- **Decision** — restates `cio.verdict` in the truth vocabulary so
  every surface reads one shape (label · confidence_pct ·
  escalation_rule · confidence_breakdown · engine).
- **Recommendation** — concrete analyst actions:
  * Malicious → `contain (p0) · hunt (p1) · notify (p1)`
  * Suspicious → `investigate (p2)`
  * Runtime Dependent → `investigate (p3)`
  * Undetermined / Informational → `allow (p3)`

## Implementation
- New module `nivxforge/investigation/truth_model.py` (~330 lines).
  Pure `build_truth(cio) → InvestigationTruth` — deterministic,
  idempotent, replayable. Never mutates the CIO.
- `CIO.truth` field added (optional `Dict[str, Any]`) at
  `nivxforge/investigation/models.py`.
- `build_cio` now calls `build_truth(cio)` after summary composition
  and stashes the JSON-dumped result on the CIO.
- `refresh_verdict()` also re-derives `cio.truth` so post-metadata /
  post-OSINT verdict changes stay in sync — zero drift by construction.

## Investigation Quality Benchmark

- `tests/quality/benchmark_corpus.py` — permanent 10-entry corpus
  spanning benign · ambient · attack-chain · c2 categories with
  analyst-recorded `expected_label`, confidence bounds, IOC substrings,
  escalation-rule expectations, and shellcode-expectation flags.
- `tests/quality/test_investigation_benchmark.py` — grades the live
  engine against 8 permanent KPIs:

    | KPI                          | Threshold | Current |
    |------------------------------|-----------|---------|
    | label_agreement_pct          | 80.0      | 80.0 ✓  |
    | confidence_bounds_pct        | 80.0      | 100.0 ✓ |
    | ioc_extraction_recall_pct    | 50.0      | 100.0 ✓ |
    | escalation_rule_recall_pct   |  0.0      | 100.0 ✓ |
    | shellcode_recall_pct         | 100.0     | 100.0 ✓ |
    | no_over_promotion_pct        | 100.0     | 100.0 ✓ |
    | determinism_pct              | 100.0     | 100.0 ✓ |
    | e2e_latency_p95_ms           | 5000.0    | ~1 ms ✓ |

- Report persisted at `/app/docs/benchmarks/investigation_quality.json`
  on every run — the assessment (Phase 5) will cite it directly.

## Live E2E Verification
BITS-downloader input through `/api/decode/smart` → `cio.truth`:

- 6 observations · 5 findings · 1 hypothesis (validated) · 1 validation
- **Decision: Malicious @ 80 %**
- 3 recommendations: `contain (p0) · hunt (p1) · notify (p1)`

## Tests
- New: `tests/parity/test_truth_model.py` — 7 tests
  (shape · determinism · traceability · coverage · purity)
- New: `tests/quality/test_investigation_benchmark.py` — 2 tests
  (benchmark grader · determinism)
- Full parity suite: **74 passed, 13 skipped, 0 failed**.
- Combined parity + benchmark: **76 passed, 13 skipped**.

## Constitutional Compliance
- [x] CIO Supremacy — truth is a pure derivation of the CIO; no new
      exchange objects
- [x] No new architectural layer — one module, one CIO field, no bus
- [x] Deterministic — pure function of CIO state
- [x] Backward-compatible — `cio.truth` defaults to None; existing
      readers unaffected
- [x] Every finding traces to a graph node (or `SYNTH-*` / `META-*`
      id with matching source)

## Next
- **Phase 2 · P2-05d** — Recursive Command Investigation (fixed-point
  decode → extract → investigate loop).
- **Phase 3 · P2-08** — Investigation Ledger + Ledger Lens (surface
  the truth model's validation trace as clickable UI).
- **Phase 4 · P2-05** — IDI Adapter Layer.
- **Phase 5 · Full Architecture Assessment** — 20-part evidence-based
  review at `/app/docs/assessments/`.

## References
- `/app/docs/BACKLOG.md` · P1-02d / P1-02e
- `/app/docs/architecture/*.md` · constitution
- Prior completion: `P1-02c-verdict-polish-plus-shellcode-parity.md`
- Benchmark artefact: `/app/docs/benchmarks/investigation_quality.json`
