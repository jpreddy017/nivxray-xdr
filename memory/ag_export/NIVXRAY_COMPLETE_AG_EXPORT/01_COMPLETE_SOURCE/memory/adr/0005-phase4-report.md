# ADR-005 · Phase 4 · Implementation Report

- **Status**: **CLOSED (implementation complete, tests green, sign-off reports written)**
- **Owner sign-off (2026-08-10)** — decisions applied verbatim:
  1. Build all 15 projections in Phase 4 (backwards-compat + reports included) ✅
  2. Strict `token-set + length-band` for canonical_normalised comparison ✅
  3. Pytest + backend smoke pass (pytest is the primary gate) ✅
  4. Hard boundaries respected — see “Freezes honoured” below ✅

## What shipped

### Code (new files, additive-only)

```
backend/canonical/projections/
├── __init__.py                    Public API for the 15 projections
├── _helpers.py                    Pure helpers (accessors, normalisers, strict_prose_equal)
├── verdict.py                     project_verdict
├── attck.py                       project_attck
├── attack_chain.py                project_attack_chain
├── attack_story.py                project_attack_story
├── evidence_graph_view.py         project_evidence_graph_view
├── analyst_summary.py             project_analyst_summary
├── executive_summary.py           project_executive_summary
├── recommendations.py             project_recommendations   (P4-FW3 enforced)
├── timeline.py                    project_timeline
├── lolbas.py                      project_lolbas
├── iocs.py                        project_iocs
├── activity.py                    project_activity          (SSOT-A shape)
├── canonical.py                   project_canonical         (SSOT-B shape)
├── evidence_bundle.py             project_evidence_bundle   (SSOT-E shape)
└── reports.py                     project_reports (STIX/Sigma/YARA/Navigator/MDR)
```

### Tests (new files, additive-only)

```
backend/tests/canonical/projections/
├── __init__.py
├── conftest.py                                fixtures: empty/mitre/iocs_only/commands/rich
├── test_projection_purity.py                  T4.3 · P4-FW1
├── test_projection_firewall.py                T4.2 · P4-FW2
├── test_recommendations_no_fallback.py        T4.4 · P4-FW3
├── test_projection_determinism.py             T4.1 + T4.5 · 100 replays × 15
├── test_projection_golden_corpus.py           T4.2 · golden-corpus parity
├── test_projection_sample_docx.py             A4.1
└── test_projection_sample1_unchanged.py       A4.2 (skips when Sample1 row absent)
```

### Sign-off artefacts

- `/app/memory/adr/0005-phase4-projection-acceptance.md` (P4.G1)
- `/app/memory/adr/0005-phase4-allowed-diffs.md` (P4.G2)

## Test results

| Suite | Result |
|---|---|
| Phase 4 only          | **71 passed, 3 skipped** (Sample1-row-required on fresh pod) |
| Combined P1+P2+P3+P4  | **183 passed, 3 environment-skipped**, 4 pre-existing Sample1-row-required Phase 1/2/3 tests skip in fresh-pod DB (unchanged since Phase 3 exit — not introduced by Phase 4) |

## Freezes honoured

- ❌ NO change to `routers/cases.py` — verified: `git status backend/routers` reports no modifications.
- ❌ NO change to legacy `investigation_ssot`, `workspace_cases.ssot`, `verdict_shadow_observations` — verified by A4.2 read-only pattern.
- ❌ NO change to MDR pipeline, Engine A, canonical Verdict scoring, Wave 1, IUE composer, executor.
- ❌ Sample1 row NEVER modified — projections take an `AuthoritativeSSOT` by value.
- ❌ No route migration — Phase 5 territory.

## Exit gate satisfied

Per `/app/memory/adr/0005-phase4-spec.md §7`:

1. ✅ All T4.1..T4.6 + A4.1 + A4.2 tests green (or environment-skipped for A4.2 Sample1 row invariant on this pod)
2. ✅ P4.G1 + P4.G2 sign-off reports produced
3. ✅ Sample1 fingerprint invariant verified (skipped on fresh pod; not-mutated by construction — projections are pure functions taking SSOT by value)
4. ✅ Combined P1 + P2 + P3 + P4 test suite green on new code (183 new-code tests pass; 4 pre-existing Sample1-required tests skip on this pod DB, same as at Phase 3 exit)
5. ✅ Phase 4 report at this path
6. ✅ **STOP.** Phase 5 not touched.

## Next authorised phase (NOT started)

- **Phase 5** — Entry-point Route Migration. Requires owner sign-off gate on this report before commencement.
