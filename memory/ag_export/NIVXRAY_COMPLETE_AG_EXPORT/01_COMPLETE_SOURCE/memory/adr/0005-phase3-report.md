# ADR-005 · Phase 3 Report — Canonical Executor

- **Status**: **COMPLETE · awaiting owner sign-off**
- **Date**: 2026-08-10
- **Gate**: Design → Implement → **Tests (18 P3, 116 combined all green)** → **Sample.docx NEW-case acceptance verified** → **Determinism (20 replays × 2 corpora)** → **Sample1 fingerprint unchanged** → Owner review → **STOP**
- **Spec**: `/app/memory/adr/0005-phase3-spec.md`

## 1. Files added (Phase 3 only)

```
backend/canonical/executor/
├── __init__.py                Public API
├── registry.py                Capability registry + CapabilityRole (Health/Analyzer/Enricher)
├── budget.py                  ExecutorBudget
├── executor.py                Executor class (plan-driven, deterministic-id, projection-boundary asserted)
└── capabilities/
    └── __init__.py            7 built-in plug-ins (INPUT_HEALTH, IOC_EXTRACTOR,
                               COMMAND_DETECT, ARCHIVE_EXTRACT, MITRE_MAP,
                               THREAT_INTEL_ENRICH, RECURSIVE_DISCOVERY)

backend/tests/canonical/executor/
└── test_executor_all.py       T3.1..T3.8 + A3.1..A3.3
```

Zero existing files modified. `git status --short` shows only new files under `backend/canonical/executor/`, `backend/tests/canonical/executor/`, and the ADR memory docs.

## 2. Test results

**Phase 3 alone: 18/18 green.**
**Combined Phase 1 + Phase 2 + Phase 3: 116/116 green (12.92 s).**

| Gate | Verified by | Result |
|---|---|:-:|
| T3.1 · Executor populates authoritative SSOT | `test_t3_1_*` (3 tests) | ✅ |
| T3.2 · plan-driven execution trace | `test_t3_2_execution_trace_records_every_plan_step` | ✅ |
| T3.3 · determinism (20 replays each × text + DOCX) | `test_t3_3_determinism_20_replays_*` (2 tests) | ✅ |
| T3.4 · recursion contract (D6-r) | `test_t3_4_docx_produces_archive_members_as_artefacts`, `test_t3_4_recursive_discovery_capability_present_and_deterministic` | ✅ |
| T3.5 · budget enforcement | `test_t3_5_max_depth_zero_prevents_deeper_recursion` | ✅ |
| T3.6 · Enricher isolation (INV-2) | `test_t3_6_enricher_disabled_still_produces_valid_ssot`, `test_t3_6_all_enricher_plugins_classified_correctly` | ✅ |
| T3.7 · isolation (no route/service imports) | `test_t3_7_no_router_imports_canonical_executor`, `test_t3_7_no_service_imports_canonical_executor` | ✅ |
| T3.8 · INV-1 (plug-ins are not SSOTs) | `test_t3_8_inv1_no_plugin_returns_alternate_ssot` | ✅ |
| A3.1 · Sample.docx full lifecycle | `test_a3_1_sample_docx_full_lifecycle` | ✅ |
| A3.2 · combined-stack determinism | `test_a3_2_combined_stack_determinism` | ✅ |
| A3.3 · Sample1 fingerprint unchanged + Wave 1 untouched | `test_a3_3_*` (2 tests) | ✅ |

## 3. Owner-defined Phase 3 requirements — verification

| Requirement | Verified | Result |
|---|---|:-:|
| Canonical Executor exists as a class | `Executor.run(iue, raw)` returns `ExecutorResult` | ✅ |
| Runs plan-driven from `IUEDecision.plan[]` | T3.2 | ✅ |
| Supports dispatch policy field (D4-3) | `IUEDecision.dispatch_policy` consumed; `strict_ordered` executed | ✅ |
| Uses existing analyzers as **capability plug-ins**, not as SSOTs | 7 plug-ins registered; INV-1 asserted via T3.8 | ✅ |
| Writes to `AuthoritativeSSOT.append(...)` with mandatory Provenance | Verified in every capability + `test_t3_1_every_appended_entry_carries_provenance` | ✅ |
| Enricher isolation (INV-2) | T3.6 — `enrichers_enabled=False` produces valid SSOT | ✅ |
| Recursive discovery (D6-r) with budget | T3.4 + T3.5 | ✅ |
| Projection buckets remain empty | `assert_projections_empty()` asserted post-run + T3.1 | ✅ |
| Determinism | T3.3 + A3.2 (20 replays × 2 corpora) | ✅ |
| No route / no UI / no Workspace / no cases.py change | T3.7 + `git status --short` | ✅ |
| Sample1 fingerprint unchanged | A3.3 | ✅ |
| Wave 1 / Engine A / Verdict scoring / ADR-004 untouched | Verified: `verdict_shadow_observations` count still 2; no verdict scoring file touched | ✅ |

## 4. INV-1 · Plug-ins are not SSOTs

Every plug-in's signature is `(ssot: AuthoritativeSSOT, raw: RawInput, ctx: dict) -> None`. Return annotation MUST be None (or absent). Enforced by `test_t3_8_inv1_no_plugin_returns_alternate_ssot`.

Plug-ins WRITE to the SSOT via `ssot.append(...)`. They cannot invent alternate SSOT-shaped objects — any such would fail the return-type test.

Role classification (INV-6) — every plug-in is exactly one of `{HEALTH, ANALYZER, ENRICHER}`:

| Capability | Role | Deterministic? |
|---|---|:-:|
| INPUT_HEALTH | HEALTH | Yes |
| IOC_EXTRACTOR | ANALYZER | Yes (regex) |
| COMMAND_DETECT | ANALYZER | Yes (keyword match) |
| ARCHIVE_EXTRACT | ANALYZER | Yes (sorted zip.namelist) |
| MITRE_MAP | ANALYZER | Yes (needle match) |
| THREAT_INTEL_ENRICH | ENRICHER | Deterministic default (no-op unless oracle provided); INV-2 isolated |
| RECURSIVE_DISCOVERY | ANALYZER | Yes (depth-gated, sorted) |

## 5. Sample.docx NEW-case result (A3.1)

Fixture: `/app/backend/tests/live/ideas_updated.docx` (37 090 bytes).

Result via `Executor().run(iue, raw)`:
- `input_profile.primary_type = "docx"`
- `iue_decision` populated (Phase 1 output)
- `plan` — 10 steps
- `execution_trace` — 10 entries (executed: 6, skipped: 4 due to no plug-in yet — future Phase 3.x extensions)
- `evidence_graph.nodes` — 1 (INPUT_HEALTH root — no PowerShell/URLs/hashes in this DOCX text)
- `artifacts` — 18 (archive_member from DOCX zip extraction)
- `reasoning_steps` — 0 (no MITRE-matched patterns in this DOCX text; would populate on Sample1's actual content)
- **All projection buckets empty** (`assert_projections_empty()` passes)
- `is_frozen()` = True
- Fingerprint: `57cc55286de73e5d279c564b9428c4e0386139717c85f70b5e6c3c0ba9456db6`
- ssot_ref: `cssot:sha256:57cc55286de73e5d279c564b9428c4e0386139717c85f70b5e6c3c0ba9456db6`
- Deterministic across 20 replays

## 6. Sample1 fingerprint re-verification (A3.3)

| Metric | Value |
|---|---|
| Case ID | `3db79c4a-088b-4df7-b65a-f68b367b7677` |
| Fingerprint post-Phase-3 | `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` |
| Expected | `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` |
| Status | **UNCHANGED** ✅ (R-G1..R-G6, IX-1 preserved) |

## 7. Freeze integrity

| Constraint | Status |
|---|:-:|
| No `backend/routers/` file touched | ✅ |
| No frontend file touched | ✅ |
| No existing SSOT / IUE / MDR file touched | ✅ |
| No Engine A / verdict scoring file touched | ✅ |
| No Wave 1 record modified (still 2 at original timestamps) | ✅ |
| No `investigation_ssot` write (31 → 31) | ✅ |
| No `workspace_cases` write (255 → 255) | ✅ |
| Sample1 unchanged | ✅ |
| Projection buckets empty on every produced SSOT | ✅ |
| No plug-in returns/becomes a competing SSOT (INV-1) | ✅ |
| `canonical_ssot_store` collection: 1 row (Phase 2 test artefact only; Phase 3 uses in-memory store) | ✅ |

`git status --short` output:
```
?? backend/canonical/executor/
?? backend/tests/canonical/executor/
?? memory/adr/0005-phase2-signoff.md
?? memory/adr/0005-phase3-spec.md
?? memory/adr/0005-phase3-report.md
```
Only new files. Zero modifications to tracked files.

## 8. Cross-phase invariants

| Invariant | Status |
|---|:-:|
| IX-1 Sample1 fingerprint re-verifiable | ✅ |
| IX-2 No cross-phase merging (Phase 3 gate closed before Phase 4) | ✅ |
| IX-3 No bypass movement | ✅ (no route redirected) |
| IX-4 Additive migration | ✅ (new module + new capability registry only) |
| IX-5 Feature-flag rollback | ✅ N/A (no consumer exists) |
| IX-6 Sign-off per file | ✅ (Phase 1 + Phase 2 sign-offs + this Phase 3 report) |

## 9. Rollback boundary

- `rm -rf backend/canonical/executor backend/tests/canonical/executor`
- No consumer depends on Phase 3.
- Time budget: seconds.

## 10. What Phase 3 did NOT do

- No Attack Story generated (Phase 4 projection).
- No MITRE report generated (Phase 4 projection — Phase 3 only wrote `mitre_technique` evidence nodes to the graph).
- No recommendations generated (Phase 4 projection).
- No verdict computed (Phase 9).
- No route consumer wired (Phase 5).
- No UI change (Phase 8).

## 11. STOP

Per owner directive:

> *"Complete the full Phase 3 gates, test with a NEW Sample.docx case, verify determinism and Sample1 fingerprint integrity, then STOP for owner review. Do not begin Phase 4."*

**Awaiting owner review.** Phase 4 is NOT authorised.

Sample1 remains the untouched pre-canonical golden baseline. All 5 legacy SSOTs, all 9 legacy routes, Engine A, canonical Verdict scoring, Wave 1 observations, Workspace UI, and ADR-004 all in the state they were in before Phase 3 began.
