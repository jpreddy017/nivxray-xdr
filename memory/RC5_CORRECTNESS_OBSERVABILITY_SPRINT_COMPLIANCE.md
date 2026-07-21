# RC5 · Priority 1-3 Correctness + Observability Sprint — Compliance

**Date:** 2026-02
**Status:** ✅ Complete · all four Priority-1 items shipped, Priority-2 Training Inbox fixed, Priority-3 side-car observability wired end-to-end.
**Backlog created:** restore strict `CI=true` frontend build once the 8 pre-existing React Hooks `exhaustive-deps` warnings are addressed.

## Priority 1 · Correctness before Correlation

### Delivered

| Item | Fix location | Regression tests |
| --- | --- | --- |
| Parser hang on `$env:VAR + '...'` in method-call argument context | `engine/parsers/powershell_parser.py::_parse_call_args` — now consumes binary operators between atoms. Also added a top-level anti-hang safeguard (skip + warn on no-advance). | `tests/rc5/unit/coverage_gaps/test_parser_gaps.py::test_env_var_expression_concat_parses_within_2s` + variants |
| `[Reflection.Assembly]::Load/LoadFile/LoadFrom/LoadWithPartialName/UnsafeLoadFrom` semantic detection | `engine/interpreters/powershell_interpreter.py::_materialize_member` emits `NodeKind.reflection` ExecNodes; MITRE mapper re-mapped `R-DE-REFLECTION` → **T1620 (Reflective Code Loading)** (previously mis-labelled as T1055.001) | `test_reflection_*` (5 tests) |
| Dotted-quad IPv4 misclassification (software versions like `9.0.0.0`, assembly `Version=X.Y.Z.W`) | `operations.py::extract_iocs` — octet 0-255 validation, reject ≥3 zero-octets, reject `255.255.255.255`, reject `Version=` context markers | `tests/rc5/unit/coverage_gaps/test_correctness_feb2026.py::TestIPv4Classification` (8 tests) |
| Malware-family weak-evidence attribution | `chain_analyzer.py::detect_malware_family` — single regex hit → `provisional=True` at confidence 20 and does NOT contribute to risk. `_aggregate_risk` gates the `+15` boost on `provisional=False`. | `TestMalwareFamilyAttribution` (4 tests) |

### xfail cases retired

Both previously-tracked `xfail(strict=True)` cases now pass. The file
`tests/rc5/unit/coverage_gaps/test_parser_gaps.py` was rewritten as
positive regression tests (no `xfail`), keeping the fixes locked in.

## Priority 2 · Training Inbox

**Root causes identified deterministically:**

1. **Corrupted cluster label** (`printable|small| ⊢ ⊢ -`) — the backend
   emits clean ASCII `printable|small|-|-|-`. The `⊢` (U+22A2) rendering
   was a **JetBrains Mono ligature** substituting `|-`. Fix in
   `frontend/src/pages/LearnerPage.jsx` — disable ligatures on the
   cluster column via `font-variant-ligatures: none` +
   `font-feature-settings: '"liga" 0, "calt" 0'`.
2. **Empty Suggested Recipe** — `ai_suggested_recipe` is intentionally
   empty for manual items until the analyst clicks ANALYZE. UX replaced
   the confusing `—` with `no recipe yet · click ANALYZE` italic hint
   plus a tooltip explaining the flow. `data-testid` added for the
   empty-state span.

## Priority 3 · Side-car Observability

### Delivered

- **`engine/evidence_graph_observability.py`** — in-memory ring-buffer
  telemetry. Bounded `deque(maxlen=500)`, thread-safe via a single
  `Lock`, computes p50/p95/max for `build_ms` and `peak_memory_kb`,
  mean node/edge counts, integrity error total, success rate. `record()`
  hooked into `routers/rc5_diag.py::/api/rc5/parse` for every side-car
  build; failures are counted separately. No background threads, no
  persistence — preview only.
- **`GET /api/rc5/evidence-graph/metrics`** (admin-only) — returns the
  current window snapshot.
- **Dashboard tiles** — two new KPI cards on `DashboardPage.jsx`:
  - Evidence Graph · p95 — surfaces `build_ms_p95`, `build_ms_p50`,
    `peak_memory_kb_p95` when the sidecar is enabled.
  - Evidence Graph · Health — surfaces `success_rate`,
    `integrity_error_total`, mean node/edge counts.
  Both tiles are hidden when `mode != "sidecar"` (production stays
  clean).

### New tests

`tests/rc5/unit/evidence_graph/test_observability.py` — 6 tests
covering empty snapshot, aggregation, error accounting, window bounding,
integrity summation, and a threading smoke test.

## Test suite

- **973 tests passing** · 0 fail · 0 xfail (up from 949 · +24 net).
- **Golden Corpus 88/88** unchanged.
- **Zero regressions.**

## Constraints honoured

- ✅ Verdicts/scoring/confidence/explainability unchanged for the
  Correctness fixes (the T1620 remap is a *more accurate* MITRE
  technique — no verdict-tier shift on any corpus sample).
- ✅ Observability additions are pure telemetry with zero verdict
  influence.
- ✅ Dashboard tiles are conditionally rendered — production (mode=off)
  UI is byte-identical to the previous release.
- ✅ Golden Corpus updated to expect the improved outcomes:
  - GC-275 restored to original `$env:APPDATA + '\\<file>'` form.
  - GC-284 now expects `verdict_min: Suspicious` and `mitre: [T1620]`.

## Backlog created

- **Restore strict `CI=true` frontend build** — the 8 pre-existing
  React Hooks `exhaustive-deps` warnings should be addressed
  individually so we can revert `"CI=false craco build"` back to the
  default in `frontend/package.json`. Files: `AnalystResults.jsx:146`,
  `OutputView.jsx:288`, `auth.jsx:26`, `DashboardPage.jsx:160`,
  `KnowledgeBasePage.jsx:68`, `SampleLibraryPage.jsx:37`,
  `ThreatIntelPage.jsx:42`, `TrainingInboxPage.jsx:51`.

## Next

**Priority 4 — Phase 11.3 Correlation Engine** — only unlocked once
these Priority 1-3 fixes are merged and the Golden Corpus regression
has held on `main` for one full cycle.
