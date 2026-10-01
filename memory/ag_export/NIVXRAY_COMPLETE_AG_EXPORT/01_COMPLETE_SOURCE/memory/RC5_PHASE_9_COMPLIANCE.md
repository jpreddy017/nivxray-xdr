# RC5 · Phase 9 · Shadow Run + A/B Toggle + Delta Analyzer · Compliance Report

**Date:** 2026-02-21
**Phase:** 9 — Shadow-Run Delta Analyzer (12 dimensions) + Admin A/B Toggle
**Feature flag:** `SEMANTIC_ENGINE_V2` = `false` (Prod) · `true` (Preview)
**Shadow emit flag:** `RC5_SHADOW_EMIT` (env) or admin toggle at runtime

---

## 1 · Scope

Ship the infrastructure that lets Prod continue serving legacy RC4
verdicts while, in parallel, recording an RC5 snapshot per analysis and
producing daily + cumulative delta reports. Nothing user-visible changes
on Prod until Phase 10 cutover — which is now gated by the shadow-run's
own success-criteria endpoint.

---

## 2 · Approved Recommendations vs. Delivery

| # | Recommendation                                                              | Status | Notes |
|--:|-----------------------------------------------------------------------------|:------:| ----- |
| 1 | 30-day shadow run infrastructure                                            |   ✅   | `engine/shadow.py` + `routers/rc5_shadow.py`. MongoDB collection `rc5_shadow_runs`. Indexes on `sample_hash`, `day`, `ts` created at startup. |
| 2 | Admin A/B toggle                                                            |   ✅   | `POST /api/rc5/shadow/toggle {enabled:bool}` (admin JWT). Persists to `settings._id="rc5_shadow"` for restart durability. `GET /api/rc5/shadow/status` returns flag + emit state + snapshot count. |
| 3 | Delta Analyzer over 12 dimensions                                           |   ✅   | `compute_delta_report()` covers verdict, MITRE (added/removed/kept), LOLBIN (state-model vs flat), behaviors + tactic histogram, confidence per stage, reconstruction, latency (p50/p95/p99 + regression ratio), graph completeness, parser warnings/exceptions, FP change, FN change, unresolved nodes. |
| 4 | Daily + cumulative reports                                                  |   ✅   | `daily_report(day)` and `cumulative_report(since_days)`. Both exposed on the API and by CLI `scripts/rc5_delta_report.py`. |
| 5 | CLI `rc5_delta_report.py`                                                  |   ✅   | `python scripts/rc5_delta_report.py --daily` / `--cumulative --days 30` / `--both --json`. Live-verified with 1 snapshot; correct data reproduced. |
| 6 | Prod stays on `SEMANTIC_ENGINE_V2=false`                                   |   ✅   | Default `false` unchanged. Preview keeps `true` for diag endpoint. |
| 7 | Phase 10 cutover GATED until shadow succeeds                                |   ✅   | New endpoint `GET /api/rc5/shadow/gate` computes success criteria and returns `ready_for_cutover: bool`. Criteria: ≥200 snapshots · crash delta <0.5/1000 · FP change ≤5 · FN change ≤5 · dangling refs =0 · p95 latency regression ≤1.30. Any failure blocks the automated cutover script. |
| 8 | 10 tracked metrics per § 15                                                 |   ✅   | crash rate · FP · FN · graph integrity · schema validation · confidence calibration (via median stages) · perf p50/p95/p99 · memory (deferred, see § 6) · latency · execution-graph correctness (sample). All except memory covered in the report; memory tracking is a follow-up. |
| 9 | Deterministic reports (byte-equal on repeat)                                |   ✅   | Sorted MITRE sets, `Counter.most_common()` stable ordering, `sorted()` on tactic aggregation. Fully deterministic once snapshots are frozen. |
| 10 | No AI import in shadow module                                              |   ✅   | `test_shadow_module_no_ai_imports` passes (docstring-stripped scan). |
| 11 | No regex on raw text                                                       |   ✅   | `test_shadow_module_no_regex_on_raw_text` passes. |
| 12 | Admin gating on every endpoint                                             |   ✅   | Every route uses `Depends(require_admin)`. |
| 13 | 30+ tests                                                                  |   ✅   | 40 unit tests in `tests/rc5/unit/shadow/test_shadow.py`. Full RC5 suite = **658 pass / 0 fail**. |
| 14 | Snapshot builder tolerates missing / partial input                         |   ✅   | `make_snapshot()` with all-optional RC4/RC5 params; tested via `test_make_snapshot_no_rc5_response_yields_empty_lists`. |
| 15 | Cutover gate self-audits ready state                                       |   ✅   | `test_cutover_gate` — 4/6 checks pass on preview with 1 snapshot; correctly blocks (min_snapshots and latency_regression fail as expected). |

---

## 3 · Files Added / Modified

**Added:**
- `backend/engine/shadow.py` — data model, snapshot builder, delta analyzer, Mongo helpers, daily/cumulative reports.
- `backend/routers/rc5_shadow.py` — 5 admin endpoints (status, toggle, record, report daily, report cumulative) + cutover gate.
- `scripts/rc5_delta_report.py` — CLI daily/cumulative reporter for cron / CI.
- `backend/tests/rc5/unit/shadow/test_shadow.py` — 40 tests.

**Modified:**
- `backend/server.py` — imports `rc5_shadow_router`, mounts it on `/api`, and calls `ensure_shadow_indexes(db)` at startup.

---

## 4 · Live Verification (2026-02-21 · Preview)

```
GET  /api/rc5/shadow/status          → flag=false, emit=false, snapshots=0
POST /api/rc5/shadow/toggle {on}     → emit=true, toggled_by=admin@nivxray.com
POST /api/rc5/shadow/record          → recorded=true, sample_hash=72d9af450d7fae24
GET  /api/rc5/shadow/report/daily    → 1 snapshot; verdict Suspicious→Malicious; 5-stage confidence 100/100/100/92/95/97
GET  /api/rc5/shadow/gate            → ready_for_cutover=false (min_snapshots, latency_regression fail — expected with 1 sample)
```

**Deployment:** Production successful at https://nivxray.nivxforge.com. Prod runs with `SEMANTIC_ENGINE_V2=false` by design — no user-visible change. Shadow-emit collection is not active on Prod; will be enabled once corpus collection begins on Preview (30-day timer starts today).

---

## 5 · Deviations from Recommendation

**Memory-usage metric (spec §15 item 8) deferred.** Reason: reliable per-analysis peak-RSS measurement requires a `resource.getrusage` snapshot around each pipeline call, which is a non-trivial integration into the existing `/api/analyze` path (not the RC5 diag path). Target phase: **Phase 9.5** or the "shadow-collector wrapper" work below. All other 9 metrics are covered.

**Automatic RC4↔RC5 dual-execution wrapper deferred.** The shadow snapshot API is *passive* — callers must `POST /api/rc5/shadow/record` with both sides. Wiring the existing `POST /api/analyze` route to auto-invoke the RC5 pipeline and post the delta is a small follow-up (~1 hour). Target phase: **Phase 9.5**. Until then, snapshots can be recorded via the batch corpus runner or manually from the Analyst UI when it lands.

## 6 · Known Follow-ups (deferred, tracked)

1. **Auto-collector wrapper** — Phase 9.5. Wire into `/api/analyze` so every user analysis produces a shadow snapshot when `emit_enabled=true`.
2. **Memory-usage metric** — Phase 9.5, using `resource.getrusage` deltas.
3. **Analyst UI (P1)** — SOC Prime-inspired dashboard: everything the UI needs is now on `/api/rc5/parse` + `/api/rc5/shadow/*`. Charts include verdict matrix, MITRE add/remove heatmap, LOLBIN state distribution, per-stage confidence, latency percentile lines, shadow-gate readiness widget.
4. **Cutover script (Phase 10)** — reads `/api/rc5/shadow/gate`; only proceeds when `ready_for_cutover: true`. Deletes `_KEYWORD_MITRE_MAP`, `_KEYWORD_LOLBAS_HITS`, `_regex_verdict_score()` and tags `rc5-legacy-safety-net`.

---

## 7 · Phase 9 Exit Criteria — Met

- [x] Shadow-run collection infrastructure landed
- [x] Admin A/B toggle (persisted)
- [x] Delta Analyzer with 12 dimensions
- [x] Daily + cumulative reports (API + CLI)
- [x] Cutover gate blocking Phase 10 until success criteria met
- [x] Deterministic reports, no AI imports, no regex on raw text
- [x] Admin-JWT gating on every endpoint
- [x] 30+ regression tests (delivered 40); full RC5 suite 658/0
- [x] Production deployment successful; `SEMANTIC_ENGINE_V2=false` preserved on Prod

**Phase 9 complete. 30-day shadow-run clock is now armed. Phase 10 held until gate returns `ready_for_cutover: true`.**
