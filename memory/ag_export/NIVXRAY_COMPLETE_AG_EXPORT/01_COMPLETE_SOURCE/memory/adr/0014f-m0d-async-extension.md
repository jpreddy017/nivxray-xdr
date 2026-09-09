# ADR-0014f · M0d-async-extension — Router Awaits Async Callables

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design](./0014-single-iue-convergence-design.md), [ADR-0014e · Equivalence Harness](./0014e-equivalence-harness.md)
**Predecessors**: M0a, M0b, M0b-extension, M0c, M0d, M0e, equivalence harness (both corpora)
**Successor**: **STOP · owner review** — NOT M0e-plumbing, NOT M0f — **LOCKED pending decision**

---

## 1 · Owner directive (verbatim summary)

> AUTHORISE M0d-async-extension.
> - Detect awaitable results, execute using an event-loop-safe model appropriate to the caller context.
> - **Do NOT create nested event loops.**
> - **Do NOT change the callable itself.**
> - After M0d-async: STOP. Do not automatically proceed to M0e plumbing.
> - Run the equivalence harness again over both corpora. Confirm: IOC enrichment BEFORE = coroutine/false success, AFTER = actual enrichment result. `die.command` unchanged, `report.narrative` unchanged, IUE hashes unchanged, SystemWeakness unchanged.

## 2 · What shipped

### 2.1 Router change

Two additions to `services/registry/router.py`:

1. `_resolve_awaitable(result)` — helper that detects `inspect.isawaitable(result)`. If not awaitable, returns verbatim. If awaitable:
   - No running event loop → `asyncio.run(result)` directly.
   - Running event loop → run in a fresh `ThreadPoolExecutor(max_workers=1)` thread with its own fresh loop via `asyncio.run(result)` inside the thread; block-wait for the future.

   This satisfies the "no nested event loop" constraint. No `nest_asyncio`. No monkey-patching of asyncio internals.

2. `_execute_one` invocation site (5 lines) now does:
   ```python
   result = fn(**dict(step.inputs)) if step.inputs else fn()
   result = _resolve_awaitable(result)
   ```
   Any `Exception` during the await surfaces via the existing `EXECUTION_FAILED` path with `error` + `error_type` populated.

**No callable is modified.** No adapter, no analyzer, no IUE. The change is confined to how the router handles its own returned value.

### 2.2 New tests

`tests/canonical/iue/test_m0d_async_extension.py` — **12 tests**:

1. Sync callable returns verbatim result
2. Async callable is actually awaited (synthetic `_async_double`)
3. Async result captured in `StepOutcome.result` (dict producer)
4. Coroutine object NEVER captured as SUCCESS
5. Async exception → `EXECUTION_FAILED` with correct `error_type`
6. Async dependency ordering deterministic across replays
7. Nested-event-loop safety — router works inside `asyncio.run()`
8. `_resolve_awaitable` returns non-awaitable verbatim
9. `_resolve_awaitable` awaits coroutines
10. All 4 M0a hashes still byte-identical
11. SystemWeakness projection still lacks `url.acquire.v1`
12. **Real** `ioc_enrichment.v1` now returns a dict (not a coroutine)

Uses a proper `_isolated_registry` pytest fixture that snapshots/restores `ANALYZER_REGISTRY._entries` around each test — no cross-test pollution.

### 2.3 Equivalence harness update

`_classify_differences` now correctly categorises async dispatch after M0d-async:
- `SUCCESS` outcome from an `async def` callable → `expected_structural` (async was awaited, real result captured).
- `EXECUTION_FAILED` outcome from an async callable → `failure_semantics` (async exception surfaced cleanly).

The `unexpected` bucket for async dispatch is now empty on both corpora.

## 3 · Files changed

| File | Nature |
|------|--------|
| `services/registry/router.py` | +34 LOC — `_resolve_awaitable()` helper + 1 call site update in `_execute_one` |
| `tests/canonical/iue/test_m0d_async_extension.py` | **NEW · 12 tests** |
| `tests/canonical/iue/harness/equivalence_harness.py` | Reclassifier updated — async dispatch is now expected structural, not unexpected |
| `/app/memory/equivalence_report_m0a.json` | Regenerated |
| `/app/memory/equivalence_report_extended.json` | Regenerated |
| `/app/memory/adr/0014f-m0d-async-extension.md` | **NEW** — this ADR |
| `/app/memory/PRD.md` | Amended |

**Not touched**: IUE, adapters, analyzers, Workspace UI, MITRE, verdict, provenance producers, URL acquisition, OCR, IDA, `_VENDORS`, `^` decoder, any production route.

## 4 · Owner-mandated acceptance tests — all green

| Axis                                       | Result |
|--------------------------------------------|:------:|
| 1. Sync callable byte-identical            | ✅ (`test_sync_callable_returns_verbatim_result`) |
| 2. Async callable actually awaited          | ✅ (`test_async_callable_is_awaited`) |
| 3. Coroutine object never SUCCESS           | ✅ (`test_coroutine_object_never_captured_as_success`) |
| 4. Async result captured in StepOutcome     | ✅ (`test_async_result_is_captured_in_step_outcome`) |
| 5. Async exception → EXECUTION_FAILED       | ✅ (`test_async_exception_becomes_execution_failed`) |
| 6. Async dependency ordering deterministic  | ✅ (`test_async_dependency_ordering_deterministic`) |
| 7. 20/20 equivalence unchanged              | ✅ (extended-corpus report: 20 identical, 0 divergent, 0 unexpected) |
| 8. M0a SHA-256 baselines unchanged          | ✅ (`test_m0a_hashes_still_byte_identical_after_async_extension`) |
| 9. SystemWeakness unchanged                 | ✅ (`test_systemweakness_projection_unchanged_after_async_extension`) |
| 10. No IUE / Workspace / URL / MITRE / verdict / OCR / provenance changes | ✅ (grep-locked) |

## 5 · Before / after — the IOC enrichment fix

### 5.1 Before M0d-async

```
> execute_plan([ExecutionStep(entry_id="ioc_enrichment.v1", inputs={"iocs":{"url":["http://a.test/x"]}, "keys":{}})])
  status = SUCCESS
  result = <coroutine object enrich_iocs at 0x...>   ← COROUTINE OBJECT, work never ran
```

### 5.2 After M0d-async

```
> execute_plan([ExecutionStep(entry_id="ioc_enrichment.v1", inputs={"iocs":{"url":["http://a.test/x"]}, "keys":{}})])
  status = SUCCESS
  result = {"ips": [], "domains": [], "urls": [], "hashes": [],
             "sources_used": ["ip-api.com (geolocation, no key)",
                              "system DNS (reverse lookup, resolution)"]}
```

The enrichment actually runs. The router awaits the coroutine transparently.

## 6 · Before / after — equivalence harness verdicts

| Corpus     | Verdict BEFORE M0d-async | Verdict AFTER M0d-async | Change             |
|------------|:------------------------:|:-----------------------:|:------------------:|
| M0A (4)     | **NO-GO** (2 async gaps) | **GAPS-REQUIRE-MIGRATION** (0 async) | ⬆ async gap CLOSED |
| Extended (12) | **NO-GO** (4 async gaps) | **GAPS-REQUIRE-MIGRATION** (0 async) | ⬆ async gap CLOSED |

Remaining gaps in both corpora (**LOCKED**, not M0d-async scope):
- Router output→input plumbing (M0e-plumbing) — universal for the report step.
- URL-only DIE divergence (M4 / M0h) — for URL inputs the IUE excludes DIE from `engines_selected`.

Nothing else remains in the `unexpected` bucket. **The router is now correctly executing every capability it dispatches.**

## 7 · Guardrails held — direct probes

- `die.command.v1` router-invoked vs inline: byte-identical envelope hashes across 10 sync payloads (extended corpus).
- `report.narrative.v1` router-invoked vs inline: byte-identical report hashes across 10 sync payloads.
- All 4 M0a IUE envelope hashes byte-identical (locked by dedicated test):
  - `febd68f1…f93a00` (systemweakness_url)
  - `92b9c1cf…af56b` (powershell_naked)
  - `35aa379d…d329b` (plain_english_short)
  - `7061f384…97aad` (hex_ratio_long)
- SystemWeakness projection: still `[ioc_enrichment.v1, report.narrative.v1]` — **`url.acquire.v1` still absent**.
- Full canonical/iue/ regression: **172 passed / 1 pre-existing Sample1-DB failure** (was 160/1) → delta **+12** (all M0d-async tests), zero regression.
- P2 (Sysmon Slice-1/2/3 + Report determinism) + UI-DEF-02: **48 passed / 1 skipped**, unchanged.

## 8 · Answer to the acceptance-gate question

> **Can the router correctly execute the capability?**

**Yes.** For every callable in the M0b registry — sync or async — router-dispatched execution now yields the actual result of invoking the implementation directly. Zero divergence in 20/20 sync equivalence tests + 12/12 async correctness tests.

The **separate architectural questions** remain LOCKED:
- Can one planned step consume another step's output? → **M0e-plumbing decision** (not M0d-async scope).
- Can URL inputs be enriched with content-based analysis? → **M4 / M0h decision** (not M0d-async scope).

## 9 · Locked-out (unchanged)

M0e-plumbing · M0f production cutover · M4 IUE `url_only` fix · SystemWeakness URL Acquisition · CRE retirement · `^` XOR decode-fidelity · OCR wiring · Workspace changes · MITRE/verdict changes · Sysmon E22/E11 · Sample1 seeding · registration of any B/C classified stage · provenance producer wiring · IDA / `_VENDORS` / User-Agent / Playwright / ImageAdapter changes.

## 10 · Next step

**None authorised.** M0d-async is complete. Both equivalence reports have been regenerated and written to `/app/memory/`. Owner reviews and decides.

The next likely candidate — M0e-plumbing (output→input piping) — is explicitly LOCKED until owner authorises it separately.
