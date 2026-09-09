# ADR-0014e · Equivalence Harness — Legacy vs Router-Dispatched

**Status**: 🟢 CLOSED — harness delivered, report produced, owner-review-ready (2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design (D0)](./0014-single-iue-convergence-design.md)
**Predecessors**: M0a, M0b, M0c, M0d, M0e, M0b-extension
**Successor**: **Owner decision** on the report — NOT M0f — **LOCKED pending review**
**Overall verdict**: **NO-GO** — cutover requires closing 2 unexpected gaps + 1 architectural divergence first

---

## 1 · Purpose

Compare legacy (`analyze() → generate_report()`) against router-dispatched (`plan_to_execution_steps() → execute_plan()`) execution over the frozen 4-input M0a corpus. **Diagnostic only** — not a cutover mechanism. Differences are reported, never normalised away.

## 2 · What shipped

| File | Nature |
|------|--------|
| `tests/canonical/iue/harness/__init__.py` | Package marker |
| `tests/canonical/iue/harness/equivalence_harness.py` | **NEW · +230 LOC** — `run_legacy()`, `run_router()`, `_classify_differences()`, `run_equivalence_harness()` |
| `tests/canonical/iue/test_m0f_equivalence_harness.py` | **NEW · +80 LOC · 5 tests** |
| `/app/memory/equivalence_report_m0a.json` | **Owner-review artefact** — full structured report |
| `/app/memory/adr/0014e-equivalence-harness.md` | This ADR |
| `/app/memory/PRD.md` | Amended |

**Not touched**: no adapter, no analyzer, no router, no projection, no IUE, no Workspace, no MITRE, no verdict, no provenance producer, no production route.

## 3 · Corpus and comparison axes

The 4 frozen M0a inputs (no modification, no normalisation):
- `bare_url_medium_style` — `https://systemweakness.com/some-report`
- `powershell_naked` — `powershell.exe -EncodedCommand SGVsbG8=`
- `plain_english_short` — `the quick brown fox jumps over the lazy dog`
- `hex_ratio_long` — `4d5a` + `90` × 260

Per input the harness computes 8 comparison axes: envelope hash, envelope keys, report section titles, report hash, per-step result hash, execution order, unmapped-engines list, plumbing gaps.

Differences are classified into 8 buckets: `identical`, `expected_additive`, `expected_structural`, `unexpected`, `missing_capability`, `duplicate_execution`, `ordering`, `failure_semantics`.

## 4 · Per-input results (from `equivalence_report_m0a.json`)

### 4.1 `powershell_naked` — **NO-GO**

| Router step               | Status  | Router `result_hash` | Legacy hash    | Match? |
|---------------------------|---------|----------------------|----------------|:------:|
| `die.command.v1`          | success | `6cd5794c94b5dda9…`  | `6cd5794c94b5dda9…` | ✅ **BYTE-IDENTICAL** |
| `report.narrative.v1`     | success | `457c0280eb6ada8f…`  | `457c0280eb6ada8f…` | ✅ **BYTE-IDENTICAL** |
| `ioc_enrichment.v1`       | success | *(coroutine object)* | *(async, not directly comparable)* | ❌ Async gap |

**Unexpected findings**: 1 × async-dispatch (ioc_enrichment).
**Missing capability**: 3 × router-plumbing gaps (harness plumbed each step's inputs manually).

### 4.2 `plain_english_short` — **GAPS-REQUIRE-MIGRATION**

| Router step           | Router hash          | Legacy hash          | Match? |
|-----------------------|----------------------|----------------------|:------:|
| `die.command.v1`      | `f06a2a309b1f9e95…`  | `f06a2a309b1f9e95…`  | ✅ **BYTE-IDENTICAL** |
| `report.narrative.v1` | `255a068742a8bb08…`  | `255a068742a8bb08…`  | ✅ **BYTE-IDENTICAL** |

No `unexpected` findings — but 2 plumbing gaps remain.

### 4.3 `hex_ratio_long` — **GAPS-REQUIRE-MIGRATION**

| Router step           | Router hash          | Legacy hash          | Match? |
|-----------------------|----------------------|----------------------|:------:|
| `die.recursive.v1`    | `4f53cda18c2baa0c…`  | *(bundled in analyze)* | — |
| `die.command.v1`      | `f06a2a309b1f9e95…`  | `f06a2a309b1f9e95…`  | ✅ **BYTE-IDENTICAL** |
| `report.narrative.v1` | `2d7e45aa95abf41d…`  | `2d7e45aa95abf41d…`  | ✅ **BYTE-IDENTICAL** |

No `unexpected` findings — 3 plumbing gaps.

### 4.4 `bare_url_medium_style` (SystemWeakness) — **NO-GO**

| Legacy path                  | Router path                                     |
|------------------------------|-------------------------------------------------|
| `analyze(url_str)` → envelope | *(no `die.command.v1` in projection at all)*  |
| `generate_report(env)` → report | `report.narrative.v1` failed with `env={}` (execution_failed) |

**Missing capability**: DIE envelope entirely absent from the router path. Legacy `/api/die/analyze` calls `analyze()` **unconditionally** regardless of IUE's `engines_selected`. Router path follows IUE strictly. For `url_only`, the IUE selected `[IOC Enrichment, Report Generator]` — no DIE — so `report.narrative.v1` received an empty env and crashed.

## 5 · Two blocking discoveries (owner decision required)

### 5.1 Async dispatch — M0d router-layer limitation ⚠️

`ioc_enrichment.v1` → `analysis_core:enrich_iocs` is an `async def` coroutine. The M0d router invokes callables synchronously (`fn(**inputs)`) and captures the returned coroutine object as `result`. The coroutine is never awaited — the enrichment work never runs. `StepStatus` is (misleadingly) `SUCCESS`.

**Verified by direct probe**:
```python
> import inspect
> from analysis_core import enrich_iocs
> inspect.iscoroutinefunction(enrich_iocs)   # → True
```

**Impact**: any registered analyzer that is `async def` would silently no-op through the router. Today, `ioc_enrichment.v1` is affected. Any future async-io analyzer would be too.

**This is a M0d-blocking gap**. Fixing it requires either:
- (a) extending the router to detect coroutines and `asyncio.run(fn(**inputs))` them, OR
- (b) forcing all router-dispatched callables to be sync (rewriting `enrich_iocs` sync — REJECTED, breaks the existing production async chain).

**Recommendation**: option (a), as a separately authorised M0d-async-extension migration BEFORE M0f.

### 5.2 URL-only investigation divergence ⚠️

Legacy production `/api/die/analyze` calls `analyze()` unconditionally. The IUE's `engines_selected` is currently **advisory** — the Workspace UI reads it for display, but the analyze pipeline ignores it.

The router path treats `engines_selected` as **authoritative**. For `url_only`, the IUE returns `engines_selected = ['IOC Enrichment', 'Report Generator']` — no `DIE (Semantic AST)`. Router path therefore never runs `analyze()` on URLs. Legacy path does.

**Impact**: cutting over URL-only investigations to the router would **eliminate all DIE analysis** (AST, chain, DKP, Attack Intent, technique extraction) for URLs. Legacy path currently runs those (albeit on the raw URL string, which yields limited-but-non-empty results). This is a real behavioural regression waiting to happen.

**Two migration options** (BOTH require explicit owner authorisation, NOT part of this harness):

- **Option-A**: Update the IUE's `url_only` `engines_selected` to include `DIE (Semantic AST)` and `Report Generator`. Preserves parity with legacy. Would change M0a-locked `engines_selected` for `url_only` → M0a baseline hash breaks. This is precisely the IUE-side migration the ADR-0014 M4 debt captured.
- **Option-B**: The router path additionally runs `die.command.v1` for URLs even when not in `engines_selected`. This makes `engines_selected` no more authoritative than it is today — undermines the whole M0e projection semantics. **Do not recommend.**
- **Option-C**: Register `url.acquire.v1` in the projection for `url_only` (fetch content first, then DIE-analyse the fetched content). This is the ORIGINAL ADR-0014 M4 design intent. Still requires IUE-side migration. Same class as Option-A.

**All three options are LOCKED under the current authorisation matrix.** M0e cannot be extended, M4 is not yet authorised, and the harness is not permitted to fix divergences.

### 5.3 Router plumbing gap (structural, not blocking)

The M0d router lacks an output→input piping primitive. `report.narrative.v1` depends on `die.command.v1`'s envelope as its `env` kwarg, but the router today only knows how to (a) resolve entry_id, (b) invoke fn(**inputs), (c) declare a dependency exists. There is no way to say "step B's `env` kwarg = step A's return value".

**Harness worked around it**: the harness populates each step's `inputs` manually between invocations. Documented as `plumbing_gap` in every affected outcome.

**Recommendation**: introduce an output-to-input binding contract as part of the future M0f migration (`ExecutionStep.input_bindings: Dict[str, StepRef]`), OR keep the plumbing inside the caller and accept that the M0d router is intentionally minimal. Owner decision.

## 6 · Positive findings (strong equivalence signal)

**Router-dispatched invocation of `die.command.v1`, `die.recursive.v1`, and `report.narrative.v1` is BYTE-IDENTICAL to inline invocation** across every case where they were exercised (3 of 4 corpus inputs). The M0d dispatcher does not perturb the callable — it invokes it faithfully.

The registry/router indirection does NOT change:
- DIE envelope semantics (hashes match to the last bit).
- Report content (12 section titles + all data — byte-identical).
- Recursive decoder output (deterministic across router/inline).

This is a strong signal that the core M0d/M0e/M0b-extension architecture is sound. The blocking gaps (5.1, 5.2, 5.3) are separate router-layer/IUE-layer issues, not equivalence problems for the deterministic capabilities themselves.

## 7 · Guardrails held

- All 4 M0a IUE envelope hashes byte-identical (locked by `test_m0a_iue_envelope_hashes_unchanged_by_harness`).
- SystemWeakness projection still contains **no `url.acquire.v1`** (locked by `test_systemweakness_projection_still_lacks_url_acquire_v1`).
- Legacy path itself is deterministic across replays (precondition; locked).
- Harness performs no production writes (grep-locked in `test_harness_never_modifies_production_files`).
- No adapter/analyzer/router/IUE/Workspace/MITRE/verdict code modified.
- Full canonical/iue/ regression: **159 passed / 1 pre-existing Sample1-DB failure**, delta +5 over the M0b-extension baseline.

## 8 · Acceptance-gate answer (owner-facing)

> **Can router-dispatched execution reproduce the legacy investigation without losing, duplicating, or materially altering existing behaviour?**

**Not today. Three gaps must close first:**

1. **Async dispatch (5.1)** — router silently drops all work for async analyzers. Blocking.
2. **URL-only DIE divergence (5.2)** — router path loses DIE analysis for URLs because IUE's advisory `engines_selected` becomes authoritative. Blocking for the SystemWeakness class of investigations.
3. **Output→input plumbing (5.3)** — router has no primitive for wiring producer outputs to consumer inputs. Non-blocking (callers can plumb) but incomplete for a true convergence.

**Byte-equivalence for the deterministic sync capabilities is proven** (`die.command.v1`, `die.recursive.v1`, `report.narrative.v1`).

## 9 · Smallest safe next step (recommendation, requires authorisation)

**Not M0f.** Three separate small migrations, each independently authorisable:

- **M0d-async-extension**: teach the router to detect coroutine callables and `asyncio.run()` them, with a new `StepStatus.ASYNC_UNSUPPORTED` fallback if execution context can't run an event loop.
- **M0e-plumbing**: add `ExecutionStep.input_bindings: Dict[str, StepRef]` and a router-side wiring layer.
- **M4 (IUE url_only fix)**: authorised separately per the ADR-0014 M4 debt.

After all three land AND the equivalence harness re-runs to **overall_verdict = GO**, then M0f may be considered.

## 10 · Locked-out (unchanged)

M0f production wiring · M0d-async-extension · M0e-plumbing · M4 IUE `url_only` fix · SystemWeakness URL Acquisition · CRE retirement · `^` XOR decode-fidelity · OCR wiring · Workspace changes · MITRE/verdict changes · Sysmon E22/E11 · Sample1 seeding · registration of any B/C classified stage · provenance producer wiring.

**Nothing is authorised as a follow-up to this harness. Owner reviews the report.**

---

## 11 · Extended-corpus addendum (owner note 2026-02-15)

> *"Just a note: You can take different payloads and test not only sample1."*

The harness was extended with a broader real-world payload set (**12 additional inputs**, no adapter/analyzer/router/IUE code touched). Written to `/app/memory/equivalence_report_extended.json` for parallel owner review.

### 11.1 Extended corpus

| # | Payload                                    | Class                        |
|---|--------------------------------------------|------------------------------|
| 1  | `lolbas_certutil_download`                | LOLBAS · certutil URL cache  |
| 2  | `lolbas_bitsadmin_transfer`               | LOLBAS · bitsadmin transfer  |
| 3  | `lolbas_mshta_javascript`                 | LOLBAS · mshta JS            |
| 4  | `lolbas_rundll32_javascript`              | LOLBAS · rundll32 JS proxy   |
| 5  | `cmd_chain_amp`                           | cmd shell chain (`&&`)       |
| 6  | `powershell_encoded_realistic`            | PowerShell -EncodedCommand   |
| 7  | `base64_wrapping_iocs`                    | base64 blob                  |
| 8  | `narrative_short_attack`                  | prose narrative              |
| 9  | `netsh_firewall_off`                      | T1562.004 fixture            |
| 10 | `wmic_process_create`                     | T1047 fixture                |
| 11 | `url_with_suspicious_path`                | URL (mirrors M0a bare_url)   |
| 12 | `empty_input`                             | edge case                    |

### 11.2 Equivalence result

| Capability            | IDENTICAL | MISSING (no step projected) | DIVERGENT | Total |
|-----------------------|:---------:|:---------------------------:|:---------:|:-----:|
| `die.command.v1`      | **10**    | 2 (URL, empty)              | **0**     | 12    |
| `report.narrative.v1` | **10**    | 2 (URL, empty)              | **0**     | 12    |
| `ioc_enrichment.v1`   | — (async) | —                           | 4 async-gap flags | 12 |

**Zero byte-level divergence across 10 diverse sync payloads for both `die.command.v1` and `report.narrative.v1`.** The equivalence claim generalises: it is not a fluke of the 4 M0a fixtures. LOLBAS chains, cmd chains, encoded PowerShell, base64 wrappers, narrative prose, netsh/T1562.004, WMIC/T1047 — all router-invoked = inline byte-identical.

### 11.3 Confirms — the 3 blocking gaps are systematic, not fixture-specific

- The **URL-only DIE divergence** reproduces on the extended `url_with_suspicious_path` fixture — every URL input hits the same pattern (IUE excludes DIE for `url_only`).
- The **async dispatch gap** fires on 4/12 records — every payload whose IUE selected `IOC Enrichment` reveals the coroutine capture. Systematic router-layer limitation.
- The **router plumbing gap** fires on every record that has a `report.narrative.v1` step depending on a `die.command.v1` step — universal for the current projection.
- The **empty_input edge** produces zero projected steps → router path is a no-op → legacy vs router is trivially non-comparable (documented as MISSING, no failure).

### 11.4 Overall extended-corpus verdict

**NO-GO** — same as M0a. The blocking gaps are:
1. Async dispatch (systematic)
2. URL-only DIE divergence (systematic)
3. Router plumbing gap (structural)

But the **positive equivalence signal broadens dramatically**: 20/20 successful sync capability invocations (10 die.command + 10 report.narrative) are byte-identical inline vs router. This is the strongest possible evidence that the M0d dispatcher itself is faithful — the remaining gaps are in adjacent layers, not in the dispatcher.

### 11.5 New tests

`test_m0f_equivalence_harness.py::test_harness_runs_extended_corpus` — writes the extended report and asserts that EVERY record with both legacy and router `die.command.v1` outcomes has byte-identical envelope hashes (strict — would fail loudly if any router-dispatched invocation ever diverged). Currently green.

Canonical/iue/: **160 passed / 1 pre-existing Sample1-DB failure** (was 159/1) → delta **+1**, zero regression.
