# ADR-0014b · M0d — Thin Execution Router

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design (D0)](./0014-single-iue-convergence-design.md)
**Migration step**: M0d (Thin Execution Router)
**Predecessors**: M0a (Contract freeze), M0b (Passive registry), M0c (Provenance schema)
**Successor**: M0e (IUE-v3 contract → produces `ExecutionStep`s) — **LOCKED**

---

## 1 · Owner authorisation (verbatim summary)

Objective: activate the M0b registry as an execution dispatcher.
Constraints: router is a dispatcher, NOT a classifier/IUE/analyzer/adapter/MITRE/verdict engine. Registry is the sole resolution source. No hard-coded dispatch table. No silent fallback. Unknown IDs fail explicitly. Deterministic ordering. StepOutcome preserves execution provenance. Zero behaviour change outside router dispatch — **SystemWeakness must remain empty after M0d**. The `^` decode-fidelity defect stays untouched.

## 2 · M0d architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Caller (test today · IUE tomorrow via M0e/M0g authorisation) │
│      │                                                          │
│      ▼                                                          │
│  plan: Sequence[ExecutionStep]                                 │
│      │  step_id, entry_id, inputs, depends_on, failure_policy  │
│      ▼                                                          │
│  execute_plan(plan)  ← the ONLY public entry-point             │
│      │                                                          │
│      ├── _validate_plan()   (shape only, no classification)    │
│      ├── _topological_order() (deterministic, ties by index)   │
│      └── for each step in exec order:                          │
│              _execute_one():                                    │
│                  1. dep-check → DEPENDENCY_FAILED               │
│                  2. _lookup_entry() ← M0b registry SSOT         │
│                  3. optional accepts_formats check → N/A        │
│                  4. _resolve_callable() ← importlib             │
│                  5. fn(**inputs) → SUCCESS | EXECUTION_FAILED   │
│      ▼                                                          │
│  List[StepOutcome]  (in ORIGINAL step order)                    │
└──────────────────────────────────────────────────────────────┘
```

- Router lives inside `services/registry/` — intra-package with the M0b registries it consults.
- **Not wired to any production route.** M0e/M0g are the only steps authorised to consume it.
- The router does not read `step.inputs` to decide what to run — it splats them into the resolved callable and captures whatever comes back.

## 3 · Router files changed

| File | Change |
|------|--------|
| `services/registry/router.py` | **NEW · 227 LOC** — `ExecutionStep`, `StepOutcome`, `StepStatus`, `FailurePolicy`, `RouterError`, `execute_plan()` |
| `tests/canonical/iue/test_m0d_router_dispatch.py` | **NEW · 397 LOC · 27 tests** — the 18 owner-mandated axes |
| `tests/canonical/iue/test_m0b_registry_hygiene.py` | **1-line filter** — `test_registry_is_passive_no_production_imports` now excludes the entire `services/registry/` package (intra-package imports are legitimate) rather than just `__init__.py` |
| `memory/adr/0014b-m0d-execution-router.md` | **NEW** — this ADR |
| `memory/PRD.md` | Amended — M0d entry |

**No adapter, analyzer, IUE, router (existing routes), verdict engine, MITRE engine, Workspace UI, IKG, Attack Chain, Attack Story, Verdict scoring, canonical narrative, CSV/EDR analyzer, recursive decoder, behavioural adapter, EVTX transport, or evidence producer was modified.**

## 4 · Registry resolution mechanism

```python
def _lookup_entry(entry_id: str) -> Optional[RegistryEntry]:
    for reg in (ADAPTER_REGISTRY, ANALYZER_REGISTRY):
        try:
            return reg.get(entry_id)
        except RegistryError:
            continue
    return None
```

Two ordered lookups → `None` if neither matches. No secondary index. No entry-id inference. No `if entry_id.startswith("die.")`-style shortcuts. If both registries miss, the outcome is `UNKNOWN_IMPLEMENTATION` — never a fallback to a "default" adapter.

Test `test_registry_lookup_is_the_public_resolution_api` asserts `router.ADAPTER_REGISTRY is registry.ADAPTER_REGISTRY` (same object identity — no shadow copy).

Test `test_router_source_contains_no_hardcoded_dispatch_table` grep-locks the absence of literals like `"die.command.v1":`, `IMPLEMENTATIONS = {`, `DISPATCH_TABLE = {`.

Test `test_router_only_imports_from_m0b_registry` grep-locks the router source for direct imports of concrete adapters/analyzers (`from services.die`, `from services.behavioral`, `from services.ida`, `from services.adapters`, `from analysis_core`, …). None present.

## 5 · Execution lifecycle

For each step, in topological order:

1. **Dependency check** — sorted iteration over `step.depends_on`. If any dependency finished non-`SUCCESS` and `failure_policy != "continue"`, this step becomes `DEPENDENCY_FAILED` with `failed_dependency` populated. Missing deps in the plan also become `DEPENDENCY_FAILED`.
2. **Registry resolution** — `_lookup_entry(step.entry_id)`. Miss → `UNKNOWN_IMPLEMENTATION`.
3. **Format check** (optional) — if the caller supplied `input_format`, verify set membership against `entry.accepts_formats`. Miss → `NOT_APPLICABLE`. This is set membership on caller-declared data, **not** classification.
4. **Callable resolution** — `importlib.import_module(module) → getattr(attr)`. Missing attr or non-callable → `UNKNOWN_IMPLEMENTATION` with a router-level error.
5. **Invocation** — `fn(**step.inputs)`. Any `Exception` (not `BaseException`, so `KeyboardInterrupt` still propagates) → `EXECUTION_FAILED` with `error` + `error_type`.
6. **Success** — `StepOutcome(status=SUCCESS, result=<verbatim return>, implementation=<registry impl_path>)`.

Return order matches original input order for analyst-friendly reading; execution order was topological.

## 6 · Failure semantics

Owner-required distinct statuses, all shipped:

| Status                    | When it fires                                                     |
|---------------------------|-------------------------------------------------------------------|
| `SUCCESS`                 | callable returned without raising                                |
| `SKIPPED`                 | *reserved for M0e caller-driven skip; router does not emit today* |
| `NOT_APPLICABLE`          | caller-declared `input_format` ∉ `entry.accepts_formats`         |
| `DEPENDENCY_FAILED`       | any `depends_on` step finished non-`SUCCESS` (or is missing)     |
| `UNKNOWN_IMPLEMENTATION`  | `entry_id` not in either registry / impl path missing/uncallable |
| `EXECUTION_FAILED`        | callable raised `Exception`; `error` + `error_type` populated    |

`SKIPPED` is deliberately reserved — the router does not decide to skip; that decision belongs to the IUE. Reserving the enum value now avoids a schema break at M0e.

**Exceptions are never swallowed.** They are converted to a first-class outcome with the exception message + type. The caller can distinguish a step that ran and failed (`EXECUTION_FAILED`) from a step that never ran (`DEPENDENCY_FAILED` / `UNKNOWN_IMPLEMENTATION` / `NOT_APPLICABLE`).

## 7 · Dependency handling

- **Deterministic topological sort**: Kahn's algorithm, tie-broken by original input index (`bisect.insort` on ready-queue). Test `test_deterministic_topological_tie_break_by_input_index` locks this.
- **Deep chains**: 5-step linear chain works (`test_dependency_ordering_deep_chain`).
- **Cyclic dependencies**: `RouterError("cyclic dependency in plan")` raised before any step runs (`test_cyclic_dependency_raises_router_error`).
- **Missing dependency ID**: converted to `DEPENDENCY_FAILED` at execution time; the topo sort tolerates it so the rest of the plan still runs.
- **failure_policy="continue"**: dependents run even after a dep failure (`test_failure_policy_continue_lets_dependents_run`).

## 8 · Provenance interaction

`StepOutcome` carries `step_id`, `entry_id`, and `implementation` — execution-time metadata directly analogous to the M0c `Provenance` fields (`step_id`, `adapter_id` / `analyzer_id`). However, the router **does NOT auto-attach an M0c `Provenance` block to outcomes**, for two reasons:

1. `StepOutcome` is an EXECUTION artefact. M0c `Provenance` is an EVIDENCE artefact — a category difference.
2. Attaching provenance to evidence produced by an analyzer requires knowing which output fields are evidence, which is analyzer-shape awareness (drift risk).

**Reported integration gap** (for a future migration, not for M0d): when M0e wires the IUE→router→analyzer chain, whichever step converts analyzer output into canonical evidence records should call `services.registry.provenance.attach_to_record()`. That is not M0d's scope.

The router imports nothing from `services.registry.provenance`, and `services.registry.provenance` imports nothing from the router — they remain fully decoupled today.

## 9 · Tests added (27, all green)

`tests/canonical/iue/test_m0d_router_dispatch.py`:

| # | Axis | Test |
|--|-----|------|
| 1  | Known adapter ID resolves          | `test_known_adapter_id_resolves_and_executes` |
| 2  | Known analyzer ID resolves         | `test_known_analyzer_id_resolves_and_executes` |
| 3  | Unknown ID fails explicitly        | `test_unknown_entry_id_returns_unknown_implementation` |
| 4  | Unknown analyzer ID fails explicitly | `test_unknown_analyzer_id_returns_unknown_implementation` |
| 5  | Adapter executes real impl         | `test_adapter_result_is_verbatim_from_implementation` |
| 6  | Analyzer executes real impl        | `test_analyzer_returns_die_envelope_structure` |
| 7  | Topological ordering               | `test_dependency_ordering_topological`, `test_dependency_ordering_deep_chain`, `test_cyclic_dependency_raises_router_error` |
| 8  | Dep failure blocks dependents      | `test_failed_dependency_produces_dependency_failed_and_skips_impl`, `test_missing_dependency_in_plan_is_dependency_failed` |
| 9  | failure_policy respected           | `test_failure_policy_continue_lets_dependents_run`, `test_failure_policy_halt_is_default`, `test_invalid_failure_policy_rejected` |
| 10 | Execution order deterministic      | `test_deterministic_execution_across_runs`, `test_deterministic_topological_tie_break_by_input_index` |
| 11 | Registry is only resolution source | `test_router_source_contains_no_hardcoded_dispatch_table`, `test_router_only_imports_from_m0b_registry`, `test_registry_lookup_is_the_public_resolution_api` |
| 12 | M0a hashes byte-identical (parametrised × 4) | `test_m0a_iue_hashes_still_byte_identical[*]` |
| 16 | Workspace unchanged (no consumers) | `test_router_has_zero_production_consumers` |
| 17 | SystemWeakness envelope locked     | `test_systemweakness_url_iue_envelope_still_locked` |
| 18 | `^` decoder untouched              | `test_recursive_decode_caret_behaviour_unchanged`, `test_recursive_decode_module_untouched_by_m0d` |

Axes 13/14/15 are covered by re-running M0b/M0c/UI-DEF-02 suites (see §10).

## 10 · Full regression results

| Suite                                                | Before M0d | After M0d | Delta |
|------------------------------------------------------|:----------:|:---------:|:-----:|
| `canonical/iue/` (all M0-tier)                       | 93 / 1 fail| 120 / 1 fail | **+27** |
| M0a+M0b+M0c+M0d focused stack                        | 50 / 0     | 77 / 0    | +27 |
| P2 stack (Slice-1 + Slice-2 + Slice-3 + Report determinism) | 40 / 1 skip | 40 / 1 skip | 0 |
| Payload-shape + Sample1 immutability + Workspace isolation + UI-DEF-02 convergence | 25 / 2 skip | 25 / 2 skip | 0 |

The single `canonical/iue/` failure remains `test_a1_2_sample1_fingerprint_unchanged` — the pre-existing Sample1-DB baseline exception characterised in the M0d gate report (unrelated to M0d, `nivxray_ci_local` vs `test_database` seed).

## 11 · Before/after hashes

Direct probe of `services.die.input_understanding.understand(text, execute=False)` on the four M0a corpus inputs, both before and after M0d:

| Corpus                | Hash (before / after — identical)                                     |
|-----------------------|-----------------------------------------------------------------------|
| `systemweakness_url`  | `febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00`    |
| `powershell_naked`    | `92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b`    |
| `plain_english_short` | `35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b`    |
| `hex_ratio_long`      | `7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad`    |

**All four hashes byte-identical.** IUE classification, plan generation, and engine selection are provably unchanged.

## 12 · SystemWeakness governance witness

The single most-important acceptance criterion:

```
> understand("https://systemweakness.com/some-report", execute=False)
  engines_selected = ['IOC Enrichment', 'Report Generator']
  hash             = febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00
```

- `URL Acquisition` is **NOT** in `engines_selected` (it was omitted before M0d; still omitted after M0d).
- The IUE envelope hash matches the M0a-locked value exactly.

**M0d has not accidentally crossed into M0e/M1/M4 territory.** The SystemWeakness URL remains empty by design, and this test now guards against future scope creep.

## 13 · Discovered adapter/analyzer incompatibilities

**None.** Two real implementations were exercised end-to-end through the router:

| Registry ID              | Implementation                             | Invocation shape           | Result             |
|--------------------------|--------------------------------------------|----------------------------|--------------------|
| `text.passthrough.v1`    | `builtins:str`                             | `str(object=<val>)`        | ✅ verbatim string  |
| `die.command.v1`         | `services.die.api:analyze`                 | `analyze(src=<text>)`      | ✅ DIE envelope dict |

Both accept plain-Python kwargs matching the `step.inputs` splat pattern; no signature adaptation was required. The remaining 8 adapters and 8 analyzers in the M0b registry have not been exercised by M0d — their invocation shapes will be exercised as M0e wires the IUE to the router, at which point each will be reported case-by-case per the owner directive.

## 14 · Confirmation of zero behavioural change

- No file under `routers/`, `canonical/`, `services/die/`, `services/behavioral/`, `services/ida/`, `services/adapters/`, `services/files/`, `services/uaie/`, `analysis_core.py`, `operations.py`, `evidence_extractor.py`, `server.py`, or any Workspace UI file was modified.
- `services.registry.router` has zero production consumers (grep-locked).
- M0a IUE hashes byte-identical for all 4 corpus inputs.
- M0b registry hygiene: 8 tests still green (the one filter tweak is architecturally correct: the router legitimately lives inside `services/registry/`).
- M0c provenance tests: 27 still green — schema still has zero production consumers.
- P2 Slice-1/2/3 tests: 40 pass / 1 skip — Sysmon adapter, EVTX transport, Event 3 unchanged.
- UI-DEF-02 convergence tests: unchanged.
- Payload-shape + Sample1-immutability + Workspace-isolation tests: unchanged.
- `services/die/recursive_decode.py` has zero references to `services.registry` — the `^` XOR fidelity defect could not have been altered by M0d.

## 15 · What is explicitly out of scope for M0d (locked-out, unchanged)

- M0e IUE-v3 contract → router wiring — **LOCKED**
- M0f / M0g / M0h — **LOCKED**
- M1–M8 (universal routing, OCR enablement, User-Agent tuning, Playwright install) — **LOCKED**
- `^` XOR decode-fidelity fix — **LOCKED**
- Workspace behaviour / re-routing — **LOCKED**
- OCR wiring — **LOCKED**
- Sysmon Event 22 / Event 11 — **LOCKED**
- Attack Chain auto-scroll (Task 3) — **LOCKED**
- Source-agnostic architecture audit (Task 4) — **LOCKED**

## 16 · Next authorised step

**None.** M0d is complete. Stopping here awaiting explicit owner authorisation for M0e.
