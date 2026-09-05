# ADR-0014c · M0e — IUE-v3 Execution Contract (Projection Only)

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design (D0)](./0014-single-iue-convergence-design.md)
**Migration step**: M0e (IUE-v3 execution-contract projection)
**Predecessors**: M0a (contract freeze), M0b (passive registry), M0c (provenance schema), M0d (thin execution router)
**Successor**: M0f (production wiring: IUE → projection → router) — **LOCKED**

---

## 1 · Current IUE contract (verbatim from live probe)

The M0a-frozen `InputUnderstanding` dataclass keeps 18 top-level fields. Two of them together carry the routing decision:

- `plan[]` — a **fixed 7-step pipeline template** (`iue → preprocessor → die → dkp → intent → story → report`). Identical for every input. Each step: `{id, label, engine, status, ms, detail}`. Machine engine tokens: `{iue, preprocessor, die, dkp, decoder, attack_story, report}`.
- `engines_selected[]` — the **actual routing decision**, varies by `input_type`. Friendly names such as `DIE (Semantic AST)`, `Decoder`, `IOC Enrichment`, `URL Acquisition`, `DKP (Decoder Knowledge Pack)`, `Attack Intent`, `Attack Story`, `Report Generator`, `Preprocessor`, `CRE (Command Reconstruction)`, `Chain Analyzer`, `Investigation Confidence`, `Artifact Intelligence`.

The M0a test `test_url_only_plan_omits_url_acquisition_today` locks that for `url_only`, `engines_selected == ['IOC Enrichment', 'Report Generator']` and `URL Acquisition` is in `engines_skipped`.

## 2 · IUE-v3 contract (M0e)

M0e defines the machine-readable execution contract that the M0d router understands:

```python
@dataclass(frozen=True)
class ExecutionPlanProjection:
    steps:            List[ExecutionStep]     # router-executable subset
    unmapped_engines: List[str]                # legacy engines with no M0b entry
    legacy_plan:      List[dict]               # original IUE plan[] verbatim
```

The projection is derived from `engines_selected` (the authoritative routing decision). It is a **pure function of IUE output**. The IUE dataclass is not modified; the M0a-frozen fields keep their exact values; all M0a hashes stay byte-identical.

## 3 · Legacy → v3 projection

The projection walks `engines_selected` in order. Each friendly name is looked up in the fixed name-mapping table `_LEGACY_ENGINE_TO_ENTRY_ID`:

| Friendly name (from `engines_selected`) | M0b registry `entry_id` |
|---|---|
| `DIE (Semantic AST)`  | `die.command.v1`      |
| `Decoder`             | `die.recursive.v1`    |
| `IOC Enrichment`      | `ioc_enrichment.v1`   |
| `URL Acquisition`     | `url.acquire.v1`      |

Every other friendly name (`DKP`, `Attack Intent`, `Attack Story`, `Report Generator`, `Preprocessor`, `CRE`, `Chain Analyzer`, `Investigation Confidence`, `Artifact Intelligence`) is **legitimately unmapped** — those legacy stages don't have a standalone M0b capability today. They are surfaced in `unmapped_engines` for analyst visibility. **Silently dropping them would be a defect**; the projection does not.

The mapping table is validated at import time (`_validate_mapping_at_import`) against `ADAPTER_REGISTRY.ids() ∪ ANALYZER_REGISTRY.ids()`. If a value points at a dead id, `ProjectionError` is raised at import — a stale table cannot ship silently.

## 4 · ExecutionStep schema (unchanged, re-used from M0d)

The projection emits the exact `ExecutionStep` shape shipped in M0d:

```python
step_id:         str            # deterministic: f"s{ord:02d}_{entry_id.replace('.', '_')}"
entry_id:        str            # M0b registry id (validated at import time)
inputs:          Mapping = {}   # populated by caller (M0f will do this)
depends_on:      FrozenSet[str] # previous mapped step or empty
failure_policy:  str = "halt"   # M0d default
input_format:    Optional[str]  = None
```

`inputs` is intentionally left empty by the projection — populating them requires knowing each analyzer's signature, which is analyzer-shape awareness (drift risk). The caller (future M0f) is responsible.

## 5 · Example plans for 3 representative input types

Live probe (all hashes match the M0a baseline exactly):

### 5.1 · `url_only` — SystemWeakness URL (governance witness)

```
engines_selected : ['IOC Enrichment', 'Report Generator']
steps            : [('s00_ioc_enrichment_v1', 'ioc_enrichment.v1')]
depends_on       : [[]]
unmapped_engines : ['Report Generator']
```

**`url.acquire.v1` is NOT in the steps.** `URL Acquisition` is in `engines_skipped` and never enters the projection. SystemWeakness content-processing behaviour is unchanged.

### 5.2 · `powershell_naked`

```
engines_selected : ['DIE (Semantic AST)', 'DKP (Decoder Knowledge Pack)', 'Attack Intent',
                    'Attack Story', 'Report Generator', 'IOC Enrichment']
steps            : [('s00_die_command_v1',    'die.command.v1'),
                    ('s05_ioc_enrichment_v1', 'ioc_enrichment.v1')]
depends_on       : [[], ['s00_die_command_v1']]
unmapped_engines : ['DKP (Decoder Knowledge Pack)', 'Attack Intent',
                    'Attack Story', 'Report Generator']
```

`ioc_enrichment.v1` depends on `die.command.v1` because it appears later in `engines_selected`.

### 5.3 · `base64_blob` — hex-ratio-long

```
engines_selected : ['Decoder', 'DIE (Semantic AST)', 'Report Generator']
steps            : [('s00_die_recursive_v1', 'die.recursive.v1'),
                    ('s01_die_command_v1',   'die.command.v1')]
depends_on       : [[], ['s00_die_recursive_v1']]
unmapped_engines : ['Report Generator']
```

Decoder → DIE dependency chain preserved.

## 6 · Router handoff

```
InputUnderstanding
      │
      ▼
plan_to_execution_steps()  ← M0e projection (pure function)
      │
      ▼
ExecutionPlanProjection.steps  (List[ExecutionStep])
      │
      ▼
execute_plan(steps)             ← M0d router (unchanged)
      │
      ▼
_lookup_entry(entry_id)         ← M0b registry (unchanged)
      │
      ▼
importlib → fn(**step.inputs)   ← existing adapter/analyzer (unchanged)
```

The projection module never imports the router's `execute_plan` — only its `ExecutionStep` / `FailurePolicy` types. Executing the plan remains the caller's decision. Enforced by test `test_projected_steps_are_router_compatible_shape` (validates plan shape via the router's own `_validate_plan`) — no execution runs from within M0e's tests.

## 7 · Registry resolution

Same as M0d — the router does two ordered `reg.get(entry_id)` calls against `ADAPTER_REGISTRY` then `ANALYZER_REGISTRY`. M0e adds one additional import-time guard (`_validate_mapping_at_import`) that pre-verifies every value in the name-mapping table exists in the union of both registries.

## 8 · Compatibility mechanism

Two layers:

1. **Name-mapping table** — `_LEGACY_ENGINE_TO_ENTRY_ID` (4 entries today). Explicit, hand-authored, and audit-only — not populated by content inspection. Grep-locked to have no `if input_type` / `if language` / `if hero_sentence` classification pattern.
2. **`unmapped_engines` field** — first-class output. Legacy stages without an M0b entry are surfaced, not dropped. This is the honest gap report the owner mandated ("STOP if the implementation requires changing an existing analyzer") — the projection reports the gap instead of hiding it.

The legacy IUE surface is fully preserved:
- The 18 M0a-frozen fields are unchanged.
- `ExecutionPlanProjection.legacy_plan` re-serialises the original `plan[]` verbatim for any caller who still needs the legacy view.
- `asdict(understand(...))` is byte-identical pre- and post-M0e.

## 9 · Files changed

| Path | Change |
|------|--------|
| `services/registry/iue_projection.py` | **NEW · +125 LOC** — `plan_to_execution_steps`, `ExecutionPlanProjection`, `ProjectionError`, `_LEGACY_ENGINE_TO_ENTRY_ID` |
| `tests/canonical/iue/test_m0e_execution_plan_projection.py` | **NEW · +303 LOC · 21 tests** |
| `memory/adr/0014c-m0e-iue-v3-execution-contract.md` | **NEW** — this ADR |
| `memory/PRD.md` | Amended — M0e entry |

**Not touched**:
- `services/die/input_understanding.py` (IUE) — zero modification
- `services/die/api.py`, `services/die/recursive_decode.py`, `services/die/canonical_bridge.py`, `services/die/canonical_narrative_enrichment.py` — zero
- `services/ida/*`, `services/adapters/*`, `services/behavioral/*`, `services/files/*` — zero
- `analysis_core.py`, `operations.py`, `evidence_extractor.py`, `server.py` — zero
- `routers/*` — zero (production still runs the legacy path)
- Workspace UI — zero
- `services/registry/router.py`, `services/registry/__init__.py`, `services/registry/provenance.py` — zero

## 10 · Tests added (21, all green)

All 14 owner-mandated axes covered plus 5 additional witnesses:

| # | Axis | Test |
|---|------|------|
| 1  | M0a baselines still deterministic (parametrised × 4) | `test_m0a_baseline_hashes_unchanged_after_projection[*]` |
| 2  | 21 input types keep classification | `test_all_21_input_types_still_classifiable` |
| 3  | Every emitted entry_id is registered | `test_all_projected_entry_ids_are_registered` |
| 4  | Stale mapping fails explicitly | `test_stale_mapping_raises_projection_error` |
| 5  | Deterministic dependency chain | `test_dependency_chain_is_linear_and_deterministic`, `test_first_step_has_no_dependencies` |
| 6  | Byte-identical projection across runs | `test_projection_is_byte_identical_across_runs`, `test_step_id_is_stable_by_construction` |
| 7  | Legacy IUE view preserved | `test_projection_preserves_legacy_plan_verbatim`, `test_projection_accepts_both_dataclass_and_dict` |
| 8-11 | Full IUE regression | (implicit — 141/1 in `canonical/iue/`) |
| 12 | SystemWeakness locked | `test_systemweakness_projection_locked` |
| 13 | PrevMode envelope unchanged | `test_execute_false_envelope_matches_baseline_across_all_corpus` |
| 14 | Zero production consumers | `test_projection_module_has_zero_production_consumers` |
| 15 | Pure function (100 replays) | `test_projection_is_pure_100_replays` |
| 16 | Never mutates IUE | `test_projection_does_not_mutate_iue_input` |
| 17 | Unmapped surfaced not dropped | `test_unmapped_engines_are_surfaced_not_silently_dropped` |
| 18 | No adapter/analyzer imports | `test_projection_module_never_imports_adapters_or_analyzers` |
| 19 | Router-compatible shape | `test_projected_steps_are_router_compatible_shape` |

## 11 · Regression results

| Suite                                            | Before M0e | After M0e | Delta |
|--------------------------------------------------|:----------:|:---------:|:-----:|
| `canonical/iue/` (all M0-tier + legacy)          | 120 / 1 fail | 141 / 1 fail | **+21** |
| M0a+M0b+M0c+M0d+M0e focused stack                | 77 / 0     | 98 / 0    | +21 |
| P2 stack (Sysmon Slice-1/2/3 + Report determinism + UI-DEF-02) | 48 / 1 skip | 48 / 1 skip | 0 |

The single canonical/iue/ failure remains the pre-existing Sample1-DB baseline (`nivxray_ci_local` vs `test_database` seed) — characterised in the M0d gate report.

## 12 · Before/after hashes

Live probe:

| Corpus                | Hash (before / after — identical)                                     |
|-----------------------|-----------------------------------------------------------------------|
| `systemweakness_url`  | `febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00`    |
| `powershell_naked`    | `92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b`    |
| `plain_english_short` | `35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b`    |
| `hex_ratio_long`      | `7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad`    |

**IUE classification and envelope shape provably unchanged.**

## 13 · SystemWeakness proof

Direct probe of the projection on the SystemWeakness URL:

```
> plan_to_execution_steps(understand("https://systemweakness.com/some-report"))
  steps            = [('s00_ioc_enrichment_v1', 'ioc_enrichment.v1')]
  unmapped_engines = ['Report Generator']
  legacy_plan      = [<original 7-step pipeline template, verbatim>]
```

- `url.acquire.v1` is **NOT** in `steps` (would be M4/M0f-territory to add).
- Envelope hash unchanged from M0a: `febd68f1…f93a00`.
- `URL Acquisition` remains in `engines_skipped` (unchanged from M0a).

**M0e has NOT crossed into M1/M4 territory.** SystemWeakness content processing is byte-identical.

## 14 · Architectural conflict discovered (transparent report)

**Structural fact, not a bug**: legacy `engines_selected` contains 13 distinct friendly names. Only 4 map to M0b registry entries today (`DIE (Semantic AST)`, `Decoder`, `IOC Enrichment`, `URL Acquisition`). The other 9 (`DKP`, `Attack Intent`, `Attack Story`, `Report Generator`, `Preprocessor`, `CRE`, `Chain Analyzer`, `Investigation Confidence`, `Artifact Intelligence`) correspond to legacy pipeline stages that:

- Either run as bundled sub-behaviour inside `services.die.api:analyze` (e.g. Attack Intent, Chain Analyzer, DKP).
- Or run as bundled sub-behaviour inside `services.ida.report_extractors:extract_all` (Report Generator projection).
- Or are advisory-only stages not registered as standalone capabilities.

**This is not a defect that M0e can or should fix.** It is a legitimate gap between the legacy IUE's engine taxonomy and the M0b capability taxonomy. Closing that gap requires either:
- (a) registering more capabilities in M0b (creates a bigger router-executable surface), or
- (b) accepting these stages as sub-behaviour of the already-registered analyzers.

Either choice is a future migration. M0e stops here, surfaces the gap in `unmapped_engines`, and lets the owner decide. **No adapter, analyzer, or IUE was modified**.

## 15 · What is explicitly out of scope for M0e (locked-out, unchanged)

- M0f production wiring (IUE → projection → router) — **LOCKED**
- M0g / M0h — **LOCKED**
- M1–M8 (universal routing, OCR enablement, User-Agent tuning, Playwright install) — **LOCKED**
- SystemWeakness URL acquisition — **LOCKED**
- `^` XOR decode-fidelity fix — **LOCKED**
- Workspace behaviour / re-routing — **LOCKED**
- OCR wiring — **LOCKED**
- Sysmon Event 22 / Event 11 — **LOCKED**
- Attack Chain auto-scroll (Task 3) — **LOCKED**
- Sample1 seeding into `nivxray_ci_local` — **LOCKED**

## 16 · Next authorised step

**None.** M0e is complete. Stopping here awaiting explicit owner authorisation for M0f.
