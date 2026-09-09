# ADR-0014d · M0b-extension — Report Generator + Artifact Intelligence

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design (D0)](./0014-single-iue-convergence-design.md)
**Migration step**: M0b-extension (passive registration of two class-A capabilities)
**Predecessors**: M0a, M0b, M0c, M0d, M0e + pre-M0f architecture reassessment
**Successor**: **Equivalence harness** (legacy pipeline vs router-dispatched) — not M0f — **LOCKED**

---

## 1 · Owner authorisation

The pre-M0f architecture reassessment classified the 9 unmapped legacy engine stages:
- **A** (independent capability, register) — `Report Generator`, `Artifact Intelligence`
- **B** (bundled sub-behaviour, do NOT register) — DKP, Attack Intent, Attack Story, Preprocessor, Chain Analyzer, Investigation Confidence
- **C** (legacy label only, retire) — CRE
- **D** (uncertain) — none

Owner authorised the two class-A registrations only, passive. All B, C, and D stages remain unregistered. No production wiring. No IUE / DIE / artifact-intelligence / Workspace / MITRE / verdict / provenance producer touch. SystemWeakness `url.acquire.v1` must NOT appear in the projection.

## 2 · What shipped

### 2.1 Two passive registrations in `services/registry/__init__.py`

```python
RegistryEntry(
    entry_id="report.narrative.v1",
    kind="analyzer", version="1",
    implementation_path="services.die.narrative:generate_report",
    accepts_formats=frozenset({"die_envelope"}),
    role="Deterministic 12-section report generator over the DIE envelope.",
    live_today=True,
    notes="Independent capability — consumes an already-analyzed env; "
          "not called from inside services.die.api:analyze. "
          "See ADR-0014d for the duplicate-execution proof.",
),
RegistryEntry(
    entry_id="artifact.intel.v1",
    kind="analyzer", version="1",
    implementation_path="services.artifact_intelligence:dispatch",
    accepts_formats=frozenset({"bytes"}),
    role="Pluggable artifact analyzers (PE, DOCX, PDF, shellcode, …) "
          "dispatched by content magic.",
    live_today=True,
    notes="Independent top-level package with its own analyzers/ "
          "subdirectory and routes/artifacts.py entry-point.",
),
```

Registry sizes: adapters **9** (unchanged), analyzers **10 → 12**.

### 2.2 Mapping table grown 4 → 6 in `services/registry/iue_projection.py`

```python
_LEGACY_ENGINE_TO_ENTRY_ID: Dict[str, str] = {
    "DIE (Semantic AST)":    "die.command.v1",
    "Decoder":               "die.recursive.v1",
    "IOC Enrichment":        "ioc_enrichment.v1",
    "URL Acquisition":       "url.acquire.v1",
    # ── M0b-extension ──
    "Report Generator":      "report.narrative.v1",
    "Artifact Intelligence": "artifact.intel.v1",
}
```

Import-time validation (`_validate_mapping_at_import`) still holds — every value is in `ADAPTER_REGISTRY ∪ ANALYZER_REGISTRY`.

### 2.3 Tests updated / added

- `tests/canonical/iue/test_m0b_registry_hygiene.py` — `EXPECTED_ANALYZER_IDS` grew to 12; `len(ANALYZER_REGISTRY) == 12`.
- `tests/canonical/iue/test_m0e_execution_plan_projection.py::test_systemweakness_projection_locked` — updated to expect `['ioc_enrichment.v1', 'report.narrative.v1']` with `unmapped_engines == []`, and now includes an explicit anti-scope-creep assertion that `url.acquire.v1` is NOT in the projection.
- `tests/canonical/iue/test_m0b_extension_new_capabilities.py` — **NEW · 12 tests**:
  - `report.narrative.v1` registered, resolvable, healthy, callable
  - `artifact.intel.v1` registered, resolvable, healthy, callable
  - No class-B/C stage was accidentally registered (grep-locked forbidden tokens)
  - Mapping table has exactly 6 entries with the correct pair
  - SystemWeakness gains `report.narrative.v1` but NOT `url.acquire.v1`
  - All 4 M0a hashes byte-identical (parametrised)
  - Zero new router wiring for the new entry_ids (grep-locked outside `services/registry/`)
  - Registry `health_check()` fully green

## 3 · Duplicate-execution proof

The two new registrations are **passive** — no adapter/analyzer/router/route code references them. But even if a future authorised M0f wired them into production, they would NOT cause duplicate execution:

```
report.narrative.v1  →  services.die.narrative:generate_report
    called from: routers/die.py::/api/die/narrate  (existing)
                 NEVER called from services.die.api:analyze()
    dependency chain:
      die.command.v1  →  {DIE envelope}
                            ↓
                     report.narrative.v1  →  12-section report
    ⇒ SAFE — the two capabilities are pipelined, not overlapping.

artifact.intel.v1    →  services.artifact_intelligence:dispatch
    called from: routers/artifacts.py                (existing)
                 services/recipe_planner.py          (existing)
                 services/recursive_child_pipeline.py (existing)
                 NEVER called from services.die.api:analyze()
                 NEVER called from services.die.narrative:generate_report()
    ⇒ SAFE — independent capability, no overlap.
```

The 6 class-B stages remain unregistered, which prevents duplicate execution of anything that already runs inside `die.command.v1` or `report.narrative.v1` (DKP, Attack Intent, Attack Story, Preprocessor, Chain Analyzer, Investigation Confidence).

## 4 · SystemWeakness governance witness — HELD

Live probe (unchanged from ADR-0014c aside from the additive `report.narrative.v1` step):

```
> understand("https://systemweakness.com/some-report", execute=False)
  input_type       = "url_only"
  engines_selected = ["IOC Enrichment", "Report Generator"]
  engines_skipped  = [..., "URL Acquisition", ...]
  envelope hash    = febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00

> plan_to_execution_steps(u)
  steps            = [("s00_ioc_enrichment_v1",  "ioc_enrichment.v1"),
                      ("s01_report_narrative_v1", "report.narrative.v1")]
  unmapped_engines = []
  legacy_plan      = [<original 7-step template unchanged>]
```

- IUE envelope hash **byte-identical to M0a**: `febd68f1…f93a00`.
- `URL Acquisition` **still in `engines_skipped`** — not touched.
- `url.acquire.v1` **NOT in the projected steps** — governance witness holds.
- The additive appearance of `report.narrative.v1` in the projection is expected and matches the owner-approved acceptance criterion:
  > *"It is acceptable for: SystemWeakness → ioc_enrichment.v1 → report.narrative.v1 to appear in the projection."*

Wiring M0f in the future would still **not** solve the SystemWeakness content problem — `url.acquire.v1` isn't in the projection, so no router path can select it. That fix belongs to a later IUE migration (M0h/M1/M4), all LOCKED.

## 5 · Guardrails held

| Component                     | Modified? |
|-------------------------------|:---------:|
| M0d router (`router.py`)      | ❌ No      |
| M0c provenance (`provenance.py`) | ❌ No   |
| `services/die/*` (analyzers)  | ❌ No      |
| `services/artifact_intelligence/*` | ❌ No |
| `services/die/input_understanding.py` (IUE) | ❌ No |
| Workspace UI / any frontend   | ❌ No      |
| MITRE / verdict / evidence    | ❌ No      |
| Provenance producer wiring    | ❌ No      |
| Any production route          | ❌ No      |
| `services/registry/__init__.py` | ✅ 2 new passive `RegistryEntry` records |
| `services/registry/iue_projection.py` | ✅ 2 new mapping-table entries |
| M0b hygiene test              | ✅ EXPECTED set + count updated |
| M0e SystemWeakness test       | ✅ expectations updated to reflect additive `report.narrative.v1` |
| M0b-extension test file       | ✅ NEW · 12 tests |
| ADR + PRD                     | ✅ this ADR + PRD entry |

## 6 · Regression results

| Suite                                                | Before M0b-ext | After M0b-ext | Delta |
|------------------------------------------------------|:--------------:|:-------------:|:-----:|
| `canonical/iue/` (all M0-tier + legacy)              | 141 / 1 fail   | 154 / 1 fail  | **+13** |
| M0a+M0b+M0b-ext+M0c+M0d+M0e focused stack             | 98 / 0         | 111 / 0       | +13 |
| P2 (Sysmon Slice-1/2/3 + Report determinism + UI-DEF-02) | 48 / 1 skip | 48 / 1 skip | 0 |

The single canonical/iue/ failure is the pre-existing Sample1-DB baseline (`nivxray_ci_local` vs `test_database` seed), unrelated to this extension.

## 7 · Before/after hashes (all 4 M0a inputs)

Byte-identical pre- and post-M0b-extension:

| Corpus                | Hash                                                                    |
|-----------------------|-------------------------------------------------------------------------|
| `systemweakness_url`  | `febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00`      |
| `powershell_naked`    | `92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b`      |
| `plain_english_short` | `35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b`      |
| `hex_ratio_long`      | `7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad`      |

## 8 · Projections for the M0a corpus

| Input                | Steps (M0b-ext)                                                     | Unmapped                                            |
|----------------------|---------------------------------------------------------------------|-----------------------------------------------------|
| `systemweakness_url` | `[ioc_enrichment.v1, report.narrative.v1]`                          | `[]`                                                 |
| `powershell_naked`   | `[die.command.v1, report.narrative.v1, ioc_enrichment.v1]`          | `[DKP, Attack Intent, Attack Story]`                 |
| `plain_english`      | `[die.command.v1, report.narrative.v1]`                             | `[DKP, Attack Intent]`                               |
| `hex_ratio_long`     | `[die.recursive.v1, die.command.v1, report.narrative.v1]`           | `[]`                                                 |

The `unmapped_engines` list is now populated ONLY with class-B stages (bundled sub-behaviour) — the 4 class-A/C stages have all been handled by the registry decisions.

## 9 · Locked-out (unchanged)

- M0f production wiring — **LOCKED**
- M0g / M0h · M1–M8 — **LOCKED**
- SystemWeakness URL Acquisition fix — **LOCKED** (M0h/M1/M4)
- CRE legacy label retirement — **LOCKED** (IUE-side migration)
- `^` XOR decode-fidelity fix — **LOCKED**
- OCR wiring — **LOCKED**
- Workspace behaviour / re-routing — **LOCKED**
- Sysmon Event 22 / Event 11 — **LOCKED**
- Attack Chain auto-scroll (Task 3) — **LOCKED**
- Sample1 seeding into `nivxray_ci_local` — **LOCKED**
- Registration of any B or C classified stage — **LOCKED**
- Any producer wiring of the M0c `Provenance` schema — **LOCKED**

## 10 · Next authorised step

**None.** Owner directive:
> *"After M0b-extension, the next thing I want is not M0f. I want the equivalence harness first: legacy pipeline vs router-dispatched pipeline across the frozen M0a corpus, with differences reported rather than normalized away."*

Stopping here. Awaiting explicit owner authorisation for the equivalence harness.
