# NivXForge Phase 0 — Completion Record

_Permanent audit document. Do not edit after acceptance._

- **Phase:** 0 · Platform Foundation
- **Closed:** 2026-02-28
- **Status:** ACCEPTED · dormant, isolated, Workspace unchanged

---

## 1 · Objectives (approved)

1. Establish an architecturally isolated NivXForge package alongside the
   NivXRay Workspace, without modifying any Workspace file.
2. Define the foundational data primitives every future NivXForge engine
   will use (Canonical Investigation Object, Evidence Ledger).
3. Define the Engine Protocol shape without shipping any engine.
4. Enforce the Workspace Protection Policy structurally (static tests),
   not by convention alone.
5. Publish the three-document governance triad
   (`PRODUCT_CHARTER.md` · `NORTH_STAR.md` · `IMPLEMENTATION_ROADMAP.md`)
   and mark Phase 0 complete in the Roadmap.
6. Introduce zero user-facing capability, zero runtime coupling with
   Workspace, and zero regressions.

Result: all six objectives satisfied and verified.

---

## 2 · Files created (Phase 0 deliverables)

### Backend

| Path | Role |
|---|---|
| `/app/backend/nivxforge/__init__.py` | Package marker + version |
| `/app/backend/nivxforge/config.py` | `FORGE_*` env prefix · `/nivxforge` route prefix · `forge_` Mongo prefix |
| `/app/backend/nivxforge/router.py` | Dormant FastAPI `APIRouter` (not mounted) |
| `/app/backend/nivxforge/README.md` | Package README |
| `/app/backend/nivxforge/core/__init__.py` | Core primitives marker |
| `/app/backend/nivxforge/core/cio.py` | Canonical Investigation Object (append-only, 15 buckets) |
| `/app/backend/nivxforge/core/evidence.py` | Evidence Ledger (`Finding · Evidence · Engine · Confidence`) |
| `/app/backend/nivxforge/engines/__init__.py` | Engines marker |
| `/app/backend/nivxforge/engines/base.py` | Engine `Protocol` — zero implementations |
| `/app/backend/nivxforge/engines/README.md` | Explicit "no engines yet" statement |
| `/app/backend/nivxforge/observability/__init__.py` | Observability marker |
| `/app/backend/nivxforge/observability/logging.py` | Isolated `nivxforge.*` logger namespace |
| `/app/backend/nivxforge/tests/__init__.py` | Tests package marker |
| `/app/backend/nivxforge/tests/test_cio.py` | CIO invariants (6 tests) |
| `/app/backend/nivxforge/tests/test_evidence.py` | Evidence Ledger invariants (4 tests) |
| `/app/backend/nivxforge/tests/test_engine_interface.py` | Engine Protocol conformance (3 tests) |
| `/app/backend/nivxforge/tests/test_router_prefix.py` | Route prefix invariants (2 tests) |
| `/app/backend/nivxforge/tests/test_workspace_isolation.py` | AST scan · zero Workspace imports (1 test) |
| `/app/backend/nivxforge/tests/test_workspace_compatibility.py` | No mount, protected paths intact, no side effects (3 tests) |

### Frontend

| Path | Role |
|---|---|
| `/app/frontend/src/nivxforge/README.md` | Reserved namespace, no UI |

### Governance

| Path | Role |
|---|---|
| `/app/memory/NORTH_STAR.md` | Aspirational architecture (created) |
| `/app/memory/IMPLEMENTATION_ROADMAP.md` | Active work + entry gate (created; Phase 0 marked complete) |
| `/app/memory/PRD.md` | Phase 0 entry appended (audit trail) |

---

## 3 · Files intentionally left untouched (Workspace Protection)

The following paths were **read-only for the duration of Phase 0** and
remain byte-identical to their pre-Phase-0 state:

- `/app/backend/decoders/`
- `/app/backend/engine/`
- `/app/backend/heuristics/`
- `/app/backend/knowledge_base/`
- `/app/backend/routers/`
- `/app/backend/extractors/`
- `/app/backend/enrichment/`
- `/app/backend/file_extractors.py`
- `/app/backend/server.py`
- `/app/backend/analysis_core.py`
- `/app/backend/wrapper_archetypes.py`
- `/app/backend/magic_decoder.py`
- `/app/backend/operations.py`
- `/app/backend/command_analyzer.py`
- `/app/backend/shellcode_analyzer.py`
- `/app/backend/chain_analyzer.py`
- `/app/backend/v2/**`
- `/app/frontend/src/pages/**` (all existing Workspace pages)
- `/app/frontend/src/components/**`
- `/app/frontend/src/lib/**` (except `selectCanonicalOutput.js` which
  was modified in the earlier PS_ASCII_XOR_IEX hotfix — not Phase 0)

**Independent verification:**
- `grep -c "nivxforge" /app/backend/server.py` → `0`
- `curl /api/health` → `200`
- `curl /api/nivxforge/health` → `404` (router unmounted)

---

## 4 · Tests executed (26 · all PASSED)

### NivXForge Phase 0 · foundational invariants (19)

| # | Test |
|---|---|
| 1 | `nivxforge/tests/test_cio.py::test_cio_starts_empty` |
| 2 | `nivxforge/tests/test_cio.py::test_cio_append_returns_entry_and_records_provenance` |
| 3 | `nivxforge/tests/test_cio.py::test_cio_append_is_additive_never_overwrites` |
| 4 | `nivxforge/tests/test_cio.py::test_cio_entry_is_frozen` |
| 5 | `nivxforge/tests/test_cio.py::test_cio_rejects_unknown_field` |
| 6 | `nivxforge/tests/test_cio.py::test_cio_append_requires_engine` |
| 7 | `nivxforge/tests/test_evidence.py::test_finding_requires_evidence` |
| 8 | `nivxforge/tests/test_evidence.py::test_finding_with_evidence_is_valid` |
| 9 | `nivxforge/tests/test_evidence.py::test_finding_confidence_bounded` |
| 10 | `nivxforge/tests/test_evidence.py::test_finding_is_frozen` |
| 11 | `nivxforge/tests/test_engine_interface.py::test_noop_engine_satisfies_protocol` |
| 12 | `nivxforge/tests/test_engine_interface.py::test_engine_process_appends_via_cio` |
| 13 | `nivxforge/tests/test_engine_interface.py::test_non_engine_object_is_rejected` |
| 14 | `nivxforge/tests/test_router_prefix.py::test_all_routes_under_nivxforge_prefix` |
| 15 | `nivxforge/tests/test_router_prefix.py::test_router_has_dormant_health_endpoint` |
| 16 | `nivxforge/tests/test_workspace_isolation.py::test_no_nivxforge_module_imports_from_workspace` |
| 17 | `nivxforge/tests/test_workspace_compatibility.py::test_nivxforge_router_not_registered_in_workspace_server` |
| 18 | `nivxforge/tests/test_workspace_compatibility.py::test_workspace_protected_paths_intact` |
| 19 | `nivxforge/tests/test_workspace_compatibility.py::test_importing_nivxforge_has_no_workspace_side_effects` |

### Workspace regression (pre-existing · re-run for compatibility) (7)

| # | Test |
|---|---|
| 20 | `tests/test_phase1a_plain_text_cli.py::test_verdict_band_is_unknown_not_benign` |
| 21 | `tests/test_phase1a_plain_text_cli.py::test_verdict_reason_cites_insufficient_evidence` |
| 22 | `tests/test_phase1a_plain_text_cli.py::test_no_forbidden_phrases_anywhere_in_output` |
| 23 | `tests/test_phase1a_plain_text_cli.py::test_no_zoom_vendor_claim` |
| 24 | `tests/test_ps_ascii_xor_iex_output_selection.py::test_ps_ascii_xor_iex_handler_produces_correct_plaintext` |
| 25 | `tests/test_ps_ascii_xor_iex_output_selection.py::test_ps_ascii_xor_iex_engine_name_stable` |
| 26 | `tests/test_ps_ascii_xor_iex_output_selection.py::test_ps_ascii_xor_iex_recipe_replay_is_not_self_reproducible` |

**Result:** `26 passed, 0 failed` in a single pass.

---

## 5 · Compatibility guarantees (verified)

| Guarantee | Method | Result |
|---|---|---|
| Zero Workspace source modifications outside earlier hotfix scope | `grep -c "nivxforge" server.py` = 0 | ✅ |
| Workspace API surface unchanged | `curl /api/health` = 200 | ✅ |
| No new API route reachable via `/api/*` | `curl /api/nivxforge/health` = 404 | ✅ |
| NivXForge imports zero Workspace modules | Static AST scan test | ✅ |
| Importing NivXForge triggers no Workspace side effects | Runtime `sys.modules` diff test | ✅ |
| Existing Workspace regression tests still green | 7 tests re-run in the same pass | ✅ |
| No new backend dependencies introduced | Only stdlib + fastapi + pydantic (already used) | ✅ |
| No new Mongo collection created | `forge_*` prefix reserved but unused | ✅ |
| No new env var read in Phase 0 | `FORGE_ENABLED` reserved; default `False` | ✅ |

---

## 6 · Known limitations (deliberate)

- **Router is unmounted.** `/api/nivxforge/*` is unreachable by design.
  Phase 0 contains no runtime capability.
- **CIO and Evidence Ledger have no writers.** Their shape is locked
  but no engine emits data into them yet.
- **Engine Protocol has no implementations.** `_NoopEngine` in the tests
  is a fixture only, not a shipped engine.
- **No UI.** The `frontend/src/nivxforge/` folder is a README-only
  namespace reservation.
- **Compatibility contract for future NivXForge releases is partial.**
  Phase 0 verifies structural non-mutation; behavioral golden-baseline
  comparisons will be added when the first real NivXForge feature ships.

None of the above are defects. They are the boundaries Phase 0 was
scoped to draw.

---

## 7 · Activation criteria for Phase 1

Phase 1 (or any subsequent NivXForge phase) does not begin
automatically. The full entry gate in
`/app/memory/IMPLEMENTATION_ROADMAP.md §1` applies:

```
Observed Need
    ↓
Repeated Evidence     (real cases in REAL_WORLD_LOG.md)
    ↓
Architecture Decision Record (ADR)
    ↓
Charter compatibility check
    ↓
Workspace Protection review
    ↓
Roadmap approval (append to IMPLEMENTATION_ROADMAP.md §3)
    ↓
Implementation
    ↓
Validation (regression + compat + benchmarks)
    ↓
Release
```

Additional preconditions specific to Phase 1:

- The Missing-Evidence tally in the scorecard (`PRODUCT_CHARTER.md §4.5`)
  must show a repeated pattern (≥ N cases as agreed in the ADR).
- An ADR must exist under `/app/memory/adr/` (folder to be created on
  first ADR) that names the specific capability being lifted out of the
  North Star into the Roadmap.
- The Workspace Compatibility Contract must be extended to cover the
  behavioral surface the new capability could affect (even indirectly).
- Router mounting (Decision A1 reversal) requires an explicit
  paragraph in the ADR justifying the runtime integration point.

Until all preconditions are met, NivXForge remains **dormant**.

---

## 8 · Deferred items (explicitly NOT in Phase 0)

The following were identified but intentionally deferred per governance.
They do NOT block Phase 0 close-out:

| Item | Reason for defer |
|---|---|
| Delete dead `DashboardPage.jsx` | Workspace maintenance, not NivXForge. Follows the normal Workspace change process. |
| `xor-brute` hard input-size cap | Workspace technical debt. Follows the normal Workspace change process. |
| Verdict-Evidence Gating (Gap #2) | Requires more real-case evidence per Charter Principle P-C. |
| Recipe self-reproducibility (server-side fix) | Frontend guard covers current harm; server-side hardening awaits evidence of harm at scale. |

---

## 9 · Sign-off

- **Governance triad in force:** `PRODUCT_CHARTER.md` · `NORTH_STAR.md` · `IMPLEMENTATION_ROADMAP.md`
- **Workspace protection:** verified, zero mutations
- **Test suite:** 26/26 passed in a single validation pass
- **Runtime coupling:** none (router dormant)
- **Next action:** maintenance mode — wait for the next real SOC case or an approved ADR before any further implementation

Phase 0 is **closed**.
