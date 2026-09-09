# ADR-005 · Phase 2 Report — Canonical SSOT Authoritative Tier

- **Status**: **COMPLETE · awaiting owner sign-off**
- **Date**: 2026-08-10
- **Gate**: Design → Implement → **Tests (54/54 green + 44 Phase 1 still green = 98/98)** → **Sample.docx canonical SSOT constructed + store roundtrip verified** → **Determinism verified** → Owner review → **STOP**
- **Spec**: `/app/memory/adr/0005-phase2-spec.md`
- **Sample1**: **UNTOUCHED** (fingerprint `5b4337d5…08261d` re-verified unchanged)

---

## 1. Files added (Phase 2 only)

```
backend/canonical/ssot/
├── __init__.py                Public API
├── models.py                  Authoritative + projection dataclasses
├── authoritative.py           AuthoritativeSSOT (append-only, freeze, fingerprint)
├── ssot_ref.py                SSOTRef type + validation (D6-r)
├── store.py                   InMemorySSOTStore + Mongo SSOTStore (new collection)
└── projections.py             Phase 4 scaffold placeholder

backend/tests/canonical/ssot/
├── test_ssot_contract.py                (T2.1 · 10 tests)
├── test_ssot_provenance.py              (T2.2 · 6 tests)
├── test_ssot_append_only.py             (T2.3 · 6 tests)
├── test_ssot_determinism.py             (T2.4 · 5 tests)
├── test_ssot_ref_recursion.py           (T2.5 · 8 tests)
├── test_ssot_projection_boundary.py     (T2.6 · 8 tests)
├── test_ssot_isolation.py               (T2.7 · 3 tests)
└── test_ssot_sample_acceptance.py       (A2.1..A2.3 · 8 tests)
```

## 2. Test results

**Phase 2 alone: 54/54 green (3.80 s wall time).**
**Combined Phase 1 + Phase 2: 98/98 green (10.90 s wall time).**

| Gate | File | Result |
|---|---|:-:|
| T2.1 · contract vs ADR-005 §4.1 (25+ buckets) | `test_ssot_contract.py` | ✅ 10/10 |
| T2.2 · Provenance mandatory (D3-z) | `test_ssot_provenance.py` | ✅ 6/6 |
| T2.3 · Append-only invariant | `test_ssot_append_only.py` | ✅ 6/6 |
| T2.4 · Determinism / canonical JSON / sha256 | `test_ssot_determinism.py` | ✅ 5/5 |
| T2.5 · `ssot_ref` roundtrip + recursion (D6-r) | `test_ssot_ref_recursion.py` | ✅ 8/8 |
| T2.6 · Projection boundary | `test_ssot_projection_boundary.py` | ✅ 8/8 |
| T2.7 · Isolation from existing code | `test_ssot_isolation.py` | ✅ 3/3 |
| A2.1 · Sample.docx canonical SSOT | `test_ssot_sample_acceptance.py` | ✅ 3/3 |
| A2.2 · Store roundtrip | `test_ssot_sample_acceptance.py` | ✅ 2/2 |
| A2.3 · Sample1 fingerprint unchanged + no legacy collection touched | `test_ssot_sample_acceptance.py` | ✅ 2/2 |

## 3. Owner-defined Phase 2 acceptance requirements — verification

| # | Requirement | Verified by | Result |
|---|---|---|:-:|
| 1 | Canonical SSOT schema satisfies ADR-005 minimum information | `test_authoritative_ssot_has_all_required_top_level_fields` | ✅ 17 authoritative + 12 projection fields declared |
| 2 | Provenance is mandatory | `test_append_without_provenance_raises` + 5 more | ✅ Every bucket rejects no-provenance append |
| 3 | Fingerprint / addressability works | `test_to_ssot_ref_matches_fingerprint` + `test_store_put_get_roundtrip_byte_identical` | ✅ `cssot:sha256:<64hex>` |
| 4 | Append-only semantics work | `test_append_grows_bucket_monotonically`, `test_freeze_locks_future_appends` | ✅ mutation forbidden post-freeze; growth monotonic |
| 5 | Recursive child-artifact references work | `test_recursive_artefact_references_child_ssot`, `test_deep_recursion_two_levels_deep`, `test_a2_2_recursive_child_artefact_roundtrip` | ✅ 3-level chain traversal verified |
| 6 | Schema versioning works | `test_schema_version_is_declared` | ✅ `2.0.0-phase2` |
| 7 | Authoritative tier clearly distinguished from projections | `test_authoritative_populated_projections_empty_passes_guard`, 6× parameterised `test_every_projection_bucket_is_guarded` | ✅ `assert_projections_empty()` catches any projection bucket write |
| 8 | Deterministic serialization / fingerprinting works | `test_canonical_json_stable_across_replays` (50 replays), `test_key_order_does_not_affect_fingerprint` | ✅ byte-stable |
| 9 | Existing SSOTs remain untouched | `test_no_router_imports_canonical_ssot`, `test_no_service_imports_canonical_ssot` + git diff | ✅ zero imports; 0 route/service files touched |
| 10 | A new Sample.docx can be represented in the canonical SSOT without modifying Sample1 | `test_a2_1_*` + `test_a2_3_*` | ✅ new SSOT constructed; Sample1 fingerprint `5b4337d5…08261d` unchanged |
| 11 | Rollback leaves the existing NivXRay behavior completely unchanged | Zero imports of `canonical.ssot` outside its own namespace; new collection only | ✅ `rm -rf backend/canonical/ssot backend/tests/canonical/ssot` reverses Phase 2 in seconds |

## 4. "Not populated by copying one existing SSOT wholesale"

The canonical SSOT was built from the ADR-005 §4.1 contract, not copied from any existing SSOT:

- **From ADR-0014 CIO (donor)**: `evidence_graph{nodes, edges}` shape + `reasoning_steps` shape — but declared fresh in `canonical.ssot.models`, not imported.
- **From North Star CIO (donor)**: Mandatory per-entry `Provenance{engine, version, at, upstream_evidence_ids}` envelope — enforced at runtime via `AuthoritativeSSOT.append()`, not copied from `nivxforge/core/cio.py`.
- **From InvestigationModel (donor)**: `activity{processes, files, network, registry, auth}` typed activity buckets — declared as a **projection** (empty in Phase 2), NOT as an authoritative field.
- **From die-Canonical (donor)**: `plan[]` shape hint — but populated by the IUEDecision output, not by copying `Canonical.plan`.
- **From EvidenceBundle (donor)**: fingerprint-based determinism — implemented directly, not imported.

No `from services.die.canonical import Canonical`. No `from nivxforge.investigation.models import CIO`. No `from v2.investigation.model import InvestigationModel`. Verified by `test_no_service_imports_canonical_ssot` running the inverse (nothing imports us either) and by `grep`:

```
$ grep -rn "from services.die.canonical\|from nivxforge.investigation.models\|from v2.investigation.model\|from l2_investigation.schemas" backend/canonical/
(no results)
```

## 5. Sample.docx canonical SSOT (A2.1)

Fixture: `/app/backend/tests/live/ideas_updated.docx` (37 090 bytes).

Construction pipeline (Phase 2 only):
```
Sample.docx bytes
    │
    ▼
canonical.iue.classify()           ← Phase 1 output
    │
    ▼
IUEDecision (input_profile, input_health, plan, ...)
    │
    ▼
AuthoritativeSSOT.__init__(
    input_raw=docx_bytes,
    input_profile=iue.input_profile,
    input_health=iue.input_health,
    iue_decision=iue.to_dict(),
    plan=iue.plan,
    source=Source(channel="document_reinvestigate"),
    provenance=Provenance(engine="canonical.ssot.builder", ...),
)
    │
    ▼
.append("evidence_graph.nodes", GraphNode(id="input.root", kind="input", ...), PROV)
    │
    ▼
.freeze() + .fingerprint() + .to_ssot_ref()
    │
    ▼
cssot:sha256:<64-hex>   ← content-addressed SSOT reference
```

Result:
- `schema_version = "2.0.0-phase2"`
- `iue_decision.input_profile.primary_type = "docx"`
- `plan` populated (10 steps from Phase 1)
- `evidence_graph.nodes` = 1 (input.root)
- Every projection bucket EMPTY (`assert_projections_empty()` passes)
- Fingerprint deterministic across 20 replays (test `test_a2_1_sample_docx_ssot_is_deterministic`)

## 6. Store roundtrip (A2.2)

- `InMemorySSOTStore.put(ssot) -> ssot_ref` (content-addressed by sha256 fingerprint)
- `.get(ref) -> AuthoritativeSSOT` — byte-identical readback verified by `to_canonical_json()` string equality
- Idempotent: same-content `.put()` twice returns the same ref, count stays 1
- Recursive: parent SSOT carrying `artifacts[].investigation_ref = child_ref`; 3-level chain traversal verified

Mongo-backed `SSOTStore` (`test_a2_3_new_docx_case_does_not_touch_workspace_cases`) proves:
- Writes go to NEW `canonical_ssot_store` collection
- `workspace_cases` count unchanged (255 before → 255 after)
- `investigation_ssot` count unchanged (31 before → 31 after — legacy collection UNTOUCHED)

## 7. Sample1 fingerprint re-verification (A2.3)

| Metric | Value |
|---|---|
| Case ID | `3db79c4a-088b-4df7-b65a-f68b367b7677` |
| Recorded fingerprint | `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` |
| Live fingerprint post-Phase-2 | `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` |
| Status | **UNCHANGED** ✅ — R-G1..R-G6, IX-1 preserved |

## 8. Freeze integrity (Phase 2 forbidden actions)

| Constraint | Status |
|---|:-:|
| No `backend/routers/` file touched | ✅ |
| No frontend file touched | ✅ |
| No existing SSOT file touched (`nivxforge/investigation/models.py`, `v2/investigation/model.py`, `services/die/canonical.py`, `nivxforge/core/cio.py`, `l2_investigation/schemas.py` all bytes-identical) | ✅ |
| No Wave 1 modification (2 records still at original timestamps) | ✅ |
| No `investigation_ssot` legacy collection write | ✅ (31 → 31) |
| No `workspace_cases.ssot` write | ✅ (255 → 255) |
| No projection populated | ✅ (every projection bucket empty) |
| No route consumer of canonical.ssot | ✅ (isolation test green) |
| Sample1 unchanged | ✅ (fingerprint verified) |

`git diff --name-only` at end of Phase 2 → empty (all Phase 2 files are new/untracked).

## 9. Cross-phase invariants (from sequence)

| Invariant | Status |
|---|:-:|
| IX-1 Sample1 fingerprint re-verifiable | ✅ |
| IX-2 No cross-phase merging (Phase 2 gate closed before Phase 3) | ✅ |
| IX-3 No bypass movement | ✅ (no route redirected) |
| IX-4 Additive migration | ✅ (new module + new collection only) |
| IX-5 Feature-flag rollback | ✅ N/A (no consumer exists) |
| IX-6 Sign-off per file | ✅ (this report + Phase 1 sign-off) |

## 10. Rollback boundary

- Delete `backend/canonical/ssot/` and `backend/tests/canonical/ssot/`.
- Delete the `canonical_ssot_store` Mongo collection (`db.canonical_ssot_store.drop()` — 1 test row).
- No existing code depends on Phase 2.
- Time budget: seconds.

## 11. What Phase 2 did NOT prove (deliberately)

- No route entry point converges on the canonical SSOT (Phase 5).
- No Analyzer writes into the canonical SSOT (Phase 3 Executor).
- No projection is populated (Phase 4).
- No Verdict Engine consumes the canonical SSOT (Phase 9).

## 12. STOP

Per owner directive:

> *"Start ADR-005 Phase 2 only, following the existing implementation sequence and gates. Stop completely at Phase 2 completion for owner review. No Phase 3 or route migration."*

**Awaiting owner review.** Phase 3 (Canonical Executor) is NOT authorised until this report is signed off in `/app/memory/adr/0005-phase2-signoff.md` (or equivalent).

**Sample1 remains untouched. `canonical_ssot_store` is a new empty-almost collection (1 test row). All 5 legacy SSOTs remain byte-identical. All 9 legacy routes behave identically.**
