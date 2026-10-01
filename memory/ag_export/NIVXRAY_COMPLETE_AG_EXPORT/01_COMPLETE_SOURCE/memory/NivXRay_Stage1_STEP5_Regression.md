# NivXRay Stage 1 · STEP 5 — Compatibility + Regression Design

**Date:** 2026-02-14
**Prerequisites:** STEP 1 (v3) audit · STEP 2 (Reuse Matrix) · STEP 3 (Compatibility) · STEP 4 (Data Flows)
**Scope:** Prove — by design — that Stage 1 keeps every existing path bit-identical when `IUE_STRUCTURED_LANE=off`, and remains contract-compatible when the flag is flipped. Zero code.
**Gate:** STOP at end. STEP 6 (implementation) remains LOCKED.

---

## 0. What "compatibility" means in Stage 1

Three tiers, in decreasing strictness:

| Tier | Applies to | Guarantee |
|---|---|---|
| **T1 · Byte-identical** | Fix 1 `acquisition_failed` envelope · existing `report_extraction` keys · SSOT authoritative-tier writes · Prod-mode `build_session` output shape · Prev-mode `render()` output shape | Output bytes MUST match today when flag=off. Golden fixtures pin this. |
| **T2 · Contract-compatible** | New `report_extraction` keys (`logical_events`, `intake_decision`, `iue_failures`, `content_fingerprint`) | Additive only. No consumer errors on unexpected keys (Python dict access is tolerant). |
| **T3 · Behaviourally-equivalent** | UAIE recursion / ledger / depth cap · ICE `_build_incident` reunification · P1a projection | Semantics unchanged. IUE recurse.py must produce the same ledger state as a direct UAIE call for the same input. |

---

## 1. Aggregation ≠ Correlation (locked, three-ways)

This is the single most consequential design boundary in Stage 1. Stated three ways to make regression testable:

### 1.1 Definitional

- **Aggregation** (`services/iue/aggregator.py`) collapses records that share every canonical grouping key (STEP 3 §3.4). It preserves count, first/last seen, provenance, and `record_refs`. It does **not** infer relationships across events.
- **Correlation** (`services/ice/correlate.py::_build_incident`) unifies events across tenants/devices/processes/users/sessions/artifacts/timestamps/entities into a single incident graph. It reads report_extraction + IKG and produces incident-level narrative.

### 1.2 Operational

- Aggregator input: `Iterable[NormalizedRecord]` from ONE file.
- Aggregator output: `list[LogicalEvent]` — each event traces back to N ≥ 1 raw records in the same file.
- ICE input: report_extraction from potentially multiple sources plus SSOT graph.
- ICE output: incident graph with cross-source edges.

### 1.3 Regression-test statable (STEP 6 must implement these)

- `test_iue_aggregator_does_not_correlate_across_files.py`: submit two NDJSON files with identical grouping keys → aggregator returns 2 separate `LogicalEvent` lists (one per file), not 1. ICE (called later) unifies them into 1 incident.
- `test_iue_aggregator_preserves_provenance.py`: every `LogicalEvent.record_refs` is a non-empty subset of the input `record_id`s.
- `test_ice_correlation_unchanged.py`: golden fixture — same input, same ICE incident graph output before and after Stage 1 wiring (with `IUE_STRUCTURED_LANE=off`).

---

## 2. Regression matrix — existing paths proved unchanged

Each row lists an existing user-visible or contract-visible behaviour, the test that pins it today (where one exists), and the STEP 6 test that will prove it stays green when Lane A is added.

| # | Existing behaviour | Owner file(s) | Existing test (grep-verified) | Stage 1 regression test |
|---|---|---|---|---|
| 1 | Fix 1 `acquisition_failed` envelope shape when URL fetch fails | `services/die/investigation_results.py` L478–505 | (implicit in Prev-mode integration tests) | `test_iue_fix1_parity.py` — golden dict equality against fixture |
| 2 | Prev-mode `render()` output for CISA advisory URL (P1a case) | `services/die/investigation_results.py::render()` | `/app/backend/tests/canonical/iue/test_prev_mode_p1a_evidence_source.py` | Same test remains green; flag=off |
| 3 | Prod-mode `build_session` output shape | `services/session/adapter.py::build_session` L315 | (Prod-mode gate tests) | `test_iue_prod_session_shape_unchanged.py` — flag=off golden JSON diff |
| 4 | ICE `_build_incident` graph output | `services/ice/correlate.py::_build_incident` L1206 | (existing ICE tests) | `test_ice_correlation_unchanged.py` |
| 5 | SSOT authoritative tier writes | `canonical/ssot/authoritative.py`, `services/ssot_store.py` | (SSOT integration tests) | `test_iue_ssot_write_shape_unchanged.py` |
| 6 | P1a projection (MITRE / Actors / Malware / Behaviors) | `services/die/investigation_results.py` (P1a additions) | `/app/backend/tests/canonical/iue/test_prev_mode_p1a_evidence_source.py` | Same test remains green; flag=off |
| 7 | Phase-D lazy `InvestigationGraph` chunk | `frontend/src/components/ThreatAnalysis.jsx` | (frontend smoke) | Untouched — Stage 1 is backend-only |
| 8 | UAIE recursion cycle detection | `services/uaie/orchestrator.py`, `services/uaie/ledger.py` | (UAIE ledger unit tests) | `test_iue_recurse_shares_uaie_ledger.py` |
| 9 | Command normalizer output | `services/die/preprocessor/command_normalizer.py` | (unit) | Untouched |
| 10 | Existing input classifier vocabulary | `services/ida/input_classifier.py::IDA_INPUT_CLASSES` | `services/ida/input_classifier.py` inline docstring examples | `test_iue_intake_preserves_ida_class.py` — every `IDA_INPUT_CLASSES` value still emitted verbatim in `IntakeDecision.ida_class` |
| 11 | Existing IUE-1 vocabulary | `services/die/input_understanding.py::classify` | `/app/backend/tests/test_input_understanding.py` | `test_iue_intake_preserves_iue_type.py` — every existing type still surfaces as `IntakeDecision.iue_type` |
| 12 | Frontend Prev-mode WorkspacePage projection | `frontend/src/pages/WorkspacePage.jsx` (P1b fixes) | (frontend Playwright suite) | Untouched — same `report_extraction` keys arrive |

**Rows 1–6 are T1 (byte-identical) guarantees.** Rows 7–12 are T3 (behaviourally equivalent).

---

## 3. Proof obligations (STEP 6 must satisfy these before merge)

The following are the concrete regression proofs that MUST be executed before Stage 1 is considered production-ready. They are enumerated here so that STEP 6 cannot omit them.

### 3.1 Byte-identical proofs (T1)

- **P1** Fix 1 golden equality. Fixture: broken-URL submission. Expected: identical serialised `report_extraction["acquisition_failed"]` shape with and without Lane A wired.
- **P2** Prev-mode CISA advisory golden. Fixture: known CISA URL (mocked HTML). Expected: identical `report_extraction.mitre_techniques`, `threat_actors`, `malware_families`, `behaviors`, `evidence_source`, `evidence_source_url` before/after.
- **P3** Prod-mode session golden. Fixture: known text sample. Expected: identical `build_session()` JSON output before/after (with tenant fixed).
- **P4** SSOT write golden. Fixture: same investigation. Expected: identical authoritative-tier serialised bytes.
- **P5** ICE incident golden. Fixture: known multi-artifact investigation. Expected: identical `_build_incident()` output edges/nodes.

### 3.2 Contract-compatibility proofs (T2)

- **P6** `report_extraction` superset check. Expected: every existing key still present; new keys (`logical_events`, `intake_decision`, `iue_failures`, `content_fingerprint`) are additive.
- **P7** No consumer raises on new keys. Sweep of every reader of `report_extraction` (grep for `report_extraction[` and `report_extraction.get(`) verifies tolerance.

### 3.3 Behavioural-equivalence proofs (T3)

- **P8** Recursion parity. Same input walks UAIE-direct vs IUE-recurse; ledger fingerprint set identical after each round.
- **P9** Depth-cap parity. UAIE `max_depth=12` reached via IUE-recurse produces identical `SKIP_DEPTH_CAP` behaviour.
- **P10** Cycle detection parity. Same cycle detected regardless of entry path.
- **P11** Aggregation-does-not-correlate. Two files with identical grouping keys → 2 separate LogicalEvent lists at aggregator; 1 incident at ICE.
- **P12** Aggregation preserves provenance. Every `LogicalEvent.record_refs` equals the union of collapsed `ParsedRecord.record_id`s.

### 3.4 Security proofs (v3 §23)

- **P13** Size cap. File > cap → `IUEFailure(collect_size_exceeded)`, no bytes read into memory beyond the cap.
- **P14** Decompression bomb. Nested archive → `collect_denied_by_policy` at cap, no OOM.
- **P15** Path traversal. Archive with `../` entries → `collect_denied_by_policy`.
- **P16** SSRF unchanged. Existing acquisition guards still fire; IUE adds no bypass path.
- **P17** Tenant isolation. Prod-mode never leaks records across tenants; test walks two tenants, asserts SSOT reads scoped.
- **P18** Recursion cap. Depth > 12 → `recurse_depth_exceeded`, no runaway.

### 3.5 Feature-flag proofs

- **P19** Flag off → Lane A code paths unreached in production traffic. Coverage check on production trace.
- **P20** Flag off → all T1/T3 proofs still pass.
- **P21** Flag on → new Lane A functionality demonstrable via NDJSON fixture (STEP 4 §1.2 micro-flow).
- **P22** Flag override at test time → CI exercises both states of the flag.

---

## 4. Consolidation of pre-existing duplication (audit-only in Stage 1)

STEP 3 §8 risk 1 called out that `services/die/input_understanding.py` and `nivxforge/investigation/input_understanding.py` are **two existing IUE modules**. Stage 1 does not touch either. STEP 5 formally acknowledges this and locks:

- `services/die/input_understanding.py` — the authoritative IUE for Prev-mode + Prod-mode. Referenced by `investigation_results.py` L332.
- `nivxforge/investigation/input_understanding.py` — an older/parallel module. STEP 5 marks it as a **Stage-2 reconciliation task** and forbids Stage 1 from adding new callers.

**Audit action for STEP 6 preparation:** grep every call site of `nivxforge/investigation/input_understanding.py`. If any live production code path reaches it, that path must be surveyed for parity with the authoritative module *before* Stage 2 begins. This is documented as backlog, not blocking Stage 1.

---

## 5. Failure of the compatibility contract — how STEP 5 detects it

Compatibility is broken by:

1. **A T1 fixture drifts.** Golden files updated silently. Mitigation: golden files are checked-in, human-readable JSON; every PR touching Stage 1 requires golden re-approval.
2. **A `report_extraction` key changes type.** Mitigation: P6 sweep runs on every PR.
3. **A new lane bypasses `intake()`.** Mitigation: STEP 3 §5 recursion contract; test `test_iue_no_bypass.py` asserts every new call site goes through `intake()`.
4. **Feature flag read at more than one location.** Mitigation: STEP 3 §7 pins single call site; `test_iue_flag_single_read.py` asserts (via ast walk) the flag is read only in `services/iue/intake.py`.
5. **Aggregator invoked on non-structured lanes.** Mitigation: STEP 4 §5 invariant #3; `test_iue_aggregator_lane_scoped.py` asserts aggregator called only on Lane A.
6. **UAIE ledger writes from IUE recurse diverge from UAIE-direct recurse.** Mitigation: P8/P9/P10.
7. **New IUE modules invent a second Provenance schema.** Mitigation: `test_iue_provenance_schema.py` — grep-based, asserts no `@dataclass` in `services/iue/**` declares `engine` + `version` + `at` fields outside of composition with existing `Provenance`.

Each failure mode has a named regression test scheduled for STEP 6.

---

## 6. Contradictions & residual risks surfaced (per owner directive)

| # | Residual risk | Severity | Design mitigation | Requires user acknowledgement before STEP 6? |
|---|---|---|---|---|
| 1 | Golden fixtures for P1–P5 do not yet exist as checked-in artefacts. STEP 6 will need to generate them from current `main` before wiring Lane A. | HIGH | STEP 6 opening task: capture goldens from current production paths *before* introducing any IUE code. Only then start wiring. | ✅ YES — owner must acknowledge that Stage 1 STEP 6 begins with fixture capture, not code. |
| 2 | Prev-mode `__prev_public__` tenant fallback (STEP 3 §4) weakens tenant isolation contract for the Prev route. | MEDIUM | Documented explicitly. Prod-mode strictly enforces tenant presence. Prev-mode is single-user by design. | ✅ YES — owner must acknowledge Prev-mode tenant fallback is intentional. |
| 3 | Feature flag `IUE_STRUCTURED_LANE` has no admin UI. Flip requires env-var deploy. | LOW | Acceptable for Stage 1 rollout. Admin toggle is a Stage-2 concern. | ⚠️ Nice-to-have acknowledgement. |
| 4 | Second existing IUE (`nivxforge/investigation/input_understanding.py`) not consolidated in Stage 1. | MEDIUM | Explicitly deferred (§4). No new callers added. | ✅ YES — owner must acknowledge Stage-2 reconciliation task exists. |
| 5 | 1-second aggregation bucket may not match all customer telemetries. | LOW | Documented as intentional Stage 1 pin. Configurable is Stage 2. | ⚠️ Nice-to-have. |
| 6 | Structured-event → MITRE dispatcher inside `understanding.py` risks growing into a second IUE. | MEDIUM | STEP 4 §7 contradiction 1: capped at 40 LOC in `understanding.py`; if exceeded, split. | ✅ YES — owner must acknowledge the 40-LOC ceiling as a hard rule for STEP 6. |
| 7 | UAIE ledger sharing across orchestrator instances is unverified in code. | HIGH | P8/P9/P10 proofs are mandatory before STEP 6 merges Lane A. | ✅ YES — owner must acknowledge UAIE ledger parity is a merge gate. |
| 8 | `services/artifact_intelligence/` was chosen as the primary artifact contract (STEP 3 §8 risk 6). If it diverges from `services/ida/artifact_router.py`, Lane C's wrapper picks the wrong one. | MEDIUM | STEP 6 first task on Lane C: verify contract equivalence, or explicitly declare the primary owner. | ✅ YES — owner must acknowledge artifact-router consolidation review before Lane C wiring. |

Items marked ✅ YES must be explicitly acknowledged by the owner before STEP 6 begins. They constitute the STEP-6 pre-condition set.

---

## 7. Migration & rollback plan

**Rollout:**

1. Merge STEP 6 with `IUE_STRUCTURED_LANE=off` in all environments.
2. CI proves T1/T2/T3 tiers via P1–P22.
3. Preview environment flip: `IUE_STRUCTURED_LANE=on` in preview only. Run smoke tests.
4. Production flip: env-var update, no code deploy.

**Rollback:**

- Remove the env var → Lane A code inert.
- If a T1 fixture regresses in production: revert the deploy that flipped the flag; no code revert required.
- If Lane A code itself regresses under flag=off (should be impossible if design honoured): standard revert.

**Blast radius:** with flag off, Lane A introduces zero production traffic. Blast radius under flag off = 0. Blast radius under flag on = structured-log submissions only.

---

## 8. Definition of "STEP 5 complete"

- ✅ Compatibility tiers T1/T2/T3 defined (§0).
- ✅ Aggregation vs. Correlation locked, three-ways, testable (§1).
- ✅ Regression matrix drawn against 12 existing behaviours (§2).
- ✅ 22 proof obligations enumerated (§3.1–3.5), each mapped to a named STEP 6 test.
- ✅ Pre-existing duplication (§4) audited and deferred to Stage 2 with a named backlog item.
- ✅ 7 compatibility-failure modes enumerated with matching regression tests (§5).
- ✅ 8 residual risks surfaced (§6); 6 flagged for owner acknowledgement before STEP 6.
- ✅ Rollout / rollback plan stated (§7).
- ✅ Zero code written.

---

## 9. Combined design summary (STEPS 3 + 4 + 5)

| Artefact | Location | Status |
|---|---|---|
| STEP 3 · Compatibility layer | `/app/memory/NivXRay_Stage1_STEP3_Compatibility.md` | ✅ delivered |
| STEP 4 · Data flows | `/app/memory/NivXRay_Stage1_STEP4_DataFlows.md` | ✅ delivered |
| STEP 5 · Regression + compatibility | `/app/memory/NivXRay_Stage1_STEP5_Regression.md` | ✅ delivered (this doc) |
| STEP 6 · Implementation | — | 🔒 **LOCKED** — awaiting owner authorisation |

**STOP.** Awaiting owner review of the three design artefacts and explicit acknowledgement of the six items marked "✅ YES" in §6. Once acknowledged, STEP 6 may commence with the fixture-capture task (§6 residual risk 1).
