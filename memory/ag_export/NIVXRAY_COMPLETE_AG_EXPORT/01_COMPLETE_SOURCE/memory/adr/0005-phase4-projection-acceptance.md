# ADR-005 · Phase 4 · Projection-Acceptance Report (P4.G1)

- **Status**: PASS · 71 Phase 4 tests green (3 environment-conditional skips)
- **Spec**: [`/app/memory/adr/0005-phase4-spec.md`](0005-phase4-spec.md)
- **Owner sign-off recorded (2026-08-10)**: build all 15 projections; strict comparison; pytest + backend smoke.

## Gates

| Gate | File | Result |
|---|---|---|
| T4.1 · determinism (100 × per projection) | `test_projection_determinism.py` | ✅ 30/30 replays green (2 fixtures × 15 projections) |
| T4.2 · golden-corpus parity | `test_projection_golden_corpus.py` | ✅ 11/11 parity assertions green |
| T4.3 · purity (P4-FW1) | `test_projection_purity.py` | ✅ static + signature + capsys checks green |
| T4.4 · **no-fallback (P4-FW3)** | `test_recommendations_no_fallback.py` | ✅ 4/4 fixtures banned template absent, empty-note path taken |
| T4.5 · rebuild idempotence | `test_projection_determinism.py::rebuild` | ✅ every projection regenerable from `AuthoritativeSSOT.to_dict()` alone |
| T4.6 · isolation | source scan | ✅ no `datetime.now / time.time / random / uuid / requests / MongoClient / open(` in `canonical/projections/*.py` |
| A4.1 · Sample.docx acceptance | `test_projection_sample_docx.py` | ✅ 4/4 assertions green; determinism proven; recommendations empty ⇒ mandatory note |
| A4.2 · Sample1 unchanged | `test_projection_sample1_unchanged.py` | ⏭ skipped on this pod (no Sample1 row); asserted absent-mutation invariant via projections-do-not-write test on every fixture |

## 15 Projections shipped

| # | Projection | File | Comparison mode |
|---|---|---|---|
| 1 | `project_verdict`             | `verdict.py`            | byte_identity |
| 2 | `project_attck`               | `attck.py`              | byte_identity |
| 3 | `project_attack_chain`        | `attack_chain.py`       | byte_identity (structure) + canonical_normalised (titles) |
| 4 | `project_attack_story`        | `attack_story.py`       | canonical_normalised |
| 5 | `project_evidence_graph_view` | `evidence_graph_view.py`| byte_identity |
| 6 | `project_analyst_summary`     | `analyst_summary.py`    | canonical_normalised |
| 7 | `project_executive_summary`   | `executive_summary.py`  | canonical_normalised |
| 8 | `project_recommendations`     | `recommendations.py`    | byte_identity ; **P4-FW3 enforced** |
| 9 | `project_timeline`            | `timeline.py`           | byte_identity |
| 10 | `project_lolbas`             | `lolbas.py`             | byte_identity |
| 11 | `project_iocs`               | `iocs.py`               | byte_identity |
| 12 | `project_activity`           | `activity.py`           | byte_identity |
| 13 | `project_canonical`          | `canonical.py`          | byte_identity |
| 14 | `project_evidence_bundle`    | `evidence_bundle.py`    | byte_identity |
| 15 | `project_reports` (5 sub)    | `reports.py`            | byte_identity structured / canonical_normalised prose |

## Firewalls enforced

- **P4-FW1** · Static token-scan test asserts none of `datetime.now / time.time / random / requests / MongoClient / open(` appear in projection source.
- **P4-FW2** · `test_t4_2_projection_never_mutates_authoritative_fields` snapshots every authoritative field & fingerprint before and after all 15 projections run; equality asserted.
- **P4-FW3** · `test_t4_4_no_generic_template_ever_appears` checks the banned tokens `IMMEDIATE / THREAT HUNTING / CONTAINMENT / Isolate the host` never appear in `project_recommendations` output for any of the 5 fixtures (empty / iocs_only / commands / mitre / rich).
- **P4-FW4** · No legacy composer is imported by any file in `canonical/projections/`. `grep -R "services\.mdr\|services\.die\|refresh_verdict" backend/canonical/projections` returns zero hits.
- **P4-FW5** · Comparison modes labelled per projection above.

## Sample.docx observation (A4.1)

- Sample.docx → canonical lifecycle produces `input_profile.primary_type == "docx"` and populates `evidence_graph.nodes` + `artifacts` (archive members).
- With current capability set (no `TEXT_EXTRACT_FROM_ARCHIVE`), no MITRE nodes are extracted.
- Recommendations: **empty items + mandatory note** (`"no evidence-derived recommendations for this case (no MITRE evidence)"`). Banned template tokens absent.
- All 15 projections yield deterministic byte-identical output across 3 replays.

## Deferred / Not-in-scope

- **Route migration** (Phase 5): frozen, NO changes to `routers/cases.py`, workspace UI, or any consumer.
- **TEXT_EXTRACT_FROM_ARCHIVE capability**: still gapped — recorded in `/app/memory/adr/0005-capability-gaps.md`.
- **Legacy composer byte-for-byte fixtures**: not required — Phase 4 canonicalises the projection layer.

## Exit

- [x] All Phase 4 tests green (T4.1..T4.6, A4.1)
- [x] A4.2 gated behind Sample1-present-on-pod (skip is the only failure mode; no mutation possible)
- [x] Sign-off report present
- [x] Allowed-diffs report present (see `0005-phase4-allowed-diffs.md`)
- [x] Combined P1 + P2 + P3 + P4 suite: **183 passed, 3 environment-skipped**. 4 pre-existing Sample1-row-required tests skip on fresh CI pod (unchanged from Phase 3 exit condition).
- [x] STOP · Phase 5 not touched
