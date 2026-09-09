# ADR-005 · Phase 4 Specification — Projection Tier

- **Status**: **SPEC only — awaiting owner review** (owner authorised Phase 4 to begin subject to gates 2026-08-10)
- **Prerequisites**: Phase 1 CLOSED, Phase 2 CLOSED, Phase 3 CLOSED, capability gaps recorded (`/app/memory/adr/0005-capability-gaps.md`)
- **Owner decisions**: D2-d (two-tier — projections are pure functions of the authoritative tier), INV-1 (no consumer becomes an SSOT), no-generic-recommendation-fallback rule.
- **Sample1 record**: NEVER modified (R-G1..R-G6, IX-1).
- **Amendment 2 (2026-08-10)**: comparisons against legacy oracles are **byte-identity** where legacy output is fully deterministic; **canonical-normalised** where legacy output is prose/narrative. Every allowed diff enumerated per input per projection with the comparison mode labelled.

## 1. Scope (this phase spec)

### Allowed in Phase 4
- Author every projection function as a **pure function of the authoritative SSOT tier**:
  - `project_verdict`, `project_attck`, `project_attack_chain`, `project_attack_story`,
    `project_evidence_graph_view`, `project_analyst_summary`, `project_executive_summary`,
    `project_recommendations`, `project_timeline`, `project_lolbas`, `project_iocs`,
    `project_activity`, `project_canonical`, `project_evidence_bundle`, `project_reports`.
- Golden-corpus test fixtures + allowed-diffs file.
- Determinism tests (100 replays × per projection).
- Sample.docx NEW-case projection assertions (using verified fixture `/app/memory/fixtures/Sample.docx`).

### NOT allowed in Phase 4
- ❌ Route changes / Workspace / cases.py.
- ❌ Any modification to existing SSOTs, executor, IUE, MDR pipeline, Engine A, canonical Verdict scoring, Wave 1 records.
- ❌ Any generic-recommendation fallback (`IMMEDIATE / THREAT HUNTING / CONTAINMENT` block MUST NOT appear).
- ❌ Populating authoritative SSOT fields (Phase 3 territory).
- ❌ Consumer switch (Phase 5).
- ❌ Phase 5 auto-start.
- ❌ Sample1 modification.
- ❌ TEXT_EXTRACT_FROM_ARCHIVE (deferred per capability-gaps doc).

## 2. Firewall rules

- **P4-FW1 · Pure function**: every projection reads ONLY from `AuthoritativeSSOT` (no I/O, no network, no clock, no random). Enforced by unit tests that pass a hand-crafted SSOT and assert byte-identical outputs across replays.
- **P4-FW2 · Never populate authoritative fields**: projections MAY be written back into the SSOT's projection buckets (via a Phase-4-only helper), but never into `evidence_graph`, `reasoning_steps`, `artifacts`, `execution_trace`, `input_*`, or `iue_decision`.
- **P4-FW3 · No fallback templates**: `project_recommendations` MUST return empty + a reasoning step `"no evidence-derived recommendations for this case (no MITRE evidence)"` when SSOT has no MITRE. It MUST NOT emit the generic `IMMEDIATE / THREAT HUNTING / CONTAINMENT` block.
- **P4-FW4 · Legacy oracles**: legacy composers (MDR narrative/report/executive_card, DIE analyst_narrative, refresh_verdict) stay untouched. Phase 4 uses them as byte-oracle for comparison, not as dependencies.
- **P4-FW5 · Comparison mode explicit** (Amendment 2): every allowed diff labelled `byte_identity` OR `canonical_normalised`.

## 3. Deliverables

```
backend/canonical/projections/
├── __init__.py                    Public API: project_*(ssot)
├── verdict.py
├── attck.py
├── attack_chain.py
├── attack_story.py
├── analyst_summary.py
├── executive_summary.py
├── recommendations.py             NO generic fallback (P4-FW3)
├── timeline.py
├── lolbas.py
├── iocs.py
├── activity.py                    projection of InvestigationModel shape (SSOT-A)
├── canonical.py                   projection of die-Canonical shape (SSOT-B)
├── evidence_bundle.py             projection of EvidenceBundle shape (SSOT-E)
└── reports.py                     stix / sigma / yara / navigator / mdr

backend/tests/canonical/projections/
├── test_projection_purity.py           P4-FW1 (no I/O, no clock, no random)
├── test_projection_firewall.py         P4-FW2 (never write authoritative fields)
├── test_recommendations_no_fallback.py P4-FW3
├── test_projection_determinism.py      100 replays × each projection
├── test_projection_golden_corpus.py    per-input per-projection byte-identity OR canonical-normalised diff
├── test_projection_sample_docx.py      A4.1
└── test_projection_sample1_unchanged.py A4.2
```

## 4. Tests / gates

| Gate | File | Verifies |
|---|---|---|
| T4.1 · determinism | `test_projection_determinism.py` | `project_X(SSOT)` byte-identical across 100 replays per projection |
| T4.2 · golden-corpus parity | `test_projection_golden_corpus.py` | byte-identity OR canonical-normalised diff vs. legacy oracle |
| T4.3 · purity (INV-1 + P4-FW1) | `test_projection_purity.py` | no I/O, no clock, no random access; hand-crafted SSOT yields stable output |
| T4.4 · **no-fallback** (P4-FW3) | `test_recommendations_no_fallback.py` | empty MITRE SSOT ⇒ empty recommendations + reasoning step; no template |
| T4.5 · rebuild idempotence | `test_projection_determinism.py::rebuild` | projections regenerable from SSOT alone |
| T4.6 · isolation | (implicit via imports) | no projection reads outside `AuthoritativeSSOT` |
| P4.G1 · golden-corpus report | `/app/memory/adr/0005-phase4-projection-acceptance.md` | signed off before Phase 5 |
| P4.G2 · allowed-diffs report | `/app/memory/adr/0005-phase4-allowed-diffs.md` | per-input per-projection |
| A4.1 · Sample.docx acceptance | `test_projection_sample_docx.py` | canonical SSOT from real Sample.docx → each projection deterministic; recommendations = empty (no MITRE evidence) — NOT the generic template |
| A4.2 · Sample1 unchanged | `test_projection_sample1_unchanged.py` | fingerprint `5b4337d5…08261d` intact |

## 5. Amendment 2 categorisation

| Projection | Comparison mode | Reason |
|---|---|---|
| `project_iocs`, `project_lolbas`, `project_attck`, `project_timeline`, `project_activity`, `project_canonical`, `project_evidence_bundle` | **byte_identity** | Legacy oracle output is a structured list/dict — deterministic |
| `project_reports` (STIX / Sigma / YARA / Navigator) | **byte_identity** | Legacy output is machine-schema |
| `project_reports.mdr` | **byte_identity** for structured fields; **canonical_normalised** for prose sub-fields | Mixed |
| `project_verdict` (label + confidence + input_completeness) | **byte_identity** | Numeric + enum-labelled |
| `project_attack_chain` | **byte_identity** for stage structure; **canonical_normalised** for stage titles | Mixed |
| `project_attack_story`, `project_analyst_summary`, `project_executive_summary`, `project_recommendations` | **canonical_normalised** | Prose |

## 6. Sample1 protection

- Phase 4 projections run against **NEW ingestions** of Sample.docx via `/app/memory/fixtures/Sample.docx` (verified byte-identical to Sample1's DOCX source).
- Phase 4 NEVER writes to the Sample1 case row.
- `test_projection_sample1_unchanged.py` re-verifies the fingerprint at the end of the Phase 4 test run.

## 7. Exit condition

1. All T4.1..T4.6 + A4.1 + A4.2 tests green.
2. P4.G1 + P4.G2 sign-off reports produced.
3. Sample1 fingerprint verified unchanged.
4. Combined P1 + P2 + P3 + P4 test suite green.
5. Phase 4 report at `/app/memory/adr/0005-phase4-report.md`.
6. **STOP.** No Phase 5 auto-start.

## 8. Owner-approval required BEFORE implementation

This document is the Phase 4 **spec** only. Per the sequence gate, owner review of the spec is required BEFORE code is written for Phase 4. Two questions for the owner:

1. **Do you approve this Phase 4 spec's scope as written?** (15 projections; no generic fallback; byte-identity vs canonical-normalised categorisation per §5.)
2. **Do you approve the projection catalog?** Specifically:
   - Should `project_activity` / `project_canonical` / `project_evidence_bundle` — the "backwards-compat projections" for the three legacy SSOTs — be built in Phase 4, or deferred to Phase 5 EntryAdapter migration where their consumers actually live?
   - Should `project_reports` (STIX/Sigma/YARA/Navigator/MDR) be built in Phase 4, or deferred to a later phase since no consumer switch happens until Phase 5+?

On owner sign-off, implementation begins with the same gate pattern used for Phase 1/2/3.
