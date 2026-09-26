# ADR-005 · Phase 1 Sign-off

- **Phase**: 1 — Canonical IUE Composer
- **Status**: **APPROVED / CLOSED** (owner sign-off 2026-08-10)
- **Report**: `/app/memory/adr/0005-phase1-report.md`
- **Spec**: `/app/memory/adr/0005-phase1-spec.md`

## Owner review outcome (verbatim summary)

- Implementation matches the sequence.
- 44/44 tests green (T1.1–T1.7 satisfied).
- Sample.docx tested as a NEW case (Sample1 record untouched — fingerprint `5b4337d5…08261d` re-verified unchanged).
- IUE-2 / IUE-3 / IUE-4 / IUE-5 all demonstrated to participate through the composer.
- Deterministic hash stable across 100 replays × 20-input corpus.
- Provenance envelope on every emitted evidence (D3-z).
- No-network constraint satisfied (INV-2).
- Zero existing files modified: no route, no Workspace, no MDR, no Engine A, no verdict, no Wave 1 change.
- Rollback is genuinely clean: nothing depends on `backend/canonical/` yet.
- The canonical IUE was built **beside** the existing architecture, not by migrating anything prematurely.

## What Phase 1 did NOT prove (deliberately)

- `Canonical IUE → Canonical SSOT → Executor → Analyzers → Attack Story / MITRE / Recommendations / Verdict / Reports` — that end-to-end lineage is Phase 2+ territory.

## Next authorised work

- **Phase 2 — Canonical SSOT authoritative tier**, and **only Phase 2**.
- Phase 3 / route migration / projections are NOT authorised.
- Sample1 remains untouched as the pre-canonical golden baseline.
