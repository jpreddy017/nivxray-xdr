# Release Validation Report · TEMPLATE

> Every release (RC, beta, GA, patch) produces one file in this
> directory named `<RELEASE>-<date>.md` (e.g. `RC3.2-2026-03-15.md`).
> This is engineering hygiene — NOT an architectural artefact.
> It aggregates the Completion Records merged since the previous
> release into a single executive view.
>
> Follows the same governance rules as `/app/docs/completions/`: does
> not modify the Constitution, does not reopen architectural debate.

---

## Release
`<e.g. RC3.2>`

## Date
`<YYYY-MM-DD>`

## Previous release
`<e.g. RC3.1 · 2026-03-01>`

## Backlog Items Completed
_Bullet list of backlog IDs merged since the previous release. Each
must link to its Completion Record._

- `P1-01` — Live OSINT Wiring · `/app/docs/completions/P1-01-live-osint-wiring.md`
- `P2-08` — Investigation Ledger · `/app/docs/completions/P2-08-investigation-ledger.md`
- ...

## §13 KPI Board (release-over-release)

| KPI | Target | Previous | This Release | Δ | Status |
|-----|--------|----------|--------------|---|--------|
| Adapter detection accuracy         | ≥ 99 %  |  |  |  |  |
| Normalisation correctness          | ≥ 95 %  |  |  |  |  |
| Cross-vendor equivalence pass rate | 100 %   |  |  |  |  |
| Investigation replay determinism   | 100 %   |  |  |  |  |
| Verdict parity                     | 100 %   |  |  |  |  |
| E2E investigation latency P95      | ≤ 4 s   |  |  |  |  |
| Deep-command investigation success | ≥ 90 %  |  |  |  |  |
| Golden-corpus coverage             | ≥ 95 %  |  |  |  |  |

## Golden Corpus Changes
_Added / updated / removed corpora, per vendor. Rationale for each._

## Parity Status
_Verdict parity, cross-vendor equivalence, and replay determinism —
green / yellow / red per adapter._

## Constitutional Compliance
- [ ] No PR merged this release introduced a new architectural layer.
- [ ] No PR merged this release bypassed the CIO contract.
- [ ] No ADR was required (or, if required: linked below).
- [ ] Every merged item has a Completion Record.

## ADRs merged this release
_None (default). If any ADR filed → link + short justification._

## Known Limitations
_Anything shipped intentionally incomplete, with follow-up backlog IDs._

## Sign-off
_Release manager · date · reviewers._
