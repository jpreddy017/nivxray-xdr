# Completion Record · TEMPLATE

> Every merged backlog item produces one file in this directory named
> `<BACKLOG_ID>-<slug>.md` (e.g. `P1-01-live-osint-wiring.md`). This
> is engineering hygiene — NOT an architectural artefact.
> It complements governance; it does not change the Constitution.

---

## Backlog ID
`<e.g. P1-01>`

## Objective
_One sentence stating the intent from `/app/docs/BACKLOG.md`._

## Implementation
_Files touched, endpoints added, components introduced. Bullet list._

## Tests Added
- Unit: `<path>`
- Integration: `<path>`
- Parity: `<path>` (if applicable)
- Golden corpus: `<path>` (if applicable)

## Golden Corpus Updated
_Yes / No. If yes, which corpora, which cases, and why._

## Parity Status
_All parity CI green? If not, which tests, which cases, and why deferral is acceptable._

## KPI Impact (§13)
| KPI | Before | After | Δ |
|-----|--------|-------|---|
| Adapter detection accuracy |  |  |  |
| Normalisation correctness |  |  |  |
| Cross-vendor equivalence  |  |  |  |
| Replay determinism        |  |  |  |
| Verdict parity            |  |  |  |
| E2E investigation latency P95 |  |  |  |
| Deep-command investigation success rate |  |  |  |
| Golden-corpus coverage    |  |  |  |

## Constitutional Compliance
- [ ] Preserves the CIO contract (§10)
- [ ] Adds no new architectural layer (§11)
- [ ] Consumes/emits only CIO or named CIO derivatives
- [ ] Remains deterministic
- [ ] Passes the four PR gates
- [ ] No ADR required (ADR checklist all-yes)

## Known Limitations
_Anything shipped intentionally incomplete, with the follow-up
backlog ID that will close it._

## References
- Backlog line: `/app/docs/BACKLOG.md`
- Constitution sections referenced: `<e.g. §8, §10>`
- ADRs (only if this item required one): `<n>-<slug>.md`
