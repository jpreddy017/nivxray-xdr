# NivXRay · Roadmap · Product Hardening Phase
_Baseline: M2 Hero build (approved). New capability development frozen._

## Rule of the road
> Perfect one workflow → observe analyst → improve workflow → only then add capability.

No feature moves to the next phase until the phase it lives in is production-quality.

---

## P0 — Complete Investigation Experience (in-flight)
Hard block on any new capability until every box below is checked. Verified against
the six analyst tasks in `USABILITY_REVIEW.md`.

- [ ] Root process immediately identifiable on landing
- [ ] Parent-child ancestry rendered from real adapter data (blocked by P1)
- [ ] Process lifetimes render as accurate spans (start → end)
- [ ] Event density comparable to enterprise EDR (30+ rows in 900 px)
- [ ] Evidence panel synchronization is instantaneous on click
- [ ] Hover and selection states polished (no flicker, no lag, no dropped tooltips)
- [ ] Keyboard navigation complete (↑ ↓ ← → F H L Esc ⌘K ⌘\ ⌘D ?)
- [ ] Smooth pan, zoom, focus (60 fps sustained)
- [ ] Investigation workflow requires minimal scrolling (fit-to-content default)
- [ ] Every major analyst task completes naturally (see usability review)

## P1 — Adapter Ancestry (backend, engineering-priority)
Every emitted event must include: `entity.iid`, `parent.iid`, `root.iid`,
`process_start` (epoch ms), `process_end` (epoch ms).
Contract change lives in `/app/backend/v2/adapters/` and the shadow observation
schema. Without this, canvas ancestry is a heuristic. **Blocks P0 items 2 and 3.**

## P2 — Report Export
PDF · Markdown · JSON · STIX 2.1 · Evidence Package. Unlocks direct customer
value the moment P0 + P1 ship.

## P3 — Phase 2 (deferred)
- Analyst Playback
- Case Comparison

Not blockers. Do not start until P0 + P1 + P2 are complete.

---

## Milestone-closing template (all future milestones must follow this)
Each milestone ends with exactly four lines:
1. What was completed.
2. Screenshot or short video of the result.
3. Any blockers (if any).
4. The single next priority.

No feature suggestions, no roadmap speculation, no "next action items" list.
