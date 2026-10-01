# Architecture Decision Records (ADR)

_Empty on purpose. Every ADR that lands here represents evidence-earned
work about to enter `/app/memory/IMPLEMENTATION_ROADMAP.md §3`._

## When to write an ADR

An ADR is required before any code is written for:

- Any capability lifted from `/app/memory/NORTH_STAR.md` into
  `/app/memory/IMPLEMENTATION_ROADMAP.md §3`
- Any change to Workspace files beyond documentation / dead-code
  deletion (per Roadmap §5)
- Any router mount, dependency addition, or resource-namespace change
  in NivXForge (e.g. reversing Decision A1)
- Any change to the compatibility contract or the Workspace Protection
  Policy itself

If you are writing production code and no ADR exists, stop and write one.

## Filename convention

```
adr/NNNN-slug.md
```

- `NNNN` — zero-padded sequence number, starting `0001`
- `slug` — kebab-case one-line summary (e.g. `verdict-evidence-gating`)

## Mandatory sections

Every ADR MUST contain these six sections in this order. Anything less
is not eligible for Roadmap promotion (see `IMPLEMENTATION_ROADMAP.md §1`).

```markdown
# ADR NNNN — <one-line title>

- Status: Proposed | Accepted | Superseded by ADR-XXXX | Rejected
- Date: YYYY-MM-DD
- Author(s): <name(s)>

## 1 · Problem Statement
What recurring evidence are we addressing? State the concrete
analyst pain point in one paragraph.

## 2 · Supporting Evidence
Cite real SOC cases from `/app/memory/REAL_WORLD_LOG.md` by number.
No case list = no ADR. Include the Missing-Evidence tally row that
justifies the priority.

## 3 · Proposed Change
Which North Star item is being lifted into the Roadmap, and what
does the concrete first-cut implementation look like? Reference
files, modules, and data shapes. Do NOT propose more than one
capability per ADR.

## 4 · Alternatives Considered
List at least two alternatives and state why each was rejected.
"Do nothing" and "do it in Workspace" are always valid alternatives
that must be considered explicitly.

## 5 · Workspace Impact
- Is any Workspace file affected? Yes / No.
- If yes, name every file, describe the change, and justify against
  the Workspace Protection Policy (`NORTH_STAR.md §7`).
- If no, state which structural test will prove non-mutation
  (e.g. `test_workspace_compatibility.py`).

## 6 · Success Criteria
- Which regression tests prove the feature works?
- Which benchmark thresholds prove no performance regression?
- Which compatibility test proves Workspace behavior unchanged?
- Which Missing-Evidence row will drop in count when this ships?

## Consequences
Optional: describe follow-on work this ADR unlocks or forbids.
```

## Lifecycle

```
Proposed  →  Accepted  →  (feature ships)  →  Accepted forever
              ↓
         Superseded by ADR-XXXX
              ↓
           Rejected
```

Accepted ADRs are never edited. If a decision changes, write a new
ADR that supersedes the old one.

## Current ADRs

_None._ The first ADR will address the top row of the
Missing-Evidence tally in `PRODUCT_CHARTER.md §4.5` when the
scorecard's "Phase 1b justified?" flag reads `Yes`.
