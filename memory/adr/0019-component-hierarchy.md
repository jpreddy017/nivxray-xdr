# ADR-0019 · Component Hierarchy

**Status**: Accepted · **Phase -1 · Architecture Lock**

## Context

Constitution §10: every component declares its CIO fields, dependencies, tests, a11y, keyboard shortcuts, perf budget. §12: no implicit dependencies.

## Decision

Six-tier hierarchy. Every file belongs to exactly one tier. Cross-tier imports flow downward only (higher-tier imports lower-tier; never the reverse).

```
Tier 1 · AppShell           (root routing + providers + theme + a11y roots)
Tier 2 · Workspace          (InvestigateShell — the CIO-loaded shell)
Tier 3 · Lens               (Story · Source · Behavior · Timeline · ATT&CK · Entity · Report · Knowledge)
Tier 4 · Panel              (VerdictRibbon · FindingsPanel · EvidenceBar · CaseSpine · Notebook)
Tier 5 · Widget             (EvidenceToken · DecodeLadderRung · TacticCard · ConfidenceDots · CategoryBadge · TimelineScrubber)
Tier 6 · Primitive          (Button · Input · Dialog · Tooltip · Popover — token-driven Radix wrappers)
```

Every component file declares (in a JSDoc block at the top):

```
@tier         (1..6)
@consumes     (CIO fields — dotted paths)
@publishes    (Selection actions / events)
@deps         (siblings on same tier, only when unavoidable)
@a11y         (role, aria-*, focus behaviour)
@keyboard     (shortcuts owned)
@perf         (initial render budget in ms)
@tests        (unit + component + visual)
```

Storybook stories are mandatory from Tier 3 down. **Every new React component MUST ship with a `*.stories.tsx` file BEFORE it is considered complete** (operator directive 2026-02-28) — enables independent visual review, catches regressions, and naturally builds the reusable design system.

## Consequences

- No Widget imports a Panel. No Primitive imports anything above Tier 6.
- ESLint import-order rule enforces the tier direction (custom rule).
- A missing header block fails CI.
- Adding a new lens is additive — never modifies existing lenses.
