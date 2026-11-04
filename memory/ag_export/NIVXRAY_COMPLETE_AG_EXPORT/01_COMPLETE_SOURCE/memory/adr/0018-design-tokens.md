# ADR-0018 · Design Tokens

**Status**: Accepted · **Phase -1 · Architecture Lock**

## Context

Constitution §11: use semantic design tokens only. Never hardcode colours in components. Three themes required (Dark · Light · High-Contrast).

## Decision

Two-layer token system. Every visible property in the Workspace resolves through tokens.

### Layer 1 · Primitive tokens (per theme, hidden from components)

```
--color-slate-50 … --color-slate-950
--color-emerald-{100..900}
--color-amber-{100..900}
--color-rose-{100..900}
--color-sky-{100..900}
--color-neutral-{100..900}
```

### Layer 2 · Semantic tokens (the only ones components use)

```
--bg-canvas              --bg-panel             --bg-elevated
--fg-primary             --fg-quiet             --fg-accent
--border                 --border-strong        --border-focus
--verdict-critical       --verdict-suspect      --verdict-info      --verdict-benign
--evidence-token         --evidence-selected    --evidence-not-counted
--graph-lane-evade       --graph-lane-decode    --graph-lane-acquire   --graph-lane-execute
--space-1 … --space-8    (0.125rem × 2ⁿ)
--radius-sm --radius-md --radius-lg
--motion-quick (120ms)   --motion-narrative (260ms)   --motion-graph-reveal (380ms)
--font-sans              --font-mono
--fs-caption --fs-body --fs-strong --fs-h3 --fs-h2 --fs-h1
--fw-regular --fw-medium --fw-semibold --fw-bold
--elevation-1 --elevation-2 --elevation-3
```

Themes attach at `<html data-theme="dark|light|hc">`. Auto-follows `prefers-color-scheme` unless the analyst has set a preference.

### Rule

Components import ONLY semantic tokens. `bg-[#123456]` and hex literals are forbidden and blocked by ESLint (`no-restricted-syntax`).

## Consequences

- Adding a new theme = re-mapping semantic tokens to primitive palette. Zero component churn.
- Accessibility contrast is enforced at the token level (HC theme guarantees WCAG AAA).
- Motion-reduce media query overrides motion tokens globally.
