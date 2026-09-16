# ADR-0017 · Routing

**Status**: Accepted · **Phase -1 · Architecture Lock**

## Context

The Workspace is one context (one CIO loaded) with multiple lenses. Routing must reflect this: cases are addressable, lenses are addressable, and deep-links must survive browser refresh.

## Decision

React Router v6. Three URL primitives:

```
/nivxforge/investigate                      · Workspace shell, no case loaded (empty state)
/nivxforge/investigate/:cio_id              · CIO loaded · default lens (Story)
/nivxforge/investigate/:cio_id/:lens        · CIO loaded · explicit lens
/nivxforge/investigate/:cio_id/:lens/:nodeId  · lens open · specific evidence node pre-selected
```

Rules:
- `cio_id` is the deterministic `CIO-<hex12>` id emitted by the builder.
- `lens ∈ { story, source, behavior, timeline, attack, entity, report, knowledge }`.
- Split view uses a query param: `?split=behavior` opens `behavior` alongside the primary lens.
- Live-mode / static-mode is a query param: `?live=1`.
- Presence / collaboration state is NOT in the URL — kept in the Selection Store side-channel.

Route ownership:
- `nivxforge/routes/InvestigateShell.tsx` — the shell (TopBar + CaseSpine + LensCanvas outlet + FindingsPanel + EvidenceBar). Renders once.
- `nivxforge/lenses/<lens>/index.tsx` — one lens per file, lazy-loaded via `React.lazy`.

## Consequences

- Every URL is shareable and reproduces exactly what the analyst saw.
- Browser back/forward navigates lens history — not CIO history.
- CIO history is a Case Spine concept, not a routing concept.
- The current Workspace (`/auto-investigate`) route is untouched.
