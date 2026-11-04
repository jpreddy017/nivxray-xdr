# ADR-0016 · State Management

**Status**: Accepted · **Phase -1 · Architecture Lock**

## Context

Constitution §2: the CIO is the only source of truth. §12: no competing state. Frontend must never compose reasoning. State architecture must enforce this structurally.

## Decision

Three stores, no more. Each has one owner and one purpose.

```
SSE  →  API Client (fetch/EventSource wrapper)
             │
             ▼
     TanStack Query cache   ← keyed on cio_id
             │
             ▼
      CIO Store (Zustand · derived selectors)   ← useCIO() · useSummary() · useVerdict() · useGraph() · useTimeline() · useEntity(id)
             │
             ▼
   Selection Store (Zustand)                    ← useSelection() · setSelection(nodeId | entityId | tacticId)
             │
             ▼
   Workspace Store (Zustand)                    ← lens · split · layout · flags
             │
             ▼
              Components (subscribe via selectors)
```

- **No component owns business state.** Components read via selectors, write via actions on the three stores.
- **TanStack Query owns network + cache**; components never call `fetch` directly.
- **Selection Store is the workspace spine** (Constitution §4). Selecting anywhere writes here; every subscriber updates.
- **Workspace Store owns UI layout** (active lens, split ratio, panel visibility, saved workspaces).
- **CIO Store is read-only from the component's perspective.** Only TanStack Query populates it.

## Consequences

- Any prop drilling of CIO data through more than one component boundary is a code smell → replace with a selector.
- `useState` for business data is forbidden. `useState` is only for local UI state (hover, open/closed, transient input).
- Middleware (undo/redo, replay) attaches to the Selection Store first, then Workspace Store — never the CIO Store (immutable).
