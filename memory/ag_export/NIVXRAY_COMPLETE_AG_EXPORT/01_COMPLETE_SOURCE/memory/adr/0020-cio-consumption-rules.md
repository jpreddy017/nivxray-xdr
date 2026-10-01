# ADR-0020 · CIO Consumption Rules

**Status**: Accepted · **Phase -1 · Architecture Lock**

## Context

Constitution §3 & §12: the frontend is a pure consumer. Never duplicate backend logic. Never infer, calculate, or compose reasoning. This ADR codifies the exact mechanics.

## Decision

### 1 · Selector hooks are the only sanctioned way to read the CIO

```
useCIO()                → the whole object (rarely needed)
useSummary()            → cio.summary
useVerdict()            → cio.verdict
useGraph()              → cio.evidence_graph
useTimeline()           → cio.timeline
useEntity(id)           → resolves a node by id
useAttackChain()        → cio.summary.attack_chain
useKeyFindings()        → cio.summary.key_findings
useUnknowns()           → cio.summary.unknowns
useRecommendations()    → cio.summary.recommendations
useSchemaVersion()      → cio.schema_version
```

Every hook does ONE thing: return a slice of the CIO. **No transformation. No sorting. No filtering. No formatting.**

### 2 · Forbidden operations

- Client-side prose composition (verdict text, summary text, recommendation text)
- Client-side confidence calculation
- Client-side ATT&CK inference
- Client-side IOC classification (backend already ran `ioc_classifier.py`)
- Client-side priority scoring (already computed by `evidence_priority.py`)
- Merging or de-duplicating CIO arrays (backend already deduped)
- Reordering arrays (backend already sorted by weight / confidence)

### 3 · Sanctioned client-side transformations

Only three:
- **Text truncation** for layout (e.g. `label.slice(0, 60) + "…"`) — display only, original preserved on hover
- **Grouping for rendering** (e.g. group nodes by kind for a section header) — never changes counts
- **Local UI state** (hover, expand/collapse, focus) — never persisted, never affects CIO

### 4 · Missing fields

If `cio.summary.entities_digest.hosts === []`, render the empty state `"No hosts recorded"`. Never `"Loading…"` unless the network request is genuinely in flight. Never silently hide.

### 5 · Schema-version guard

Every entry to the Workspace calls `useSchemaVersion()` and mounts a `<SchemaGuard>` component. If `cio.schema_version` is not in the allow-list, render a friendly upgrade notice and refuse to render lenses. Prevents silent drift.

### 6 · Enforcement

- ESLint rule: components in `lenses/` / `panels/` / `widgets/` may only import from `hooks/useCIO*`, `stores/`, `components/primitives`, and `lib/tokens`.
- Any direct network call (fetch / axios / EventSource) inside a component file fails CI.

## Consequences

- Backend can evolve prose, order, priority, and classification without any frontend change.
- Frontend bugs cannot corrupt investigation results (the CIO is read-only from the frontend's perspective).
- Debugging is triage-by-hook: if a value looks wrong, the fix is in the backend composer, not the component.
