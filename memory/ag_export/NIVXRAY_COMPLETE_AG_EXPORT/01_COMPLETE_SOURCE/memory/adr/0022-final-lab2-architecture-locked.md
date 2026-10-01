# ADR-0022 · Final Lab 2.0 Architecture (Locked)

**Status**: ACCEPTED · LOCKED (2026-02)
**Supersedes**: ADR-0019 §3 (Lab 2.0 rendering strategy)
**Complements**: ADR-0014, ADR-0018, ADR-0020, ADR-0021

---

## 1. Objective

Lab 2.0 is **NOT** a separate application.
Lab 2.0 is the **next-generation renderer** of the existing
`LAB → Investigate` experience.

There must always be:

- One Investigate product
- One backend
- One Canonical Investigation Object (CIO)
- One frozen API contract

Only the **UI renderer** changes.

---

## 2. Navigation (Frozen)

Top-level navigation remains unchanged:

```
WORKSPACE · TRAJECTORY · BATCH · HEATMAP · LAB · TOOLS · LEARN · ADMIN
```

Inside `LAB`:

```
LAB
 ├── Investigate
 ├── Decode
 ├── History
 └── …
```

There will **NEVER** be a permanent "Lab 2.0" navigation item.

---

## 3. Routing (Stable)

Routing is stable:

```
/nivxforge/investigate          ← LAB → Investigate
```

**During migration only**, the same route accepts a query parameter:

```
/nivxforge/investigate?lab2=1
```

The `?lab2=1` flag is a **migration artifact**. It is removed at cutover.

---

## 4. Rendering Architecture

The route owns the experience. The renderer is selected internally.

```
/nivxforge/investigate
        │
        ▼
 InvestigationLoader
        │
        ▼
 FeatureFlagResolver
        │
 ┌──────┴─────────┐
 │                │
LegacyRenderer   Lab2Renderer (Lab2Shell)
```

The route never changes. Only the renderer changes.

---

## 5. Backend Architecture (Untouched)

```
Decode Engine
      │
Evidence Graph
      │
Verdict Engine
      │
Summary Composer
      │
Canonical Investigation Object (CIO)
      │
Frozen API Contract
```

**No renderer may bypass the CIO.** Backend is out of scope for this ADR.

---

## 6. Frontend Architecture

```
App
 │
 └── LAB
      │
      └── Investigate
              │
              ▼
      InvestigationLoader
              │
              ▼
      FeatureFlagResolver
              │
      ┌───────┴────────┐
      │                │
LegacyInvestigate   Lab2Shell
```

`Lab2Shell` is the **permanent workspace layout contract**:

```
Lab2Provider
    │
    ▼
Lab2Shell
├── AppHeader
├── VerdictRibbon
├── Toolbar
├── LeftNavigation
├── WorkspaceCanvas
├── RightContextPanel
└── StatusBar
```

Every future feature plugs into this shell. The shell remains stable.

---

## 7. Workspace Layout

```
┌────────────────────────────────────────────────────────────┐
│ Header                                                     │
├────────────────────────────────────────────────────────────┤
│ Verdict Ribbon                                             │
├────────────────────────────────────────────────────────────┤
│ Toolbar                                                    │
├───────────────┬─────────────────────────────┬──────────────┤
│ Left Nav      │ Workspace Canvas            │ Context      │
│               │                             │ Panel        │
│               │ Story                       │ Findings     │
│               │ Timeline                    │ Evidence     │
│               │ Graph                       │ Entities     │
│               │ ATT&CK                      │ Notes        │
│               │ Report                      │              │
├───────────────┴─────────────────────────────┴──────────────┤
│ Status Bar                                                 │
└────────────────────────────────────────────────────────────┘
```

---

## 8. Data Flow

```
Backend
      │
      ▼
Canonical Investigation Object
      │
      ▼
Generated TypeScript Types (cio.ts)
      │
      ▼
Selector Hooks
      │
      ▼
React Components
      │
      ▼
Workspace
```

**No component talks directly to the backend.**

---

## 9. Selector Layer

Every component consumes only selectors:

- `useCIO()`
- `useSummary()`
- `useVerdict()`
- `useTimeline()`
- `useGraph()`
- `useEntities()`
- `useRecommendations()`
- `useKeyFindings()`

No component performs investigation logic.

---

## 10. Component Rules

Every Lab 2.0 component MUST:

1. Consume only CIO selectors
2. Never call backend APIs directly
3. Never duplicate business logic
4. Use semantic design tokens only
5. Be responsive
6. Be accessible (WAI-ARIA)
7. Ship with a Storybook story
8. Include loading state
9. Include empty state
10. Include error state
11. Include tests

---

## 11. Feature Flag

During migration only:

```
?lab2=1
```

Flow:

```
Feature Flag OFF
    LAB → Legacy Investigate

Feature Flag ON
    LAB → Lab2Shell
```

No other UI changes.

---

## 12. Migration Plan

| Phase | Contents |
|-------|----------|
| **A** | Legacy Investigate + Lab2Shell (feature-flagged) |
| **B** | + Story Lens, Timeline, Graph, ATT&CK, Entity, Report |
| **C** | Enterprise capabilities |
| **D** | Streaming (SSE) |
| **E** | Evidence Certification |
| **F** | AI overlay |

### Final Cutover

When Lab2 satisfies all acceptance criteria:

**Remove**:

- `LegacyInvestigate`
- `FeatureFlagResolver`
- `?lab2=1`

**Keep**:

```
LAB
 └── Investigate
          │
          ▼
      Lab2Shell
```

- No route changes
- No navigation changes
- No backend changes

---

## 13. Architectural Principles

1. One LAB product.
2. One Investigate route.
3. One backend.
4. One Canonical Investigation Object.
5. One API contract.
6. Multiple renderers **only during migration**.
7. `Lab2Shell` becomes the permanent workspace.
8. Legacy renderer is deleted after successful cutover.
9. Frontend is a pure projection of the CIO.
10. All future enhancements plug into `Lab2Shell` without changing the backend.

---

## 14. Definition of Success

The end state is **NOT** "Lab 2.0 inside Lab."

The end state is:

```
LAB
 └── Investigate
        │
        ▼
     Lab2Shell
        │
        ▼
Professional Investigation Workspace
        │
        ▼
Driven entirely by the Canonical Investigation Object (CIO)
```

This is the **final target architecture** for Lab 2.0.

---

## 15. Immediate Implementation Consequences (Phase A · this slice)

1. **Introduce `<InvestigationLoader>` + `<FeatureFlagResolver>`** at
   `/nivxforge/investigate` so the route owns which renderer runs.
   `?lab2=1` triggers the resolver to mount `Lab2Shell`; unset flag
   mounts the legacy renderer verbatim.
2. **Do NOT** render `Lab2Shell` as a "preview widget" inside the
   legacy page. That is a temporary migration convenience and violates
   §4 (route owns the experience).
3. **Do NOT** add a "Lab 2.0" nav item, new route, or backend endpoint.
4. `Lab2Shell` uses the CIO from the SAME request the legacy renderer
   uses — one investigation, one CIO, chosen renderer.

---

*Last reviewed: 2026-02 · Locked by operator directive.*
