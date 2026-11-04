# NivXRay Investigation Workspace (Lab 2.0) — Constitution

> **Source of truth**: The `Absolutely.docx` operator specification
> `https://customer-assets-4nw71qhi.emergentagent.net/job_greeting-app-5782/artifacts/hpp5mbfe_Absolutely.docx`
> **This file** distils the binding constraints so they survive session boundaries.
> **Rule**: If this file and the DOCX diverge, the DOCX wins.

---

## 1 · The Immutable Core (backend is source of truth)

**COMPLETE and MUST NOT be reimplemented in the frontend:**

- Deterministic Investigation Engine
- Canonical Investigation Object (CIO)
- Evidence Graph
- Verdict Engine (`unified-verdict-engine-v1`)
- Summary Composer (`cio.summary`, composer_version `slice-d-v1`)
- Frozen API Contract (`/app/memory/lab-2.0-api-contract.md`)
- Investigation Report
- Streaming endpoints
- Tests (237/237 passing)

The frontend is a **pure consumer**. Never duplicate backend logic. Never infer missing data. Never calculate verdicts / ATT&CK / summaries / reasoning.

## 2 · The Single Rule

**The CIO is the only source of truth.**

Every UI screen renders from the CIO. Nothing else. No competing state. No duplicate investigation logic. No conflicting representations.

## 3 · Frontend Philosophy (Non-negotiable)

- Frontend is **not** an investigation engine.
- Never move business logic into React.
- Never duplicate backend reasoning.
- Never calculate anything already produced by the backend.
- Do not build pages · Do not build dashboards · Do not build isolated components.
- **Build an Investigation Workspace.**

## 4 · Workspace Rules

- Exactly **ONE investigation loaded** at any time.
- Every component observes it. Every component updates together.
- Selecting anywhere updates everywhere. **No exceptions.**
- Selecting `Process` must simultaneously update Story · Timeline · ATT&CK · Entity · Graph · Findings · Evidence · Report · Notebook.

## 5 · Lens Consumption Contracts (per lens)

| Lens | Consumes | Rule |
|---|---|---|
| Story | `cio.summary.analyst` | No formatting logic. No interpretation. Only rendering. Clicking evidence synchronises Evidence Bar · Graph · Timeline · ATT&CK · Entity. |
| Source | `cio.decode_chain` | — |
| Behavior | `cio.evidence_graph` | **Do NOT use SVG. Render via Sigma.js WebGL. No client graph generation.** |
| Timeline | `cio.timeline` | — |
| ATT&CK | `cio.attack` (or `cio.summary.mitre_digest`) | **Never infer techniques on the client.** |
| Entity | `cio.entities` (or `cio.summary.entities_digest`) | — |
| Report | `cio.summary.report_sections` | **No export modal.** |
| Knowledge | *(feature flagged)* | Slice-F cross-case fingerprint index |
| Findings | `cio.summary.key_findings` | **Never calculate priority. Already sorted by backend.** |
| Verdict Ribbon | `cio.verdict` | **Always visible. Never hidden.** |
| Unknowns | `cio.summary.unknowns` | First-class findings. **Never hide them.** |
| Recommendations | `cio.summary.recommendations` | — |

## 6 · AI Overlay (§1.1.5 hardening)

- Consumes `cio.summary`.
- Writes **ONLY** `cio.summary.llm_overlay`.
- **Never modifies** `verdict` · `confidence` · `attack` · `findings` · `entities` · `graph` · `evidence`.
- Only after every deterministic feature is complete.

## 7 · Machine-Readable Schema (governance must-have)

Create `cio.schema.json`. Validate:
- Backend (Pydantic → JSON Schema)
- Frontend (TypeScript types generated from schema)
- CI (contract diff fails PR)
- SDK / Streaming / Every payload

The schema becomes the canonical public contract.

## 8 · API Views

Support explicit views. Never overload `format=json`.

```
?view=cio          Full CIO
?view=summary      cio.summary only
?view=executive    cio.summary.executive only
?view=technical    cio.summary.technical only
?view=report       cio.summary.report_sections only
```

## 9 · Phase Order (mandatory)

- **Phase 0 · Workspace Parity Guard** — MANDATORY before any React refactor. Playwright `tests/workspace_parity.spec.js` screenshot-locks current Workspace + current `InvestigationReport`. CI fails on visual regressions.
- **Phase A · Workspace Foundation** — TypeScript, tokens, `useCIO()`, Verdict Ribbon, Command Palette
- **Phase B · Seven-Lens Renderers** — every lens a pure function of the CIO
- **Phase B.5 · Workspace Infinite Canvas** — dockable panels, split view, saved workspaces
- **Phase C · Enterprise Features** — Notebook, Case Comparison, Similar-Case, Cross-Case IOC, Knowledge lens
- **Phase D · Streaming Collaboration Presence** — SSE, `@mention`, multi-analyst
- **Phase E · Confidence Certificate** — signed manifest export
- **Phase F · AI Overlay** — only after every deterministic feature is complete

## 10 · Component Ownership (declared per component)

Every component must explicitly declare:
- CIO fields consumed
- API contract version
- Dependencies
- Loading strategy
- Error handling
- Accessibility behaviour
- Keyboard shortcuts
- Test coverage
- Performance budget

**No implicit dependencies.**

## 11 · UI Acceptance Contract (Non-Negotiable)

- You are not building a React application. You are building the flagship NivXRay Investigation Workspace.
- Comparable craftsmanship to Apple professional software · Linear · Figma · Framer · Notion · Arc Browser.
- **Do not imitate.** Create an original visual identity.
- Immediately communicate: this is an investigation platform, not a dashboard.
- **Glass-free enterprise aesthetic** (avoid unnecessary frosted-glass effects).
- Every component: loading · empty · populated · error states · keyboard nav · a11y · responsive · unit + visual regression tests.
- Animations communicate state. **Never animate for decoration.** Respect `prefers-reduced-motion`.
- Provide Dark · Light · High-Contrast themes. All themes use semantic tokens. **Never hardcode colours.**
- Target **WCAG 2.2 AA**.

## 12 · Implementation Constitution (Non-Negotiable)

- **Never optimise for writing less code. Optimise for building a world-class investigation platform.**
- **There must never be competing state.**
- **There must never be duplicate investigation logic.**
- **There must never be conflicting representations.**
- Do not design pages. Design workflows.
- Do not design dashboards. Design investigations.
- Do not design widgets. Design analyst experiences.
- Never require more than two interactions to reach supporting evidence.
- Evidence is rendered exactly as provided by the CIO. No modifying, reordering (unless CIO says so), suppressing, merging heuristically, or inferring.
- Every score / verdict / recommendation / technique / finding / timeline event / graph node **must be traceable back to evidence**. No unexplained output.

## 13 · Quality Gate (per feature)

A feature is not complete until it passes:
- TypeScript · ESLint
- Unit tests · Integration tests
- Playwright visual regression
- Accessibility validation
- Performance budget
- CIO contract validation
- Workspace Parity Guard

## 14 · Release Readiness (per phase)

A phase is complete only if:
- CI is green
- Visual regressions are zero
- API contract unchanged (unless versioned)
- Existing Workspace unaffected
- Documentation updated · Storybook updated
- Screenshots regenerated
- ADR references updated

## 15 · Product Standard

The final product should be good enough to:
- Demo live
- Present at conferences
- Showcase to enterprise CISOs
- Onboard Fortune 500 SOC teams
- Be used daily by internal analysts
- Become the flagship NivXRay experience

## 16 · Architecture Volumes (from `Absolutely.docx`)

The DOCX defines 18 architecture volumes:

1. Overall System Architecture
2. Backend Architecture
3. Frontend Architecture
4. State Architecture (SSE → API Client → React Query → CIO Store → Selection Store → Workspace State)
5. CIO Architecture (see `/app/memory/lab-2.0-api-contract.md`)
6. Component Architecture
7. Selection Architecture
8. Streaming Architecture
9. Plugin Architecture
10. Graph Architecture (Sigma.js WebGL)
11. Theme Architecture
12. Design System
13. Workspace Architecture
14. Performance Architecture
15. Security Architecture
16. Deployment Architecture
17. Testing Architecture
18. Future Architecture

Each volume is a first-class deliverable, produced before its corresponding phase begins.

---

*This file is the operator's Constitution distilled. The DOCX remains canonical for any content this file omits.*
