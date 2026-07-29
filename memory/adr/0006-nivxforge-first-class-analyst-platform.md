# ADR-0006 — NivXForge as a First-Class Analyst Platform

- **Status:** Proposed
- **Date:** 2026-02-28
- **Deciders:** Operator (product owner) · Emergent (implementation)
- **Supersedes / Amends:** Extends ADR-0005 (router mount for read-only preview).
- **Does not affect:** ADR-0001 (framework), ADR-0004 (attribution accuracy).

## 1. Context

NivXForge currently exposes a **read-only governance dashboard** at `/nivxforge`, backed by
`/api/nivxforge/preview/*` (GET-only). It surfaces governance state (Platform Status,
ADRs, Framework Status, Evidence Inventory, Diagnostics, Governance Documents) but does
not perform any investigation.

Workspace remains the sole analyst entry point:
- `WorkspacePage.jsx` (2 770 lines) — decode / recipe / verdict
- `AutoInvestigatePage.jsx` (3 959 lines) — v2 orchestration

The operator has decided that NivXForge should evolve into a **first-class analyst
platform** that is analytically equivalent to Workspace, with governance surfaced as
additional tabs inside NivXForge. Workspace must remain fully supported and unmodified.

## 2. Decision

NivXForge becomes a **complete analyst platform** offering full feature parity with
Workspace, while Workspace continues to exist unchanged.

Both surfaces MUST consume the same backend services. No analysis logic is duplicated
on the backend. The nivxforge backend package (`/app/backend/nivxforge/`) remains
governance-only; analyst APIs continue to live in the Workspace router hierarchy under
`/api/`.

### 2.1 Invariants
1. **Single source of truth (backend)**: NivXForge frontend calls the same
   `/api/decode/smart`, `/api/v2/auto-investigate/*`, `/api/iocs/*`, etc. that Workspace
   calls. Any change to analytical behaviour lands in the Workspace router and takes
   effect on both surfaces simultaneously.
2. **Backend isolation preserved**: The `nivxforge` Python package continues to import
   nothing from Workspace modules (`test_workspace_isolation.py`). NivXForge frontend
   reuses Workspace APIs via HTTP.
3. **Workspace Protection Policy preserved**: No modifications to Workspace pages,
   components, or routers under this ADR. New shared abstractions extracted from
   Workspace require a separate, authorised refactor ADR.
4. **Presentation-layer reuse**: NivXForge orchestration pages import Workspace-owned
   result-rendering components from `/app/frontend/src/components/*` as-is
   (VerdictCard, AttackGraph, TIShieldPanel, ProcessTreeView, RecoveredPayloadCard,
   InvestigationTimeline, OutputView, ThreatAnalysis, etc.).
5. **Governance stays**: All current `/api/nivxforge/preview/*` endpoints and the
   Preview page cards continue to serve. They move under `/nivxforge/governance` in
   the new IA.
6. **Feature-parity gate**: Any new analytical panel/feature landed in Workspace
   must be wired into NivXForge in the same change, unless the ADR-approved exception
   is documented.

## 3. Rationale

- Backend duplication is prohibited outright — it defeats the framework goal.
- Presentation-layer reuse of `/components/*` is safe: those files are pure React
  components taking props; they have no coupling to Workspace orchestration.
- Refactoring the giant orchestration files (`WorkspacePage.jsx`,
  `AutoInvestigatePage.jsx`) into shared hooks would be the ideal long-term shape,
  but doing so under this ADR would violate the Workspace Protection Policy. Deferred
  to a future authorised refactor.

## 4. Consequences

### Positive
- Analyst choice — traditional Workspace or evolved NivXForge experience.
- Single backend evolves cleanly; both frontends benefit from every improvement.
- Governance is embedded in the analyst platform, not a separate destination.

### Negative
- Orchestration logic (state, SSE, streaming) is re-implemented (not just re-rendered)
  in NivXForge until a future ADR authorises Workspace refactor. This is bounded and
  measurable — see Design Memo §7 for the duplication budget.
- Risk of feature drift if analytical additions land in only one surface. Mitigated
  by the feature-parity gate and by a new regression test that pins the two surfaces
  to the same backend endpoints for the same inputs.

### Neutral
- New test suite: `nivxforge/tests/test_parity_endpoints.py` — asserts that both
  surfaces route to the same analytical endpoints (contract test, not UI test).

## 5. Alternatives considered

- **A. Route-bridge (embed Workspace pages under `/nivxforge/*`)** — rejected: no
  NivXForge branding, no governance integration, no ability to evolve the analyst
  experience independently.
- **B. Extract shared hooks now (authorised Workspace refactor)** — rejected for this
  ADR: violates Workspace Protection Policy scope; deferred to a future ADR after the
  parity surface is proven in production.
- **C. Backend duplication in `nivxforge` package** — rejected outright: violates
  §2 invariant 1 and §2 invariant 2.

## 6. Scope

This ADR covers:
- Architectural direction (single backend, dual frontend, presentation reuse).
- IA / navigation restructure of `/nivxforge`.
- Feature-parity gate as a governance principle.

This ADR does **not** cover:
- Specific UI layout — see `/app/memory/DESIGN_NIVXFORGE_ANALYST_PLATFORM.md`.
- Implementation phases — see the same design memo.
- Extraction of shared hooks from Workspace — a future ADR (P2 backlog).

## 7. Approval gate

Implementation MUST NOT begin until:
1. This ADR is marked **Accepted**.
2. The design memo referenced in §6 is reviewed and Phase 1 scope is explicitly
   approved by the operator.

## 8. Revisit

Revisit once Phase 1 is live and the parity contract test is green. At that point,
evaluate whether the duplicated orchestration justifies a Workspace-refactor ADR.
