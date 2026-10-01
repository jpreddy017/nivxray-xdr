# Design Memo — NivXForge as a First-Class Analyst Platform

**Status:** Proposal — awaiting operator review
**Scope:** IA / UI / reuse / risk / phasing under ADR-0006 (Proposed)
**Non-scope:** Backend changes to analytical endpoints (§ADR-0006, §2 invariant 1)

---

## 1. Current state (honest survey)

| Surface           | Route          | Lines             | Owns                                              |
| ----------------- | -------------- | ----------------- | ------------------------------------------------- |
| `WorkspacePage`   | `/analyze`     | 2 770             | Decode / recipe / verdict orchestration           |
| `AutoInvestigate` | `/auto-investigate` | 3 959        | v2 orchestration (SSE, ancestry, IRG)             |
| Preview           | `/nivxforge`   | ~170              | Governance dashboard (read-only)                  |
| Shared components | `/components/*` | ~40 files, 8–1000 lines each | Result-rendering primitives (props-only)  |
| API layer         | `/api/*`       | —                 | The one thing both surfaces MUST share            |

**Key observation:** Workspace pages are ~90% orchestration state and ~10% presentation.
The presentation is already extracted into `/components/*`. The orchestration is not.

---

## 2. Target architecture

```
                    Shared FastAPI backend
                    ─────────────────────
                    /api/decode/smart
                    /api/v2/auto-investigate/*
                    /api/iocs/*
                    /api/report-writer/*
                    /api/nivxforge/preview/*   (governance-only)
                          │
             ┌────────────┴────────────┐
             │                         │
       Workspace (React)         NivXForge (React)
       ────────────────         ────────────────────
       /analyze                 /nivxforge/investigate
       /auto-investigate        /nivxforge/auto
       /heatmap                 /nivxforge/timeline/:caseId
       /threat-intel            /nivxforge/reports
       ...                      /nivxforge/governance/*
                                (existing preview cards)

       imports /components/*    imports /components/*
                    ↑                       ↑
                    └───── shared ──────────┘
                    (VerdictCard, AttackGraph,
                     TIShieldPanel, OutputView, ...)
```

---

## 3. Proposed UI layout — NivXForge analyst workspace

### 3.1 Landing (`/nivxforge`)

Two panels stacked:
1. **Investigate Now** (primary CTA card) — analyst input surface (see §3.2).
2. **Platform Status** (existing situational-awareness block, unchanged).

Below: a compact strip linking to `Governance ▸`.

### 3.2 Investigate page (`/nivxforge/investigate`)

```
┌─ NivXForge / Investigate ─────────────────────────────────────────────┐
│  ┌─ INPUT ─────────────────────────────────────────────────┐         │
│  │ [ TEXTAREA – paste command line / script / IOC / URL ]  │         │
│  │  (InputToolbar overlay: copy · lock · clear)            │         │
│  │  [Upload file] [Recipe: Auto-Smart ▾] [SSE: on]         │         │
│  │  [ AUTO INVESTIGATE ]  [ DECODE ]  [ CLEAR ]            │         │
│  └─────────────────────────────────────────────────────────┘         │
│                                                                       │
│  ┌─ RESULT (progressive) ──────────────────────────────────┐         │
│  │ 1. Decoded output          (OutputView)                 │         │
│  │ 2. Verdict card            (VerdictCard)                │         │
│  │ 3. IOCs + TI shield        (TIShieldPanel)              │         │
│  │ 4. MITRE map / attack path (AttackPathClean)            │         │
│  │ 5. Attack graph            (AttackGraph)                │         │
│  │ 6. Recovered payloads      (RecoveredPayloadCard)       │         │
│  │ 7. Timeline                (InvestigationTimeline)      │         │
│  │ 8. Report menu             (ReportMenu)                 │         │
│  └─────────────────────────────────────────────────────────┘         │
└───────────────────────────────────────────────────────────────────────┘
```

Every component in the RESULT column is imported unchanged from `/components/*`.

### 3.3 Auto Investigate (`/nivxforge/auto`)

Same structure, but the trigger calls `POST /api/v2/auto-investigate/jobs` and the
result column adds `InvestigationBrainPanel` above the standard panels.

### 3.4 Timeline / Trajectory (`/nivxforge/timeline/:caseId`, `/nivxforge/trajectory/:caseId`)

Wraps existing `InvestigationTimeline` component and (for trajectory) `ProcessTreeView`.

### 3.5 Reports (`/nivxforge/reports`)

Consumes existing report-writer endpoints. Reuses `ReportMenu`.

### 3.6 Governance section (`/nivxforge/governance/*`)

The current Preview surface, moved under a sub-navigation:
```
/nivxforge/governance                → Platform Status + Governance Docs
/nivxforge/governance/adrs           → ADR list + individual view
/nivxforge/governance/framework      → Framework status (ADR-0001)
/nivxforge/governance/evidence       → Evidence Inventory (latest markdown)
/nivxforge/governance/diagnostics    → Diagnostic reports
/nivxforge/governance/real-world     → REAL_WORLD_LOG.md viewer
```
All existing `/api/nivxforge/preview/*` endpoints continue to serve these tabs.

---

## 4. Navigation structure

**Top-level header inside `/nivxforge/*`:**
```
NivXForge  |  Investigate · Auto Investigate · Timeline · Reports · Governance ▾
```

**Governance dropdown**: Platform Status · ADRs · Framework · Evidence · Diagnostics · Real-World Log.

**Cross-surface link**: A subtle "Open in Workspace →" link at the top-right of each
investigate route hands the analyst off to the equivalent Workspace page. No state
carry-over in Phase 1 (see risk §6.3).

**Existing top-nav (Workspace / Auto Investigate / ...)**: unchanged. Users toggle
between Workspace and NivXForge via the existing `NIVXFORGE` tab.

---

## 5. Reuse strategy

### 5.1 What's reused as-is (zero new code)

| Component / lib                        | Purpose in NivXForge                                       |
| -------------------------------------- | ---------------------------------------------------------- |
| `components/InputToolbar.jsx`          | copy / lock / clear buttons on the paste textarea          |
| `components/OutputView.jsx`            | render decoded output                                       |
| `components/VerdictCard.jsx`           | verdict UI                                                 |
| `components/AttackGraph.jsx`           | attack graph visual                                        |
| `components/AttackPathClean.jsx`       | MITRE kill-chain path                                      |
| `components/TIShieldPanel.jsx`         | threat-intel enrichment                                    |
| `components/ProcessTreeView.jsx`       | process tree                                               |
| `components/RecoveredPayloadCard.jsx`  | nested payload extraction                                  |
| `components/InvestigationTimeline.jsx` | timeline events                                            |
| `components/ThreatAnalysis.jsx`        | threat panel                                               |
| `components/ReportMenu.jsx`            | report download menu                                       |
| `components/GuidanceBanner.jsx`        | inline guidance / warnings                                 |
| `components/investigation/*`           | Brain, semantic panel, decode-failure card                 |
| `lib/api.js`                           | HTTP + JWT client                                          |
| `lib/sse.js`                           | server-sent events                                         |
| `lib/clientOps.js`, `magicLite.js`, `shellcodeDetect.js`, `mergeIocs.js`, `selectCanonicalOutput.js`, `inputClassifier.js` | client-side helpers |

### 5.2 What's newly written for NivXForge

Files under `/app/frontend/src/nivxforge/`:
```
pages/
  InvestigatePage.jsx           (~250 lines, orchestrates the input + results panels)
  AutoInvestigatePage.jsx       (~300 lines, wraps v2 flow)
  TimelinePage.jsx              (~120 lines)
  TrajectoryPage.jsx            (~120 lines)
  ReportsPage.jsx               (~100 lines)
  governance/
    LayoutShell.jsx             (~60 lines, wraps existing preview cards under sub-nav)
    PlatformStatusTab.jsx       (existing PreviewPage refactored into a tab)
    AdrsTab.jsx                 (existing card, standalone route)
    FrameworkTab.jsx            (existing card, standalone route)
    EvidenceTab.jsx             (existing card, standalone route)
    DiagnosticsTab.jsx          (existing card, standalone route)
    RealWorldTab.jsx            (new markdown viewer for REAL_WORLD_LOG.md)
hooks/
  useSmartDecode.js             (~150 lines, NivXForge's copy of Workspace decode orchestration)
  useAutoInvestigate.js         (~200 lines, NivXForge's copy of v2 orchestration)
components/
  NivXHeader.jsx                (top nav + governance dropdown, keeps NivXForge visual identity)
  InvestigateInput.jsx          (composes InputToolbar + upload + recipe picker)
  ResultsColumn.jsx             (composes the existing result-rendering components)
```

Total new code estimate: **~1 500 lines**. Compared to the ~7 000-line Workspace
orchestration surface, this is intentional: NivXForge re-orchestrates but re-uses
100% of the presentation and 100% of the backend.

### 5.3 Duplication budget (transparency)

The two hooks (`useSmartDecode`, `useAutoInvestigate`) are the honest cost of
respecting the Workspace Protection Policy. They embody ~20-30% of the logic in
`WorkspacePage.jsx` and `AutoInvestigatePage.jsx`. This duplication is:
- **Bounded**: the two files won't grow beyond ~500 combined lines.
- **Testable**: the parity contract test (§6.6) pins both surfaces to the same API
  contracts, so drift is caught at CI time.
- **Removable later**: A future ADR can authorise extracting these hooks from
  Workspace into `lib/*` shared modules. This is deferred so the operator can see
  the parity surface working before committing to a Workspace refactor.

---

## 6. Architectural risks

### 6.1 Orchestration duplication drift
**Risk:** Workspace evolves the decode orchestration; NivXForge lags.
**Mitigation:** Parity contract test (§6.6). Feature-parity gate in ADR-0006 §2.1(6).

### 6.2 Routing collisions
**Risk:** New `/nivxforge/*` sub-routes collide with the existing single-page mount.
**Mitigation:** Convert `/nivxforge` to a nested React Router outlet (child routes).
No changes to Workspace routing.

### 6.3 State carry-over between surfaces
**Risk:** Analyst pastes on Workspace, switches to NivXForge — input is lost.
**Decision (Phase 1):** No cross-surface state. Optional in later phase via
localStorage handoff (`nvx_last_input` already stored — reuse it).

### 6.4 Performance / bundle size
**Risk:** NivXForge imports the same heavy result components as Workspace — bundle
grows.
**Mitigation:** Lazy-load NivXForge routes with `React.lazy` + `Suspense`. Present
on the Workspace side already for large pages; adopt the same pattern for NivXForge.

### 6.5 SSE double-subscription
**Risk:** If a user is on Workspace and opens NivXForge in another tab for the same
job, both subscribe to the SSE stream.
**Mitigation:** No change needed. `sse.js` is stateless per-client and the backend
supports multiple subscribers. Documented in the design so it's not later "found".

### 6.6 The parity contract test (new)
`nivxforge/tests/test_parity_endpoints.py` — a **backend** test asserting that:
- The NivXForge frontend's declared API contracts (extracted at build time from the
  new hooks) match the Workspace analytical routes exactly.
- Both frontends' JSON payloads for the same input produce byte-identical field
  extraction (verdict.severity, iocs.count, mitre.techniques).

This is a **structural** test — it does NOT test UI parity, only the backend
contract shared by both surfaces.

### 6.7 Governance visibility on the analyst path
**Risk:** Analysts using NivXForge/Investigate never look at Governance and miss
platform health signals.
**Mitigation:** A one-line status pill in NivXForge header showing
`46/46 · read-only` (green) or a red state if `platform-health` reports issues.
Clickable → jumps to `/nivxforge/governance`. Presentation-layer only.

### 6.8 Design consistency
**Risk:** Two visual languages if NivXForge and Workspace look wildly different.
**Mitigation:** NivXForge chrome uses the current Preview's monospaced, dark
palette. Result components render with their existing styles (unchanged), giving
visual consistency inside result panels.

---

## 7. Phased implementation plan

Each phase is independently deployable and testable. **Nothing ships without the
operator's per-phase approval.** After every phase, the parity contract test must
be green.

### Phase 1 — "Golden Path" (proves the architecture)      *~1 session*
- Add nested routing under `/nivxforge/*`.
- New `InvestigatePage.jsx` (paste text only, no upload).
- Trigger `POST /api/decode/smart` — same endpoint Workspace uses.
- Render decoded output via `OutputView`, verdict via `VerdictCard`, IOCs via `TIShieldPanel`.
- Governance content moved to `/nivxforge/governance` under a sub-nav.
- New test: `test_parity_endpoints.py::test_smart_decode_contract_shared`.
- **Acceptance:** paste an identical payload on `/analyze` and `/nivxforge/investigate`;
  the decoded output and verdict severity match exactly.

### Phase 2 — File upload + Recipe picker                   *~0.5 session*
- Add file upload (uses existing `/api/upload`).
- Add recipe selector (uses existing `/api/operations`, `/api/recipe/run`).

### Phase 3 — Auto-Investigate                              *~1.5 sessions*
- New `AutoInvestigatePage.jsx` under NivXForge.
- SSE streaming (reuses `sse.js`).
- Adds `InvestigationBrainPanel`, `AttackGraph`, `AttackPathClean`, `RecoveredPayloadCard`.
- Parity test extended to cover `POST /api/v2/auto-investigate/jobs`.

### Phase 4 — Timeline + Device Trajectory                  *~1 session*
- `TimelinePage.jsx` (reuses `InvestigationTimeline`).
- `TrajectoryPage.jsx` (reuses `ProcessTreeView`).
- No new backend.

### Phase 5 — Reports                                       *~1 session*
- `ReportsPage.jsx`; consumes `POST /api/v2/report-writer/generate/from-model`.
- Reuses `ReportMenu`.

### Phase 6 — Governance IA polish                          *~0.5 session*
- Break the existing single Preview page into 6 governance tabs (Platform Status,
  ADRs, Framework, Evidence, Diagnostics, Real-World Log).
- No functional changes; IA reshape only.

**Total estimated effort: ~6 sessions.**

Each phase ends with:
- Full NivXForge pytest suite green (currently 46 tests; grows by ~3-5 per phase).
- Parity contract test green.
- Operator sign-off on the phase before the next starts.

---

## 8. Explicit non-goals (this project)

- No backend changes to analytical endpoints.
- No changes to `WorkspacePage.jsx` or `AutoInvestigatePage.jsx` or their
  supporting hooks.
- No extraction of shared orchestration into `lib/*` (future ADR).
- No cross-surface state hand-off in Phase 1.
- No changes to authentication, JWT, or session behaviour.
- No changes to the Workspace navigation.

---

## 9. What we need from the operator before we begin

Please review §2 (target architecture), §3 (proposed layout), §5 (reuse strategy),
§6 (risks), and §7 (phased plan).

Specific approval needed on:

1. **ADR-0006 status → Accepted** (or amendments requested).
2. **Landing page decision**: is `/nivxforge` (a) Investigate + Platform Status stacked,
   or (b) a chooser between Investigate / Auto Investigate / Governance?
   (Design memo assumes (a).)
3. **Duplication budget acceptance**: ~1 500 lines of new orchestration code in
   NivXForge under Phase 1-6, in exchange for zero Workspace modification.
   (Alternative: authorise a Workspace refactor first — different ADR.)
4. **Phase 1 scope**: paste + decode + verdict + IOCs, targeting the "identical
   payload → identical output" acceptance criterion. Approve to start?
