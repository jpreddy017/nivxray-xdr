# NivXRay — Master Reminders + Product Requirements

**Authoritative execution baseline (locked 2026-08-29).**
This file supersedes all prior architecture instructions.  Every future
NivXRay XDR session must obey these rules verbatim.

---

## 🔴 The one rule that supersedes everything else

> If the change is required to make **NivXRay XDR** work, implement it in
> `/app/apps/nivxray-xdr/` (repo `jpreddy017/nivxray-xdr`, live at
> https://nivxray-xdr.vercel.app) **or through an existing API
> contract**.  If the change would modify the existing NivXRay product
> itself, **do not do it**.

When there is ambiguity between "modify NivXRay" and "build NivXRay
XDR", the default interpretation is always **BUILD THE STANDALONE
NIVXRAY XDR**.

---

## Architecture (one picture)

```
        ┌─────────────────────────────┐
        │      EXISTING NIVXRAY       │
        │      (protected · read-only) │
        │                             │
        │ Workspace · Evidence · IKG  │
        │ Activity Inventory · Verdict│
        │ Process Tree · Trajectory   │
        │ Command Intel · MITRE       │
        │ Threat Intel · Reports      │
        └──────────────┬──────────────┘
                       │
              Authenticated APIs
                       │
                       ▼
        ┌─────────────────────────────┐
        │       NIVXRAY XDR           │
        │     STANDALONE TOOL          │
        │                             │
        │ Dashboard · Incidents        │
        │ Investigation Console        │
        │ Endpoints · NivXForge EDR    │
        │ Activity · Response          │
        │ Intelligence · Operations    │
        └─────────────────────────────┘

One security truth. Two application boundaries.
Separate application  ≠  Separate security truth.
```

---

## 🔴 Non-negotiable guardrails (every session)

- **Never modify** `/app/frontend`, `/analyst`, `/edr/trajectory`, or any existing NivXRay engine.
- **Never duplicate** Workspace · Evidence SSOT · Incident SSOT · Verdict Engine · Process Tree · Device Trajectory · Command Intelligence · MITRE · IKG · Activity Inventory · TI · Reports.
- **Never fake telemetry.**  Preserve semantically distinct states: `NOT CONNECTED · NOT AVAILABLE · NO MATCHING EVIDENCE · ERROR`.  Never collapse them into "Benign".
- **Never inflate severity** to populate KPI cards.  Severity is evidence-driven.
- **Never make destructive actions instant one-click.**  Response goes through the Approval Loop.
- **Never claim a capability that isn't wired.**  Negative Explainability is a first-class product feature.
- **Never co-host** XDR under the base frontend.  Separate build, runtime, deployment.
- **Never repeat scope-confirmation questions** once a direction is locked.  Start implementing.
- **Never work on Cisco Device Trajectory fidelity** during the current P0.  That is a separate future slice.
- **Address the implementation agent as Emergent**, not Claude or Claude Code.

---

## Product identity

- NivXRay is an **evidence-first, investigation-centric security intelligence platform** — not merely EDR/XDR/SIEM/SOAR/TIP/NDR/UEBA/etc.
- Core loop: **Evidence → Context → Correlation → Reasoning → Verdict → Decision → Response → New Evidence** (recursive via IUE).
- Deterministic-first; AI is optional assistance, never the decision authority.
- Every conclusion traces back to evidence with full provenance.  Reproducible.

## NivXRay XDR identity

- **Standalone tool.**  New frontend, build, runtime, deployment, repo, auth UI.
- Consumes existing NivXRay APIs.  Never re-implements engines.
- Live: https://nivxray-xdr.vercel.app · Repo: `jpreddy017/nivxray-xdr` · Vercel auto-deploy on push to `main`.
- Brand: circuit-tree mark + `NiVXRAY XDR` wordmark (orange `i` accent) + `EXTENDED DETECTION / RESPONSE` tagline.  Enterprise, not sci-fi.
- Visual identity is NivXRay-original.  ~95% operational equivalence to Cisco Secure Endpoint is a *behavioral* benchmark for the future Trajectory slice, not a visual clone.

---

## Current execution point

**Build the entire `nivxray-one-xdr-console_New.html` mockup slice-by-slice** — verbatim visual + behavioral fidelity — while enforcing every architecture guardrail below.  Device Trajectory is **UNLOCKED** as of 2026-08-29 (owner directive) and is now part of the standalone-XDR native surface.

### Slice queue (owner-locked build order)

| # | Slice | Notes |
| :- | :---- | :---- |
| 1 | **Pivot menus** — hover-triggered contextual overlay on every entity (process, user, ip, hash, domain, mitre). Unlocks all downstream slices. | Small, high-leverage |
| 2 | **Native Investigation sub-tab bodies** — replace "Open on existing NivXRay ↗" with inline rendering: Evidence (datalake) · Timeline · Attack Story · Evidence Graph · MITRE ATT&CK · Verdict Summary · Report. Reuses `/api/incidents/:id/summary`, `/api/activity/inventory`, IKG APIs. | 6 sub-tabs |
| 3 | **Detection Sourcing** — first-class `detected_by` column across Suspicious Elements + Detections tables, with pivot back to the source engine. | Small polish |
| 4 | **Deterministic Severity Mapper** — XDR-side projection over `verdict_stage2` + evidence rollup; preserves source severity, adds provenance. Never inflate. | Small |
| 5 | **Forge EDR landing** — richer device inventory (OS · IP · user · risk score · agent version · linked incident) matching mockup columns. | Extends current Endpoints page |
| 6 | **Device Trajectory 3-pane canvas** — left inventory · center timeline canvas (density strip + time window + incident-centering) · right activity details. Consumes existing `/edr/*` telemetry projections; XDR renders natively. **Do NOT modify `/edr/trajectory` on the base app.** | Largest slice — likely multi-session |
| 7 | **Command Intelligence native page** — XDR-native decode viewer with `/api/analyze` under the hood.  Handoff receives incident context. | Medium |
| 8 | **Response Approval Loop + Response Global** — REQUESTED → PENDING → APPROVED/REJECTED → QUEUED → EXECUTING → SUCCEEDED/FAILED → VERIFIED, immutable audit, no fake success. | Medium |
| 9 | **Admin sub-pages** (13 items: Integrations · Data Sources · Collectors · Agents · Telemetry Studio · Telemetry Health · Parsers · Normalization · Detection Rules · Response Policies · Users & Roles · API/Webhooks · Platform Health). | Large — dashboard-style pages |
| 10 | Evidence drawer overlay · Attachments · Analyst Notes | Polish |

### Master rule (unchanged)

Every slice is implemented **only** in `/app/apps/nivxray-xdr/` (mirror) + `jpreddy017/nivxray-xdr` (canonical).
Consume existing NivXRay APIs; never duplicate engines, SSOT, or database.
Base NivXRay (`/app/frontend`, `/analyst`, `/edr/trajectory`) stays untouched.
For Trajectory: XDR builds its own native canvas — it does not embed, iframe, or modify the base `/edr/trajectory` implementation.  Data comes from existing telemetry APIs.

Structure:
```
Summary
Investigation
  ├── Attack Story
  ├── Evidence
  ├── Entities
  ├── MITRE ATT&CK
  └── Timeline
Activity
Response
```

**Contextual pivots** (each opens the base NivXRay capability in a new tab; XDR never re-implements):

| Entity          | Pivot destination                    |
| :-------------- | :----------------------------------- |
| Process         | base `/edr/trajectory` (Process Tree scope) |
| Command line    | base `/analyze` (Command Intelligence)      |
| Endpoint        | base `/edr/trajectory?device=…`             |
| Detection       | base `/edr/trajectory?event=…`              |
| IOC             | base `/threat-intel?ioc=…`                  |
| MITRE technique | base `/heatmap?technique=…`                 |
| Evidence node   | base `/analyst?case=…&evidence=…`           |

**Data sources** — all consumed via authenticated API from the base NivXRay backend:
- `GET /api/incidents/{id}` (Incident SSOT)
- `GET /api/incidents/{id}/summary` (deterministic summary + gaps)
- `POST /api/activity/inventory` (Activity + Timeline)
- Existing Attack Story / IKG / Verdict / MITRE projections

**Summary tab must include:** verdict · severity · confidence · attack progression · evidence summary · affected entities · important detections · evidence gaps (Negative Explainability) · recommended next evidence · available response actions.

---

## Roadmap after P0

- **P1** — Native Endpoints view at `/xdr/endpoints` reusing `/api/edr/*`.  No new endpoint engine.  ✅ **DONE (Slice 6 · 2026-02)**.
- **P2** — Deterministic severity mapper.  Evidence-driven only.
- **Later — Response Approval Loop** — `REQUESTED → PENDING → APPROVED/REJECTED → QUEUED → EXECUTING → SUCCEEDED/FAILED → VERIFIED`, immutable audit (actor · timestamp · action · target · prev state · new state · verification).
- **Later — Device Trajectory operational fidelity** (~95% Cisco Secure Endpoint behavioral equivalence) — Slice 6 v2 (deeper canvas density + zoom-to-window).
- **Later — Additional telemetry domains** — NDR / ITDR / Email / Cloud / Application-API / Data Security / CTEM.  Each shows honest state until wired.

---

## Live baseline (verified this session)

- Standalone XDR shipped: Dashboard operational, KPIs filter queue, sidebar/top-nav all clickable (no dead UI), Incident detail 4 tabs, NivXForge EDR launcher opens base `/edr/trajectory` in new tab.
- Cross-origin auth confirmed: shared `nvx_token` in localStorage, tenant scoping enforced server-side.
- Backend regression: **821 passed / 0 failed / 4 skipped** (held after Slice 6 · 2026-02).
- Base NivXRay: untouched.

## Session log

### 2026-02 · Slice 6 · Native XDR Device Trajectory Canvas · SHIPPED
- New backend projections (additive, `/app/backend/routers/edr.py`):
  - `GET /api/edr/endpoints` — device inventory aggregated from `workspace_cases`.
  - `GET /api/edr/device-trajectory?device=<host>&hours=<n>` — device-scoped detections + activity nodes, lane-mapped, time-windowed.
- New XDR pages:
  - `/xdr/endpoints` — `XdrEndpointsPage.jsx` with row → **View Trajectory**.
  - `/xdr/endpoints/:device/trajectory` — `XdrDeviceTrajectoryPage.jsx` (3-pane).
- New components:
  - `TrajectoryTimelineCanvas.jsx` — hybrid `<canvas>` (density + hour ticks) + `<svg>` overlay (interactive markers, hover, selection).
  - `Pivot.jsx` — Slice 1 contextual pivots consumed by details pane (host/process/file/rule/ip/domain/hash/url).
- SSOT isolation test allow-list extended to Slice 6 paths (`tests/canonical/ssot/test_ssot_isolation.py`).
- Verified: `pytest tests/canonical` → **821 passed, 4 skipped** (no regressions).
- Verified via screenshot: endpoints, trajectory canvas w/ markers, selected event details w/ Pivot.

## Session-start prompt for the next agent

> Continue mockup slice-by-slice build per PRD.md.  Standalone NivXRay
> XDR only.  Do not touch the base NivXRay application.  Slice 6
> (Device Trajectory Canvas) is DONE.  Next candidate: **Slice 3 ·
> Detection Sourcing** (elevate `detected_by` as first-class column
> across Suspicious Elements + pivot back to source engine), or
> **Deterministic Severity Mapper**.  Do not begin without owner
> confirmation of slice order.

## Test credentials

See `/app/memory/test_credentials.md` — `admin@nivxray.com` (same token on both hosts).
