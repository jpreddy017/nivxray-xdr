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

**P0 — Incident Investigation Console** at `/xdr/incidents/:id`.

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

- **P1** — Native Endpoints view at `/xdr/endpoints` reusing `/api/edr/*`.  No new endpoint engine.
- **P2** — Deterministic severity mapper.  Evidence-driven only.
- **Later — Response Approval Loop** — `REQUESTED → PENDING → APPROVED/REJECTED → QUEUED → EXECUTING → SUCCEEDED/FAILED → VERIFIED`, immutable audit (actor · timestamp · action · target · prev state · new state · verification).
- **Later — Device Trajectory operational fidelity** (~95% Cisco Secure Endpoint behavioral equivalence) — separate slice, standalone XDR only.
- **Later — Additional telemetry domains** — NDR / ITDR / Email / Cloud / Application-API / Data Security / CTEM.  Each shows honest state until wired.

---

## Live baseline (verified this session)

- Standalone XDR shipped: Dashboard operational, KPIs filter queue, sidebar/top-nav all clickable (no dead UI), Incident detail 4 tabs, NivXForge EDR launcher opens base `/edr/trajectory` in new tab.
- Cross-origin auth confirmed: shared `nvx_token` in localStorage, tenant scoping enforced server-side.
- Backend regression: **821 passed / 0 failed / 4 skipped**.
- Base NivXRay: untouched.

## Session-start prompt for the next agent

> Work only in `/app/apps/nivxray-xdr/`.  Build the standalone NivXRay XDR.
> Do not touch the existing NivXRay application.  Continue with P0 —
> `/xdr/incidents/:id` Incident Investigation Console per PRD.md.  Start
> implementation immediately without asking for scope confirmation.

## Test credentials

See `/app/memory/test_credentials.md` — `admin@nivxray.com` (same token on both hosts).
