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

## Locked slice roadmap (owner-approved, mockup-order)

- Slice 1  — Contextual Pivot menus ✅
- Slice 2  — Native Investigation sub-tab bodies ✅
- Slice 3  — Detection Sourcing (`detected_by` first-class + engine pivot) ✅
- Slice 6  — Native XDR Device Trajectory Canvas (v1 · category-lane) ✅
- Slice 7  — Sidebar correction + Overview IA + Domain Cards + Domain routes ✅
- **Slice 8**  — Device Trajectory IA rewrite (entity-per-row · density strips · compromise band · lineage connectors · tri-directional sync)
- **Slice 9**  — Lifecycle audit tightening (button matrix · Hold modal · banner · immutable Activity writes)
- **Slice 10** — Native XDR Admin Console (all 14 admin surfaces reading authoritative APIs, never deep-linking base `/admin`) ✅
- **Slice 11** — Response Approval Loop (Requested → Policy Check → Executed → Verified · immutable audit)
- **Slice 12** — Global Response Center (cross-incident view)
- **Slice 13** — Other Domain Consoles (NDR / ITDR / Email / Cloud / App / Data / Exposure / IOC — reproduce `tab*()` from the mockup)
- **Slice 14** — Native Command Intelligence (inline in XDR, consumes existing decoder API)
- **Slice 15** — Activity / Notes / Attachments completion (separated sections, SHA-256, previews)
- **Slice 16** — Final native-XDR / deep-link elimination audit

## Permanent rules (owner-locked)

1. **No base-UI deep-links in "complete" XDR features.**  Before any
   XDR capability is declared complete, audit it for `/analyze`,
   `/heatmap`, `/analyst`, `/v2/irg`, `/edr/trajectory`, or `/admin`
   deep-links.  If the capability belongs to the XDR product it
   must ultimately have a native XDR implementation reading the
   authoritative NivXRay APIs.
2. **Reuse APIs, not UI.**  Native XDR UI → existing authoritative
   NivXRay APIs (Verdict, Evidence, IKG, Activity Inventory,
   Process Tree, Decoder, MITRE, Health).  No engine, SSOT, or
   security-model duplication.
3. **Data honesty · four distinct states** — never collapse into a
   generic "empty":
     - `NOT OBSERVED`     — telemetry ran, negative result
     - `NOT ESTABLISHED`  — projection not built yet
     - `NOT AVAILABLE`    — capability absent from the SSOT
     - `NOT CONNECTED`    — integration not wired for tenant
4. **Quality bar (locked)** — every component must be more
   reliable + explainable + efficient than Microsoft Defender XDR,
   CrowdStrike Falcon, Cisco Secure Endpoint / Cisco XDR:
     - provenance on every field
     - rule + weight + source engine on every verdict/detection
     - sub-second incident open
     - immutable audit on every state transition + response action
     - server-side tenant firewall (never client-side filtering)
5. **Enterprise design bar (locked)** — every tab, page, button,
   icon, table, badge, modal, empty-state, chart, and micro-
   interaction must be first-class enterprise-grade.  No inline
   ad-hoc styling; every surface consumes the shared design tokens
   + component primitives.  Before designing or building a new
   surface, invoke `design_agent_full_stack` for the visual
   blueprint, then implement against it.  Reference bar:
   Splunk MC · Elastic Security · Sentinel · Palo Alto XSIAM ·
   CrowdStrike Falcon Next-Gen · Vercel dashboard.  Ordinary
   framework-default look is a bug.

---

## Live baseline (verified this session)

- Standalone XDR shipped: Dashboard operational, KPIs filter queue, sidebar/top-nav all clickable (no dead UI), Incident detail 4 tabs, NivXForge EDR launcher opens base `/edr/trajectory` in new tab.
- Cross-origin auth confirmed: shared `nvx_token` in localStorage, tenant scoping enforced server-side.
- Backend regression: **821 passed / 0 failed / 4 skipped** (held after Slice 6 · 2026-02).
- Base NivXRay: untouched.

## Session log

### 2026-02 · Slice 10 · Native XDR Admin Console · SHIPPED
- 14 native admin surfaces at `/xdr/admin/*`, each reading authoritative NivXRay APIs.  No deep-link to base `/admin`.
- Verified: `/admin/stats` populates Overview KV grid; `/admin/users` renders real table; `/health` populates Platform Health; unconnected surfaces (Collectors / Agents / Parsers / Normalization / Response-Policies / API-Webhooks) surface `NOT CONNECTED` with integration guidance.
- Sidebar Administration items no longer disabled — every one navigates natively.
- Files: `src/xdr/admin/adminMeta.js`, `src/xdr/pages/XdrAdminPage.jsx`.
- `pytest tests/canonical/{ssot,edr,incidents}` — 87 passed.

### 2026-02 · Slice 7 · Sidebar + Overview IA + Domain routes · SHIPPED
- Sidebar Operations reduced to `Incidents · My Queue · Response`.  Dashboard duplicate + global Endpoints peer removed.
- Investigation sub-tabs corrected: removed erroneous `summary`; Summary body moved onto Overview.
- New `DomainCardsGrid` on Overview + persistent `IncidentContextStrip` on all six domain routes.
- Intelligence deep-links replaced by native `XdrReservedPage` placeholders naming the authoritative API each future slice will consume.
- Files: `src/xdr/domains/domainMeta.js`, `src/xdr/components/{DomainCardsGrid,IncidentContextStrip}.jsx`, `src/xdr/pages/{XdrIncidentDomainPage,XdrReservedPage}.jsx`.

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
> XDR only.  Do not touch the base NivXRay application.  Slice 10
> (Native XDR Admin Console) is DONE.  Next: **Slice 8 · Device
> Trajectory IA rewrite** — entity-per-row, density strips,
> compromise-window band, lineage connectors, tri-directional pane
> sync, right-pane default Device Summary, `x3` duplicate grouping,
> time-navigation beyond the incident window.  Do not begin without
> owner confirmation of slice.

## Test credentials

See `/app/memory/test_credentials.md` — `admin@nivxray.com` (same token on both hosts).

---

## 2026-02 Fork — Session Delivery Log

### Native MITRE ATT&CK Heatmap (COMPLETE · deployed)
- Route: `/xdr/intelligence/mitre` (was a locked "reserved" deep-link).
- Ships the FULL MITRE ATT&CK Enterprise v16 top-level taxonomy: 14
  tactics, **199 distinct techniques (230 cell mappings)**.
- Live vs. static separation: KPI grid shows only live metrics
  (Detections window, Techniques Observed, Rule Coverage, Incidents
  Scanned). Static catalog constants moved to a meta strip.
- Refresh button: spinner + label + clears filter + clears selection
  + drops cached incidents + increments a visible `Refreshes` counter.
  Auto-poll every 30s. "Last synced Xs ago" ticks live.
- Sidebar entry promoted from reserved (locked) to live.
- Deployed to Vercel: commits `bddca0b → 1d9be9c → e293ada` on
  `jpreddy017/nivxray-xdr` `main`. Vercel auto-build handles rollout.

### XDR Collector Phase B (COMPLETE · service ready to deploy)
Location: `/app/apps/nivxray-xdr-collector` (independent Docker service).
Three generic transport connectors, all with real transport code (not
UI stubs):

- **REST Poller** — httpx-based, bearer/basic/api-key auth, cursor
  pagination, checkpoint advancement, 429 → rate_limited, 401 →
  authentication_failed. Async scheduler runs one task per instance
  at `interval_seconds`.
- **Webhook Receiver** — `POST /api/xdr/webhooks/{secret_id}`, HMAC
  verification (`hmac.compare_digest`), replay window 5 min via
  `X-Timestamp`. Missing/mismatched signature → HTTP 401 with reason,
  never 500.
- **Syslog Collector** — asyncio UDP + TCP listeners, RFC3164 and
  RFC5424 parsers, bind-conflict safety, per-instance socket in
  `SyslogRunner`.

Cross-cutting:
- `ConnectorStore` — in-memory + optional JSON mirror at
  `${XDR_STATE_DIR}/connectors.json` (chmod 600), credentials
  redacted in every API response.
- `DedupCache` — bounded per-connector LRU keyed on `source_event_id`.
- `IngestClient` — best-effort forwarder to `NIVX_INGEST_URL`.
  Honestly reports `queued` when no ingest URL is configured; Phase
  B.5 replaces with durable outbox + DLQ.
- Full management API surface: `/api/xdr/source-types`,
  `/api/xdr/connectors` CRUD + control (test/start/stop/inject),
  `/api/xdr/telemetry-health`, `/api/xdr/data-sources`,
  `/api/xdr/webhooks/{secret_id}`.

Testing:
- 27/27 pytest pass (parsers 7, REST poller 4, webhook 7, syslog 5
  with real UDP+TCP socket binds, routes 3 with FastAPI lifespan).
- Live E2E verified via curl: created webhook, POSTed 3 events,
  `events_collected: 3`, cleanup successful.

Base backend invariant preserved: `/api/health` = 200, `/app/frontend`
and `/app/backend` untouched, 87-pass baseline unaffected.

### Immediate backlog (post-fork)
- **P0 · Phase B.5** — durable outbox + DLQ + retry/backoff, real
  forwarding to authoritative NivXRay ingest, observability metrics
  in `/api/xdr/telemetry-health`.
- **P1 · Deploy the collector** — publish Docker image, wire
  `NIVX_INGEST_URL`/`NIVX_INGEST_TOKEN` at the tenant edge.
- **P2 · Phase C** — CrowdStrike / Defender / SentinelOne / Cisco SEP
  vendor connectors on the Phase B foundation.
- **P3 · Phase D** — Windows WEF / WinRM / WMI collectors.
- **P4 · Slice 8** — Device Trajectory IA rewrite (entity-per-row).
- **P4 · Slice 9** — Lifecycle + immutable Activity.
- **P4 · Slice 11** — Response Approval Loop.
- **P4 · Slice 12** — Global Response Center.
- **P5 · Slices 13-16** — remaining domain consoles, native Command
  Intelligence, Notes/Attachments.
