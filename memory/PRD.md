# NivXRay — Product Requirements + Progress

## 2026-08-29 · Session close · 🟢 STANDALONE XDR LIVE

Standalone tool deployed independently at
**https://nivxray-xdr.vercel.app/xdr**, consuming the existing NivXRay
platform (`https://greeting-app-5782.preview.emergentagent.com/api/*`)
through authenticated HTTPS calls.  Base tool untouched apart from a
one-file cleanup (`frontend/src/App.js` — XDR routes removed only).

### Architecture (locked)

```
NEW NIVXRAY XDR                     EXISTING NIVXRAY TOOL
─────────────────                   ─────────────────────
https://nivxray-xdr.vercel.app     https://greeting-app-5782.preview.emergentagent.com
Vite · React · own repo             CRA · React · this Emergent pod
Repo: jpreddy017/nivxray-xdr        /analyst · /edr/trajectory · /api/*
Src on this pod: /app/apps/nivxray-xdr (reference only)
        │                                    ▲
        └─── authenticated HTTPS ────────────┘
                    /api/*
```

### What shipped this session

**Application separation**
- Standalone Vite + React app at `/app/apps/nivxray-xdr/` (own build, own runtime, own repo, own deployment).
- Base app `App.js` cleaned of XDR-owned imports and routes; `/analyst` + `/edr/trajectory` verbatim untouched.
- Cross-origin auth wired via shared `nvx_token` in localStorage; base backend CORS is already permissive.

**Dashboard**
- Mockup-fidelity Security Operations console: 46px top-bar with circuit-tree mark + wordmark, 198px left sidebar (6 sections · 20 items), 8-KPI grid, incident-queue panel with search + 6 filter chips + 10-column table.
- Live data from `GET /api/incidents?limit=500`.
- Every KPI card is clickable (Critical / High → severity filter; Unassigned → owner filter; My Queue → tenant scope; Response / SLA → honest reserved-modal; Evidence → deep-link to base `/analyst`).
- Every sidebar item and top-nav item either routes inside XDR, deep-links to an existing NivXRay capability in a new tab (with a `↗` chevron), or opens a "Reserved · later slice" modal.  No dead click.

**Brand**
- Inline-SVG circuit-tree mark (owner-approved 2026-08-29) + wordmark
  `NiVXRAY XDR` (orange `i` accent) + tagline
  `EXTENDED DETECTION / RESPONSE` on the login lockup.

**Incident detail (unchanged from prior slice)**
- `/xdr/incidents/:id` renders the 4-tab shell (Overview · Investigation · Activity · Response).
- "OPEN NIVXFORGE EDR →" now opens the **base** NivXRay `/edr/trajectory?incident_id=…` in a new tab (skips the intermediate Console overview).

**Deploy artifacts**
- `Dockerfile` (Node 20 build → nginx-alpine runtime with SPA fallback) — for portability.
- `vercel.json` (SPA history fallback) — used by the live deployment.
- `README.md` (complete deploy recipe + no-duplication rules).

**Verification (this session)**
- Standalone build: ✅ (Vite, 1642 modules).
- Base build: ✅ (CRA/craco, unchanged).
- Live login → dashboard → incident → all 4 tabs → EDR launch to base `/edr/trajectory` → all deep-links to `/analyst`, `/heatmap`, `/threat-intel`, `/analyze` → new-tab semantics: ✅.
- Backend regression: **821 / 0 / 4** — zero regressions.

---

### Next-session roadmap (owner-directed 2026-08-29)

**P0 — Incident Investigation Console** (`/xdr/incidents/:id`)
Make this the strongest part of the standalone XDR.

```
Incident
 ├── Summary       (existing /api/incidents/{id}/summary)
 ├── Investigation
 │    ├── Attack Story   → existing IUE projection
 │    ├── Evidence       → existing evidence pointers
 │    ├── Entities       → existing IKG projection
 │    ├── MITRE ATT&CK   → existing heatmap deep-link
 │    └── Timeline       → existing Activity Inventory
 ├── Activity      (existing /api/activity/inventory)
 └── Response      (approval workflow — deferred, see below)
```

Every entity in the incident must offer contextual pivots (always
new tab, always to an existing NivXRay capability):

| Entity                | Pivot destination                                 |
| :-------------------- | :------------------------------------------------ |
| Process               | base `/edr/trajectory` (Process Tree scope)       |
| Command line          | base `/analyze` (Command Intelligence)            |
| Endpoint / host       | base `/edr/trajectory?device=…`                   |
| Detection             | base `/edr/trajectory?event=…`                    |
| IOC (hash/ip/domain)  | base `/threat-intel?ioc=…`                        |
| MITRE technique       | base `/heatmap?technique=…`                       |
| Evidence node         | base `/analyst?case=…&evidence=…`                 |

**P1 — Native Endpoints view** (`/xdr/endpoints`)
Reuse `/api/edr/*`.  No new endpoint data engine.

**P2 — Deterministic Severity Mapper**
Only if the existing evidence supports the classification.  Evidence
→ deterministic rules → `critical / high / medium / low`.  Do **not**
inflate labels to populate KPI counts.

---

### Guardrails (locked · do not violate in future sessions)

- ❌ No changes to `/app/frontend`
- ❌ No changes to `/analyst`
- ❌ No changes to existing `/edr/trajectory`
- ❌ No duplicate Process Tree, Verdict Engine, Evidence, IKG, or SSOT
- ❌ No fake telemetry — always use `NOT CONNECTED / NOT AVAILABLE / NO MATCHING EVIDENCE / ERROR`
- ❌ No Cisco Device Trajectory fidelity work yet
- ❌ No co-hosting of XDR inside the base frontend
- ❌ No Response Wiring in feature work yet
- ✅ XDR source lives at `/app/apps/nivxray-xdr` (mirror) + GitHub `jpreddy017/nivxray-xdr` (canonical)
- ✅ XDR deployed independently at https://nivxray-xdr.vercel.app
- ✅ All security data consumed through authenticated APIs from the existing NivXRay backend

---

### Deferred backlog (post-P0/P1/P2)

- Response Wiring (Requested → Pending → Approved → Executing → Verified · immutable audit)
- Device Trajectory ~95% operational fidelity — separate slice
- Additional telemetry domains: NDR / ITDR / Email / Cloud / Application·API / Data Security / CTEM
- Administration control plane (Integrations · Data Sources · Collectors · Parsers · Normalization · Telemetry Health · Policies)

---

### Test credentials (see `/app/memory/test_credentials.md`)

- **Email:** `admin@nivxray.com`
- **Password:** rotated — see credentials file (last rotation preserved in that file).
- Same credentials on both hosts (base + XDR); shared `nvx_token` in localStorage.
