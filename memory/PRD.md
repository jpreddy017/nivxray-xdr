# NivXRay — Product Requirements + Progress

_See earlier historical entries in `/app/memory/PRD.archive.md` (grows over time).
This file is the current, authoritative product record._

## 2026-08-29 · Session close · 🟢 SHIPPED — Application Separation Complete

**Original problem statement.** Extract NivXRay XDR into a genuinely
separate, independently buildable/deployable frontend application that
consumes the existing NivXRay platform through authenticated APIs.  The
existing `/app/frontend` (specifically `/analyst` and existing
`/edr/trajectory`) MUST remain completely untouched and independently
buildable.

### Architecture (locked)
```
EXISTING NIVXRAY TOOL                 NEW NIVXRAY XDR TOOL
─────────────────────                 ─────────────────────
/app/frontend  (CRA · Craco)          /app/apps/nivxray-xdr/  (Vite)
/app/backend   (FastAPI)              own build · own runtime · own deploy
Authoritative data, engines,          consumes existing NivXRay APIs only
SSOT, /analyst, /edr/trajectory  ←── authenticated HTTP calls ─
```

### What shipped this session

1. **Application Separation — /app/apps/nivxray-xdr/**
   - Vite + React 18 standalone app · own `package.json`, `vite.config.js`,
     `index.html`, `main.jsx`, `App.jsx`, `.env`.
   - Own axios/api client, AuthContext (reuses `POST /api/auth/login`),
     LoginPage.
   - Moved (via `git mv`, history preserved) into standalone:
     - `xdr/**` (shell + Dashboard/Incidents/IncidentDetail pages)
     - `nivxforge/{NivXForgeConsole, edrApi, nivxforge.css,
       pages/{EdrOverview,EdrDetections,EdrProcessTree,EdrReserved}}`
     - `components/incidents/**` (Header · LifecycleBar · 4 tab bodies)
     - `constants/incidentTestIds.js`, `lib/incidentsApi.js`
   - Deleted from base app (obsolete duplicates):
     `pages/incidents/{IncidentsListPage,IncidentShellPage,xdr.css}`.

2. **Base app cleanup — `frontend/src/App.js` only**
   - Removed XDR-owned imports (`XdrDashboardPage`, `XdrIncidentsPage`,
     `XdrIncidentDetailPage`, `EdrOverviewPage`, `EdrDetectionsPage`,
     `EdrProcessTreePage`, `EdrFilesPage`…`EdrResponsePage`,
     `IncidentsListPage`, `IncidentShellPage`) and their routes.
   - **KEPT untouched:** `/analyst` and `/edr/trajectory` route lines
     verbatim.  Every other route in the base app is unchanged.

3. **NivXRay XDR visual identity**
   - Inline SVG `NivxrayBrand` — mint-green angular N glyph + orange dot
     accent (matches the parent NIVXRAY logo language) · wordmark
     `NIVXRAY XDR` with mint-accented XDR suffix · tagline
     `EXTENDED DETECTION / RESPONSE`.
   - Placed at Login (large lockup), XDR shell top bar (compact),
     NivXForge Console top bar (compact).

4. **Deployment packaging**
   - `Dockerfile` — Node 20 build stage → `nginx:alpine` runtime with
     SPA history-fallback + immutable cache for `/assets/*`.  Builds
     ONLY this package.
   - `README.md` — purpose, structure, install/build/preview/serve,
     env vars, API dependencies, auth expectations, tenant/security,
     Emergent deployment recipe, no-duplication architecture.

### Verification

| Check | Result |
| :--- | :--- |
| Standalone build (`cd /app/apps/nivxray-xdr && yarn build`) | ✅ 1642 modules · `dist/index.html` + hashed assets |
| Base app build (`cd /app/frontend && yarn build`) | ✅ succeeds independently |
| Base app `/analyst` route | ✅ present, untouched |
| Base app `/edr/trajectory` route | ✅ present, untouched |
| Base app XDR/EDR-Console routes | ✅ removed (0 hits) |
| Local runtime (`yarn preview → :3100`) | ✅ all routes HTTP 200 |
| Login (browser QA) | ✅ NivXRay lockup renders |
| Login → Dashboard | ✅ 105 real incidents, tenant `admin@nivxray.com` |
| Incident detail (browser QA) | ✅ `INC-61B8AD · Phase1` rendered end-to-end |
| Investigation → Summary | ✅ 4-state Evidence-Gaps grid live |
| Response tab | ✅ approval-workflow stepper renders |
| Activity tab | ✅ canonical Activity Inventory loads |
| NivXForge EDR Console `/edr?incident_id=…` | ✅ full 10-tab shell renders with incident context banner |
| API connectivity (Login → /auth/me → /incidents) | ✅ real backend responses, JWT flow |
| Tenant scoping | ✅ enforced server-side by base NivXRay backend |
| No duplicate SSOT / engines | ✅ grep-confirmed (no `services/` / `workspace_cases` in XDR) |
| Backend regression | 🟢 **821 passed / 0 failed / 4 skipped** (+13 net additive vs 808 baseline · zero regressions) |
| Docker build | Verified statically; runtime `docker build` requires host with docker daemon (not present in this pod) |

### Deployment steps (for the operator)

1. **Save-to-GitHub** the base pod, then move `apps/nivxray-xdr/` into
   its own GitHub repository.
2. Emergent dashboard → **New app → From GitHub → this repo**.
3. Build command: `yarn install --frozen-lockfile && yarn build`
4. Static-serve directory: `dist/` (enable SPA history-fallback).
5. Build-time env: `REACT_APP_NIVXRAY_API_URL=https://<base-nivxray-host>`.
6. Deploy · gets its own `https://xdr-<slug>.preview.emergentagent.com/`.

### Guardrails held

- **`/analyst` untouched** (last touched pre-separation).
- **`/edr/trajectory` canvas untouched** (Device Trajectory
  implementation stays authoritative on the base host).
- **No parallel SSOT / no duplicate engines.**
- **No co-hosting inside `/app/frontend/public/xdr/`** (rejected by
  owner directive — hosting-only shim would blur boundaries).
- **Base preview URL unchanged.**
- **Regression baseline preserved.**

### Backlog (owner-directed queue)

- **Phase 2** — NivXForge EDR: full Detections table, Process Tree,
  Files, Network (currently reserved · later slice).
- **Phase 3** — Investigation cross-domain: Evidence, Timeline,
  Attack Story, Evidence Graph, ATT&CK, Verdict, Negative
  Explainability first-class.
- **Phase 4** — Intelligence pivots: Command Intelligence, IOC
  Intelligence, Malware Intelligence, Threat Intelligence.
- **Phase 5** — Response workflow wiring (Requested → Pending →
  Approved → Executing → Verified · immutable audit).
- **Phase 6** — Additional telemetry domains: NDR, ITDR, Email, Cloud,
  Application/API, Data Security, CTEM.
- **Phase 7** — Administration control plane: Integrations, Data
  Sources, Collectors, Parsers, Normalization, Telemetry Health,
  Policies.

None of these are started this session — separation is the only
delivered item, per owner directive.
