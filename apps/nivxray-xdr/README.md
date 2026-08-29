# NivXRay XDR — standalone tool

**NivXRay XDR is a separate Emergent application** that consumes the
existing NivXRay platform (`/app/frontend` + `/app/backend`) through
authenticated HTTP APIs.  It has its own source tree, its own build,
its own runtime, and its own deployment.  The base NivXRay tool is
**never modified** to make this app work.

```
EXISTING NIVXRAY TOOL              NEW NIVXRAY XDR TOOL
─────────────────────              ─────────────────────
/app/frontend  (SPA)               /app/apps/nivxray-xdr/  (this repo)
/app/backend   (FastAPI)                 │  authenticated
Authoritative data, engines,             │  HTTP API calls
SSOT, /analyst, /edr/trajectory  ◀──────┘
```

---

## 1 · Project purpose

- Enterprise SOC operating tool for the analyst who owns Incidents.
- Orchestrates the existing NivXRay platform — it does NOT re-implement
  Workspace, Device Trajectory, Process Tree, Command Intelligence,
  MITRE, Verdict, Evidence, or the Incident SSOT.
- Owns the Operations · Investigations · Intelligence · Exposure ·
  Data · Administration surfaces that were formerly threaded inside
  the base SPA.

## 2 · Directory structure

```
apps/nivxray-xdr/
├── Dockerfile                  # multi-stage · builds ONLY this app
├── README.md                   # this file
├── package.json                # own deps · no reach into /app/frontend
├── vite.config.js              # base `/` · classic JSX runtime
├── index.html                  # SPA entry
├── .env                        # local dev config (REACT_APP_NIVXRAY_API_URL)
└── src/
    ├── main.jsx                # React root · BrowserRouter · AuthProvider
    ├── App.jsx                 # standalone router
    ├── styles/globals.css      # document reset
    ├── lib/
    │   ├── api.js              # axios client · reads REACT_APP_BACKEND_URL
    │   ├── auth.jsx            # AuthContext · POST /api/auth/login
    │   └── incidentsApi.js     # /api/incidents/* wrapper
    ├── constants/
    │   └── incidentTestIds.js
    ├── components/
    │   ├── brand/NivxrayBrand.jsx     # inline SVG lockup (N glyph + wordmark)
    │   └── incidents/                  # header · lifecycle · 4 tab bodies
    ├── xdr/                     # XDR shell + operations pages
    │   ├── XdrShell.jsx
    │   ├── xdr-console.css
    │   ├── components/IncidentQueue.jsx
    │   └── pages/{Dashboard,Incidents,IncidentDetail}Page.jsx
    ├── nivxforge/               # NivXForge EDR Console (endpoint domain)
    │   ├── NivXForgeConsole.jsx
    │   ├── nivxforge.css
    │   ├── edrApi.js
    │   └── pages/{EdrOverview,EdrDetections,EdrProcessTree,EdrReserved}Page.jsx
    └── pages/LoginPage.jsx      # own login (reuses existing auth API)
```

## 3 · Install

```bash
cd /app/apps/nivxray-xdr
yarn install
```

Requires Node 18+ (Node 20 recommended, matching the Dockerfile).

## 4 · Build

```bash
yarn build
# → /app/apps/nivxray-xdr/dist/
```

Deterministic, hashed asset names (`assets/[name]-[hash].js`).
The bundle is entirely self-contained.

## 5 · Local preview

```bash
yarn preview
# → http://localhost:3100/
```

Any SPA path (`/`, `/login`, `/xdr`, `/xdr/incidents/…`, `/edr/…`) is
served from a single `index.html` with history-fallback routing.

## 6 · Production serving

Any static host that speaks HTTP + SPA history-fallback works.  The
included `Dockerfile` uses `nginx:alpine` with an SPA rewrite rule
and immutable long-cache for `/assets/*`.

```bash
docker build \
  --build-arg REACT_APP_NIVXRAY_API_URL="https://<base-nivxray-host>" \
  -t nivxray-xdr:latest .

docker run --rm -p 8080:80 nivxray-xdr:latest
# → http://localhost:8080/
```

## 7 · API base URL configuration

The moved source reads `process.env.REACT_APP_BACKEND_URL` (CRA
convention).  Vite `define` inlines that value at build time from
either `REACT_APP_NIVXRAY_API_URL` (preferred) or the legacy
`REACT_APP_BACKEND_URL`, so no source file needs edits.

`.env` for local dev:

```
REACT_APP_NIVXRAY_API_URL=https://<base-nivxray-preview-host>
```

For Docker / CI, pass it as a build-arg:

```
--build-arg REACT_APP_NIVXRAY_API_URL=https://<base-nivxray-host>
```

**Never hard-code the base host into application source.**

## 8 · Authentication expectations

- The app reuses the existing NivXRay `POST /api/auth/login` endpoint.
- The JWT is stored in `localStorage.nvx_token` (the same key the
  base NivXRay SPA uses, so both tools share the login when hosted on
  the same origin — but they do NOT share JS runtime).
- Every axios request attaches `Authorization: Bearer <token>`.
- `401` clears the token and bounces the tab to `/login?returnTo=…`.
- **The XDR frontend is never a security boundary.**  Tenant scoping
  is enforced by the base NivXRay backend on every request.

## 9 · Required environment variables

| Variable                       | When    | Purpose                                                                |
| :----------------------------- | :------ | :--------------------------------------------------------------------- |
| `REACT_APP_NIVXRAY_API_URL`    | build   | Base URL of the existing NivXRay platform (must include the scheme).  |
| `REACT_APP_BACKEND_URL`        | build   | Optional legacy fallback for the same value.                          |

No runtime env vars are required — everything is inlined at build.

## 10 · How XDR talks to the existing NivXRay backend

Every network call is an authenticated HTTP request to the existing
`https://<base-nivxray-host>/api/*` surface:

| XDR surface                | Base NivXRay endpoint                                    |
| :------------------------- | :------------------------------------------------------- |
| Login                      | `POST /api/auth/login` · `GET /api/auth/me`             |
| Dashboard / Incident queue | `GET /api/incidents?limit=…`                             |
| Incident detail            | `GET /api/incidents/{id}`                                |
| Investigation → Summary    | `GET /api/incidents/{id}/summary`                        |
| Lifecycle transitions      | `PATCH /api/incidents/{id}/state`                        |
| Assignee                   | `PATCH /api/incidents/{id}/assignee`                     |
| Activity tab               | `POST /api/activity/inventory`                           |
| EDR Detections             | `GET /api/edr/detections?incident_id=…`                  |
| EDR Process Tree           | `GET /api/edr/process-tree?incident_id=…`                |

Every domain launch point in the Overview grid opens the existing
NivXRay capability in a **new browser tab** — never a modal, never an
embedded iframe, never a re-implementation.

## 11 · Deploying as a separate Emergent project

XDR is **not** deployed from the same Emergent pod as the base
NivXRay app.  To ship it as its own preview:

1. Push `/app/apps/nivxray-xdr/` to a new GitHub repository (via the
   **Save to GitHub** feature in the base pod, then extract this
   subdirectory into its own repo).
2. In the Emergent dashboard, **New App → From GitHub → this repo**.
3. Build command: `yarn install --frozen-lockfile && yarn build`
4. Serve directory: `dist/` (single-page-app; enable history-fallback
   for any path → `index.html`).
5. Build-time env var:
   `REACT_APP_NIVXRAY_API_URL=https://<base-nivxray-host>`
6. Deploy.  Emergent assigns a preview URL like
   `https://xdr-<slug>.preview.emergentagent.com/`.

The base NivXRay preview stays exactly where it is.

## 12 · Expected static build directory

```
apps/nivxray-xdr/dist/
├── index.html
├── assets/index-*.js
├── assets/index-*.css
└── assets/*.{js,css}          # route-lazy chunks + component CSS
```

## 13 · SPA fallback routing

The bundled app owns these client-side routes: `/`, `/login`,
`/xdr`, `/xdr/incidents`, `/xdr/incidents/:id`, `/edr`,
`/edr/detections`, `/edr/process-tree`, `/edr/files`, `/edr/network`,
`/edr/hunting`, `/edr/forensics`, `/edr/live-query`, `/edr/response`.
Any unknown path redirects to `/xdr`.  The host **must** rewrite all
of these to `index.html` (nginx `try_files $uri /index.html;` — the
included Dockerfile already does this).

## 14 · Tenant / security requirements

- Tenant scoping is enforced entirely by the base NivXRay backend on
  the `Authorization: Bearer` bound to the request.
- The URL context hints (`?incident_id=…`, `?device=…`, `?tenant=…`)
  are navigation-only — the backend must never trust them for
  authorisation.
- No PII, no case data, no token is logged from this app.  The XDR
  frontend has no direct database access.

## 15 · No-duplication architecture

This app must **not**:

- run a second backend
- implement a second `workspace_cases` model
- run a second Verdict, Command Intelligence, MITRE, or Process Tree
  engine
- redefine the canonical Activity/Evidence SSOT
- embed the Device Trajectory canvas — clicks always deep-link back to
  the existing `/edr/trajectory` surface on the base NivXRay host

If a feature needs new server-side capability, add a projection API on
the base NivXRay backend (`/api/incidents/*`, `/api/edr/*`, etc.) and
call it from this app.

---

**Ownership:** every file in this directory is owned by NivXRay XDR.
Nothing here imports from `/app/frontend/src`.
