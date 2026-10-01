# Production domain inventory — measured, not assumed · 2026-09-08

Every row below was established by HTTP request against the live hosts and
compared with the preview environment. Nothing here is inferred from the
repo or from a previous plan.

## What is actually live

| host | serves | evidence |
|---|---|---|
| `nivxray.nivxforge.com` | **NivXMachines Workspace** (CRA) — the tool the owner thought was only in preview | bundle `static/js/main.b4fd60ad.js` contains `"/auto-investigate"` and `"/analyze"`; `/auto-investigate` → **200**, `/analyze` → **200** (SPA rewrite already configured) |
| `nivxforge.com` + `www.nivxforge.com` | **an older build of the same product family** — NOT empty | bundle `main.f12358da.js` (354 KB) mentions `NivXForge`, `Decoder`, `AutoInvestigate`, `EDR`, but has no `/auto-investigate` or `/xdr` route string; `/api/health` → 404 while `/api/` → `{"service":"NivXRay","status":"ok"}` |
| `www.nivxmachines.com` → `nivxmachines.com` | **a live, properly branded marketing site** | `<title>NivX Machines · Cybersecurity, AI & Threat Intelligence</title>`, `main.c6b21c2c.js` (514 KB), none of the Workspace routes |
| `greeting-app-5782.preview…` | **NivXRay XDR + NivXForge EDR** (Vite) | supervisor `[program:frontend] directory=/app/apps/nivxray-xdr` |

**No custom domain currently serves the XDR/EDR Vite app.** The Vite build
emits `assets/index-*.js`; every custom domain above serves CRA
(`static/js/main.*.js`).

## The backend / database split

`nivxray.nivxforge.com/api` runs **the current repo code**:
`/api/openapi.json` reports **785 paths, identical to preview**, and
includes routes created on 2026-09-08 (`/api/edr/telemetry/freshness`,
`/api/edr/agent/heartbeat`). Control: `/api/zzz-not-a-route-12345` → 404,
so those routes genuinely exist rather than being a blanket 403.

But the **database is separate**:

```
POST /api/auth/login  (admin@nivxray.com, preview password)
  preview                  → 200  + access_token
  nivxray.nivxforge.com    → 401  {"detail":"Invalid credentials"}
```

**Corollary that affects the migration plan:** the only real Linux sensor
runs in the *preview* pod and writes to the *preview* database. A
production XDR/EDR deployment therefore starts with **zero endpoints and
zero telemetry**, and P0-3 will correctly report
`NEVER_DELIVERED` / `NO_ENROLLED_ENDPOINTS`. "Sensor still DELIVERING"
cannot be an acceptance criterion for a production deployment until a
sensor is enrolled against the production backend.

## The armed hazard

Repo root `vercel.json`:

```
buildCommand:     cd apps/nivxray-xdr && node ./node_modules/vite/bin/vite.js build
outputDirectory:  apps/nivxray-xdr/dist
rewrites:         /(.*) → /index.html
```

The live Workspace on `nivxray.nivxforge.com` is the artefact of an
**earlier** deploy. The build config now produces the **XDR/EDR** app.
Emergent support confirms a redeploy rebuilds from current repo state and
**replaces** what was there.

> **Pressing "Deploy" on this project silently replaces the live
> Workspace on `nivxray.nivxforge.com` with the XDR app.** The
> destructive act is the deploy, not the domain change. Verify domain
> ownership first: Home → *View all deployed apps* → find the deployment
> holding `nivxray.nivxforge.com`.

## Platform constraints confirmed with Emergent support

- **One frontend deployment per project.** Two frontends from one repo
  require **two Emergent projects** (pull the same GitHub repo into a
  second project and point it at the other app directory).
- **Preview and production databases are always separate** by default;
  sharing one is possible via env but not recommended.
- **No host-based routing at the platform edge.** `www.nivxforge.com/ → /edr`
  and `nivxray.nivxforge.com/ → /xdr` from one bundle must be done in-app
  (`window.location.hostname`) or by using two deployments.
- Custom domains: unlimited per deployment, no extra credit cost.
  Deployments cost 50 credits/month each.
- Rollback exists per deployment and restores the **previous build**.

## Repo-side Stage-1 readiness (done, non-destructive)

`frontend/vercel.json` added — **inert**: only the config at a
deployment's configured Root Directory is read, so the repo-root
`vercel.json` still governs the existing deployment and was **not
touched** (verified after the change). It supplies the two things the
Workspace app needs and did not have:

- `CI=false` (CRA promotes its 9 `react-hooks/exhaustive-deps`
  advisories to errors when CI is truthy)
- `rewrites: /(.*) → /index.html` — without it `/auto-investigate`
  returns 404 on a static host while `/` works

`REACT_APP_BACKEND_URL` is deliberately **not** baked in: CRA inlines env
at build time, and preview/production are different databases, so the
deploying environment must supply the correct one.

## Recommended corrections to the staged plan

1. **`www.nivxmachines.com` is occupied.** Use
   **`workspace.nivxmachines.com`** (CNAME) and leave the marketing site
   and its apex/`www` A+CNAME records alone.
2. **Workspace is already in production** — Stage 1 is not "deploy a tool
   that has never been deployed", it is "give the already-live Workspace
   its own deployment and hostname **before** anything rebuilds the
   project".
3. **Do not deploy this project until `nivxray.nivxforge.com` is either
   detached or the Workspace has a proven new home.**
4. `nivxforge.com` is not empty — decide consciously that the stale build
   there is replaceable.
