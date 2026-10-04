# PRE-PUBLISH DEPLOYMENT BOUNDARY MAP — COLLECTOR AUTH P0 (`ce627691`)

Read-only analysis. **Nothing published. No Vercel deployment triggered.**
No code, config, secret or data changed.

---

## 1 · WHAT SERVES WHAT (verified live, not assumed)

| host | evidence | serves |
|---|---|---|
| `nivxray.nivxforge.com` | `/` returns `<title>Emergent \| Fullstack App</title>` (= `frontend/public/index.html`), `__emg_vid`/`__emg_sid` cookies, no `server: Vercel` | **Emergent production**: `/app/backend` (FastAPI) **+** `/app/frontend` (CRA "Workspace") |
| `xdr.nivxforge.com` | `307 → /xdr`, `server: Vercel`, `x-vercel-id: sfo1::…`, `<title>NivXRay XDR</title>`, entry `assets/index-CmdMrjfH.js` | **Vercel project `nivxray-xdr-production`**, Root Directory `apps/nivxray-xdr` |
| `edr.nivxforge.com` | `server: Vercel`, entry `assets/index-5e0IbMeq.js` | **second Vercel project**, SAME Root Directory `apps/nivxray-xdr`, `NIVX_PRODUCT_SCOPE=edr` |

Note for completeness: in THIS preview pod, supervisor's `frontend` program runs
`yarn dev` in **`apps/nivxray-xdr`** (Vite). That is why the tenant-selector /
Refresh verification I ran was genuinely against the XDR SPA — but it was the
POD's copy, not Vercel's.

## 2 · THE CANDIDATE, SPLIT BY DEPLOYMENT

### 2a · Deployed by ONE Emergent Republish (`nivxray.nivxforge.com`)
| file | why it is in the Emergent deployment |
|---|---|
| `backend/routers/collector_authz.py` **(NEW)** | the guard |
| `backend/routers/xdr_collector_landing.py` | attaches the guard at mount time |
| `apps/nivxray-xdr-collector/framework/route_classification.py` **(NEW)** | the collector package is imported **in-process** by the backend (`xdr_collector_landing._ensure_importable()` puts `/app/apps/nivxray-xdr-collector` on `sys.path`), so these files ship with the backend |
| `apps/nivxray-xdr-collector/framework/authz.py` **(NEW)** | same |
| `apps/nivxray-xdr-collector/routes/collectors.py` | same — the pod-hostname removal |
| `backend/tests/test_collector_plane_auth.py`, `apps/nivxray-xdr-collector/tests/*` | tests; not served |
| `apps/nivxray-xdr-collector/main.py` | standalone Docker entrypoint only — neither Emergent nor Vercel serves it |

`/app/frontend` (the CRA served at `nivxray.nivxforge.com`) has **no collector
changes** in this candidate, and greps show it never calls
`/api/xdr/collector/*` at all.

### 2b · NOT deployed by an Emergent Republish — needs Vercel
| file | host that needs it |
|---|---|
| `apps/nivxray-xdr/src/xdr/admin/collectorApi.js` (bearer attachment) | `xdr.nivxforge.com` |
| `apps/nivxray-xdr/src/xdr/design/IntegrationControlCenter.jsx` (`formatRefusal`, `TenantBar`, refresh-nonce) | `xdr.nivxforge.com` |
| `apps/nivxray-xdr/src/xdr/pages/XdrAdminPage.jsx` (passes the nonce) | `xdr.nivxforge.com` |

## 3 · DIRECT ANSWER

**Correct: one Emergent Republish deploys the backend Collector Auth P0 closure
and will NOT deploy the XDR SPA tenant-selector / Refresh / error-rendering
changes.** Those live in a separately deployed Vercel project.

Project to deploy for the frontend changes:
```
project          nivxray-xdr-production          (host xdr.nivxforge.com)
Root Directory   apps/nivxray-xdr
vercel.json      apps/nivxray-xdr/vercel.json
buildCommand     bash scripts/vercel-build.sh    (NIVX_PRODUCT_SCOPE unset/"xdr")
outputDirectory  dist
```

## 4 · THE ORDERING RISK — LIVE VERCEL IS OLDER THAN YOU THINK

I fetched the live Vercel bundles and grepped them. This is measured, not
inferred:

| marker | `xdr.nivxforge.com` entry chunk | `edr.nivxforge.com` entry chunk | candidate build (pod) |
|---|---|---|---|
| `nvx_token` (session bearer) | present (1) | present (1) | present |
| `X-Tenant-Id` | **ABSENT (0)** | **ABSENT (0)** | present |
| `nvx_tenant` (active-tenant module) | **ABSENT (0)** | **ABSENT (0)** | present |

So the live Vercel SPAs predate **not just this candidate but the entire B7
tenant-header closure**. Consequences of publishing the backend alone:

- `xdr.nivxforge.com` sends **no `X-Tenant-Id`** and **no Authorization** to the
  collector plane ⇒ after this publish every Integrations call returns
  `403 ACCESS_DENIED`, and because the old bundle also lacks `formatRefusal`
  it will render the `[object Object]` you already saw — the exact defect we
  just fixed, still visible on the customer-facing host.
- `xdr.nivxforge.com` has **no tenant selector**, so a production operator has
  no in-product way to establish tenant context there.
- Both Vercel hosts already fail closed against the CURRENT production build's
  EDR/XDR tenant authority (they cannot send a tenant at all), so that part is
  pre-existing, not caused by this publish.

**This does not make the backend publish unsafe** — it closes 9 anonymous-mutate
and 9 anonymous-leak operations, and a fail-closed UI is strictly better than an
anonymous control plane. But "Collector Auth P0 production closed" and "the
`xdr.nivxforge.com` UI is usable" are two different statements, and only the
first is achieved by the Emergent Republish.

## 5 · RECOMMENDED SEQUENCE (your call, nothing executed)

```
1. Emergent Republish  (ce627691)      -> closes the anonymous collector plane
2. Agent-side anonymous production checks (GET only)
3. Vercel deploy · nivxray-xdr-production · root apps/nivxray-xdr
4. Owner-side authenticated checks ON xdr.nivxforge.com
   (tenant dropdown shows the ACTIVE tenant by display name, Integrations
    loads, Refresh works)
5. STOP · report · then W1 GO
```
Step 4's UI checks (dropdown / Integrations load / Refresh) **cannot pass on
`xdr.nivxforge.com` until step 3 happens**. They can pass against
`nivxray.nivxforge.com` APIs via curl, but the dropdown is a Vercel artefact.

Optional, separate, NOT requested: the EDR Vercel project (same Root Directory,
`NIVX_PRODUCT_SCOPE=edr`) is equally stale. Deploying it is not required for W1
and I have not touched it.

## 6 · STATUS
```
deployment map        DONE
emergent publish      NOT PERFORMED (awaiting owner)
vercel deploy         NOT PERFORMED (awaiting owner)
candidate             ce627691 · unchanged
W1                    HELD
```
