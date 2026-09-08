# PHASE 1 · Workspace deployment runbook — `workspace.nivxmachines.com`

**Status: the code side is DONE and PROVEN. The platform side is BLOCKED on
an owner-side action that I cannot perform and that is not unambiguous, so
per the owner lock I STOP here.**

Owner decisions applied: **Q1 = A · Q2 = A · Q3 = B · Q4 = B · Q5 = A**,
API = `https://nivxray.nivxforge.com` as a declared
`TEMPORARY_MIGRATION_DEPENDENCY`.

---

## 0 · The blocker, stated before the steps

I asked the platform team directly. **Emergent cannot deploy two
independent frontends from one repository.** There is no per-deployment
"Root Directory" setting, so a second Emergent project pulled from this
same repo would still build whatever the **repo-root** `vercel.json` builds
— which is `apps/nivxray-xdr`, the XDR app, **not** the Workspace.

That kills the plan I would otherwise have recommended, and it means
`frontend/vercel.json` — correct and ready as it is — **cannot be reached by
an Emergent deployment**. It is only honoured by a host that lets you point
a project at the `frontend` directory.

**And the armed hazard is still armed:**

> Pressing **Deploy** on the existing Emergent project rebuilds from current
> repo state and would replace the live legacy Workspace on
> `nivxray.nivxforge.com` with the XDR app. Do not press Deploy on that
> project. Nothing in this pass changed that; nothing in this pass touched
> it either.

### Two supported routes — pick one (owner decision required)

| | Route A · Vercel, root directory `frontend` | Route B · second GitHub repo, second Emergent project |
|---|---|---|
| Works today | **Yes** — Vercel supports monorepo Root Directory natively, and `frontend/vercel.json` is already written for exactly this | Yes |
| Touches the existing Emergent project | **No** | No |
| Extra cost | Vercel free tier is sufficient for a static SPA | 50 credits/month |
| Ongoing burden | One repo, two hosts | **Two copies of the code to keep in sync** — a permanent divergence risk, i.e. the exact failure this migration exists to end |
| Recommendation | **Recommended** | Only if you want everything on Emergent and accept the sync burden |

I recommend **Route A**. Route B re-creates the "which source built the live
bundle?" question that cost the previous session an entire pass.

---

## 1 · What is already done, in the repo, and proven

| item | state | evidence |
|---|---|---|
| `REMOVE_LEGACY_XDR` — nav item removed | DONE | `nav-xdr` occurrences in the shipped bundle: **0** |
| `REMOVE_LEGACY_INVESTIGATIONS` — nav item removed, 4 routes retained (Q1 = A) | DONE | `nav-investigations`: **0**; `/investigations`, `/investigations/:id`, `/investigations/:id/replay`, `/investigation-summary` all still route |
| `/nivxforge/*` — 9 product routes removed, **source retained** (Q2 = A) | DONE | all 9 bounce to `/`; `src/nivxforge/**` untouched on disk |
| `/edr/trajectory` removed, **source retained**, no dead outbound link created (Q3 = B) | DONE | bounces to `/`; no `edr.nivxforge.com` string exists in the bundle |
| `/analyst*`, `/investigate*`, `/v2/*` retained with flags OFF (Q4 = B) | DONE | 17 routes present; all three `REACT_APP_NIVX_FLAG_*` inline as `"disabled"` |
| `/benchmark` behind authentication (Q5 = A) | DONE | unauthenticated `/benchmark` → `/login` |
| Production API baked in | DONE | 22 refs to `https://nivxray.nivxforge.com`, **0** refs to preview |
| SPA fallback rewrite | CONFIGURED | proven both ways: without it `/auto-investigate` → **404**; with it → **200** |
| Cross-origin call will work | PROVEN | `OPTIONS https://nivxray.nivxforge.com/api/auth/login` with `Origin: https://workspace.nivxmachines.com` → **200**, `access-control-allow-origin: *`, `authorization` allowed |
| Legacy host unharmed | VERIFIED | `nivxray.nivxforge.com/` **200**, `/auto-investigate` **200**, live bundle `main.b4fd60ad.js` **200** — unchanged, no deploy performed |
| Preview XDR / EDR unharmed | VERIFIED | preview `/xdr/incidents` **200**, `/edr` **200**; `apps/nivxray-xdr` not modified |

Proof scripts (re-runnable):
`scripts/phase1_workspace_build_proof.py` → **32/32 PASS**
`scripts/phase1_workspace_authenticated_proof.py` → **43/43 PASS**
Results: `memory/phase1_workspace_build_proof.json`,
`memory/phase1_workspace_authenticated_proof.json`
Screenshot of the cleaned nav: `memory/phase1_workspace_cleaned_nav.png`

### Why there is an authenticated proof at all

The production artefact points at `nivxray.nivxforge.com`, whose database is
**separate** from preview and for which **no credential exists yet**. So
authenticated behaviour could not be proven against it before you deploy.
Rather than ship an unverified product, I built the **same cleaned source**
against the preview backend and drove it with real credentials. That proves
the four removals broke nothing; it does **not** prove production data or
production auth, and it is not presented as if it does.

### A production-safety trap found and neutralised — read this before editing env

`craco.config.js:3` calls `require("dotenv").config()` at module load. That
loads `.env` into `process.env` **before** react-scripts' own env loader
runs, and dotenv never overwrites an existing variable — so in this project
**`.env` beats `.env.production`**, the opposite of stock CRA precedence.

I tried `.env.production` first. It was **silently ignored**: the build still
inlined the preview backend URL 22 times. Had that shipped, the production
Workspace would have been reading the **preview database** while looking
completely healthy. The `.env.production` file was therefore deleted and every
production variable now lives in the **build command**, where real shell
variables win. Verified: 22 production refs, 0 preview refs.

Same trap applies to the shadow flags: `.env` sets all three to `shadow`, so
without explicit overrides the `/v2/*` shadow surfaces would have shipped
**switched on** in production, contradicting Q4 = B.

---

## 2 · Route A · click-by-click (recommended)

### 2.1 Push the repo
Use **Save to Github** in the chat input. Confirm the commit includes
`frontend/src/App.js`, `frontend/src/components/Header.jsx` and
`frontend/vercel.json`.

### 2.2 Create the Vercel project
1. vercel.com → **Add New… → Project** → import this GitHub repository.
2. On the configure screen open **Root Directory** and set it to
   **`frontend`**. *(This is the one setting that makes the whole thing
   work — it is why Route A exists.)*
3. Leave Framework Preset as detected/Other. **Do not** override Build
   Command, Install Command or Output Directory: `frontend/vercel.json`
   already supplies all three, including the SPA rewrite.
4. **Environment Variables — you do not need to add any.** The build command
   in `frontend/vercel.json` sets `REACT_APP_BACKEND_URL` and the three flag
   variables explicitly, for the precedence reason above. If you prefer them
   in the dashboard instead, add them as **real** environment variables — but
   keep them in the build command too, because a dashboard variable is
   loaded into `process.env` before dotenv runs and will therefore also win;
   duplicating is harmless, removing them from the build command is not.
5. **Deploy.**

### 2.3 Attach the domain
1. Vercel project → **Settings → Domains → Add** → `workspace.nivxmachines.com`.
2. At the registrar for `nivxmachines.com` create exactly one record:

   ```
   Type   CNAME
   Name   workspace
   Value  cname.vercel-dns.com
   TTL    default
   ```

   Use the exact target Vercel shows you if it differs.
3. **This cannot disturb the live marketing site.** You are adding one new
   subdomain record; the apex `nivxmachines.com` and `www` records are not
   touched. Confirmed with the platform team.
4. Wait for the certificate to be issued (usually minutes).

## 3 · Route B · if you insist on staying entirely on Emergent

1. Create a new **empty** GitHub repo, e.g. `nivxmachines-workspace`.
2. Copy the **contents of `/app/frontend`** into its root — so `vercel.json`,
   `package.json`, `src/`, `public/`, `craco.config.js`, `.env`,
   `yarn.lock`, `jsconfig.json` sit at the repo root.
3. New Emergent project → import that repo → Deploy → **Configure
   environment variables**, and set:
   `REACT_APP_BACKEND_URL=https://nivxray.nivxforge.com`,
   `REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=disabled`,
   `REACT_APP_NIVX_FLAG_CASE_ENGINE=disabled`,
   `REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=disabled`, `CI=false`.
4. **Link domain** → `workspace.nivxmachines.com` → follow the Entri /
   CNAME instructions.
5. Cost: 50 credits/month. Custom domains are free.
6. **Accept the consequence**: the Workspace source then exists in two
   repositories and will drift. Every future Workspace change must be
   applied twice.

## 4 · Before either route — identify who owns the legacy domain

Home tab → **View all deployed apps** → find the deployment holding
`nivxray.nivxforge.com`. **Look only. Do not redeploy it.** Note its name
so nobody redeploys it by accident later; that single click is the one
action that can destroy the live Workspace.

---

## 5 · Post-deployment acceptance — the exact checks, in order

Run these against `https://workspace.nivxmachines.com`. All must pass before
Phase 1 may be classified `WORKSPACE_MIGRATION_RUNTIME_VERIFIED`.

**A · the deployment is the right app at all**
1. `/` loads and the header reads `NIVXRAY · DECODER / THREAT-LAB`.
2. Primary nav shows exactly **WORKSPACE · HISTORY · BATCH · HEATMAP ·
   TOOLS · LEARN · ADMIN**.
3. **XDR is absent. INVESTIGATIONS is absent.**

**B · the SPA rewrite actually took effect** (the classic silent failure)
4. Open `https://workspace.nivxmachines.com/auto-investigate` **directly in
   a fresh tab** — not by clicking. It must load, not 404.
5. Press **F5 on that page**. It must survive the reload.

**C · the backend binding is right, not merely reachable**
6. DevTools → Network → confirm XHRs go to
   `https://nivxray.nivxforge.com/api/...` and **never** to
   `greeting-app-5782.preview…`.
7. Sign in. **A production credential is required** — the preview admin
   password returns `401` on this database. Generate a fresh production
   admin; do not reuse any preview credential.
8. After sign-in the header shows your e-mail and the corpus pill renders.

**D · retained functionality — the actual acceptance list**
9. **Workspace**: paste a base64 string → Decode → output renders.
10. **Auto Investigate**: submit an input → a verdict/summary returns.
11. **Analyze** (Tools → Command Analyzer): submit a command line → result.
12. **History**: the list renders and reports a record total.
13. **Retained investigation drilldown (Q1 = A)**: from History open a
    correlated record → it must land on `/investigations/<id>` and render.
    **This is the check that proves the nav removal did not delete the
    capability.**
14. **Find Related**: open it from the Workspace → correlate → it must
    navigate to an investigation detail page.
15. **Quick Open**: `Ctrl/Cmd+K` → the palette opens and lists results.
16. **Batch**, **Heatmap**, **Learn → Practice Lab / Knowledge Base /
    Docs**, **Admin → Admin Panel / Documents / Training Inbox / Model
    Studio / Sample Library** all render.
17. **Share / Copy Link**: generate a share link and confirm it contains
    `workspace.nivxmachines.com`, not the old host.

**E · the removals, confirmed live**
18. `/xdr` → bounces to `/`.
19. `/nivxforge`, `/nivxforge/dashboard`, `/nivxforge/investigate`,
    `/nivxforge/governance` → all bounce to `/`.
20. `/edr/trajectory` → bounces to `/`.

**F · the security correction**
21. Sign out. Open `/benchmark`. It must land on `/login` and must **not**
    render benchmark data or the product nav.

**G · zero damage to what already exists**
22. `https://nivxray.nivxforge.com/` still loads the legacy Workspace,
    unchanged, with XDR and INVESTIGATIONS still in its nav.
23. `https://greeting-app-5782.preview.emergentagent.com/xdr/incidents` and
    `/edr` still load.
24. `https://nivxmachines.com` and `https://www.nivxmachines.com` still
    serve the marketing site.

**H · console hygiene**
25. DevTools console: no uncaught errors on `/`, `/auto-investigate`,
    `/history` or an investigation detail page.

Once A–H pass, tell me and I will record
`WORKSPACE_MIGRATION_RUNTIME_VERIFIED` and stop for your approval before
Phase 2.

---

## 6 · Standing constraints carried into later phases

- **`nivxray.nivxforge.com` MUST NOT be retired after Phase 1.** The new
  Workspace calls its `/api` — a declared `TEMPORARY_MIGRATION_DEPENDENCY`.
  Retirement stays in Phase 5, after Phase 4 establishes the permanent API
  origin and the Workspace is rebuilt against it.
- **Never press Deploy on the Emergent project that holds
  `nivxray.nivxforge.com`** until the legacy Workspace is genuinely
  disposable.
- **CRA inlines env at build time.** Every API-origin change needs a
  **rebuild**, not a config edit. There is no runtime override.
- **`localStorage` is per-origin**, so the new Workspace requires its own
  sign-in. Single sign-on across the three products is the later OIDC work.
- Backend CORS is currently `*`. It works and is proven, but it is not the
  final production posture; tightening it to explicit origins comes once all
  three hostnames are fixed.
