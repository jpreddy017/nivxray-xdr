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

### THE RECOMMENDED ROUTE — ONE, NOT TWO

**Deploy `/app/frontend` on Vercel with Root Directory = `frontend`.**

Scored against the owner's eight criteria:

| criterion | Vercel · Root Directory `frontend` |
|---|---|
| lowest chance of damaging the existing deployment | **highest score — it never touches the Emergent project at all.** No Deploy press, no env change, no rebuild trigger |
| independent frontend deployment | yes |
| supports `workspace.nivxmachines.com` | yes, one CNAME |
| SPA fallback | yes — `frontend/vercel.json` already carries the rewrite and Vercel reads it natively at that Root Directory |
| explicit build-time env vars | yes — already in the `buildCommand`, plus the dashboard if wanted |
| can deploy `/app/frontend` | yes, **without copying any code** |
| no duplication of the authoritative backend/database | yes — it is a static SPA calling the existing API |
| straightforward rollback | yes — instant "Promote to Production" on any previous deployment, no rebuild |

**The second-repo option is rejected, and it is not an equivalent choice.**
It fails the sixth criterion: it can only deploy `/app/frontend` by
**copying the Workspace source into a second repository**, which then
drifts. That is precisely the "which source built the live bundle?"
question that cost the previous session an entire pass and produced the
false 139-vs-70 finding. Duplicating the authoritative frontend to solve a
hosting limitation trades a one-time platform constraint for a permanent
correctness risk, so there is no genuine owner-level tradeoff to weigh.

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
| Migration build guard | ADDED + PROVEN | `frontend/scripts/verify-production-build.js`, chained into the `buildCommand`. Fails the build on: a preview origin, an unapproved/missing/multiple API origin, or a `/v2/*` shadow flag switched on. Proven on **1 passing** artefact and **6 distinct failing** ones, all exit 1 — including the realistic regression of *forgetting the flag overrides*, where `.env`'s `shadow` silently wins |

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

## 2 · The recommended route · click-by-click

### 2.1 Push the repo
Use **Save to Github** in the chat input. Confirm the commit includes
`frontend/src/App.js`, `frontend/src/components/Header.jsx` and
`frontend/vercel.json`.

### 2.2 Create the Vercel project
1. vercel.com → **Add New… → Project** → import this GitHub repository.
2. On the configure screen open **Root Directory** and set it to
   **`frontend`**. *(This is the single setting the whole plan rests on: it
   is what makes `frontend/vercel.json` authoritative instead of the
   repo-root one that builds the XDR app.)*
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

## 3 · Before you start — identify who owns the legacy domain

Home tab → **View all deployed apps** → find the deployment holding
`nivxray.nivxforge.com`. **Look only. Do not redeploy it.** Note its name so
nobody redeploys it by accident later; that single click is the one action
that can destroy the live Workspace.

---

## 4 · Post-deployment acceptance — the exact checks, in order

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
   password returns `401` on this database, and provisioning one is
   currently blocked by the platform. **See §5 before attempting this
   step.**
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

**I · the four checks you added on top of the 25**
26. **Shadow flags OFF**: open `/v2/workspace`. It must render the honest
    disabled notice, not a working v2 surface.
27. **No preview API URL embedded**: DevTools → Sources → search the loaded
    bundles for `preview.emergentagent.com` → **zero** hits. *(The build
    guard already fails the build on this, so this is confirmation that the
    guard ran, not a substitute for it.)*
28. **No broken API requests**: DevTools → Network, filter XHR, walk
    Workspace → Auto Investigate → History → an investigation detail. No
    `4xx`/`5xx` other than a deliberate auth challenge, and **no CORS
    errors** *(preflight already proven from this origin: `200`,
    `allow-origin: *`, `authorization` allowed)*.
29. **Retained nested / drilldown routes + deep-link reload**: open
    `/workspace/session/<id>`, `/compare`, `/investigations/<id>` directly in
    a fresh tab and press **F5** on each. All must survive the reload.

Once A–I pass, tell me and I will record
`WORKSPACE_MIGRATION_RUNTIME_VERIFIED` and stop for your approval before
Phase 2.

---

## 5 · The production administrator credential — BLOCKED BY THE PLATFORM

You instructed me not to request or reuse any credential from you, and to
provision a new production Workspace administrator through the application's
supported mechanism. I traced that mechanism and then established that it
**cannot be executed in this pass**. Reporting it rather than working around
it.

### The supported mechanism exists, and it is the right one

`backend/deps.py:359 · seed_admin()` — runs on backend startup:

- reads **`ADMIN_EMAIL`** and **`ADMIN_PASSWORD`** from the environment
- **idempotent**: `if existing: return` — it will **never** reset or disturb
  an admin that already exists
- honours **`ADMIN_FORCE_PASSWORD_CHANGE=true`**, which sets
  `must_change_password=True`. That flag is genuinely **enforced**, not
  decorative: `deps.py:297` blocks every authenticated route until the
  password is rotated through `POST /api/auth/change-password`
- hashes via the same `hash_password` used everywhere else

There is **no** self-registration route, **no** password-reset flow and
**no** admin user-creation API — I checked: `routers/auth.py` exposes only
`login`, `me` and `change-password`, and `db.users.insert_one` appears in
exactly one non-test place, `seed_admin`. So environment-driven seeding at
startup is the *only* supported path.

### Why it cannot run yet — confirmed with the platform team

| question | answer |
|---|---|
| Can env vars be changed on a deployed app? | Yes |
| Does changing one trigger a **rebuild from current repo state**? | **Yes** |
| Can the backend be restarted / env-updated **without** rebuilding the frontend? | **Not supported** — deployments are atomic |
| Any console, shell, task runner or migration hook against the production DB? | **Not supported** |
| Direct production MongoDB connection string? | **Not supported** |
| Does rollback re-run the build or restore the artefact? | **Restores the previous artefact** |

Setting `ADMIN_EMAIL` / `ADMIN_PASSWORD` on the legacy project therefore
forces a rebuild, and that rebuild would replace the live legacy Workspace
with the XDR app — the one thing you forbade. **So I did not do it, and I
did not probe production auth either**: the login route has a sliding-window
rate limiter keyed on `(email, ip)` that returns `429` on lockout, and
guessing at the production admin would be brute-forcing our own production.

### The consequence for Phase 1 acceptance, stated plainly

Checks **A, B, E, F, G, H** and **26–29** can all be proven **without**
signing in. Checks **C7–C8** and **D** cannot: they need an authenticated
session, which needs an admin on that database.

So Phase 1 splits honestly into two gates:

- **`WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED`** — achievable the moment
  `workspace.nivxmachines.com` is live. No credential, no rebuild, no risk.
- **`WORKSPACE_MIGRATION_RUNTIME_VERIFIED`** — requires the authenticated
  half, and therefore requires one owner decision.

### The decision, and why the safe answer is "later, not now"

The rebuild becomes **safe** exactly once `workspace.nivxmachines.com` is
live and unauthenticated-verified, because at that point the legacy host's
**frontend** is no longer load-bearing — only its **API** is, and the API is
rebuilt from the same backend code it is already running. The sequence that
keeps everything reversible:

1. Deploy Workspace to Vercel. Run A, B, E, F, G, H, 26–29 →
   `WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED`.
2. **Owner approval gate.** You decide whether the legacy hostname may stop
   serving the legacy Workspace UI. *(Note what the rebuild does: repo-root
   `vercel.json` builds the XDR app, so `nivxray.nivxforge.com` would begin
   serving the XDR frontend while continuing to serve the API. That is a
   change to what that hostname shows, and it is your call — not mine.)*
3. On approval: add `ADMIN_EMAIL`, `ADMIN_PASSWORD` and
   `ADMIN_FORCE_PASSWORD_CHANGE=true` to that deployment's environment and
   let it rebuild. **You type the password directly into the platform's env
   UI.** It never reaches me, the repo, the bundle, a log, a proof script or
   any document — which is exactly the handling you asked for, and is only
   achievable this way.
4. Sign in once at `workspace.nivxmachines.com`; the forced rotation makes
   the bootstrap value single-use.
5. Run C7–C8 and D → `WORKSPACE_MIGRATION_RUNTIME_VERIFIED`.
6. Rollback remains available at every step and restores the artefact
   without rebuilding.

Use a **new** production address (for example `admin@nivxmachines.com`) —
not `admin@nivxray.com`. `seed_admin` is idempotent, so if an admin with
that e-mail already exists on the production database nothing happens at
all, and the provisioning would silently no-op.

I have not written any credential anywhere, and there is none to hand over.

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
