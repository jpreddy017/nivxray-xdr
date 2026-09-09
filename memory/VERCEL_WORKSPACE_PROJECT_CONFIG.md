# Vercel project `nivxmachines-workspace` — configuration report

**Requested:** fix the repository configuration so a NEW Vercel project with
Root Directory `frontend` builds `/app/frontend` only.
**Nothing deployed. STOP for owner approval.**

Not touched: `/app/apps/nivxray-xdr`, `apps/nivxray-xdr/vercel.json`,
**repo-root `vercel.json`**, Preview XDR, Preview EDR, backend, databases,
the frozen Emergent production deployment.

---

## 1 · Why you saw `apps/nivxray-xdr` in read-only fields

Those greyed fields are Vercel telling you *"these are managed by
`vercel.json`"*, populated from the **repo-root** `vercel.json` that Vercel
read when it first imported the repository:

```json
"installCommand":  "cd apps/nivxray-xdr && yarn install --production=false --frozen-lockfile",
"buildCommand":    "cd apps/nivxray-xdr && node ./node_modules/vite/bin/vite.js build",
"outputDirectory": "apps/nivxray-xdr/dist"
```

**No repository change is required to fix this, and none was made to that
file.** Per Vercel's own documentation, `vercel.json` is read from the
**Root Directory**, and the Root Directory setting *"takes effect on your
next deployment"*. So once Root Directory = `frontend` is **saved**, the
authoritative config becomes `frontend/vercel.json` and those fields will
re-read from it.

**And the failure mode is safe either way.** If the root config were somehow
applied under Root Directory = `frontend`, then `cd apps/nivxray-xdr` and
`outputDirectory: apps/nivxray-xdr/dist` both point **outside** the Root
Directory, which Vercel forbids — you would get a **failed build**, not a
wrong site. On top of that, the build guard would reject a wrong artefact.
There is no path here that silently ships the XDR app to
`workspace.nivxmachines.com`.

> **Confirm before deploying:** Settings → Build and Deployment → Root
> Directory reads `frontend` **and is saved**. If the read-only commands
> still mention `apps/nivxray-xdr` after saving, stop and tell me — do not
> deploy.

## 2 · A REAL blocker found while verifying — your deploy would have failed

Running the exact `installCommand` from `frontend/vercel.json`:

```
$ yarn install --production=false --frozen-lockfile
error Your lockfile needs to be updated, but yarn was run with `--frozen-lockfile`.
exit 1
```

**`frontend/yarn.lock` did not cover `frontend/package.json`.** 17 top-level
dependencies were declared but absent from the lockfile:

- **runtime:** `@xyflow/react@^12.11.2`, `dagre@^0.8.5`, `konva@^10.3.0`,
  `react-konva@^19.2.5` — `konva`/`react-konva` are genuinely imported by
  `src/v2/canvas_engine/IRGGraphCanvas.jsx` and
  `src/v2/canvas_engine/InvestigationCanvas.jsx`
- **build/dev:** the seven `@storybook/*` 8.6.14 packages, `storybook`,
  `typescript@5.4.5`, `@types/node`, `@types/react@19.0.0`,
  `@types/react-dom@19.0.0`, `json-schema-to-typescript`

Local builds succeeded only because `node_modules` already had them from an
earlier non-frozen install. A clean Vercel checkout has no `node_modules`,
so **the install step would have failed and the deployment would never have
built.** Caught before you clicked Deploy, which is exactly why the install
command is run verbatim rather than assumed.

### The fix, and why it carries no dependency risk

`frontend/yarn.lock` regenerated with `yarn install --production=false`.
Measured, not assumed:

| | |
|---|---|
| existing lockfile entries whose **version changed** | **0** |
| new entries added | 223 (the missing packages + their transitives) |
| `react` / `react-dom` | 19.0.0 / 19.0.0 — unchanged |
| `react-router-dom` · `axios` · `react-scripts` · `@craco/craco` | 7.15.0 · 1.16.0 · 5.0.1 · 7.1.0 — unchanged |

**Purely additive.** Nothing already pinned moved, so there is no version
churn to re-qualify. `yarn install --production=false --frozen-lockfile` now
exits **0**.

## 3 · Node version pinned to the version the build is proven on

Added **`frontend/.nvmrc`** containing `20`.

`frontend/package.json` declares no `engines.node` and there was no
`.nvmrc`, so Vercel would have picked its own current default. This build is
proven on **Node v20.20.2** with `react-scripts@5.0.1` (CRA, unmaintained).
Pinning removes an avoidable variable from a migration; it does not claim a
newer Node is broken, only that it is unproven here. Vercel reads `.nvmrc`
from the Root Directory, so this affects **only** this project.

## 4 · Exact files changed

| file | change |
|---|---|
| `frontend/yarn.lock` | regenerated · +1329 / −37 lines · **0 version changes**, 223 additions |
| `frontend/.nvmrc` | **new** · `20` |
| `frontend/vercel.json` | unchanged in this pass (already correct) |
| `frontend/scripts/verify-production-build.js` | unchanged in this pass |
| **`vercel.json` (repo root)** | **NOT MODIFIED** |
| **`apps/nivxray-xdr/**`** | **NOT MODIFIED** |

## 5 · Exact settings Vercel should show

With Root Directory = `frontend`, all three come from `frontend/vercel.json`
and will be **read-only** — that is correct and expected:

**Root Directory**
```
frontend
```

**Install Command**
```
yarn install --production=false --frozen-lockfile
```

**Build Command**
```
CI=false GENERATE_SOURCEMAP=false REACT_APP_BACKEND_URL=https://nivxray.nivxforge.com REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=disabled REACT_APP_NIVX_FLAG_CASE_ENGINE=disabled REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=disabled yarn build && node scripts/verify-production-build.js
```

**Output Directory**
```
build
```

**Framework Preset**
```
Other  (framework: null)
```

**Node.js Version** — `20.x`, from `frontend/.nvmrc`.

**Environment Variables** — none required. Every production variable is in
the build command, deliberately: `craco.config.js` calls
`require("dotenv").config()` at module load, so `.env` beats
`.env.production` in this project and a `.env.production` file was **proven
to be silently ignored**. Real shell variables are the only reliable
override.

**Rewrites** — `/(.*) → /index.html`, from `frontend/vercel.json`. Without
it every deep link 404s while `/` works.

## 6 · Re-verified against the NEW artefact after these changes

Everything was re-run, not assumed still good:

| proof | result |
|---|---|
| `yarn install --production=false --frozen-lockfile` | **exit 0** |
| exact Vercel build command + guard | **PASSED** · 22 production API refs · 0 preview refs · all three flags `disabled` |
| `scripts/phase1_workspace_build_proof.py` | **32/32 PASS** |
| `scripts/phase1_workspace_authenticated_proof.py` | **43/43 PASS** · 0 console errors |
| `scripts/workspace_live_acceptance.py` (local dry-run) | **35/35 PASS · 11 BLOCKED (credential)** |
| `scripts/legacy_watchdog.py` | healthy · legacy untouched |

## 7 · One thing to do before importing on Vercel

**Push these changes to GitHub** with **Save to Github** — Vercel builds from
the repository, not from this workspace. The commit must include
`frontend/yarn.lock` and `frontend/.nvmrc`, or the install step will fail on
Vercel exactly as it did here.

**Then STOP.** Do not press Deploy until you have confirmed §1's Root
Directory check.
