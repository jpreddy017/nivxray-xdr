# Why `frontend/vercel.json` looks the way it does

The reasoning used to live in `$comment` / `$installComment` keys inside the
file. **Vercel's schema rejects unknown top-level properties** —
`vercel.json schema validation failed: should NOT have additional property
'$comment'` — and it fails *before* the build starts, so the notes moved
here. **Do not add `$comment` back to any `vercel.json`.**

## `installCommand` — no `--frozen-lockfile`, deliberately

`frontend/yarn.lock` in the repository does not satisfy
`frontend/package.json`: 17 top-level dependencies are missing, four of them
runtime (`@xyflow/react`, `dagre`, `konva`, `react-konva`). A regenerated
lockfile exists in the workspace (649,903 B, blob `f69fa5aa`) but the
repository holds the old one (588,753 B, blob `be098679`) — verified through
the GitHub API, not the CDN. The push captures source files but not this
lockfile, so `--frozen-lockfile` fails the install on every deploy. That is
exactly how the first XDR build died.

Proven: a clean install using the **repository's** stale lockfile plus this
command exits **0** in ~31 s and resolves `konva` and `@xyflow/react`.

Trade-off accepted knowingly: yarn resolves ranges at build time, so a newer
patch/minor may be picked up. The safety net is the **artefact** check, not
the lockfile. Restore `--frozen-lockfile` once the regenerated lockfile is
genuinely committed.

## `buildCommand` — why the env vars are inline

`craco.config.js` line 3 calls `require("dotenv").config()` at module load,
which puts `.env` into `process.env` **before** react-scripts' own loader
runs. dotenv never overwrites an existing variable, so **`.env` beats
`.env.production`** here — the opposite of stock CRA. A `.env.production`
was tried and **proven not to take effect**: the build still inlined the
preview backend URL 22 times. Real shell variables are the only reliable
override.

- `REACT_APP_BACKEND_URL=https://nivxray.nivxforge.com` is a deliberate
  `TEMPORARY_MIGRATION_DEPENDENCY`, so that host must not be retired.
- `REACT_APP_NIVX_FLAG_*=disabled` is required, not cosmetic: `.env` sets all
  three to `shadow`, so without these the `/v2/*` shadow surfaces would ship
  switched **on**.
- `CI=false` because CRA promotes warnings to errors when CI is truthy and
  this app carries react-hooks advisories. They are advisories, not defects;
  changing effect timing during a migration is not acceptable.
- `&& node scripts/verify-production-build.js` fails the build if a preview
  origin, an unapproved/missing API origin, or an enabled shadow flag reaches
  the bundle. It inspects the **artefact**, not `process.env`, precisely
  because of the dotenv trap above.

## `rewrites`

Without it `/auto-investigate` returns 404 on a static host while `/` works —
the exact symptom that looks like "the tool is missing".

## Scope

This file is inert for any deployment whose Root Directory is not
`frontend`. The repo-root `vercel.json` (which builds `apps/nivxray-xdr`) is
untouched and still governs the existing `nivxray-xdr` project.

## Outstanding

`apps/nivxray-xdr/vercel.json` still contains a `$comment` block and will hit
the **same schema rejection** when Phase 2 starts. Not changed now, per the
instruction not to modify that directory.
