# PHASE 2 · NivXRay XDR productionization — PREPARATION RECORD

**Date**: 2026-09-08 · **Status: `READY_FOR_OWNER_VERCEL_ACTION`**
Owner decisions applied: **1b · 2a · 3a · 4a · 5b** + HARD ISOLATION RULE.
No Vercel project, DNS record or deployment was created or touched.

## Source of truth
`/app/apps/nivxray-xdr` — proven to be the live **Preview NivXRay XDR**:
supervisor's `frontend` program runs `yarn dev --port 3000` with
`directory=/app/apps/nivxray-xdr` (`/etc/supervisor/conf.d/supervisord.conf:15-19`),
and the preview host returns that app's `<title>NivXRay XDR</title>`.
61 routes. `/app/frontend` was **not** read from, imported, or modified.

## Changed files (4 + 1 new dir, all inside `apps/nivxray-xdr` or `memory/`)
| file | change |
|---|---|
| `apps/nivxray-xdr/vercel.json` | `$comment` removed; single install; `--frozen-lockfile` dropped; `buildCommand` → `bash scripts/vercel-build.sh` (**28** chars); 4 `edr.nivxforge.com` redirects **deleted** |
| `apps/nivxray-xdr/package.json` | `vercel-build` script no longer re-installs (the redundant second `yarn install --frozen-lockfile`) |
| `apps/nivxray-xdr/yarn.lock` | **+283 / −0** — purely additive: `d3@^7.9.0` + transitives now recorded; **no existing package version changed** |
| `apps/nivxray-xdr/scripts/` *(new)* | `vercel-build.sh`, `verify-production-build.js` |
| `memory/PHASE2_XDR_VERCEL_CONFIG_NOTES.md` *(new)* | the `$comment` reasoning, preserved incl. the Phase-3 EDR rules to re-add |

`frontend/yarn.lock` also shows as modified — that is the **Phase 1** lockfile
fix (+1329/−37) still awaiting the owner's push. **Untouched in this pass.**
`apps/nivxray-xdr/dist/` is gitignored (`apps/nivxray-xdr/.gitignore:3`).

## Proofs
- **Clean install**: `package.json` + `yarn.lock` copied to an empty dir →
  `yarn install --production=false` → **exit 0**, 2.19 s, 0 warnings about
  missing entries. All 10 declared deps recorded (was 9/10 — `d3` missing).
- **Production build**: `bash scripts/vercel-build.sh` → **exit 0**,
  `✓ built in 3.71s`, 123 artifacts.
- **Guard PASSES** on the production build:
  `no preview origin embedded (123 artifacts scanned)` ·
  `no edr.nivxforge.com dependency` ·
  `API origin https://nivxray.nivxforge.com · 4 reference(s)` ·
  `no unauthorised origin outside the allow-list` ·
  `product scope declared "xdr"`.
- **Guard FAILS correctly** (negative controls, exit 1):
  build with the preview API → flags 4 preview refs **and** the absent
  production origin; `product_scope=""` → *"must be `xdr`, or /edr/\* would
  render EDR on the XDR host"*.
- **Runtime, from the compiled `dist/`** served locally: `/xdr` boots the XDR
  login, **0 console errors**; sign-in hits
  `POST https://nivxray.nivxforge.com/api/auth/login → 200` then `/auth/me`,
  `/incidents`, `/xdr/rbac/session-context`, `/xdr/saved-views`,
  `/xdr/mss/kpis` — **all 200 against production**; the full XDR console
  renders (Control Center · Incidents · Investigate · Intelligence · Automate ·
  Assets · Client Management · Administration).
- **Product boundary, runtime-proven**: `/edr/trajectory` on the scoped
  artifact renders `data-testid="wrong-product-host"` — *"This deployment
  serves NivXRay XDR"* — and **no EDR UI leaks** (no Device Trajectory, no
  Process Tree, no NivXForge Console). No redirect loop.

## Decision I made for safety — please confirm
`REACT_APP_PRODUCT_SCOPE=xdr` is now set by `scripts/vercel-build.sh` and
**enforced by the guard**. Reason: decision 5b deleted the server-side
`/edr/*` redirects, so nothing else would stop
`xdr.nivxforge.com/edr/trajectory` from serving **NivXForge EDR from the XDR
hostname** — the failure mode explicitly prohibited. `productScope.js` is now
the only boundary, and it needs that variable. Setting it also in the Vercel
dashboard is equivalent and harmless.

## Expectation for Phase 2 acceptance — production XDR data is EMPTY
Production returned `incidents: 0` and every KPI `0` with the honest empty
state *"NO INCIDENTS MATCH THIS FILTER"*. Preview has seeded XDR telemetry;
**production does not**. Empty ≠ broken — do not read it as a failure during
the live sweep.

## Left alone deliberately
- `apps/nivxray-xdr/.env` still points at the **preview** backend, so Preview
  XDR keeps working. Production config is injected as real env vars at build.
- `REACT_APP_XDR_URL` / `REACT_APP_EDR_URL` / `REACT_APP_WORKSPACE_URL` remain
  **unset**. Consequence seen in the header: the `NivXMachines Workspace`
  launcher shows `◇ NOT CONFIGURED` and `href="/"`, which on
  `xdr.nivxforge.com` would land back on XDR. Harmless, but a Phase 4 item —
  or a one-line owner call now that Workspace is verified.

## Zero-damage verification (read-only)
`workspace.nivxmachines.com` 200 · `nivxmachines.com` 200 ·
`www.nivxmachines.com` 308 → 200 (normal apex redirect) ·
`nivxray.nivxforge.com` 200 · `/api/` 200 · preview `/xdr` `/xdr/incidents`
`/edr` `/edr/trajectory` `/login` all 200 · supervisor `backend`, `frontend`,
`mongodb`, `nivxforge_sensor`, `xdr_collector` all RUNNING ·
`xdr.nivxforge.com` → `000` (does not exist yet, as required).
