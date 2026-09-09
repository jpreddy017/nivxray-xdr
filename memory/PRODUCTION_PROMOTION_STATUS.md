# PRODUCTION PROMOTION · NivXRay XDR · Preview → xdr.nivxforge.com

Status: **READY TO PROMOTE · NOT PROMOTED.** Steps 1–4, 6–8 complete and
verified. **Step 5 (deploy) is blocked on an owner action I cannot perform** —
see §Blocker. Cisco visual-parity work is STOPPED as instructed.

---

## 1 · Preview source / build identity

| Field | Value |
|---|---|
| Commit | `52bf787a3e4d7d5adfa1b8aeaea73e2fd8288f9c` (`52bf787a`) |
| Branch | `feature/rc2-alignment` |
| Commit time | 2026-09-09T19:02:43+00:00 |
| Working tree | **CLEAN** — 0 uncommitted files (excluding pre-existing `yarn.lock` noise). The verified Preview state is fully committed. |
| Preview host | `https://greeting-app-5782.preview.emergentagent.com` |
| What actually serves it | supervisor `[program:frontend]` → `yarn dev --host 0.0.0.0 --port 3000`, `directory=/app/apps/nivxray-xdr`. Confirmed: the Preview host serves the **standalone NivXRay XDR app** (page `<title>NivXRay XDR</title>`), not the base app. |
| Production-scoped artifact | `NIVX_PRODUCT_SCOPE=xdr bash scripts/vercel-build.sh` → `dist/` · `assets/XdrShell-_GxXIKIe.js` (47,662 B) · `assets/index-DQS7i8Np.js` |

## 2 · Production deployment identity (current, pre-promotion)

| Field | Value |
|---|---|
| URL | `https://xdr.nivxforge.com/xdr/mss-dashboard` → HTTP 200 |
| Served entry chunk | `assets/index-LG3aU4C2.js` |
| Served shell chunk | `assets/XdrShell-D5KuqOEH.js` — **18,794 B** |
| API origin baked in | `https://nivxray.nivxforge.com` only · **0** references to any Emergent preview host |
| Vercel config in repo | Root Directory `apps/nivxray-xdr` · `installCommand` `yarn install --production=false` · `buildCommand` `bash scripts/vercel-build.sh` · `outputDirectory` `dist` · host redirects for `xdr.nivxforge.com` → `/xdr` and `edr.nivxforge.com` → `/edr` · SPA rewrite `/(.*)` → `/index.html` |

## 3 · Files changed for this promotion

**None.** Promotion is a deployment of the already-committed state. No source,
config, env, DNS or database file was touched in this step.

## 4 · Build / test results

| Gate | Result |
|---|---|
| `NIVX_PRODUCT_SCOPE=xdr bash scripts/vercel-build.sh` | **PASS** |
| XDR production build guard | **PASS** — no preview origin embedded (122 artifacts scanned) · no `edr.nivxforge.com` dependency · API origin `https://nivxray.nivxforge.com` (4 refs) · no unauthorised origin · product scope `"xdr"` declared so `/edr/*` cannot render on the XDR host |
| `test_no_external_product_navigation.mjs` | **PASS** (1880 checks) |
| `test_login_branding_is_scope_aware.mjs` | **PASS** (51 checks) |
| `tests/canonical/incidents/` + `test_sec001_002_auth_hardening.py` | 30 passed · 1 skipped · **1 failed** = `test_row_projection_shape`, proven **pre-existing** (`git stash` on a clean tree reproduces it) |
| `test_capability_registry_matches_base.mjs` | 147 failures, **pre-existing**, unchanged by this work |

## 5 · Production smoke test (CURRENT production, baseline)

`/xdr/mss-dashboard` `/xdr/incidents` `/xdr/detections` `/xdr/investigate`
`/xdr/activities` `/xdr/kb` → all HTTP **200**.

**This proves nothing about route existence.** `vercel.json` rewrites
`/(.*)` → `/index.html`, so every path returns 200 whether the SPA has that
route or not. Route existence must be verified in a browser after promotion.

## 6 · Preview vs Production comparison (chunk-level, factual)

| Marker in `XdrShell` chunk | Preview build | Production (live) |
|---|---|---|
| chunk size | 47,662 B | 18,794 B |
| `xdr-ribbon` | 1 | **0** |
| `Control Center` | 1 | **0** |
| `Client Management` | 1 | **0** |
| `Activities` | 1 | **0** |
| `EXTERNAL_NAVIGATION_FORBIDDEN` | 1 | **0** |
| `Detection Engineering` (old label) | 0 | 0 |

Production is running a **substantially older shell** — it has no Ribbon, no
Cisco 8-primary rail, no Activities/Client Management, and none of the
navigation-integrity guards. Verdict: **production is materially behind the
verified Preview.**

## 7 · Rollback reference

Current live production deployment, to be retained as the rollback target:
- entry chunk `assets/index-LG3aU4C2.js`
- shell chunk `assets/XdrShell-D5KuqOEH.js` (18,794 B)
- Vercel: this is the deployment currently promoted to `xdr.nivxforge.com`.
  Roll back with Deployments → ⋯ on that deployment → **Promote to Production**
  (instant, no rebuild).

## 8 · BLOCKER — why step 5 was not executed

- `git remote -v` returns **nothing**. There is no git remote in this
  container, so I cannot `git push`.
- I have no Vercel token and no Vercel CLI access, so I cannot deploy or
  promote a Vercel deployment.
- The verified state is on `feature/rc2-alignment`. Vercel production almost
  certainly tracks `main`, so even after a push the branch has to be merged.

Owner action is required: **Save → Save to Github**, then merge to the Vercel
production branch. Vercel's GitHub integration then builds and deploys.
Constraints honoured: no redirect of `xdr.nivxforge.com` to the preview host,
no iframe/proxy, no preview URL embedded in production (guard-verified), no
change to NivXForge EDR, NivXMachines, Workspace NivXMachines, production DBs,
tenant data, backend architecture or DNS.

## 9 · FINAL

**PASS** on steps 1–4, 6–8 (preserve · verify · identify · config-verify ·
no-old-snapshot · no-rebuild · no-collateral-change).
**BLOCKED** on step 5 (deploy) and therefore on steps 9–10 (production
smoke-test vs Preview comparison), pending the owner's GitHub push.
**Overall: READY TO PROMOTE, NOT PROMOTED.**
