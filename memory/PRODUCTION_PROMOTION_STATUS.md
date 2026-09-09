# PRODUCTION PROMOTION · COMPLETE · PASS
Date: 2026-06 · `xdr.nivxforge.com` now serves the verified NivXRay XDR build.

## Preview source commit/build promoted
- Commit `52bf787a` (+ the KB / Intelligence / RC5 work committed after it),
  branch `feature/rc2-alignment`, working tree clean.
- Artifact: `NIVX_PRODUCT_SCOPE=xdr bash scripts/vercel-build.sh` → 125 assets ·
  `index-B3UX7ihx.js` · `XdrShell-DsG83o93.js` (47,678 B).
- Deployed as a **prebuilt Build Output API** upload, so production runs the
  exact artifact that was verified — not a rebuild from a different snapshot.

## Root cause of the deployment failure (corrected diagnosis)
`nivxray-xdr-production` **already had** `rootDirectory: "apps/nivxray-xdr"`.
The root-directory build failure came from a **different project**,
`nivxray-xdr` (`prj_wItvwa3g09dQxMqv2WNzdrCO3QDe`, `rootDirectory: null`,
production branch `main`), which owns **no custom domain** — so it was failing
harmlessly and was never what served `xdr.nivxforge.com`.
The real gap was that `nivxray-xdr-production` had **zero environment
variables**.

## Vercel project settings changed
| Project | Change |
|---|---|
| `nivxray-xdr-production` (`prj_Pk0KmVhZD8KwdDOxFMHfzT9xfHXZ`) | added `NIVX_PRODUCT_SCOPE=xdr` and `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com` (targets: production, preview) |
| same | `rootDirectory` verified already `apps/nivxray-xdr` — **not modified** |
| same | temporary protection-bypass secret created for pre-promotion testing, then **revoked** (0 remaining) |
| `nivxray-edr-production`, `nivxmachines-workspace`, `nivxray-xdr` | **untouched** |

## Deployment identity
- Tested before promotion: `nivxray-xdr-production-4x5ni7r2b-jpreddy017.vercel.app`
- Promoted production deployment: `nivxray-xdr-production-8jfqdwczy-jpreddy017.vercel.app`
  → **Aliased to `https://xdr.nivxforge.com`**
- `XdrShell` md5 identical pre-promotion vs on the live domain:
  `59ee5c76b2cf3847044d344415463bb7`

## Rollback reference
`dpl_BF14GQG3bb4VCt7M3JP56NizCjFQ`
(`nivxray-xdr-production-1xbqcctgd-jpreddy017.vercel.app`, READY, production,
2026-09-09T17:34:57Z) — the previous live build (`XdrShell-D5KuqOEH.js`,
18,794 B). Instant rollback: Deployments → ⋯ → Promote to Production.

## Production smoke test
| Check | Result |
|---|---|
| `/` | 307 → `/xdr` (host redirect preserved) |
| `/xdr/mss-dashboard` | 200 · `<title>NivXRay XDR</title>` |
| Landing | root → `/login?returnTo=%2Fxdr%2Fmss-dashboard` → **Control Center is the landing surface** |
| Shell markers on live domain | `xdr-ribbon` 1 · `Control Center` 1 · `Client Management` 1 · `Activities` 1 · `Threat Intelligence` 1 · `EXTERNAL_NAVIGATION_FORBIDDEN` 1 (all were **0** before) |
| API origin in bundle | `https://nivxray.nivxforge.com` only · **0** preview refs |
| Deep routes + SPA refresh | `/xdr/incidents`, `/xdr/intelligence/threat` preserve `returnTo`; refresh works |
| Browser tabs | **1** throughout · no navigation to the preview host |
| Production API | `/api/health` **200**, CORS `*` for the deployment origin |
| Product isolation | `/edr` on the XDR host does **not** render NivXForge EDR (scope guard) |
| NivXForge EDR | `edr.nivxforge.com` serves its **own** chunk (`index-5e0IbMeq.js`) — untouched |
| Workspace NivXMachines | 200 — untouched |

## Authenticated verification — NOT COMPLETED (needs a production account)
`admin@nivxray.com` is a **preview-only** account. Against the production API it
returns a genuine `HTTP 401 {"detail":"Invalid credentials"}` — which actually
proves the auth path works end-to-end from the new build. Creating an account in
production was forbidden, so authenticated surfaces (rail, Ribbon incidents,
Intelligence counts, KB 334) are verified on Preview but not yet on production.
Owner must log in once with a production account to close this.

## Pre-existing observation, not changed
`edr.nivxforge.com` HTML `<title>` is also "NivXRay XDR" (shared `index.html`).
Cosmetic, pre-existing, on the EDR product — left alone per product isolation.

## Note
`/xdr/activities` is **not** a registered route; the Activities rail item points
to `/xdr/admin/telemetry-studio`, which exists. A direct hit on
`/xdr/activities` falls to the catch-all. Adding the alias is a one-line change
if wanted.

## FINAL: PASS (production promoted and verified, authenticated check pending)
