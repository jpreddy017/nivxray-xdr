# Workspace frontend — build readiness verification (read-only)

**Owner directive:** VERIFY WORKSPACE BUILD ONLY. No deploy, no merge, no
supervisor change, no DNS, no CORS change, no boundary change.
**Date:** 2026-09-08 · **Verdict: `BUILD_READY`**

Nothing was changed in `/app/frontend` to achieve this. The only artefact
produced is `/app/frontend/build/` (git-ignored via `frontend/.gitignore:12`),
plus the captured log at `/app/memory/ws_build.log`.

---

## 1 · Build command and result

```
cd /app/frontend
CI=false GENERATE_SOURCEMAP=false NODE_OPTIONS=--max-old-space-size=4096 yarn build
   → craco build   (react-scripts via @craco/craco)
```

**PASS · exit 0 · 40.47s.** Toolchain: node v20.20.2, yarn 1.22.22.

> First attempt appeared to fail — it was my own harness, not the app: the
> pod restarted mid-run (backend uptime reset, `/tmp` wiped) and took the
> log with it. Re-run under `/app/memory/` completed cleanly. Recording it
> because "the build failed once" would otherwise be a false finding.

## 2 · Errors and warnings

- **Compile errors: 0.**
- `Compiled with warnings.` — **all 9 are eslint `react-hooks/exhaustive-deps`**,
  i.e. lint advisories, not build failures:
  `components/OutputView.jsx:269`, `components/StructuredEvidenceTab.jsx:230` (×2),
  `components/edr/EntityInventory.jsx:30`, `components/edr/TrajectoryCanvas.jsx:34` (×2),
  `components/investigation/FindRelatedDrawer.jsx:32`, `hooks/useIdlePersist.js:109`.
- **Note:** the build ran with `CI=false`. Under `CI=true` CRA treats
  warnings as errors, so a CI pipeline would fail on these 9 lint
  advisories. Either set `CI=false` in the deployment build, or fix the 9
  hooks deps first. **Not fixed here** — it changes component behaviour
  (dependency arrays alter re-render/effect timing), which the directive
  says to report rather than apply.

## 3 · Dependencies

No install step was needed (`node_modules` present, 766 MB, 1107 packages).
No peer-dependency or resolution failures during the build. No stale or
broken import was reported by webpack — a missing module is a hard error
in CRA, and there were none.

## 4 · Route inventory — verified INSIDE the production bundle

Each route string was grepped out of the emitted chunks in
`build/static/js/`, so this is the shipped bundle, not the source:

| route | present in |
|---|---|
| `/auto-investigate` | `main.60c3a843.js` |
| `/analyze` | `6479…chunk.js` |
| `/lab` | `6479…chunk.js` |
| `/threat-intel` | `main.js` |
| `/investigations` | `6479…chunk.js` |
| `/evidence-explorer` | `main.js` |
| `/compare`, `/iedde`, `/heatmap`, `/battery` | present |
| `/v2/workspace`, `/v2/trajectory`, `/v2/irg`, `/v2/ingest` | present |
| `/investigate`, `/nivxforge/investigate` | present |

Decoder / analysis API calls compiled in: `/decode/smart` (4 chunks),
`/decode/magic`, `/decode/chain`, `/ai/auto-investigate`,
`/v2/auto-investigate` (2 chunks), `/analyze` (11 chunks).
`/session/investigate` is **not** referenced from this frontend (it is a
backend-only route) — stated so the inventory is not read as a gap.

Entrypoints: `static/js/main.60c3a843.js` + `static/css/main.b3e9c0c5.css`,
70 files in `asset-manifest.json`. Build total **30 MB**; `main.js` 396 KB,
largest chunk 484 KB.

## 5 · Environment variables required in production

**Exactly one: `REACT_APP_BACKEND_URL`.** 18 references across
`lib/api.js`, `pages/AutoInvestigatePage.jsx`, `pages/WorkspacePage.jsx`,
`pages/DocsPage.jsx`, `pages/DeviceTrajectoryPage.jsx`,
`pages/BenchmarkPage.jsx`, `pages/InvestigationSessionPage.jsx` and others.

**Zero hardcoded backend URLs in source** — grep for
`emergentagent.com`, `localhost:8001`, `127.0.0.1:8001` in
`/app/frontend/src` returns nothing.

⚠️ **CRA inlines env vars at BUILD time.** The current preview URL is
baked into 23 places across 10 chunks of this build. The Workspace
deployment must therefore be **built with its own
`REACT_APP_BACKEND_URL`**, and **rebuilt** whenever the backend URL
changes. There is no runtime override.

Legacy keys in `/app/frontend/.env`: `WDS_SOCKET_PORT` (dev-server only),
`ENABLE_HEALTH_CHECK` (craco), and `REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE`
/ `_CASE_ENGINE` / `_VERDICT_ENGINE_V3`, read dynamically by
`v2/flags.js:47` (`process.env[\`REACT_APP_NIVX_FLAG_${name}\`]`) to gate
the `/v2/*` shadow surfaces. **Because they are read dynamically, CRA
cannot inline them unless they are present at build time** — so if the
`/v2/*` shadow surfaces are wanted in the Workspace deployment, these
three keys must be set in that build too. `_VERDICT_ENGINE_V3` has no
matching UI reference, so it appears to be dead.

## 6 · Same-origin assumptions — none for the API

`lib/api.js:3` is the single source: `API_BASE = ${REACT_APP_BACKEND_URL}/api`.
No relative `/api` fetch, no `axios.defaults.baseURL` fallback to the page
origin, no `withCredentials`, no cookie use.

Two `window.location.origin` uses exist and are both **correct and
origin-agnostic** — they build links to the app itself, not the backend:
`WorkspacePage.jsx:1898` (shareable `#recipe=` permalink) and
`WorkspacePage.jsx:2524` (`/?share=<token>` link). On a
`nivxmachines.com` deployment these will correctly emit
`nivxmachines.com` URLs.

**Conclusion: the production bundle can operate from a different origin
against the existing backend.** Backend CORS is currently
`CORS_ORIGINS="*"` (`wildcard=True credentials=False`) and auth is a
Bearer token in `localStorage` (`nvx_token`), so no cookie/credentialed
request is involved. Per owner decision the wildcard is **not** the final
production posture and will be replaced with explicit origins once the
domains are fixed — **no CORS change was made in this pass.**

## 7 · Asset / public-path

CRA reported *"The project was built assuming it is hosted at `/`"* — no
`homepage` field, no sub-path assumption. Correct for a root-domain
deployment; it would need a `homepage`/`PUBLIC_URL` rebuild only if served
from a sub-path.

Static serve check (`python3 -m http.server` on the build dir):
`/` → **200**, `static/js/main.*.js` → **200**.

⚠️ **`/auto-investigate` → 404 on a plain static host.** This is a
client-routed SPA, so the deployment MUST rewrite unknown paths to
`/index.html`. Without that, deep links and refresh-on-route break while
the home page works — the classic symptom that looks like "the tool is
missing" and is in fact a host rewrite rule.

## 8 · Auth / localStorage

`nvx_token` + `nvx_email` in `localStorage`, attached as
`Authorization: Bearer` by the axios request interceptor
(`lib/api.js:129`) and by the raw `fetch` paths. `localStorage` is
per-origin, so a Workspace deployment on its own domain requires **one
separate sign-in** against the same backend accounts. Accepted by the
owner for this pass; SSO deferred to the OIDC work.

## 9 · Minimum repairs required

**None to build.** Deployment prerequisites, in order:

1. Build with the target `REACT_APP_BACKEND_URL` (and the three
   `REACT_APP_NIVX_FLAG_*` keys if `/v2/*` is wanted).
2. `CI=false`, or fix the 9 hooks-deps warnings first.
3. SPA fallback rewrite → `/index.html`.
4. Cosmetic but visible: `public/index.html` still ships
   `<title>Emergent | Fullstack App</title>` and
   `<meta name="description" content="A product of emergent.sh">` — the
   Workspace app has **no product branding in its HTML head**. Not fixed
   here (it changes shipped output); trivial when approved.

## 10 · Status classification — deliberately conservative

**`BUILD_READY`** — and, adopting the owner's own framing, that is all it
means. The Workspace product is:

- ✅ **build-verified** — compiles clean, all routes in the bundle, one
  env var, no same-origin coupling, deployable from another origin
- ❌ **NOT deployed** · ❌ **NOT runtime-verified in a browser** ·
  ❌ **NOT authenticated end-to-end from its own origin**

No browser runtime proof was possible in this pod: port 3000 belongs to
the XDR/EDR Vite app and must not be touched, so the built bundle could
only be served on a local port unreachable by a real browser. Until it is
deployed at its own origin, signs in, and its AutoInvestigate/Decoder
workflows are exercised against the shared backend, the correct status
remains **implemented, not deployed, not runtime-verified.**
