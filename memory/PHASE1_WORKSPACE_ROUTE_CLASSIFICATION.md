# PHASE 1 · STEP 1–2 · Workspace route inventory + classification

**Owner lock:** *OWNER LOCK — FINAL WORKSPACE + XDR + EDR PRODUCTION ARCHITECTURE*
**Scope of this document:** inventory `/app/frontend`, classify every route,
identify what blocks deployment. **No deploy. No DNS. No backend change.**
**Date:** 2026-06 · **Status: `BLOCKED · UNKNOWN_REQUIRES_REVIEW` + 1 hard dependency blocker**

---

## 0 · Correction to the record — the "139 vs 70 files" discrepancy was a FALSE FINDING

The previous session halted on a fear that the live Workspace had features the
repo did not. **It does not.** Measured, not assumed:

| check | live `nivxray.nivxforge.com` | local `/app/frontend` build |
|---|---|---|
| `asset-manifest.json` entries | 139 | 70 |
| of which `.map` sourcemaps | **69** | **0** (`GENERATE_SOURCEMAP=false`) |
| real shipped files | **70** | **70** |
| total JS bytes (all chunks concatenated) | 3,071,059 | 3,067,516 |
| `path:"…"` router routes extracted from the shipped bundle | **62** | **62** |
| route set difference | **∅** | **∅** |
| `/api…` endpoint string set difference | **∅** | **∅** |
| baked `REACT_APP_BACKEND_URL` | `https://nivxray.nivxforge.com` ×23 | `https://greeting-app-5782.preview…` ×23 |

**`/app/frontend` IS the live Workspace source, 1:1.** The only functional
difference between the two bundles is the build-time backend URL. There is no
missing branch, no lost Chain Mode, no lost AutoInvestigate variant. The
earlier hypothesis is withdrawn.

*(62 = 59 real routes + the `*` catch-all + 2 duplicate literals; the
classification below enumerates the 59 real routes from `App.js` directly.)*

---

## 1 · The two owner-approved removals — what they actually are in code

### `REMOVE_LEGACY_XDR` — **1 nav item, 0 routes. It is already a dead link.**

`components/Header.jsx:41`
```js
{ key: "xdr", href: "/xdr", label: "XDR", icon: AlertOctagon, testId: "nav-xdr" }
```

`App.js` has **no `/xdr` route**. The XDR shell was extracted to
`/app/apps/nivxray-xdr` (see `App.js:53-58`), so the catch-all
`<Route path="*" element={<Navigate to="/" replace />} />` bounces `/xdr`
straight back to the Workspace home page.

Verified in the **live production bundle**: `href:"/xdr"` present ×1,
`nav-xdr` present ×1, `path:"/xdr"` **absent**.

> **The XDR item in the live legacy Workspace nav does nothing today.**
> Removing it is therefore not a feature removal — it removes a broken
> promise. Zero functional risk. **Executed in this pass.**

Second dead nav item found while verifying: `Header.jsx:50`
`X-LAB (DEV) → /nivxforge/x-lab`, a route deleted on 2026-08-11. It is
`devMode`-gated (`localStorage.nvx_dev_mode`), so it is invisible to normal
users. **Reported, not removed** — it is not part of the approved removal set.

### `REMOVE_LEGACY_INVESTIGATIONS` — **4 routes, and it is NOT a detachable leaf**

Routes: `/investigations` · `/investigations/:id` ·
`/investigations/:id/replay` (redirect) · `/investigation-summary`
Pages: `InvestigationsPage` · `InvestigationDetailPage` ·
`InvestigationSummaryPage`
Nav item: `Header.jsx:43` `INVESTIGATIONS → /investigations`

**Blocker: four RETAINED Workspace surfaces navigate INTO these routes.**
Deleting the routes converts each one into a catch-all bounce to `/` — a
silent functional loss inside surfaces the owner ordered preserved:

| retained surface (owner: PRESERVE) | file · line | what it does |
|---|---|---|
| **History** (`/history`, top-level nav) → HistoryDrawer | `components/HistoryDrawer.jsx:383, 391, 626` | "open correlated investigation" → `/investigations/<correlation_id>` |
| **Find Related drawer** — a Workspace *panel* | `components/investigation/FindRelatedDrawer.jsx:37, 47, 67, 160` | correlate → navigate to the resulting investigation |
| **Quick Open palette** (global, every page) | `components/QuickOpenPalette.jsx:88, 282` | `GET /investigations?limit=50` populates the "cases" section; `>open recent case` |
| **Workspace** main page | `pages/WorkspacePage.jsx:4203` | `window.open("/investigation-summary")` |

`FindRelatedDrawer` is mounted by **both** `WorkspacePage.jsx:4428` and
`HistoryDrawer.jsx:429`.

**Consequence, stated plainly:** "Investigations" in the legacy Workspace is
not a standalone top-level surface — it is the **destination** of the
retained Correlate / Find-Related / History-drilldown flows. Removing the
destination without a decision on those flows would breach the zero-damage
rule. **HELD for owner decision — see §4 Q1.**

---

## 2 · Full classification — 59 routes

Legend: `RETAIN_WORKSPACE` · `REMOVE_LEGACY_XDR` ·
`REMOVE_LEGACY_INVESTIGATIONS` · `SHARED_DEPENDENCY_DO_NOT_DELETE` ·
`UNKNOWN_REQUIRES_REVIEW`

### RETAIN_WORKSPACE — 27 routes (owner's explicit preserve list)

| route | surface | owner list entry |
|---|---|---|
| `/login` | LoginPage | Authentication / Account |
| `/` | WorkspacePage — Decoder / Analyze / Upload / Share / Cases / Reports / Threat panels | Workspace |
| `/analyze` | CommandAnalyzerPage | Tools |
| `/auto-investigate` | AutoInvestigatePage | Auto Investigate |
| `/threat-intel` | ThreatIntelPage | Threat Analysis panels |
| `/threat-model` | ThreatModelPage | Tools |
| `/history` | HistoryPage | History |
| `/batch-test` | BatchTestPage | Batch |
| `/heatmap` | MitreHeatmapPage | Heatmap |
| `/lab` | LabPage | Learn |
| `/learner` | LearnerPage | Learn |
| `/kb` | KnowledgeBasePage | Learn |
| `/docs` | DocsPage | Learn |
| `/admin` | AdminPage | Admin |
| `/admin/corrections` | CorrectionsAdminPage | Admin |
| `/admin/models` | ModelStudioPage | Admin |
| `/admin/samples` | SampleLibraryPage | Admin |
| `/admin/training-inbox` | TrainingInboxPage | Admin |
| `/documents` | DocumentsPage | Admin |
| `/platform` | PlatformHealthPage | Admin |
| `/iedde` | IEDDETracePage | Tools |
| `/compare` | ComparePage | retained drilldown |
| `/compare/:caseA/:caseB` | ComparePage | retained drilldown |
| `/battery` | MultiLayerBatteryPage | Tools |
| `/workspace/session/:sessionId` | InvestigationSessionPage | Workspace nested route |
| `/workspace/session/:sessionId/input/:inputId` | InvestigationInputDetailPage | Workspace deep link |
| `/evidence-explorer` | alias → InvestigationSessionPage | retained bookmark alias |

### REMOVE_LEGACY_XDR — 0 routes, 1 nav item
`Header.jsx:41` `nav-xdr` (dead link — see §1).

### REMOVE_LEGACY_INVESTIGATIONS — 4 routes, 1 nav item · **HELD**
`/investigations` · `/investigations/:id` · `/investigations/:id/replay` ·
`/investigation-summary` · `Header.jsx:43` `nav-investigations`.

### SHARED_DEPENDENCY_DO_NOT_DELETE — components, not routes

These are imported by RETAINED surfaces and must survive regardless of the
Investigations decision. They are the reason §1's removal is not a leaf cut:
`components/investigation/FindRelatedDrawer.jsx` ·
`components/HistoryDrawer.jsx` · `components/QuickOpenPalette.jsx` ·
`components/attackStory/*` · `components/InvestigationGraph.jsx` ·
`components/InvestigationTimeline.jsx` ·
`components/InvestigationPipeline.jsx`.
**Backend:** every `/api/investigations*` route, the Investigation SSOT and
all correlation/investigation engines are `SHARED_DEPENDENCY_DO_NOT_DELETE`
per §11 of the owner lock. Nothing in Phase 1 touches the backend.

### UNKNOWN_REQUIRES_REVIEW — 28 routes · **BLOCKS DEPLOYMENT**

These appear in neither the owner's preserve list nor the approved removal
set. I am not inventing a decision for them.

**U1 · `/nivxforge/*` — 9 routes.** A second, differently-branded console
*inside* the Workspace: `/nivxforge` · `/nivxforge/dashboard` ·
`/nivxforge/investigate` · `/nivxforge/threat-intel` · `/nivxforge/hunting` ·
`/nivxforge/knowledge` · `/nivxforge/reports` · `/nivxforge/history` ·
`/nivxforge/governance`. Four of them are `PlaceholderSections`.
**Name collision risk:** the real NivXForge product is being promoted to
`edr.nivxforge.com` in Phase 3. Shipping a "NivXForge" shell inside
`workspace.nivxmachines.com` would put two different things behind one brand.

**U2 · `/edr/trajectory` — 1 route.** The canonical Device Trajectory canvas
(`DeviceTrajectoryPage`), deliberately kept in this app when the XDR/EDR
shells were extracted (`App.js:177-185`). It is an **endpoint (EDR)
capability living in the Workspace**, and `DeviceTrajectoryPage.jsx:227`
links to `/xdr/incidents/:id` — **a route this app does not have**, i.e. a
second dead link today, and a natural Phase-4 cross-product pivot to
`xdr.nivxforge.com`.

**U3 · `/analyst`, `/analyst/rc5` — 2 routes.** Analyst Workspace /
AnalystRC5 surfaces. Reachable from the retained Quick Open palette
(`>open recent case` → `/analyst?iid=…`).

**U4 · `/investigate`, `/investigate/:caseId` — 2 routes.** The
`workspace_v4` L4 Analyst Workspace shell. Investigation-flavoured naming;
not the removed `/investigations` surface.

**U5 · `/v2/*` — 13 routes.** Flag-gated shadow surfaces, never linked from
navigation, gated by `REACT_APP_NIVX_FLAG_*` at **build** time:
`/v2/workspace`, `/v2/workspace/:caseId`, `/v2/trajectory`,
`/v2/trajectory/:caseId`, `/v2/irg`, `/v2/irg/:caseId`, `/v2/compare`,
`/v2/compare/:caseA/:caseB`, `/v2/ancestry/:caseId/:processIid`,
`/v2/case/:caseId`, `/v2/ingest`, `/v2/validation`.
If the three flag keys are absent from the production build these routes
render their flag-off state — a decision, not an accident, and it must be
made explicitly.

**U6 · `/benchmark` — 1 route. SECURITY-RELEVANT.**
`App.js:173` — `<Route path="/benchmark" element={<BenchmarkPage />} />`,
the **only** route with **no `<Protected>` wrapper**. It is labelled
"NivXRay Public Benchmark" and calls `/api/benchmark/real-world` +
`/api/benchmark/refresh` with raw `axios`, no auth header. It renders the
full `Header` (product nav) to anonymous visitors. Intentional in preview;
on a public production hostname it is an **unauthenticated product surface**
and needs a conscious decision.

---

## 3 · What was executed — all five owner decisions applied

**Owner decisions: Q1 = A · Q2 = A · Q3 = B · Q4 = B · Q5 = A.**
API for Phase 1 = `https://nivxray.nivxforge.com`, declared
`TEMPORARY_MIGRATION_DEPENDENCY`.

| # | decision | what changed | source retained? |
|---|---|---|---|
| Q1 | A · Investigations | nav item removed (`Header.jsx`); the **4 routes stay live** so Correlate / Find Related / History drilldown / Quick Open still land on real detail surfaces | yes — pages and routes untouched |
| Q2 | A · `/nivxforge/*` | 9 routes + 8 lazy imports removed from `App.js` | **yes** — `src/nivxforge/**` untouched on disk, per instruction |
| Q3 | B · `/edr/trajectory` | route + lazy import removed | **yes** — `pages/DeviceTrajectoryPage.jsx` untouched. **No link to `edr.nivxforge.com` was created**: that hostname is not live and a dead outbound link is worse than none |
| Q4 | B · `/analyst*`, `/investigate*`, `/v2/*` | 17 routes retained, unchanged; the three `REACT_APP_NIVX_FLAG_*` forced to `disabled` in the production build command | yes |
| Q5 | A · `/benchmark` | wrapped in `<Protected>` — the only route in the app that had no auth wrapper | yes, page unchanged |

Also removed: the `devMode` **X-LAB (DEV)** nav item, which pointed at
`/nivxforge/x-lab` — a route deleted on 2026-08-11 — and therefore fell
inside Q2's removal of `/nivxforge/*` exposure.

### Q2 dependency proof, performed before removal (as instructed)

The dependency direction is **one-way**, so removing the routes removes all
product exposure without touching shared code:

- **Nothing outside `App.js` imports `@/nivxforge/*`.**
- `src/nivxforge/**` imports only **into** retained shared code: `lib/api`,
  `pages/AutoInvestigatePage`, `components/Header`, `components/InputToolbar`,
  `components/InvestigationPipeline`.

Per the instruction "*retain the shared code and remove only the product
routes/exposure*", no file was deleted.

### The production-safety trap this pass found

`craco.config.js:3` calls `require("dotenv").config()` at module load, which
loads `.env` into `process.env` **before** react-scripts' env loader runs.
dotenv never overwrites an existing variable, so in this project **`.env`
beats `.env.production`** — the opposite of stock CRA precedence.

A `.env.production` was tried first and was **silently ignored**: the build
still inlined the **preview** backend URL 22 times. Shipped, that would have
pointed the production Workspace at the **preview database** while looking
perfectly healthy. The same trap would have shipped the `/v2/*` shadow flags
**switched on**, because `.env` sets all three to `shadow` — contradicting
Q4 = B.

Fix: `.env.production` deleted; every production variable now lives in the
`buildCommand` in `frontend/vercel.json`, where real shell variables win.

### Verification — two proof scripts, 75 checks, 0 failures

`scripts/phase1_workspace_build_proof.py` → **32/32 PASS**
(`memory/phase1_workspace_build_proof.json`)
- production API baked in: **22** refs · preview refs: **0**
- all three flags inline as `"disabled"`
- `/edr/trajectory`, `/nivxforge`, `/nivxforge/dashboard`, `/xdr` absent
- all retained routes present
- the SPA rewrite requirement demonstrated **both ways**: on a plain static
  host `/auto-investigate` → **404**; with the rewrite → **200**
- unauthenticated `/`, `/auto-investigate`, `/history`, `/admin`,
  `/benchmark`, `/investigations`, `/analyst`, `/investigate`, `/lab`,
  `/batch-test`, `/heatmap` all gate to `/login`

`scripts/phase1_workspace_authenticated_proof.py` → **43/43 PASS**
(`memory/phase1_workspace_authenticated_proof.json`)
Because the production database is separate and no production credential
exists yet, the **same cleaned source** was built against the preview backend
and driven with real credentials:
- login works; nav shows exactly WORKSPACE · HISTORY · BATCH · HEATMAP ·
  TOOLS · LEARN · ADMIN; `nav-xdr` / `nav-investigations` / `nav-nivxforge`
  count **0**
- 17 retained surfaces render, including `/benchmark` **while authenticated**
  (Q5 restricted access without breaking the page)
- **Q1 proven**: `/investigations`, `/investigation-summary` and a **real**
  investigation detail id (`/investigations/6a72169b3d98eb14810c9506`) all
  resolve — the nav removal did not delete the capability
- Quick Open opens and returns **25 rows** (it reads `/investigations`)
- History renders its drawer and record total
- `/nivxforge`, `/nivxforge/dashboard`, `/nivxforge/investigate`,
  `/nivxforge/governance`, `/edr/trajectory`, `/xdr` all bounce to `/`
- `/v2/workspace` resolves and renders its honest flag-off notice
- **0** uncaught page errors across the whole sweep

Screenshots: `memory/phase1_ws_workspace_home.png` (201 operations, Auto
Investigate, Decode, Cases, Share, Copy Link, Report, Save Case, Find
Related, Upload, Candidate Explorer, MoE panel, Chain Mode, Threat Analysis
— all intact), `phase1_ws_history.png`, `phase1_ws_heatmap.png`,
`phase1_ws_retained_investigations_deeplink.png` (5 correlated
investigations render with **no** INVESTIGATIONS nav item).

### Cross-origin call to the Phase-1 API — proven, not assumed

```
OPTIONS https://nivxray.nivxforge.com/api/auth/login
  Origin: https://workspace.nivxmachines.com
→ 200 · access-control-allow-origin: *
     · access-control-allow-headers: content-type,authorization
```

### Zero damage — verified after the change

- `nivxray.nivxforge.com/` **200** · `/auto-investigate` **200** · live
  bundle `main.b4fd60ad.js` **200** — unchanged, **no deploy performed**
- preview `/xdr/incidents` **200** · preview `/edr` **200**
- `apps/nivxray-xdr` **not modified**; repo-root `vercel.json` **not
  touched**; no backend, `.env`, DNS or supervisor change

## 4 · Remaining blocker — platform side, owner action required

`UNKNOWN_REQUIRES_REVIEW` is **cleared**; all 59 routes are now classified.
The blocker is now purely the platform.

**Emergent cannot deploy two independent frontends from one repository** —
confirmed with the platform team. There is no per-deployment Root Directory
setting, so a second Emergent project pulled from this repo would still
build whatever the **repo-root** `vercel.json` builds, i.e. the XDR app.
`frontend/vercel.json` is correct and ready but can only be honoured by a
host that lets you point a project at the `frontend` directory.

The two supported routes, the click-by-click steps, the DNS record, and the
25-point post-deployment acceptance list are in
**`memory/PHASE1_WORKSPACE_DEPLOYMENT_RUNBOOK.md`**.

**The armed hazard is unchanged and still armed:** pressing Deploy on the
existing Emergent project rebuilds from current repo state and would replace
the live legacy Workspace with the XDR app.

## 5 · Non-code prerequisites still outstanding (owner-side)

- `workspace.nivxmachines.com`, `api.nivxforge.com`, `xdr.nivxforge.com`,
  `edr.nivxforge.com` **do not resolve** (`curl` → `000` on all four).
- One Emergent project = one frontend deployment, so Workspace, XDR and EDR
  need **three** projects.
- **`REACT_APP_BACKEND_URL` is baked in at build time.** The live Workspace
  currently calls **its own hostname** (`nivxray.nivxforge.com/api`, 23 baked
  references). Retiring that hostname breaks the **API**, not only the UI —
  which is exactly why §9 of the owner lock puts retirement last. The new
  Workspace build cannot be produced until its API origin is decided and live.
- The `nivxray.nivxforge.com` database is **separate** from preview (preview
  admin credentials → `401` there). A production admin credential must be
  generated fresh; none is copied from preview.
