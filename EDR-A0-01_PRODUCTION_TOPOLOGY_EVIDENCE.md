# EDR-A0-01 — Production Topology and Backend Identity Evidence

**Reference:** EDR-A0-01 · **Date:** 2026-10-30 · **Mode:** READ ONLY · **Status:** investigation only, no implementation authorization
**Baseline documents:** `NivXForge_EDR_Architecture_Assessment_v0.1_2026-10-30.md`, `NivXForge_EDR_Deep_Architecture_XRay_v0.2_2026-10-30.md`
**Change performed:** NONE. No git operation, no source edit, no deployment, no DNS/env change, no database access of any kind, no VM/agent/service action, no worker execution, no paid provisioning.
**Probe method:** unauthenticated HTTPS `GET`/`HEAD` against public hosts, public DNS resolution, public build artifacts, and local read-only file inspection in this workspace.

**Confidence vocabulary**
`PRODUCTION-VERIFIED` — observed live by a probe executed in THIS task.
`SOURCE-CONFIRMED` — read in this checked-out workspace; not proof of the deployed artifact.
`INHERITED` — carried from the baseline documents (authenticated Vercel inspection at the time); not re-verified here, no Vercel credential exists in this environment.
`INFERRED` — reasoned from verified facts; requires one more check to become verified.
`UNKNOWN` — not observed and not obtainable with current permissions.

---

## 1 · Current topology

```text
                     ┌──────────────────────────────────────────────┐
  analyst browser ───▶│ https://edr.nivxforge.com                    │  Vercel static SPA
                     │ CNAME e383409f27098db0.vercel-dns-017.com     │  PRODUCTION-VERIFIED
                     │ GET /  → 307 → /edr   (server: Vercel)        │
                     │ GET /edr → 200, /assets/index-Btpjue2F.js     │
                     └───────────────┬──────────────────────────────┘
                                     │ single API origin baked into the bundle
                                     │ (only nivx* URL present in the artifact)
  analyst browser ───▶ xdr.nivxforge.com  (CNAME f0da8943…) ─┐  index-C2Od7EUX.js
  analyst browser ───▶ workspace.nivxmachines.com (CNAME 4544e63c…) ─┐ main.b59b5408.js
                                     │                       │      │
                                     ▼                       ▼      ▼
                     ┌──────────────────────────────────────────────┐
                     │ https://nivxray.nivxforge.com                │
                     │ A 162.159.142.117 / 172.66.2.113             │
                     │ server: cloudflare · __emg_vid/__emg_sid     │  → Emergent-hosted
                     │ GET /api/      → {"service":"NivXRay","ok"}   │  PRODUCTION-VERIFIED
                     │ GET /api/health→ {"service":"nivxray-api"}    │
                     │ GET / → CRA Workspace build main.6c02e095.js  │
                     └───────────────┬──────────────────────────────┘
                                     │ ONE FastAPI app, 875 paths
                                     │  /api/edr/*  86 paths   (401/403 fail-closed)
                                     │  /api/xdr/*  199 paths  (403)
                                     │  /api/auth/*, investigations, decoder …
                                     ▼
                     ┌──────────────────────────────────────────────┐
                     │ backend deployment id / revision  → UNKNOWN  │
                     │ MongoDB host / deployment / DB_NAME → UNKNOWN│
                     │ EDR processing worker in same process        │  SOURCE-CONFIRMED
                     └──────────────────────────────────────────────┘

  Separate, unrelated to the above: this workspace's preview
  https://greeting-app-5782.preview.emergentagent.com  (same byte-identical API surface)
  and the G4 lab (127.0.0.1:8101, database nivx_g4_lab).
```

---

## 2 · Frontend / deployment / source SHA evidence

| Subject | Value | Confidence |
|---|---|---|
| EDR hostname | `edr.nivxforge.com` → `216.198.79.65`, `64.29.17.65`, CNAME `e383409f27098db0.vercel-dns-017.com` | PRODUCTION-VERIFIED |
| EDR edge behaviour | `HEAD /` → `307`, `location: /edr`, `server: Vercel`, `x-vercel-id: cle1::rjqf8-…`; `GET /edr` → `200`, `x-vercel-cache: HIT`, `etag "0b79e29f059f3f27c0ce44b40ce5e899"`, `last-modified Fri, 30 Oct 2026 10:36:59 GMT` | PRODUCTION-VERIFIED |
| EDR served artifact | `/assets/index-Btpjue2F.js`, 256,470 bytes | PRODUCTION-VERIFIED |
| EDR artifact → API origin | the **only** `nivx*` origin string in the bundle is `https://nivxray.nivxforge.com` | PRODUCTION-VERIFIED |
| EDR artifact → product scope | contains `NivXForge EDR` and `NivXRay XDR` label strings (shared source package) | PRODUCTION-VERIFIED |
| Vercel project / deployment ID | `nivxray-edr-production`, `prj_KrtnUHko9opTWHv0cbXS1a2EAKV4`, `dpl_GnXW5Y5qwss3858hd1jJdrabxXME` READY | **INHERITED** (baseline v0.1/v0.2) — not re-verified; no Vercel API credential in this environment |
| Frontend source SHA | `jpreddy017/nivxray-xdr`, `phase2/edr-production`, `35d47cc96352f492bd4c603a2f2f1b65afb4119f` | **INHERITED** — the served bundle carries **no** build/commit stamp (searched: none), so artifact→SHA cannot be re-proved from the public artifact |
| Production env identity | Vercel "Production" environment for that project | INHERITED |
| Distinct projects per product | `edr`, `xdr` and `workspace` resolve to **three different** `*.vercel-dns-017.com` CNAME targets → three distinct Vercel projects/domain bindings | PRODUCTION-VERIFIED |

**Explicit limitation:** a served asset hash is not a source SHA. Re-establishing the frontend SHA requires an authenticated Vercel read (`get_deployment` / `list_deployment_events`), which this environment cannot perform.

---

## 3 · Backend identity and deployment revision

| Subject | Finding | Confidence |
|---|---|---|
| Configured API origin | `https://nivxray.nivxforge.com` — live, serving JSON on `/api/*` | PRODUCTION-VERIFIED |
| DNS / edge | `162.159.142.117`, `172.66.2.113`; `server: cloudflare`, `cf-ray: a52a31c85f61c4e5-ORD` | PRODUCTION-VERIFIED |
| Hosting platform | sets `__emg_vid` / `__emg_sid` cookies → Emergent-hosted application behind Cloudflare, **not** a Vercel function | PRODUCTION-VERIFIED |
| Service identity | `GET /api/` → `{"service":"NivXRay","status":"ok"}`; `GET /api/health` → `{"status":"ok","service":"nivxray-api"}` | PRODUCTION-VERIFIED |
| API surface | `GET /api/openapi.json` → `NivXRay API 1.0.0-rc`, **875 paths**: 86 `/api/edr/*`, 199 `/api/xdr/*`, 3 `/api/auth/*` | PRODUCTION-VERIFIED |
| EDR plane is mounted and fail-closed | `GET /api/edr/agent/whoami` → `401 {"code":"SENSOR_UNAUTHENTICATED","reason":"no bearer session token was presented",…}`; `GET /api/edr/events` → `403 Not authenticated` | PRODUCTION-VERIFIED |
| Control for blanket responses | `GET /api/edr/health` → `404`, `/api/version` → `404`, `/api/build-info` → `404` — routes are individually resolved, not blanket-answered | PRODUCTION-VERIFIED |
| Which Emergent app serves it | `nivxray.nivxforge.com` is the custom domain of **this project's own production deployment** (job `486146a0-9a5d-462a-8072-904d27d6c533`); `memory/PRODUCTION_DOMAIN_INVENTORY.md` (2026-09-08) records `/api` there running "the current repo code" and warns that deploying this project **replaces** what is live on that host | INFERRED (strong) — corroborated today by byte-identical API surface, below |
| **Backend deployment ID / revision / SHA** | **UNKNOWN.** No endpoint exposes a build stamp (`/api/version`, `/api/build-info` → 404) and no platform metadata is readable from here | UNKNOWN |

### API-surface comparison (today)

`GET /api/openapi.json` was fetched from three places and all three are **byte-identical**:

```text
md5 a8c5abe0d27abb66cb31e996864cdfaf   https://nivxray.nivxforge.com/api/openapi.json        778,868 bytes
md5 a8c5abe0d27abb66cb31e996864cdfaf   https://greeting-app-5782.preview…/api/openapi.json   778,868 bytes
md5 a8c5abe0d27abb66cb31e996864cdfaf   http://localhost:8001/api/openapi.json  (this checkout) 778,868 bytes
```

**What this proves:** production, preview and the local checkout expose the identical API *schema* — same routers, same route set, same models.
**What this does NOT prove, and must not be read as proving:** that production runs the same *handler bodies*. Frozen candidate `d2f8b742` changes only response content (`e3_detections` presence), not the OpenAPI schema, so this comparison **cannot** distinguish parent-era code from the candidate, nor detect any divergent revision whose schema is unchanged. Per the task's own rule, the checked-out backend is **not** assumed to be the production deployment.

---

## 4 · MongoDB deployment and database ownership

| Subject | Finding | Confidence |
|---|---|---|
| Production MongoDB host / cluster / deployment identity | **UNKNOWN** — readable only from the production deployment's environment, which this environment has no permission to read | UNKNOWN |
| Production `DB_NAME` | **UNKNOWN** | UNKNOWN |
| Access mechanism (source) | `backend/deps.py` builds one Motor client from `MONGO_URL` and selects `DB_NAME`; a single `db` proxy is shared by every mounted router | SOURCE-CONFIRMED |
| Mandatory config key **names** (no values) | `MONGO_URL`, `DB_NAME`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `EMERGENT_LLM_KEY` | SOURCE-CONFIRMED |
| This workspace's preview binding (names only) | `DB_NAME = test_database`, `MONGO_URL` points at a local `mongodb://` instance — **preview only**, not production | SOURCE-CONFIRMED |
| Production vs preview database separation | A 2026-09-08 control recorded in `memory/PRODUCTION_DOMAIN_INVENTORY.md`: the same login succeeded on preview and returned `401 Invalid credentials` on `nivxray.nivxforge.com` → different credential store, therefore different database | INHERITED — deliberately **not** re-run, because it would mean presenting preview credentials to production |
| G4 lab database | `nivx_g4_lab`, loopback only — isolated from both | SOURCE-CONFIRMED |

**Security-sensitive omissions:** no connection string, host, username, password, token or secret value appears in this document, and none was printed to any log during this task. Only key *names* and the preview `DB_NAME` literal are recorded.

---

## 5 · EDR / XDR / Workspace shared dependencies

| # | Shared element | Evidence | Confidence |
|---|---|---|---|
| S1 | **One API origin for all three products** | EDR bundle, XDR bundle (`index-C2Od7EUX.js`) and Workspace bundle (`workspace.nivxmachines.com/static/js/main.b59b5408.js`) each contain exactly one `nivx*` origin: `https://nivxray.nivxforge.com` | PRODUCTION-VERIFIED |
| S2 | **One backend runtime** | That single origin answers EDR (86), XDR (199) and Workspace/investigation route families from one FastAPI app, one OpenAPI document, one service name `nivxray-api` | PRODUCTION-VERIFIED |
| S3 | **Workspace runtime parity now established** | Baseline v0.1 listed Workspace route/runtime parity as UNVERIFIED. The Workspace production bundle targets the same API origin, and `nivxray.nivxforge.com/` itself still serves a CRA Workspace build (`main.6c02e095.js`) alongside `/api/*` | PRODUCTION-VERIFIED (new finding) |
| S4 | **One MongoDB client / database proxy** | `backend/deps.py` single Motor client + `db` proxy consumed by EDR, XDR and analysis routers | SOURCE-CONFIRMED |
| S5 | **EDR background worker inside the shared API process** | `backend/server.py` calls `edr_plane.processing_queue.start_workers(worker_count=1, reconcile_interval_seconds=60)` at application startup, plus EDR index creation | SOURCE-CONFIRMED |
| S6 | **EDR frontend depends on XDR-owned endpoints** | `apps/nivxray-xdr/src/nivxforge/edrApi.js` calls `/xdr/rbac/session-context`, `/xdr/respond/*`; those paths exist in the production OpenAPI | SOURCE-CONFIRMED + PRODUCTION-VERIFIED (routes present) |
| S7 | **Shared auth audience** | 3 `/api/auth/*` paths serve all products; `/api/auth/me` → `403 Not authenticated` on production | PRODUCTION-VERIFIED |
| S8 | **Shared frontend source package** | `apps/nivxray-xdr` builds EDR and XDR by scope flag; the EDR artifact carries both product labels | SOURCE-CONFIRMED + PRODUCTION-VERIFIED |
| S9 | **Separate per-product edge only** | Three distinct Vercel CNAME targets and three distinct asset hashes → isolation exists at the static-frontend layer **only** | PRODUCTION-VERIFIED |
| S10 | Shared object/file storage, retention sweeper, decoder and bootstrap tasks in the same process | `backend/server.py` registers FileStore retention sweeper and content/bootstrap tasks alongside EDR | SOURCE-CONFIRMED |
| S11 | Cross-product evidence collections (`xdr_canonical_evidence`, `v2_shadow_observations`) written from the EDR canonical bridge | `backend/edr_plane/canonical_bridge.py` | SOURCE-CONFIRMED |

**Net:** the only verified product isolation today is the static frontend edge. Backend runtime, auth, configuration, worker process, storage tasks and database client are **common to EDR, XDR and Workspace**.

---

## 6 · Evidence classification summary

| Class | Items |
|---|---|
| **PRODUCTION-VERIFIED** | EDR DNS/edge/redirect/artifact; single API origin in all three product bundles; API origin DNS + Cloudflare + Emergent cookies; `/api/` and `/api/health` service identity; 875-path OpenAPI with EDR/XDR/auth families; EDR fail-closed 401/403; 404 control probes; byte-identical OpenAPI across prod/preview/local; three distinct Vercel CNAME targets; Workspace bundle API origin |
| **SOURCE-CONFIRMED** | Single Motor client and `db` proxy; mandatory config key names; EDR worker startup in the shared app; EDR→XDR frontend endpoint dependency; shared frontend package; canonical bridge cross-product writes; preview `DB_NAME`/local Mongo binding |
| **INHERITED (not re-verified here)** | Vercel project `prj_KrtnUHko9opTWHv0cbXS1a2EAKV4`, deployment `dpl_GnXW5Y5qwss3858hd1jJdrabxXME`, frontend SHA `35d47cc9…`, production environment identity, prod-vs-preview credential-store separation (2026-09-08) |
| **INFERRED** | `nivxray.nivxforge.com` is this job's own Emergent production deployment |
| **UNKNOWN** | Backend deployment ID, revision and SHA; production MongoDB host/deployment identity; production `DB_NAME`; production collection inventory, counts and index sizes; production V3 flag value and route-by-route rendering |

---

## 7 · Dependency and missing-permission inventory

| Need | Why A0-01 needs it | Status |
|---|---|---|
| Read-only Vercel API token | Re-verify project ID, deployment ID, production environment, source SHA and env **key names** | **MISSING** — no Vercel credential in this environment; baseline values carried as INHERITED |
| Production platform/runtime metadata read | Backend deployment ID, image/revision, pod state, DB binding, secret key names | **MISSING** — requires an authorized platform read against the production app; not attempted |
| Production MongoDB metadata (names only) | Server/deployment identity, database name, collection inventory | **MISSING** — no authorized read-only path exists from here |
| Authenticated read-only production analyst session | Route-by-route UI/API behaviour, tenant and endpoint inventory, V3 rendering | **MISSING** — deliberately not attempted; preview credentials must not be presented to production |
| Backend build stamp endpoint | Would make backend SHA self-evident | **ABSENT by design** — `/api/version` and `/api/build-info` return 404 |

---

## 8 · Unresolved questions and next read-only checks

1. **Which deployment and revision actually serves `nivxray.nivxforge.com`?** → authorized read-only platform query for the production app's deployment ID, image/revision and build log; no deploy, no restart.
2. **What is the production `DB_NAME` and Mongo deployment identity?** → read the production deployment's env **key names and `DB_NAME` value only**; never the connection string.
3. **Is the production backend the parent-era code or something else?** → OpenAPI cannot answer it. Requires either the platform revision (check 1) or one authenticated read-only trajectory call checking for `e3_detections`.
4. **Re-verify the Vercel ledger** (project, deployment, SHA, production env, env key names) with a read-only token, and confirm whether `index-Btpjue2F.js` corresponds to `35d47cc9…`.
5. **Does production share the database with any other deployment?** → compare database names across the production, preview and Workspace deployments by name only.
6. **Collection ownership matrix** (route → handler → reads/writes → worker → collection → owner), built from source first, verified against production only after check 2 grants a name-level view.
7. **Production tenant/endpoint inventory**, including the pending `KUSHU` / `DESKTOP-A9HGFJJ` records — read-only, after an authenticated analyst session exists.

---

## 9 · A0-01 assessment

### **PARTIAL**

**Closed in this task**
- EDR production edge, redirect, served artifact and single configured API origin — verified live.
- The API origin is live, is an Emergent-hosted FastAPI behind Cloudflare, and mounts the EDR control/agent plane fail-closed.
- EDR, XDR **and Workspace** all consume that one origin — the Workspace linkage, previously UNVERIFIED in the baseline, is now production-verified.
- Product isolation today exists **only** at the static frontend edge.
- Production, preview and the local checkout serve a byte-identical API schema, with the explicit caveat that this cannot identify the deployed revision.

**Not closed**
- Backend deployment ID / revision / SHA → **UNKNOWN**.
- Production MongoDB deployment identity and `DB_NAME` → **UNKNOWN**.
- Vercel project/deployment/SHA ledger → **INHERITED**, not re-verified (no credential).

A0-01 cannot reach PASS from inside this environment: the two decisive facts both sit behind permissions that are absent here. No implementation, no cutover and no target-architecture work is proposed or authorized by this document.
