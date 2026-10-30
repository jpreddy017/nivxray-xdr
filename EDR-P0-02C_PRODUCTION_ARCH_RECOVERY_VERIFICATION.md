# EDR-P0-02C — Production Architecture & Recovery Verification

**Reference:** P0-02C · **Date:** 2026-10-30 · **Mode:** STRICTLY READ-ONLY · **Implementation:** NOT AUTHORIZED
**Target repository:** `nivxforgeedr/nivxforge-edr` — **not contacted, nothing pushed**
**Inputs (not repeated):** A0-01, A0-03, P0-01, P0-02A, T1, T2
**Change performed:** NONE — no deployment, no Vercel operation, no repository change, no database record read or mutation, no secret value read, no VM contact. All live evidence came from unauthenticated `GET` requests to already-public endpoints plus platform documentation.

**Classes:** **[DV]** deploy-verified live now · **[SV]** source-verified in this checkout · **[DOC]** platform-documented · **[INH]** inherited from an earlier report, not re-proved · **[INF]** inferred, needs confirmation · **[UNK]** unknown · **[BLK]** blocked by missing access

---

## TASK 1 — Production backend

### 1.1 Deployment and provider

| Item | Finding | Class |
|---|---|---|
| Production API origin | `https://nivxray.nivxforge.com` | **[DV]** |
| Edge | Cloudflare (`server: cloudflare`, `cf-ray`), then `via: 1.1 google` → Google-backed compute behind the edge | **[DV]** |
| Platform | Emergent-hosted application (`__emg_vid` / `__emg_sid` cookies); **not** a Vercel function and **not** on the Vercel ingress | **[DV]** |
| Service identity | `GET /api/` → `{"service":"NivXRay","status":"ok"}`; `GET /api/health` → `{"status":"ok","service":"nivxray-api"}` | **[DV]** |
| Per-request trace | `x-request-id: nvx-…`, `x-elapsed-ms: 3` — observability middleware active in production | **[DV]** |
| **Deployment ID / image / commit** | **UNKNOWN** — no build stamp is exposed (`/api/version`, `/api/build-info` → 404) and platform deployment metadata is not readable from here | **[UNK]** |

**Explicitly not done:** no deployed version was guessed from a local or remote branch tip. `phase2/edr-production` = `35d47cc9…` is a *frontend* branch tip and says nothing about the backend image.

### 1.2 Does the deployed source match the verified dependency manifest?

Three independent probes, strongest last:

| Probe | Result | What it proves |
|---|---|---|
| OpenAPI document | production / preview / local **byte-identical**, `md5 a8c5abe0…`, 778,868 B, 875 paths (86 EDR, 199 XDR) | identical route **declarations** only |
| `GET /api/health/deep` (prod) | `{"status":"ok","checks":{"mongo":"ok","llm_key":"ok","disk":"ok (75494 MB free)"}}` | the production process reaches MongoDB and has its LLM key; same shape as local (`240552 MB free`) |
| **`GET /api/nivxforge/preview/platform-health`** | production response is **byte-identical to this checkout's** — `md5 2d42361e204fba252b2b3f6c88637ade` both sides | **new, stronger evidence**: this endpoint reads repository **files at runtime** (charter/north-star/roadmap existence, ADR counts 4 accepted / 0 proposed / 83 other / 87 total, evidence counts 21/1/1, regression block). Identical output means the deployed image's on-disk documentation tree matches this checkout for those paths |
| `GET /api/nivxforge/preview/diagnostics` | prod and local both return exactly one file, `DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md`, **7,134 bytes** | same file content length in the deployed image |

**Verdict:** the deployed tree is **highly consistent with** the P0-01 manifest anchor (`5040c08c`) — route declarations, runtime-read repository files and file sizes all agree. But consistency is not identity: no probe returns a commit, and candidate `d2f8b742` changes only response *content*, so a schema/doc match cannot discriminate revisions. **Manifest-to-deployment match: CONSISTENT, NOT PROVEN [INF].**

⚠️ **Trap flagged:** the production `platform-health` payload contains `"build_id": "1ecec01"` inside its `regression` block. This is **static text read from a repository file** (identical locally) — a historical health-check record, **not** the deployed revision. It must not be reported as the production build.

### 1.3 Runtime services, workers and shared dependencies

| Component | Status | Class |
|---|---|---|
| Single FastAPI process serving EDR + XDR + Workspace route families | live | **[DV]** |
| EDR processing workers — `edr_plane.processing_queue.start_workers(worker_count=1, reconcile_interval_seconds=60)` started at API startup | in the same process as the API | **[SV]** |
| EDR index creation at startup (`canonical_index_contract`) | same process | **[SV]** |
| FileStore retention sweeper + content/bootstrap tasks | same process | **[SV]** |
| One Motor client / one `db` proxy shared by all products (`deps.py`) | — | **[SV]** |
| Mandatory startup config: `MONGO_URL`, `DB_NAME`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `EMERGENT_LLM_KEY` | fail-fast | **[SV]** |
| Shared runtime dependencies EDR cannot start without | `deps`, `routers.xdr_rbac`, `routers.xdr_audit_log`, `v2.ingestion.*`, `detection_content.*`, `services.session_context`/`dashboard_lenses`/`activity.projector`/`mitre_catalogue`, `security.secret_policy` (30 non-EDR modules in the 191-module closure) | **[SV]** |
| Worker-chain hazard | the worker closure reaches `services.investigator.*` and `services.iue.*` **only** through `detection_content.xdr_pipeline` | **[SV]** |

### 1.4 Frontend-to-backend connections (live)

| Frontend | Host | API origin baked at build | Class |
|---|---|---|---|
| EDR | `edr.nivxforge.com` | `https://nivxray.nivxforge.com` — `build-info.json`: `{"product":"nivxray-edr","product_scope":"edr","phase":"2","cross_product_origins":0,"built_at":"2026-10-28T16:15:44Z"}` | **[DV]** |
| XDR | `xdr.nivxforge.com` | same origin, `built_at 2026-09-30T17:37:18Z` | **[DV]** |
| Workspace | `workspace.nivxmachines.com` | same origin (CRA bundle `main.b59b5408.js`) | **[DV]** |
| EDR UI → XDR runtime endpoints | `edrApi.js` calls `/xdr/rbac/session-context`, `/xdr/respond/actions`, `/xdr/respond/health`, `/xdr/respond/pending-approvals` | **[SV]** + routes present in the production OpenAPI **[DV]** |
| Auth surface | 3 `/api/auth/*` paths shared by all products; `/api/auth/me` → `403` unauthenticated | **[DV]** |
| EDR agent plane | `/api/edr/agent/whoami` → `401 SENSOR_UNAUTHENTICATED` (fail-closed) | **[DV]** |

### 1.5 Task 1 unknowns

Deployment ID, image digest, commit, replica count, resource limits, scheduler/cron inventory, and whether more than one API replica runs (which would mean **more than one queue writer**). All **[UNK]**; all would be answered by one authorized platform read.

---

## TASK 2 — Production MongoDB

### 2.1 What is verifiable without touching data

| Item | Finding | Class |
|---|---|---|
| Production database reachable and healthy | `/api/health/deep` → `"mongo":"ok"` | **[DV]** |
| Provider | Emergent-managed **MongoDB Atlas** for deployed apps | **[DOC]** |
| Access model | a dedicated Atlas database user per app, `readWrite` + `dbAdmin` **scoped to that app's databases only**; the cluster accepts connections from the platform network (and allowlisted IPs) | **[DOC]** |
| Database exclusivity | **exclusive per deployed app** — not shared across apps or jobs | **[DOC]** |
| Preview vs production | **separate databases.** Preview = local `mongodb://localhost:27017`; production = Atlas `mongodb+srv://…`. Data moves preview→production only on first deploy | **[DOC]**, consistent with the 2026-09-08 login control **[INH]** |
| Config key custody | `MONGO_URL` and `DB_NAME` exist as platform **system** keys, `live` slot, shared mode | **[DV]** via the secret register, names only |
| **Production `DB_NAME` value** | **not read.** Documented naming convention is `{app_name}-{preview_db_name}`; with preview `DB_NAME=test_database` this implies `greeting-app-5782-test_database` — **[INF], must be confirmed** in *Manage Publishes → Database*, not assumed | **[INF]** |
| Storage/ownership metadata (size, collection counts, index footprint) | **not readable here**; no storage metric is exposed | **[BLK]** |

### 2.2 Backup owner, schedule, retention, restore — **now documented [DOC]**

| Property | Value |
|---|---|
| Owner / operator | **Emergent platform** (managed Atlas). Not user-operated |
| Automated schedule & retention | hourly → 7 days · daily → 7 days · weekly → 4 weeks · monthly → 12 months · yearly → 1 year |
| Point-in-time recovery | continuous **7-day PITR window** |
| Restore mechanism | **not self-service — user must contact support** to recover a deleted or damaged production database |
| RTO / RPO | **not documented** → **[UNK]**; obtainable only from support |
| Export path | via the in-platform MongoDB Viewer (*Manage Publishes → Database → Go to database*, "Dump DB"), or external tools from allowlisted IPs. A direct `mongodump` from this pod is **not** possible |
| On undeploy / pause | Kubernetes resources are torn down; **the Atlas database and credentials are preserved** and re-attached on redeploy |

**This materially closes gap G1 at policy level.** It does **not** close it at instance level: no backup inventory, no snapshot list, no restore test and no RTO/RPO for *this* database has been seen. Per the directive, **a documented policy is not a verified restore.**

### 2.3 Collections (A0-03 classification, unchanged)

117 authoritative names · **39 EDR-exclusive** · ~30 XDR-exclusive · ~35 shared/platform · **13 cross-product**. No record was read to produce this; it is source-derived.

### 2.4 Database dependencies that would block independent EDR operation

| # | Dependency | Why it blocks |
|---|---|---|
| D1 | `v2_shadow_observations` + `xdr_canonical_evidence` written through the shared bridge (`canonical_bridge.py:511` → `telemetry_bridge.py:375`) | EDR's live evidence write lands in shared collections |
| D2 | `counters` shared keyspace (EDR delivery counters alongside XDR framework mapping and incident numbering) | a split needs a separate keyspace or collisions occur |
| D3 | `users`, `tenants` read by `edr_plane.authority` and `services.edr.device_identity` | EDR authorization resolves against platform identity tables |
| D4 | `xdr_audit_log` read by `routers.edr_session` | audit reads cross the boundary |
| D5 | `workspace_cases`, `v2_decoded_payloads` read by `edr_plane.campaign_story` / `routers.edr` | campaign narrative depends on Workspace data |
| D6 | `routers/edr_maintenance.py` writes 13 non-EDR collections under a hardcoded tenant | excluded from any copy (P0-01 §6) |
| D7 | Single authoritative queue writer | two API replicas or an overlapping new runtime = two writers |

### 2.5 Task 2 status

**PARTIAL — policy DOCUMENTED, instance BLOCKED.** Provider, isolation model, backup schedule/retention/restore path and undeploy behaviour are now documented; database identity value, storage inventory, snapshot evidence and RTO/RPO remain **[BLK]/[UNK]**. No record was accessed; no connection string or credential appears anywhere in this report.

---

## TASK 3 — Vercel deployment (frontend)

| Item | Finding | Class |
|---|---|---|
| EDR production host | `edr.nivxforge.com` → `216.198.79.65`, `64.29.17.65`; CNAME `e383409f27098db0.vercel-dns-017.com`; `server: Vercel`; `x-vercel-cache: HIT`; `x-vercel-id: cle1::…` | **[DV]** |
| Distinct projects per product | three different `*.vercel-dns-017.com` CNAME targets for EDR / XDR / Workspace | **[DV]** |
| Project ID / deployment ID | `nivxray-edr-production`, `prj_KrtnUHko9opTWHv0cbXS1a2EAKV4`, `dpl_GnXW5Y5qwss3858hd1jJdrabxXME` | **[INH]** — not re-verified |
| **Re-verification attempt** | `VERCEL_TOKEN` **is registered** in the secret store (`live` slot, no `test` slot) but its **value is empty in this environment** (length 0); the Vercel API answered `forbidden / missingToken` | **[BLK]** |
| Connected repository / branch | `jpreddy017/nivxray-xdr`, branch `phase2/edr-production`; branch tip **= `35d47cc96352f492bd4c603a2f2f1b65afb4119f`** (confirmed via GitHub API) | branch tip **[DV]**; that the deployment was built *from* it **[INH]** — the served bundle carries **no** commit stamp |
| Build provenance of the live artifact | `build-info.json`: product `nivxray-edr`, scope `edr`, api_origin `https://nivxray.nivxforge.com`, phase `2`, `cross_product_origins: 0`, `built_at 2026-10-28T16:15:44Z`; asset `/assets/index-Btpjue2F.js` (256,470 B) | **[DV]** |
| Root directory | `apps/nivxray-xdr` — the repository root `vercel.json` sets `buildCommand: bash scripts/refuse-root-deployment.sh`, i.e. a root deployment is **deliberately refused** | **[SV]** |
| Framework | `"framework": null` (explicit), Vite build, `outputDirectory: dist`, `installCommand: yarn install --production=false` | **[SV]** |
| Build command | `bash scripts/vercel-build.sh` — refuses to build unless `NIVX_PRODUCT_SCOPE` is `edr` or `xdr`; runs `scripts/verify-production-build.js` as a post-build guard | **[SV]** |
| Environment variable **names** (no values) | build-time: `NIVX_PRODUCT_SCOPE`, `XDR_PROD_API_ORIGIN`, `API_ORIGIN`, `NIVX_CROSS_PRODUCT_ORIGINS`, `NIVX_EDR_ORIGIN`, `NIVX_XDR_ORIGIN`, `NIVX_WORKSPACE_ORIGIN`, `EDR_ORIGIN`, `XDR_ORIGIN`, `WORKSPACE_ORIGIN`; emitted into the bundle as `REACT_APP_NIVXRAY_API_URL`. Registered frontend keys: `REACT_APP_NIVX_FLAG_CASE_ENGINE`, `REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE`, `REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3`, `REACT_APP_BACKEND_URL`, `ENABLE_HEALTH_CHECK`, `WDS_SOCKET_PORT` | **[SV]** + **[DV]** (register, names only) |
| Scopes per variable (Production/Preview/Development) | **[BLK]** — needs the Vercel API |
| Routing | SPA rewrite `"/(.*)" → "/index.html"`; two host-scoped redirects: `/` → `/edr` on `edr.nivxforge.com`, `/` → `/xdr` on `xdr.nivxforge.com`. **No `/api/*` route exists in `vercel.json`** — the API origin is absolute, baked at build time | **[SV]** + **[DV]** (`307 → /edr` observed) |
| Domain assignment | `edr.nivxforge.com` resolves to Vercel and serves scope `edr`; `xdr.nivxforge.com` to a different project | **[DV]** |
| Rollback mechanism | Vercel immutable deployments + instant rollback / alias re-point to a previous `dpl_*`. **Not verified** — listing deployments requires the API token | **[DOC]/[BLK]** |

**Task 3 status: PARTIAL.** Host, edge, routing, root directory, framework, build configuration, variable names and live build provenance are verified; project/deployment IDs, variable scopes, deployment history and rollback targets are **[BLK]** until the registered `VERCEL_TOKEN` slot holds a value.

---

## TASK 4 — Recovery gap matrix

**PRESERVED** = an integrity-checked copy exists · **RESTORE-VERIFIED** = a restore was actually performed and checked · **UNKNOWN** = not established · **BLOCKED** = access required.

| # | Domain | Asset | Class | Evidence |
|---|---|---|---|---|
| 1 | **Frontend / UI-UX source** | `apps/nivxray-xdr` incl. `src/nivxforge` (102 files), design tokens, 13 EDR test files | **PRESERVED** | tracked at `5040c08c`; branch `phase2/edr-production` = `35d47cc9…` verified upstream |
| 1b | Frontend | deployed artifact ↔ commit linkage | **UNKNOWN** | bundle carries no commit stamp; `build-info.json` has scope/origin/time only |
| 2 | **Backend / engines** | 191-module closure | **PRESERVED** | P0-01 Appendix A; 191/191 in HEAD, worktree clean, blob hashes triple-checked |
| 2b | Backend | **deployed** image / revision | **UNKNOWN** | no stamp; platform read required. Deployed tree is *consistent* with the manifest (§1.2) but not proven identical |
| 3 | **Git history — main repo** | `jpreddy017/nivxray-xdr`, 56 branches / 23 PRs | **PRESERVED** | GitHub API enumeration |
| 3b | **Git history — unique `rocket-p0/src`** | 27 refs incl. `cd2b8b92d…`, plus 9 unreachable objects | **RESTORE-VERIFIED** | T1 bundle (`9ae11e50…`) cloned successfully; T2 tar (`e16ba1e1…`) fully extracted → HEAD, 27/27 refs, clean `fsck`, all 9 dangling objects resolvable. **This is the only restore-verified asset in the entire system, and it is source history — not production.** |
| 3c | Git history | off-pod copy | **UNKNOWN until download** | artifacts and a 265 MB zip (`623c9801…`) exist on the pod only; transfer path proven byte-exact |
| 4 | **MongoDB configuration** | `MONGO_URL` / `DB_NAME` custody | **PRESERVED** (custody) / **BLOCKED** (values and `DB_NAME` confirmation) | platform system keys, live slot; values never read |
| 4b | **MongoDB data — policy** | hourly/daily/weekly/monthly/yearly + 7-day PITR, platform-owned, support-initiated restore | **PRESERVED (policy only)** | platform documentation **[DOC]** |
| 4c | **MongoDB data — this instance** | snapshot inventory, restore test, RTO/RPO | **UNKNOWN** | never listed, never tested. **No production backup is claimed as verified** |
| 5 | **Windows sensor source** | `agents/nivxforge-*`, M1 source in 13 bundles | **PRESERVED** | `VERIFY.sh` = fsck + 18/18 blob SHAs + 373 portable tests; subtree `db21f422…` |
| 5b | **Installer artifacts** | `NivXForgeEDRSetup.exe`, `NivXForgeSensor.exe`, `payload-manifest.json`, image digest record | **UNKNOWN / confirmed absent** | exhaustive filesystem search found none; the VM-reported `9AF2F96B…` has no corroborating record; build is unsigned and not byte-reproducible |
| 5c | **G4 VM durable state** | `identity.json`, outbox, journal, bookmarks, policy state, `m1-ownership.json`, `m1-config.json` | **UNKNOWN** | no snapshot exists; VM deliberately untouched |
| 6 | **Vercel deployment** | config-as-code (`vercel.json`, build scripts, guards) | **PRESERVED** | tracked in the repository |
| 6b | Vercel | project/deployment IDs, env scopes, deployment history, rollback targets | **BLOCKED** | `VERCEL_TOKEN` registered but empty here |
| 7 | **Secrets / credential recovery** | 60 app + 13 system keys, live/test slots, rotation timestamps for 9 sensitive keys | **PRESERVED (register)** / **UNKNOWN (drill)** | secret register read, names only; recovery is **re-issue, never export**; no drill performed |
| 7b | Secrets | `EDR_AUTH_PEPPER`, `XDR_SECRETS_MASTER`, `XDR_ROOT_KEY`, `XDR_AUDIT_MASTER_SECRET` | **UNKNOWN** | no out-of-band custody record seen; losing the pepper invalidates every agent credential |
| 7c | Secrets | **`.tok` credential blobs (22 versions) inside the T1/T2 archives** | **ACTION REQUIRED** | T2 §4.3 — rotate, and filter before any history migration into `nivxforge-edr` |
| 8 | **Sandbox-related source & infrastructure** | `rocket-p0/` non-Git assets: `f1/` 208 MB, six gate working copies ≈ 94 MB each, `SECURE_EXPORT/` dirs | **UNKNOWN** | only the embedded `.git` was classified and preserved; the rest is unassessed |
| 8b | Sandbox infra | preview pod itself, `/data/db` 1.6 GB (preview + `nivx_g4_lab` 9.8 MB), `/app` at 90 % full | **UNKNOWN** | ephemeral by nature; no snapshot |

### 4.1 The distinction the directive demands

**Git-history restoration (T1/T2) is RESTORE-VERIFIED. Production recovery is NOT.** The former was proven by performing an actual clone and an actual extraction; the latter rests on a documented platform policy that has never been exercised for this database. These two must never be conflated in any later gate.

---

## Verdict

| Task | Status |
|---|---|
| 1 · Production backend | **PARTIAL** — provider, service, runtime, workers, shared dependencies and frontend wiring verified live; **revision/commit UNKNOWN**; manifest match CONSISTENT but unproven |
| 2 · Production MongoDB | **PARTIAL** — provider, isolation, backup schedule/retention/restore path and undeploy behaviour documented; `DB_NAME` value, storage inventory, snapshot evidence and RTO/RPO **BLOCKED/UNKNOWN** |
| 3 · Vercel | **PARTIAL** — host, routing, root dir, framework, build config, env names and live build provenance verified; IDs, scopes, history and rollback **BLOCKED** (`VERCEL_TOKEN` empty) |
| 4 · Recovery gap matrix | **DELIVERED** — 8 domains, 19 rows, each classified with evidence |

### **OVERALL: PARTIAL**

Two findings move the position forward materially: the production backup **policy** is now documented rather than unknown (hourly→yearly retention, 7-day PITR, platform-owned, support-initiated restore, database preserved on undeploy), and the production tree is now shown to match this checkout at the level of **runtime-read repository files**, not just route declarations.

Three things still block certification of recovery, and none can be closed from inside this environment:

1. **Deployed backend revision — UNKNOWN.** One authorized platform read closes it.
2. **This database's backup inventory and a restore test — UNKNOWN.** Policy ≠ proof.
3. **Vercel ledger — BLOCKED.** Populating the already-registered `VERCEL_TOKEN` slot closes it.

Plus two preservation actions that do not need production access: get the T1/T2 archives **off the pod**, and **rotate the `.tok` credential** whose 22 historical versions sit inside them.

Separation remains on **HOLD**. No implementation is authorized by this document.
