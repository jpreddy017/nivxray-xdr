# A0_CURRENT_ARCHITECTURE

Mode: READ-ONLY. Every row is marked **SRC** (confirmed by reading the source
at the stated path) or **DEPLOY-ASSUMPTION** (cannot be confirmed from source).

## 1 · Applications

| Component | Path | Responsibility | Dependencies | Product owner | Status |
|---|---|---|---|---|---|
| XDR + EDR console (one bundle) | `apps/nivxray-xdr/` (Vite, `nivxray-xdr@0.0.1`) | Both product consoles; `/xdr/*` and `/edr/*` route trees | backend `/api/*`; `REACT_APP_PRODUCT_SCOPE` | XDR **and** EDR — shared | **SRC** |
| Product scope boundary | `apps/nivxray-xdr/src/productScope.js` | `PRODUCT_SCOPE`, `isForeignPath()`, per-product brands (NivXRay XDR / NivXForge EDR) | env only | shared | **SRC** |
| Cross-product origins | `apps/nivxray-xdr/src/productOrigins.js` | `CONFIGURED` vs `SAME_ORIGIN` pivots | `REACT_APP_XDR_URL`/`_EDR_URL`/`_WORKSPACE_URL` | shared | **SRC** |
| EDR console surface | `apps/nivxray-xdr/src/nivxforge/` (`NivXForgeConsole.jsx`, `EdrSidebar.jsx`, `edrApi.js`, `managementApi.js`, `onboardingApi.js`) | EDR UI | backend `/edr/*` | EDR | **SRC** |
| Workspace console | `frontend/` (CRA + craco, `frontend@0.1.0`) — **byte-identical to the pod's `/app/frontend`** (`diff -rq` empty) | AutoInvestigate, Decoder, Analyze, Lab, Cases, Benchmark | same backend, `/analyze`, `/decode`, `/die`, `/ai`, `/cases`, `/batch`, `/behavioral`, `/documents` | NivXMachines | **SRC** |
| Backend monolith | `backend/server.py` (1,195 lines) | Single FastAPI app; **173 `include_router` calls** across **157 router modules** | MongoDB, optional LLM tier | all three | **SRC** |
| Collector/forwarder | `apps/nivxray-xdr-collector/` (`main.py`, `framework/`) | Source adapters, outbox, durable delivery, receipts, dedup, health gate | XDR ingest API | XDR | **SRC** |
| Response engine | `apps/nivxray-xdr-response/` (`main.py`, `routes/`, `framework/`, `security/`) | Approval states, vendor adapters, **simulation-only execution** | own service credential | XDR/EDR response | **SRC** |
| Windows sensor | `agents/nivxforge-windows/` (`nivxforge_sensor.py`, `Install-NivXForgeSensor.ps1`, `sysmon/`) | Endpoint telemetry, journal, delivery counters, exclusions | EDR ingest | **EDR** | **SRC** |
| Linux sensor | `agents/nivxforge-linux/` | same, Linux | EDR ingest | **EDR** | **SRC** |
| Shared agent code | `agents/_shared/nivxforge_exclusions.py` | exclusion contract shared by both sensors | — | EDR | **SRC** |

**There is no separate NivXMachines backend and no separate EDR backend.** All
three products are served by the one `backend/server.py` process.

## 2 · Backend line-count distribution

| Area | Lines |
|---|---|
| `routers/` total | 50,274 |
| └ `routers/edr_*.py` (16 files) | 6,848 |
| └ `routers/xdr_*.py` | 15,133 |
| └ other routers (Workspace/decoder/shared) | 28,264 |
| `services/` | 85,275 |
| `detection_content/` | 32,796 |
| `edr_plane/` | 22,840 |
| `engine/` | 12,495 |
| `edr_trajectory/` | 4,007 |
| `edr_behavior/` | 2,154 |
| `services/edr/` | 2,019 |

## 3 · Data layer

**MongoDB only.** `MONGO_URL` + `DB_NAME`, one database shared by all three
products. Collections observed in source, by owner:

| Owner | Collections |
|---|---|
| EDR | `edr_endpoints`, `edr_raw_events`, `v2_shadow_observations`, `edr_response_commands`, `edr_policy_endpoint_state`, `edr_policy_audit`, `edr_exclusions`, `edr_enrollment_audit`, `edr_connector_deployments` |
| XDR | `xdr_canonical_events`, `xdr_canonical_evidence`, `xdr_correlation_matches`, `xdr_response_executions`, `xdr_response_evidence`, `xdr_response_audit`, `xdr_response_timeline`, `xdr_audit_log`, `xdr_collectors`, `xdr_data_sources`, `xdr_detection_rules`, `xdr_integrations`, `xdr_saved_views`, `xdr_framework_mappings`, `xdr_investigation_findings`, `xdr_recommendations` |
| Workspace | `workspace_cases`, `investigations`, `analyze_jobs`, `sample_library`, `kb_entries`, `analyst_corrections`, `pending_training_notes`, `learning_events`, `regression_corpus`, `ai_decode_cache`, `ai_describe_cache` |
| Shared | `users`, `settings`, `iocs`, `correlations`, `incidents`, `shares` |

> **`users` is shared by all three products** — one identity store, one JWT.
> This is the single hardest constraint on product separation.

### **No Redis anywhere** — SRC

`grep -rn "import redis\|aioredis\|Redis(" backend` returns **nothing**. The
`redis` string appears only inside detection-content rule text and connector
catalogues. Asynchronous work is **Mongo-backed**, not Redis-backed.

## 4 · Workers and asynchronous jobs

All in-process `asyncio` tasks started from `backend/server.py`; there is no
separate worker container, no Celery and no cron runner in the repository.

| Worker | Evidence | Note |
|---|---|---|
| EDR durable processing supervisor | `server.py:1048-1070`, `edr_plane/processing_queue.py` (572 lines) | Mongo job queue with atomic `claim()`, `lease_until` leases, expired-lease reclaim, `mark_retry` with backoff, `mark_done`. Gated by `NIVX_EDR_WORKERS_DISABLED=1` |
| Cortex vendor poller scheduler | `server.py:584-599` (`@app.on_event("startup")`) | third-party XDR ingest |
| LOLBAS refresh | `server.py:864` | `asyncio.create_task` |
| Nightly benchmark loop | `server.py:877` | |
| Confusion-matrix prewarm | `server.py:890` | |
| FileStore retention sweeper | `server.py` (`start_retention_sweeper`) | application-controlled TTL |

## 5 · Authentication and authorisation

| Layer | Path | Note |
|---|---|---|
| Human auth | `backend/routers/auth.py`, JWT | one `users` collection for all products — **SRC** |
| Tenant/RBAC (XDR) | `routers/xdr_rbac.py` → `/api/xdr/rbac`, `/api/xdr/tenants`, `/api/xdr/scope` | `require_permission`, `verified_actor`, `_audit_scope_denial` |
| Tenant authority (EDR) | `routers/edr_tenancy.py` (`edr_tenant`, `edr_scope`, `sensor_tenant`, `_opaque_refusal`) | imported by **14 of 16** EDR routers |
| Collector/machine auth | `routers/collector_authz.py` (`collector_guard`, route classes MACHINE / HUMAN_CONTROL / TEST_PLANE), `routers/xdr_api_keys.py` | scoped API keys |
| Response service auth | `routers/xdr_respond_boundary.py` (`_service_credential`, `_bearer`, `_permissions_of`, `_scopes_for`) | analyst bearer is **not** forwarded as engine authority |
| Secret policy | `backend/security/secret_policy.py` | refuses unkeyed/repository-known values; raises `SecretPolicyError` |

## 6 · Deployment configuration

| Artefact | Path | Note |
|---|---|---|
| Staging compose | `deploy/stage1-staging/compose.yml` | 4 services: `mongodb`, `backend`, `response`, `gateway`; private network `internal: true`; volumes `mongo-data`, `response-state` |
| Staging gateway | `deploy/stage1-staging/gateway.conf` | nginx |
| Staging images | `deploy/stage1-staging/backend.Dockerfile`, `frontend.Dockerfile`, `apps/*/Dockerfile` | backend runs as uid 1001, `COPY backend/ /app/` |
| Generic compose | `deploy/docker-compose.yml`, `deploy/backend.Dockerfile`, `deploy/frontend.Dockerfile` | pre-staging |
| Vercel (root) | `vercel.json` | build command is `scripts/refuse-root-deployment.sh` — root deploys are refused by design |
| Vercel (console) | `apps/nivxray-xdr/vercel.json` | host redirects: `xdr.nivxforge.com → /xdr`, `edr.nivxforge.com → /edr`; SPA rewrite |
| Env names (values never read) | `deploy/stage1-staging/*.env.example` | includes `RESPONSE_ENGINE_SERVICE_CREDENTIAL`, `EMERGENT_LLM_KEY`, `JWT_SECRET`, `XDR_ROOT_KEY`, `XDR_AUDIT_MASTER_SECRET`, `MONGO_URL`, `DB_NAME` |

### Deployment-coupling defect — SRC, real

`backend/routers/deck_download.py` and `backend/routers/audit_downloads.py`
read absolute paths that **do not exist inside the staging image**:

```
deck_download.py:16  Path("/app/backend/downloads/NivXRay_NAIDE_Deck.pptx")
deck_download.py:32  Path("/app/deck_assets/NivXRay_Investor_Deck_v1_2.pptx")
deck_download.py:50  Path("/app/memory/NivXRay_Strategic_Master_Positioning.md")
services/platform_metrics.py:42  Path("/app/backend/nvkc/corpus")
```

`backend.Dockerfile` does `COPY backend/ /app/`, so `/app/memory`,
`/app/deck_assets` and `/app/backend/...` do not exist in the container. These
routes will fail in staging. 59 such literals exist in non-test backend code
and 316 in tests; `tests/test_p0prod1_secret_policy.py:30` audits
`pathlib.Path("/app/backend")` — i.e. the **preview pod**, not the repository
under test. P1 fixed the `sys.path.insert` family; these literal reads remain.

## 7 · What this report cannot establish

Which services actually run in production, which image digests are live, which
env values are set, whether production Mongo matches these collections, and
whether the production console is scoped. All **DEPLOY-ASSUMPTION** until read
from the running platform.
