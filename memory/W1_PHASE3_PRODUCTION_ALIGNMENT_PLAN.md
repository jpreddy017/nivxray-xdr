# PRODUCTION ALIGNMENT PLAN — bring the authoritative NivXRay XDR backend to
# the current accepted build. INSPECTION / PLAN ONLY.

Date: 2026-09-16 · HEAD `cf4aefc9022dcaeeb6973363734e28eb74fb7ede`
Nothing deployed. No Vercel change. No collector, no key, no forwarder.json,
no ingest.key, no Windows telemetry. `_COLLECTED_PRODUCTS` untouched.

## 1 · What serves nivxray.nivxforge.com

- Emergent-managed deployment behind Cloudflare. Measured: `server: cloudflare`,
  `via: 1.1 google`, `x-request-id: nvx-…`, `x-elapsed-ms`, and Emergent session
  cookies `__emg_vid` / `__emg_sid` on `/`. **No `x-vercel-*` header on any
  response** — this host is NOT Vercel.
- One deployment serves both surfaces: `/` = the CRA app built from
  `/app/frontend`, `/api/*` = the FastAPI app from `/app/backend`.
- TLS: Google Trust Services `WE1`, single-SAN `CN=nivxray.nivxforge.com`,
  notAfter 2026-12-07. `verify=0` (trusted) from outside the pod.
- Database is SEPARATE from preview (same code, different user store —
  identical login payload: preview 200, production 401).

## 2 · Vercel relevance

Vercel hosts only the SPAs: `xdr.nivxforge.com` (project
`nivxray-xdr-production`, Root Directory `apps/nivxray-xdr`, env
`NIVX_PRODUCT_SCOPE=xdr`, `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com`)
and `edr.nivxforge.com`. Repo-root `vercel.json` intentionally runs
`scripts/refuse-root-deployment.sh`, which exits 1: a project building from the
repo root would ship a bundle with no product scope and the PREVIEW api origin
baked in. **Vercel is irrelevant to the backend**; a backend republish does not
touch the Vercel projects or their domains.

## 3 · Which build production currently runs

- No build-identity endpoint exists (`/api/health` → `{"status":"ok",
  "service":"nivxray-api"}`), so the commit cannot be read from outside.
- Bounded by measurement: 785 OpenAPI paths; contains the 2026-09-08 EDR
  routes (`/api/edr/agent/heartbeat`, `/api/edr/telemetry/freshness`,
  `HeartbeatBody.queue_depth`); LACKS everything added by `c21c11dc`
  (D15/D16/D17, 2026-09-15) and `597a12b0` (D21, 2026-09-15).
  ⇒ the live build is from **2026-09-08 … 2026-09-14**.
- Exact commit + deploy logs are visible only in Emergent
  **Manage Publishes → Overview → Deployments** (shows date, deployment id,
  commit hash, View Logs).

## 4 · Replacement target

`cf4aefc9` (current HEAD, tree clean apart from one untracked memory file).
Includes: D15/D16/D17 `c21c11dc`, D21 `597a12b0`, X1 `2058b954`,
DCR-1 `6bf9dc43`, W1 host-independent Sysmon fixes `da6702e7`, W1 forwarder
`e9545f27` + hotfixes `300472ec`, `50bb092e`.

## 5 · Deployment mechanism (platform-confirmed)

Emergent **Republish**: rebuilds backend **and** `/app/frontend` into a new
container image; Kubernetes rolling update (`maxSurge=100%`,
`maxUnavailable=0`) so the custom domain keeps serving; ~10–15 minutes; the
custom domain stays attached automatically.

## 6 · Environment / secrets

- Production secrets live in **Manage Publishes → Secrets**, independent of
  `backend/.env`. On republish existing custom values are **preserved** and are
  NOT re-copied from preview.
- The aligned build introduces **no new required variable**. Names it reads
  (all optional or already present): `MONGO_URL`, `DB_NAME`, `CORS_ORIGINS`,
  `JWT_SECRET`, `JWT_EXPIRE_HOURS`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
  `ADMIN_FORCE_PASSWORD_CHANGE`, `EMERGENT_LLM_KEY` (or `ANTHROPIC_API_KEY`),
  `EDR_AUTH_PEPPER`, `EDR_*_TTL_SECONDS`, `XDR_RESPONSE_SERVICE_URL/TIMEOUT`,
  `NIVX_*` flags, OSINT keys, and optionally
  `XDR_MACHINE_RATE_LIMIT_{IP,KEY,TENANT}` / `XDR_MACHINE_RATE_WINDOW_SECONDS`
  (defaults 600 / 600 / 1200 per 60 s), `XDR_COLLECTOR_RUNTIME_URL` (absent =>
  honest "runtime not configured" answer, not a crash).
- `EDR_AUTH_PEPPER` must NOT be changed by this operation: rotating it
  invalidates existing EDR agent credentials.
- `VERCEL_TOKEN` is a workspace-side value; the backend does not need it in
  production.

## 7 · Database compatibility / migrations

**None required.** No migration scripts, no backfill, no reseed. Indexes are
created lazily at runtime (`services/ingest_idempotency._ensure_indexes`,
`services/machine_rate_limit._coll`). New collections appear on first use:
`xdr_ingest_routing_blocks`, `xdr_machine_rate_buckets`,
`xdr_live_reasoning_audit`. `deps.seed_admin()` is idempotent and **never
re-sets an existing admin password** (`backend/deps.py:359`), so the owner's
rotated production admin password survives the republish. Production DB is
preserved across redeploys.

## 8 · Redis / Mongo

No Redis anywhere (absent from `requirements.txt` and from the code path). The
machine rate limiter is deliberately Mongo-backed. Mongo is the only datastore.

## 9 · API contract impact (measured, not assumed)

- `prod_only` paths: **0** — nothing production serves today disappears.
- Shared operations: **864**, request-contract differences: **0** (no new
  required request field on any existing operation).
- Added: **5** paths — `/api/xdr/collectors/sources/catalog`,
  `/api/xdr/ingest/routing/{catalog,deliveries,summary}`,
  `/api/xdr/detections/{event_id}/citations`.
- Schema additions: `CanonicalEnvelope.declared_source` (optional field) and
  `TelemetryReceipt.routing_blocked`.
- **Behavioural change:** after alignment, an ingest delivery with no
  `declared_source`, or one outside the collector's `authorized_sources`, is
  BLOCKED (fail closed) instead of being content-routed. Production has zero
  collectors and zero ingest keys today, so no existing producer is affected —
  to be re-verified with one authenticated read immediately before republish.

## 10 · Rollback

Manage Publishes → Overview → Deployments → rollback (↺) on the previous
successful deployment. Reuses the previous container image (no rebuild), 1–3
minutes, zero downtime, last 3 successful deployments eligible.
Caveat: rollback restores the BUILD; Secrets-tab values remain at their current
setting. Therefore **do not change any secret in the same operation as this
build change** — one variable at a time.

## 11 · Health / readiness gates (post-republish, unauthenticated)

1. `GET /api/` → `{"service":"NivXRay","status":"ok"}`
2. `GET /api/health` → `{"status":"ok","service":"nivxray-api"}`
3. `GET /api/openapi.json` → **790** paths; the 5 new paths present;
   `CanonicalEnvelope.declared_source` and `TelemetryReceipt.routing_blocked`
   present.
4. `POST /api/xdr/ingest/telemetry` with no credential → **403 unauthenticated**
5. same with a syntactically valid unknown key + `X-Tenant-Id` → **401
   unknown-api-key**
6. `GET /api/xdr/collectors/sources/catalog` without a credential → **403**
   (the catalog must not be readable anonymously)
7. `/api/zzz-not-a-route-12345` → 404 (proves 3–6 are real answers)

## 12 · Content that must be present after alignment

- D15 authority chain: `services/source_routing.py` (catalog, aliases,
  fail-closed refusal codes) + `route_batch` in `routers/xdr_ingest.py`.
- W1 Sysmon DSM: `detection_content/telemetry/sysmon_dsm.py` —
  `OriginalFileName` separate from `process.name`, `Hashes` (SHA256/MD5) and
  `ParentCommandLine` preserved. Not observable over HTTP; proven by the
  in-repo gates and, later, by the first authenticated Windows envelope.
- DCR-1: `detection_content/dcr1_product_neutral.py` with
  `rule_store_binding._COLLECTED_PRODUCTS == {"linux"}` (unchanged).

## 13 · Regression gates — run today on the candidate build (preview)

`python -m pytest tests/test_d14_tenant_authority.py
tests/test_d15_declared_source_routing.py tests/test_d21_routing_visibility.py
tests/test_w1_sysmon_field_preservation.py tests/test_w1_forwarder_source_gate.py
tests/test_dcr1_detection_content_recovery.py tests/test_p0sec_rbac_fail_closed.py
tests/test_collector_api_key_auth.py tests/test_p0_ingest_idempotency.py`
→ **255 passed, 15 skipped** (2026-09-16).
Note: `tests/test_collector_api_key_adversarial_regression.py` drives the
PREVIEW URL over HTTP; its negative cases can be re-pointed at production
without any credential, and only those should be.

## 14 · Frontend impact

`/app/frontend` has **no commits since the live build window**, so the
republish rebuilds the same Workspace CRA app. `yarn build` was executed in the
pod today: **exit 0**, so the frontend step will not fail the deployment. The
Vercel XDR SPA is untouched and does not consume the 5 new endpoints — the
admin routing UI (`apps/nivxray-xdr/src/xdr/admin/IngestRoutingBody.jsx`) lives
only in the undeployed Vite tree.

## 15 · Smallest safe procedure (owner-driven, awaiting approval)

1. Owner opens Manage Publishes → Overview → Deployments; records the CURRENT
   deployment id + commit hash as the rollback point.
2. Owner opens the Secrets tab and confirms the key NAMES in §6 exist. Changes
   nothing.
3. Agent captures the pre-deploy production evidence snapshot (path count,
   fail-closed responses) — already captured today.
4. Owner presses **Republish**. No secret edits in the same operation.
5. Agent runs the §11 unauthenticated gates against
   `https://nivxray.nivxforge.com` and reports PASS/FAIL per line.
6. On any FAIL: owner rolls back to the deployment recorded in step 1 (1–3 min)
   and the agent re-reports. No enrollment is attempted until §11 is all PASS.

Only after §11 passes does Phase 3.1 (collector + scoped key in a dedicated
tenant) become eligible — as a separate owner approval.

## 16 · Backlog carried forward

- **B3.** `routers/xdr_ingest.py::_principal()` prefers `X-Principal-Id` /
  `X-Principal-Kind` headers for AUDIT attribution on the machine path.
  Authority and tenant isolation are unaffected. Target state: machine-path
  audit attribution derived from `request.state.principal_id` set by
  `authenticate_api_key()`, client-supplied attribution headers ignored.
  Not part of W1; to be scheduled before the ingestion plane is declared fully
  hardened.
