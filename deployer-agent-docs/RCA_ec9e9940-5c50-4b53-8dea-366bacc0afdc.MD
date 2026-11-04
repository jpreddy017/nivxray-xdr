# Post-Deploy Acceptance Verification — greeting-app-5782 (nivxray XDR)

**Scope:** READ-ONLY acceptance verification. No deploy/restart/scale/source/Mongo-write was performed. No telemetry posted. No endpoints (KUSHU / DESKTOP-A9HGFJJ) touched. Backlog left alone.

**Deployment:** greeting-app-5782 (deployment_id 96834a37-643a-4d79-aa15-44810db52b06)
**Active run (publish "ec9e994"):** `ec9e9940-5c50-4b53-8dea-366bacc0afdc` — type=redeploy, status=success, tier_3, template fastapi_react_mongo_shadcn_base_image, cluster target-8, created 2026-10-01T15:34:11Z, completed 15:44:18Z.
**Image:** us-central1-docker.pkg.dev/emergent-default/customers-app/greeting-app-5782:ec9e9940-5c50-4b53-8dea-366bacc0afdc (1813182676 bytes)

---

## 1. DEPLOYED BUILD IDENTITY — CONFIRMED (with one caveat on git-SHA mapping)

**Publish id → run/image mapping:** The Deployment Panel's "ec9e994" is the prefix of the active run_id `ec9e9940-...`, which is also the Docker image tag. The live pods are confirmed pulling exactly this tag (see K8s Pulled events). So "publish ec9e994" == this run == this image. CONFIRMED.

**Caveat — git SHA cannot be mapped by the platform.** The Emergent deployer does NOT record a git commit SHA; the image is tagged by run_id, not by `f900ad7d...`. I therefore cannot assert from platform metadata that the image == commit f900ad7d. What I CAN do is verify the *source content* that was packaged into this run and built into the image, via the run's pulled-source archive (extracted to /app/scratch in an eph sandbox). These greps ran against that archive:

| Check | Expected | Actual | Result |
|---|---|---|---|
| `grep -c 'PROCESSING_CONTRACT = "durable_queue_v1"' backend/edr_plane/processing_queue.py` | 1 | 1 | ✅ |
| `grep -c 'processing_created.get("created")' backend/routers/edr_enrollment.py` | 1 | 1 | ✅ |
| `grep -c 'worker_count=1' backend/server.py` | 1 | 1 | ✅ |
| `grep -c '$lookup' backend/edr_plane/processing_queue.py` | 0 | 0 | ✅ |
| `backend/edr_plane/processing_queue.py` exists (new in release) | yes | yes (16596 bytes) | ✅ |

All five source-content markers of the RC2 EDR durable-ACK release are present in the build that produced this image. Consistent with f900ad7d, though the git SHA itself is not stored/verifiable from platform metadata. (Note: the archive is the pull_source input to the build; it is not a read of the live pod's running filesystem, but image == archive by construction.)

## 2. STARTUP LOG — DURABLE WORKER SUPERVISOR — CONFIRMED, N=1

Literal line (observed on BOTH replicas):
`[startup] EDR durable processing supervisor started (workers=1, reconcile=60s)`
- Replica 1: 2026-10-01T15:44:11.372Z
- Replica 2: 2026-10-01T15:44:37.386Z

**N = 1** on both pods. ✅
`[startup] EDR durable processing supervisor failed:` — NOT present. ✅
`INFO: Application startup complete.` seen for both replicas.

## 3. PRODUCTION MONGO INDEX STATE (listIndexes only; DB greeting-app-5782-test_database)

**edr_processing_queue (4 indexes):**
- `uniq_tenant_raw` — key {raw_id:1, tenant_id:1}, unique:true ✅
- `claimable_work` — key {available_at:1, created_at:1, state:1} ✅ (present)
- `expired_leases` — key {lease_until:1, state:1} ✅ (present)
- (plus _id_)

**edr_raw_events (9 indexes):**
- `reconcile_contract_window` — PRESENT, partialFilterExpression {processing_contract:{$exists:true}} ✅
  - ⚠️ **FIELD-ORDER DISCREPANCY:** actual key is `{ingest_time:1, processing_contract:1}` (ingest_time first). You specified "(processing_contract, ingest_time)". Name + partial filter match exactly; the compound key order is reversed vs. your spec. Factual flag only — not an error, but confirm this matches the intended index definition in code.
- Other existing indexes: _id_, uniq_tenant_dedup (unique, {dedup_key,tenant_id}), tenant_id_1_ingest_time_-1, tenant_id_1_endpoint_ref_1, tenant_id_1_derivations.parser_state_1, events_keyset, events_detection_time, events_payload_hash.

**Index-build health:** `[startup] edr_raw_events + enrollment indexes ensured (append-only)` logged successfully on both pods (15:44:11 / 15:44:37). No index-build warning, stall, timeout, or `[startup] ... indexes failed` line anywhere in the startup logs. ✅

## 4. POD STABILITY — HEALTHY

2 replicas, both phase=Running, container ready=true, **restart_count=0** on both:
- r-ec9e9940-...-5b87cbbd4f-5gdld — started 2026-10-01T15:42:39Z
- r-ec9e9940-...-5b87cbbd4f-8btg9 — started 2026-10-01T15:42:39Z

No CrashLoopBackOff, no OOMKill, no liveness-probe kills, no repeated pod replacement. The only Warning events are transient **Startup** probe "connection refused" at 15:43–15:44 (6 each) while the backend was still binding port 8080 during boot — both cleared and pods went Ready. Expected boot behavior, not instability.

## 5. FEATURE-ATTRIBUTABLE RUNTIME ERRORS — NONE FOUND

Searched last 1440 min. HTTP status histogram over the sampled window: **200×59, 403×10, zero 5xx.**
- `[edr-reconcile] durable-job reconciliation FAILED` — NOT present. ✅
- `AttributeError: module 'edr_plane.processing_queue'` — NOT present. ✅
- Any traceback with frames in edr_plane/processing_queue.py or routers/edr_enrollment.py — NONE. ✅
- 5xx on POST /api/edr/agent/telemetry or /api/edr/agent/telemetry/batch — NONE (no 5xx on any route). ✅

**Observed but NOT feature-attributable (for your awareness, no action implied by this task):**
- 403s are all on `POST /api/edr/agent/session` (agent auth rejections from 35.227.215.211 / default tenant) — not telemetry, not 5xx, expected auth behavior.
- `nightly benchmark failed: can't subtract offset-naive and offset-aware datetimes` (×2, 15:49) — a pre-existing nightly-benchmark job tz bug, unrelated to the EDR durable queue release. Flagging only; out of scope for this acceptance.

## 6. AUTHORITATIVE LIVE BACKEND URL

Platform deployed URL: **https://greeting-app-5782.emergent.host** (this is what the active run serves; `/api/*` → Kubernetes backend on target-8).
Verified custom domain alias: **https://nivxray.nivxforge.com** (verified=true) — same backend. Either is authoritative; emergent.host is the canonical platform origin.

---

## VERDICT
Deploy ec9e9940 (publish ec9e994) is live and healthy and carries the RC2 EDR durable-ACK source. Build-identity markers (1), supervisor worker=1 (2), required indexes (3), pod stability (4) and absence of feature-attributable errors (5) all PASS. Two non-blocking flags: (a) `reconcile_contract_window` compound-key field order is reversed vs. your spec (name + partial filter correct); (b) git SHA f900ad7d is not independently verifiable from platform metadata — confirmed instead via build source content. No remediation performed (read-only).
