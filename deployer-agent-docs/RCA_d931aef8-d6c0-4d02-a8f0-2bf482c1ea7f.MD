# Production Verification — greeting-app-5782 (NivXForge XDR/EDR)

READ-ONLY. No republish, restart, config change, data change or load test performed.

- Deployment ID: `96834a37-643a-4d79-aa15-44810db52b06`
- Active deploy run (serving traffic): `d931aef8-d6c0-4d02-a8f0-2bf482c1ea7f` (type=redeploy, status=success, completed **2026-11-01T11:46:33Z**)
- Container/pod identity: `r-d931aef8-d6c0-4d02-a8f0-2bf482c1ea7f` on cluster `target-3`, namespace `customers-app`; 2 pods (`...-blgln`, `...-zwnzx`), both created **2026-11-01T11:44:07Z**
- Image tag: `greeting-app-5782:d931aef8-...`
- Default URL: `https://greeting-app-5782.emergent.host` | Custom domain attached: `nivxray.nivxforge.com` (verified, SSL active)
- Runtime-resolved DB name: `greeting-app-5782-test_database` (114 collections)
- Report generated at server time ~2026-11-02T09:21Z

## Evidence table

| # | Check | Observed result | Timestamp (UTC) | Verdict |
|---|-------|-----------------|-----------------|---------|
| 1 | Dedicated DB upgrade completed? | No deployer-visible record of a DB-upgrade operation. Deploy pipeline only shows code redeploys. Atlas/cluster upgrade events are not observable with deployer tooling. | — | UNVERIFIED |
| 2 | Publish/deploy ran alongside? | 4 redeploy runs on 2026-11-01 (06:55, 08:59, 09:43, 11:30→11:46), all status=success, same job_id 486146a0. Active = d931aef8. | 2026-11-01 | PASS (publishes completed) |
| 3 | Any build/pipeline errors? | Active run steps all success: wakeup, build (11:30:33→11:44:05), mongodb_migrate (11:44:06, 0s), manage_secrets (11:44:06), deploy (→11:46:32), health_check (11:46:32). No build errors. | 2026-11-01T11:46:33Z | PASS |
| 4 | Code changed vs DB-only? | All runs type=redeploy = full source rebuild → image per run (code path). mongodb_migrate took 0s (redeploys do not migrate data). So publishes rebuilt application code; no data migration performed by the pipeline. | 2026-11-01 | PASS (code redeploy; not DB-only) |
| 5 | Exact deployed commit SHA | NOT recoverable. `.git` is excluded from the deploy source archive and no commit SHA is recorded in accessible tooling. Cannot confirm/deny commit 18ccb5c (release/edr-production-2026-10-31). | — | UNVERIFIED |
| 6 | Live DB_NAME used by backend | `greeting-app-5782-test_database` (resolved server-side from the run's MONGO_URL secret = same value injected into the pod). | 2026-11-02T09:21Z | PASS |
| 7 | MONGO_URL host shape (sanitized) | Platform-managed REMOTE Mongo (reachable server-side via decrypted run secret). URI never printed. Whether it is the *upgraded dedicated* cluster vs pre-upgrade cluster = cannot see host. Definitively NOT localhost. | 2026-11-02T09:21Z | PARTIAL / host UNVERIFIED |
| 8 | Running process restarted after upgrade w/ fresh env? | Pods created 2026-11-01T11:44:07Z. Restarts since are IN-PLACE, liveness-driven (last_termination reason=Completed, exit 0; blgln restarts=2, zwnzx restarts=1). In-place container restarts do NOT re-resolve secrets. No new rollout since the 11:44 deploy. deployment_updated_at = 2026-11-01T11:46:33Z. | up to 2026-11-02T08:49Z | FAIL (no env-refreshing restart since 2026-11-01T11:44:07Z) |
| 9 | Live backend reaches the DB (runtime evidence) | `GET /api/edr/endpoints/ep_d3d5ab98601002899f01/trajectory 200 (elapsed 3092ms)` and `/trajectory/attack 200 OK` — pod serves real EDR data from these collections. Not a dashboard signal. | 2026-11-02T08:44Z | PASS |
| 10 | Collections present | users ✔, edr_endpoints ✔, v2_shadow_observations ✔, xdr_canonical_evidence ✔, edr_raw_events ✔, investigations ✔, workspace_cases ✔. **edr_connectors ABSENT** (not among the 114 collections). | 2026-11-02T09:21Z | MIXED |
| 11 | Doc counts (now) | users=1, edr_endpoints=3, investigations=8, workspace_cases=50. v2_shadow_observations / xdr_canonical_evidence / edr_raw_events: confirmed NON-EMPTY (find returned a doc) but exact count exceeded the read-query time limit. | 2026-11-02T09:21Z | PARTIAL (3 counts UNVERIFIED) |
| 12 | Indexes on EDR collections (names) | edr_endpoints: _id_, uniq_tenant_endpoint. xdr_canonical_evidence: _id_, tenant_id_1_ingest_time_-1, sd_canonical_endpointid_eventtime, sd_canonical_hostname_eventtime, sd_canonical_endpointid_observationus, sd_canonical_hostname_observationus. edr_raw_events: _id_, uniq_tenant_dedup, tenant_id_1_ingest_time_-1, tenant_id_1_endpoint_ref_1, tenant_id_1_derivations.parser_state_1, events_keyset, events_detection_time, events_payload_hash, reconcile_contract_window, tenant_raw_id_lookup. v2_shadow_observations: 14 indexes incl shadow_input_sha, shadow_adapter_ts, obs_* series. | 2026-11-02T09:21Z | PASS |
| 13 | Recent app-level DB errors (ServerSelection/Auth/not primary/pool) | NONE found in 6h window. No Mongo connection/auth errors. | 2026-11-01T15:46→2026-11-02T09:21Z | PASS |
| 14 | Other runtime errors | `504 server_timeout` on `/api/edr/endpoints/.../trajectory/hours` and `/trajectory/file-facts` (timeout_ms=30000) at 2026-11-02T08:44; nginx `upstream timed out ... GET /health ... 127.0.0.1:8001/health` at 08:49:38 and 07:14:58 → Liveness probe 503 (111 occurrences 2026-11-01T15:46:58→2026-11-02T08:49:38). TI feed: threatfox `401 Unauthorized`, urlhaus `410 Gone` (abuse.ch, external). | 2026-11-02 | FAIL (perf/stability) |
| 15 | EDR_MAINTENANCE_TOKEN present & non-empty? | EXISTS, is_empty=false (active run). Value not read. | 2026-11-02T09:21Z | PASS (exists, non-empty) |
| 16 | Upgraded-DB storage/tier/conn-limit/backup schedule | Not observable via deployer tooling (Atlas-level). K8s COMPUTE tier (not DB): tier_3 "Scale", cpu 1/limit 2, mem 4Gi/limit 8Gi, 2 replicas, 10Gi ephemeral. | 2026-11-02T09:21Z | UNVERIFIED (DB tier) |
| 17 | Pre-upgrade baseline / snapshot accessible? | None accessible. No baseline count or snapshot available to this tooling. | — | UNVERIFIED |
| 18 | Prod DB separate from preview (localhost:27017 test_database / 127.0.0.1:27019)? | Prod DB name = `greeting-app-5782-test_database` on a platform-managed remote cluster; reached server-side. NOT the preview localhost/127.0.0.1 instances; distinct database. Physical cluster host not printable but categorically not preview localhost. | 2026-11-02T09:21Z | PASS (DB-level) |

## Verdicts (explicit)
- **Upgrade completed:** UNVERIFIED — no deployer-visible record of the dedicated-DB upgrade; its completion timestamp/state must come from Platform/Atlas. Do not infer from dashboard success.
- **Production connected to upgraded database:** UNVERIFIED. The live backend IS connected to `greeting-app-5782-test_database` and serving real EDR data (PASS on reachability), but (a) whether that binding is the *upgraded dedicated* cluster cannot be confirmed (MONGO_URL host not inspectable), and (b) the running process has NOT had an env-refreshing restart since 2026-11-01T11:44:07Z — all restarts were in-place liveness-driven (exit 0), which do not re-resolve secrets. If the upgrade completed after that timestamp and no redeploy followed, the runtime still holds the pre-upgrade binding.
- **Migration integrity verified:** CANNOT BE PROVEN — no pre-upgrade baseline/snapshot is accessible, and the active run performed no data migration (mongodb_migrate 0s on a redeploy). Current counts captured for reference only.
- **Production and preview databases separate:** PASS at the database level — prod `greeting-app-5782-test_database` on a managed remote cluster is not the preview `test_database` on localhost:27017 nor 127.0.0.1:27019. Physical-cluster host identity UNVERIFIED (URI not inspectable) but not a preview instance.

## Notes / discrepancies
- User referenced production EDR domain `edr.nivxforge.com`; the ONLY custom domain attached to THIS deployment is `nivxray.nivxforge.com`. `edr.nivxforge.com` is not on this deployment.
- Recurring liveness 503 ↔ backend `/health` upstream timeout, co-timed with 30s 504s on EDR trajectory endpoints and the inability to `count` the 3 large collections — points to heavy/unbounded queries over large EDR collections, a performance/stability issue (not a DB binding or Mongo auth failure).
