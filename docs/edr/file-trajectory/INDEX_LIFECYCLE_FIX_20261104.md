# EDR file-index correction and release handoff — 2026-11-04

## Corrected
Source commit: 4018f0fbf88f04d140f3362cdc862066db69040e.

The index worker now validates up to 500 existing index records per tenant per turn, under its existing lease. Missing source evidence, unresolved ownership and superseded paths withdraw search tokens. Original derived record fields and previous tokens are retained; no source telemetry is deleted or modified. Restored evidence is reprojected. Tenant checkpoints are included in follow mode even when the endpoint directory no longer lists that tenant.

Database read failures do not cause invalidation. The validation cursor advances only after the page succeeds, so restart replays unfinished work. Validation uses a tenant/_id index. This is eventual reconciliation, not an instantaneous guarantee after source changes. Completion time depends on index size and processing throughput. Retained invalid records are not purged by this change.

## Verified
- 60 regression tests passed on de26ad94, covering index/identity, file-facts and trajectory presentation. Four new tests cover source removal/restoration, path/identity changes, bounded resume/lease/tenant isolation, and read failure.
- 5 real MongoDB tests passed on 4018f0fb, including source removal/restoration and indexed validation scans. Fixtures use unique disposable edr_file_index_test_* databases.
- Existing application /app edits were not reset or published.

## Coordinated deployment configuration
deploy/edr-supervisor.conf is an unapplied deployment template. Both API and file index worker use NIVX_RELEASE_ROOT and NIVX_RELEASE_PYTHON; they inherit the same MONGO_URL/DB_NAME and existing authentication settings from the target environment. The API starts the existing in-process processing worker pool with count 2. The file index worker runs continuously with restart supervision and bounded logs.

Before installation:
1. Confirm the production backend project and its deployment controls. The code-server pod is a preview environment, not proof of production ownership.
2. Preserve the current production release/configuration and database recovery point.
3. Stage an immutable checkout/archive of the accepted commit with all runtime dependencies (including existing sibling collector/response packages required by server.py). Do not publish the dirty /app tree.
4. Use target-owned existing secrets; do not copy preview .env into production. Set NIVX_RELEASE_ROOT, NIVX_RELEASE_PYTHON, NIVX_RELEASE_PORT and NIVX_RELEASE_LOG_DIR to verified target paths. Validate the supervisor template with that environment.
5. Start the candidate API/index worker against the candidate database first. Verify worker restart, lease recovery, newly ingested evidence reaching search, customer authorization and exact-event trajectory links.
6. Release the backend and workers together, then build EDR frontend with the normal production API origin. NIVX_EDR_INTEGRATION_PREVIEW must be disabled; never promote the temporary candidate-api preview artifact.
7. Verify the production domain and API revision, index freshness and validated_at, new-event search, and rollback readiness before declaring release complete.

## Remaining external deployment gate
This change fixes stale-index behavior in code. It does not establish production backend provisioning. The verified candidate services run in preview; production backend/worker installation and authenticated production smoke checks are still pending. No production promotion was performed.
