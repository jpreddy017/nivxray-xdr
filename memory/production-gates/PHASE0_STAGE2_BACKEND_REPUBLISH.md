# PHASE 0 PRODUCTION PROMOTION — STAGE 2 · PRE-PUBLISH SAFETY GATE

Mode: **READ-ONLY**. The republish itself was **not performed** — see §3.
No secret was read, displayed or changed. `EDR_AUTH_PEPPER` never accessed.

RESULT: **STAGE 2: BLOCKED — safety gate PASS, publish is an owner-only click.**

## 1 · Safety gate (all re-verified now, not quoted from Stage 1)

| Gate | Result | Evidence |
|---|---|---|
| SOURCE COMMIT | `8f370c7d` | live GitHub API read of `feature/rc2-alignment` |
| PHASE0 ANCESTOR | `bea8852b` → **YES** | `GET /compare/bea8852b...8f370c7d` → `status: ahead, ahead_by: 3, behind_by: 0` |
| Delta after Phase 0 | **3 non-code files only**: `.emergent/emergent.yml`, `memory/PRD.md`, `memory/production-gates/PHASE0_PROMOTION_PRECHECK.md` | same compare call |
| Phase 0 code == preview-proven | **YES** | all 10 Phase 0 files SHA-256-identical local↔remote (Stage 1), and nothing has touched them since |
| DB MIGRATION REQUIRED | **NO** | additive CES projection only |
| NEW COLLECTION REQUIRED | **NO** | writes to existing `edr_raw_events.derivations`, `v2_shadow_observations`, `edr_finding_evaluations` |
| NEW INDEX REQUIRED | **NO** | new aggregation matches `connector_id`, served by existing `obs_connector_ts` |
| BACKFILL REQUIRED | **NO** | no historical rewrite |
| SECRET CHANGE REQUIRED | **NO** | zero `environ`/`getenv` additions in the Phase 0 diff |
| ENV CHANGE REQUIRED | **NO** | same |
| RESPONSE AUTHORITY | **FAIL-CLOSED, UNCHANGED** | `edr_plane/response.py` not in the Phase 0 change set; `test_p0a_response_authority.py` passes |
| Phase 0 module loads | **PASS** | `from edr_plane import windows_eventlog` → OK; declared families `{(sysmon,1),(sysmon,3),(sysmon,11),(sysmon,12),(sysmon,13),(sysmon,22),(winsec,4624),(winsec,4688)}` — exactly the eight authorised |
| Preview backend running this code | **PASS** | supervisor `backend RUNNING`, `/api/health` → `{"status":"ok","service":"nivxray-api"}` |

No assumption has changed. The gate **passes**.

## 2 · Production baseline captured BEFORE the publish (for the after/before diff)

```
GET https://nivxray.nivxforge.com/api/health      → {"status":"ok","service":"nivxray-api"}
GET https://nivxray.nivxforge.com/api/openapi.json → 862 paths, sha256 8c04168feebf43f0
Current publish                                   → Publish 100 / build 4e76891 (pre-Phase 0)
```

## 3 · Why the publish did not happen here

Confirmed with the platform: **deployment/republish is strictly an owner action in the
Emergent UI; the agent has no access to the production deployment pod and cannot trigger it
programmatically.** Two further platform facts the owner must know before clicking:

1. **The republish cannot be scoped to backend-only.** Emergent rebuilds and redeploys the
   whole application. This is acceptable here: Phase 0 touched **no file under
   `/app/frontend`**, so the co-deployed Emergent frontend is a byte-level no-op. The two
   Vercel consoles (`edr.nivxforge.com`, `xdr.nivxforge.com`) are separate projects and are
   **not** affected by this republish — console promotion stays Stage 3.
2. **Existing production secrets and env vars are preserved** — carried forward
   automatically; platform-managed keys (`MONGO_URL`, `DB_NAME`, `CORS_ORIGINS`,
   `REACT_APP_BACKEND_URL`) are re-derived to the same values. Nothing to re-enter. No
   secret needs to be read, and none will be.

### Owner click path (one action)
`Republish` in the top toolbar → **Manage Publishes** → keep the current tier → **Deploy /
Re-publish changes** → wait for **Live** (green). Before clicking, note the current entry
(Publish 100 / build `4e76891`) so rollback is unambiguous.

### Rollback (pre-agreed, no DB rollback needed)
**Manage Publishes → Overview → Deployments → rollback icon (↺) next to Publish 100 /
`4e76891` → confirm.** Reverts the container image only; 2–3 minutes, zero downtime, URL and
database untouched. Correct precisely because Phase 0 needs no migration.

## 4 · Post-publish verification I will run the moment you confirm (all read-only)

1. `/api/health` status.
2. Route parity: expected **862**, report actual / missing / added — with the standing caveat
   that Phase 0 adds no routes, so parity alone proves nothing.
3. Deployment identity: strongest available evidence that the new build carries `8f370c7d`
   (hence `bea8852b`).
4. Phase 0 implementation presence for all eight families + `DETECTION_NOT_EVALUATED`,
   `investigability`, `RAW_ONLY_NOT_INVESTIGABLE`, ProcessGuid authority, and the
   `PID_ONLY_NOT_AUTHORITATIVE` fallback — **without creating any production telemetry**.
5. Security boundaries: auth, tenant authority, RBAC, endpoint auth, audit, and response
   authority still **FAIL-CLOSED**.
6. Counters: migrations 0, backfills 0, orgs 0, tenants 0, tokens 0, endpoints 0,
   response actions 0.

### Honest limit, stated in advance
Without an authorised production write there is **no unauthenticated production surface that
reveals Python-level implementation**, because Phase 0 adds no route and the freshness route
has no typed response model. So item 4 will be answered as
`PRESENT_IN_PUBLISHED_SOURCE (build identity + source equivalence)` rather than
`PROVEN_BY_LIVE_CANONICALISATION`. The live canonicalisation proof necessarily arrives with
the first authorised Windows endpoint — which is exactly the order you have chosen.

## 5 · Counters for this stage

```
PRODUCTION REPUBLISH PERFORMED BY AGENT: NO (owner-only action)
PRODUCTION DB WRITES: 0   MIGRATIONS: 0   BACKFILLS: 0
ORGANIZATIONS: 0   TENANTS: 0   TOKENS: 0   ENDPOINTS: 0   RESPONSE ACTIONS: 0
SECRETS READ: 0   SECRETS CHANGED: 0   ENV CHANGED: 0
VERCEL DEPLOYMENTS: 0   VERCEL RETRIES: 0   ROOT GUARD TOUCHED: NO
STALE ORACLE TEST: UNCHANGED (TEST_ONLY_HARNESS_DEBT)
CODE CHANGED: 0
```
