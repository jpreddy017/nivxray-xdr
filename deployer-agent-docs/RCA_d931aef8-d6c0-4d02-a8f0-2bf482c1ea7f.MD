# READ-ONLY Identity / Configuration Trace — nivxray.nivxforge.com / greeting-app-5782

No pipeline run, redeploy, restart, secret/domain/DNS change was performed. Production untouched.
Scope note: this agent is bound to exactly ONE Emergent deployment (96834a37 / greeting-app-5782). It has NO access to Vercel, and no tool to enumerate other apps in the account. All Vercel-side and account-wide items are UNVERIFIED by tooling, not disproven.

## Evidence table
| Check | Observed | Source | Verdict |
|---|---|---|---|
| Custom domain bound to this deployment | nivxray.nivxforge.com (ONLY one), verified=true, provider=cloudflare, ssl_status=active, ssl http validation | list_domains | PASS |
| Deployment identity | deployment 96834a37-643a-4d79-aa15-44810db52b06, slug greeting-app-5782, active_run d931aef8, template fastapi_react_mongo_shadcn_base_image, frontend_type=cloudflare, tier_3, target-3 | describe_deployment_state | PASS |
| Backend /api/health on live prod URL | 200, body {"status":"ok","service":"nivxray-api"} | preview_health_check (greeting-app-5782.emergent.host/api/health) | PASS |
| Runtime DB_NAME | greeting-app-5782-test_database (returned on every mongo_query) | mongo_query | PASS |
| Cluster identifier (MONGO_URL host) | system secret, value never returned — cannot print | list_secrets (MONGO_URL present, is_empty=false) | UNVERIFIED (not readable) |
| Collection count | 114 collections, mixed edr_* AND xdr_* in one DB | mongo_query list_collections | PASS |
| users | present, count=1 | mongo_query count | PASS |
| edr_endpoints | present, count=3 | mongo_query count | PASS |
| edr_connectors | ABSENT (collection_not_found) | mongo_query count | FAIL (does not exist) |
| v2_shadow_observations | present, non-empty (>=1 doc) | mongo_query find limit1 | PASS (exact count UNVERIFIED — count timed out) |
| xdr_canonical_evidence | present, non-empty (>=1 doc) | mongo_query find limit1 | PASS (exact count UNVERIFIED — count timed out) |
| edr_raw_events | present, non-empty (>=1 doc) | mongo_query find limit1 | PASS (exact count UNVERIFIED — count timed out) |
| investigations | present, count=8 | mongo_query count | PASS |
| workspace_cases | present, count=51 | mongo_query count | PASS |
| tenants | present, count=1 | mongo_query count | PASS |
| Other EDR-only backend in account | no tool to enumerate; only this deployment visible | — | UNVERIFIED |
| edr/xdr Vercel frontend revision / SHA | no Vercel access; .git excluded from Emergent deploy archive | — | UNVERIFIED |
| Vercel project name(s) / edr==xdr same project | no Vercel access | — | UNVERIFIED |
| Vercel env var names (VITE_E3_DT_V3, api-origin) | no Vercel access | — | UNVERIFIED |
| Vercel current/previous deployment id (dpl_...) | no Vercel access | — | UNVERIFIED |
| Backend current/previous run | current d931aef8 (success 2026-11-01T11:46:33Z); prev d892870d (success 2026-11-01T10:01:08Z) | describe_deployment_state recent_runs | PASS |
| Backend commit SHA 35d47cc… | .git excluded from deploy archive — not recoverable | — | UNVERIFIED |
| Later run 80b11cca (mongo_migration) | FAILED 2026-11-02 — mongosync did not catch up within 2h; NOT a code deploy, active run unchanged | describe_deployment_state | NOTE |

## Answers

**1) Same deployment as greeting-app-5782?** YES — authoritative. nivxray.nivxforge.com is bound as a Cloudflare custom hostname (cf_custom_hostname_id ca8c1d1d-4be3-4bea-ad47-885aaebfa4bb) directly on Emergent deployment greeting-app-5782 (96834a37), active run d931aef8. It is NOT an independent backend. The ONLY custom domain on this deployment is nivxray.nivxforge.com. The byte-identical /api/health and identical route codes you saw are consistent with this and now confirmed by the domain binding itself.

**2) Database used by the domain-served backend?** DB_NAME = greeting-app-5782-test_database — the SAME database you previously observed. Confirmed on every mongo_query. Cluster: platform-managed remote cluster reached via system secret MONGO_URL, whose value is encrypted and never returned — cluster host sanitizes to "cluster-xxxx", UNVERIFIED (not readable by tooling).

**3) Independent EDR-only backend?** From what is observable: only ONE backend deployment is visible to this agent, and it serves BOTH products — the single DB holds edr_* collections (edr_endpoints, edr_raw_events, edr_findings, edr_policies, …) AND xdr_* collections (xdr_canonical_evidence, xdr_investigations, …). No tool can enumerate other apps in the account, so the existence of a separate EDR-only backend is UNVERIFIED. If none exists, the EDR frontend cannot be redirected to an independent EDR backend — it depends on this shared backend. Report the dependency; do not assume a separate backend exists.

**4) Required services/data on that backend?** 114 collections total. Requested set: users=1, edr_endpoints=3, v2_shadow_observations present/non-empty, xdr_canonical_evidence present/non-empty, edr_raw_events present/non-empty, investigations=8, workspace_cases=51, tenants=1 — all PRESENT and non-empty. EXCEPTION: edr_connectors is ABSENT (collection does not exist). Exact counts for v2_shadow_observations / xdr_canonical_evidence / edr_raw_events are UNVERIFIED (count scans timed out; presence confirmed via find limit 1).

**5) Frontend revision (edr/xdr)?** UNVERIFIED — no Vercel access. Also the deployed git SHA is not recoverable because .git is excluded from the Emergent deploy archive, and these frontends are not hosted on this Emergent deployment at all. Vercel project name(s) and whether edr/xdr share a project: UNVERIFIED.

**6) Vercel project env vars?** UNVERIFIED — no Vercel access; cannot confirm presence of VITE_E3_DT_V3 or an api-origin variable, nor whether api_origin is a Vercel env var vs baked into the build. (For context only: the EMERGENT backend deployment holds secrets named VERCEL_TOKEN and VERCEL_AUTOMATION_BYPASS_SECRET — names only, values never read. These are on the backend, not the Vercel project.)

**7) Rollback references.** Backend (Emergent): current production run d931aef8 (redeploy, success, 2026-11-01T11:46:33Z); immediately previous d892870d (redeploy, success, 2026-11-01T10:01:08Z). Backend commit 35d47cc96352f492bd4c603a2f2f1b65afb4119f: UNVERIFIED (git excluded). Vercel current/previous deployment ids (incl. dpl_GnXW5Y5qwss3858hd1jJdrabxXME): UNVERIFIED — no Vercel access. NOTE: a later run 80b11cca (type mongo_migration) FAILED on 2026-11-02 (mongosync did not catch up within 2h) — it is not a code deploy and did not change the active serving run (still d931aef8).

No change recommended or performed.