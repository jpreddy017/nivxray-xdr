# PRODUCTION ACCEPTANCE — PUBLISH 100 / BUILD `a55ec13`

Target `https://nivxray.nivxforge.com` · run 2026-06 (UTC) · READ-ONLY.
Probe discipline honoured: **GET only**. Zero POST/PUT/PATCH/DELETE. No
anonymous mutation probe. No code, configuration, secret or tenant-data change.
No collector, connector, API key, endpoint or enrolment token created.
No Sysmon telemetry. **W1 REMAINS HELD.**

Authoritative org `org_55f6dc202dbf8995369db989ad` ·
authoritative tenant `ten_e759b7288598bd882e3dcac49d`.

---

## A · HEALTH — PASS
| gate | expected | actual |
|---|---|---|
| GET /api/ | 200 | **200** `{"service":"NivXRay","status":"ok"}` |
| GET /api/health | 200 | **200** `{"status":"ok","service":"nivxray-api"}` |
| GET /api/zzz-not-a-route-12345 | 404 | **404** |

## B · BUILD IDENTITY — THE TENANT-SAFE CANDIDATE LANDED — PASS
Production OpenAPI vs the OpenAPI generated in this pod from the frozen code
baseline `7645b2b1` (pod HEAD `f33aa487` = docs-only on top):

```
prod paths 795 · candidate paths 795
prod_only []            candidate_only []
path-object hash        IDENTICAL
schema name sets        EQUAL
schema bodies differing 0
```
⇒ deployed build is the accepted tenant-safe code. Independently corroborated
by the runtime host string observed in production (`r-a55ec136-…`).

## C · COLLECTOR TENANT-AUTHORITY DISCRIMINATOR (read-only) — PASS
`GET /api/xdr/collector/connectors`:
| tenant header | expected | actual |
|---|---|---|
| *absent* | 403 `TENANT_REQUIRED` | **403 `TENANT_REQUIRED`** |
| `ten_doesnotexist000000000000` (unknown) | 403 `TENANT_NOT_FOUND` | **403 `TENANT_NOT_FOUND`** |
| `default` | must be refused | **403 `TENANT_NOT_FOUND`** |
| `ten_e759b7288598bd882e3dcac49d` | 200 | **200** `{"connectors":[],"count":0,"phase":"B"}` |

**Old production returned 200 with no tenant. New build returns 403
TENANT_REQUIRED.** The implicit `"default"` mutation/read path is gone from the
collector connectors plane and `default` is not resolvable in the registry — no
`default` resurrection on the collector plane.

### Inactive-tenant variant — NOT TESTABLE READ-ONLY IN PRODUCTION
The production registry holds exactly one tenant and it is ACTIVE. Producing a
non-ACTIVE tenant in production would be a mutation, which this run forbids.
`TENANT_NOT_ACTIVE` is therefore evidenced on the identical code in-pod
(`services/tenant_registry.py:176`, asserted by
`tests/test_b4b5_tenant_registry_authority.py:145,339` and
`tests/test_edr_route_tenant_authority.py:215,225`):
**182 passed** (EDR route tenant authority + b4b5 registry authority) and
**105 passed** (collector app suite), 0 failed.

## D · ANONYMOUS FAIL-CLOSED ON THE AUTHENTICATED PLANES — PASS
| probe | actual |
|---|---|
| GET /api/xdr/tenants (no cred) | **403** `ACCESS_DENIED tenants.read / unauthenticated` |
| GET /api/xdr/tenants + authoritative tenant header | **403** (a valid tenant does NOT substitute for authentication) |
| GET /api/xdr/organizations | **403** `ACCESS_DENIED tenants.read` |
| GET /api/edr/endpoints (± tenant) | **403** `Not authenticated` |
| GET /api/edr/enrollment/endpoints | **403** `Not authenticated` |
| GET /api/edr/response/isolation-policy | **403** `Not authenticated` |
| GET /api/v2/security-state/streaming/status?tenant_id=`ten_e759…` | **403** `incidents.read / unauthenticated` |
| GET /api/v2/security-state/streaming/status?tenant_id=`default` | **403** |
| GET /api/auth/me | **403** `Not authenticated` |
| GET /api/xdr/collectors/sources/catalog | **403** `collectors.read` |
| GET /api/xdr/ingest/routing/summary | **403** `Not authenticated` |

## E · COLLECTOR AUTH P0 — CONFIRMED LIVE IN PRODUCTION (expected, still open)
Read-only GETs with **no credential and no tenant** returned **200** on
production:

| route | anonymous result | leak |
|---|---|---|
| GET /api/xdr/collector/source-types | **200** | product metadata (classified PRODUCT_METADATA — acceptable) |
| GET /api/xdr/collector/collectors | **200** | runtime inventory: collector id, version, python runtime, **internal host/pod name** |
| GET /api/xdr/collector/data-sources | **200** | configured data-source inventory |
| GET /api/xdr/collector/outbox | **200** | queued envelope inventory |
| GET /api/xdr/collector/outbox/health | **200** | ingest configuration state (url_set/token_set/auth_mode, delivery counters) |
| GET /api/xdr/collector/telemetry-health | **200** | transport/telemetry blind-spot map |

The tenant header is ignored on these routes (identical 200 for absent /
unknown / `default` / authoritative). This is exactly the approved
HUMAN_CONTROL classification gap: the tenant-safe republish moved the
connectors/preflight surface to *explicit authoritative tenant* but the plane
is still **unauthenticated**. Consistent with the owner's stated distinction:
production is now `unauthenticated + explicit authoritative tenant`, not yet
`authenticated → authorized → tenant-scoped → permitted`.

## F · OBJECT COUNTS (from anonymous read-only surface) — UNCHANGED
`connectors = 0` (authoritative tenant) · `data_sources = 0` ·
`outbox envelopes = 0` · outbox ingest `configured=false, token_set=false` ·
`telemetry transports = never_connected, instances 0`.
`_COLLECTED_PRODUCTS` untouched. No Windows telemetry transmitted or accepted.

## G · GATES REQUIRING THE OWNER TOKEN — NOT RUN BY THE AGENT
This workspace holds **no production credential** and none was taken from
`memory/test_credentials.md`, the pod, source or environment. The authenticated
half of A–I (registry authority + `enforcing=true`, tenant ACTIVE under the
authoritative org with XDR/EDR products, explicit-scope reads with
collectors/API-keys/endpoints/tokens still 0, security-state authoritative 200
vs `default` → `TENANT_NOT_FOUND`, Gate H scoped 200, Gate I principal-spoof →
0 attributed audit rows, console explicit-tenant contract) is supplied as an
owner-executed **GET-only** block in
`memory/W1_PHASE3_AI_OWNER_BLOCK_a55ec13.ps1`.
Gate G of the original sheet (collector-create against a nonexistent tenant) is
a POST and is therefore **excluded** under this run's read-only discipline; it
remains covered by the in-pod suites above.

## STATUS
```
PRODUCTION BUILD           publish 100 / a55ec13 / GREEN
BUILD IDENTITY             PASS (OpenAPI identical to frozen 7645b2b1 baseline)
COLLECTOR TENANT AUTHORITY PASS (TENANT_REQUIRED / TENANT_NOT_FOUND / 200 authoritative)
NO "default" RESURRECTION  PASS (default refused on collector, EDR, security-state)
ANON FAIL-CLOSED (auth'd planes) PASS
COLLECTOR AUTH P0          STILL OPEN — 6 routes answer 200 anonymously
AUTHENTICATED A-I SUBSET   PENDING OWNER TOKEN (GET-only block supplied)
MUTATIONS PERFORMED        NONE
W1                         HELD (no collector, no ingest key, no Sysmon)
```
STOP for owner review.
