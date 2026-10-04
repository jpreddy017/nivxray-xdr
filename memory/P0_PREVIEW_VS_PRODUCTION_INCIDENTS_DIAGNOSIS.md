# P0 DIAGNOSIS — Preview 351 incidents vs Production 0 (2026-06)

**DIAGNOSIS ONLY.** Nothing seeded, copied, fabricated, deleted or modified.
No auth, frontend, DNS, EDR, NivXMachines or Workspace change. Nothing deployed.
The frontend was not touched — the owner's Network capture already ruled it out.

## Root cause

**Preview and production read two physically different databases, and the 351
incidents exist only in the pod-local Mongo.**

| | Preview | Production |
|---|---|---|
| Mongo target | `mongodb://localhost:27017` (pod-local) | its own Emergent-managed Mongo, provisioned at first deploy |
| `DB_NAME` | `test_database` | managed by the deployment |
| `workspace_cases` | **637** documents | never seeded (locked policy) |
| `doc_type == "xdr_incident"` | **351** | 0 returned |
| Telemetry source | this container's own sensor + test/proof runs | none — no collector enrolled yet |

There is **no defect** in the backend deployment/version, the Mongo/collection
target, the tenant scope, the environment configuration, or the incident
query/projection. Both environments now run the **same** code (`e9978291`),
and the same handler returns 351 against one datastore and 0 against the other
because the datastores genuinely differ. Production returning
`incidents: [], count: 0` is the truthful answer for a console that has never
ingested telemetry.

## What the 351 preview "incidents" actually are — this matters

```
workspace_cases total        637
doc_type == xdr_incident     351

by tenant_id      default 284 · p0f-* throwaway proof tenants 67 (p0f-collector-auth-proof 11,
                  p0f-vt 2, 54 × one-off p0f-<hex>) · p0f-restart-retry-proof 1 · nivx-live 1
by detection_source  None 351
by name           344 × None · "R38.2 SSOT" · "R35 EDR incident" ·
                  "R37 report fixture" · "R33 EDR fixture incident"
```

The subject host in the owner's own screenshot is
`agent-env-630704a1-621f-478b-9b86-a321772d01bf` — **the Emergent development
container itself**. So the preview dataset is development/test/proof-run
artifacts plus telemetry about the dev pod. The owner's instinct not to copy it
was exactly right.

**Do NOT import preview incidents into production.** It would place named test
fixtures, 67 throwaway proof tenants and dev-infrastructure telemetry into a
production SOC console, and it would breach the locked production data policy.

## One datum I do not have — the decisive check, 10 seconds in the tab already open

`list_incidents` uses `user=Depends(get_current_user_optional)`
(`backend/routers/incidents.py:837`), so it answers **anonymous** callers with
**HTTP 200** and an honest empty state rather than a 401. Verified live,
unauthenticated, against both hosts — byte-identical shape:

```
GET /api/incidents?limit=500&sort=updated_at&order=desc     (no Authorization)
prod → {"incidents":[],"count":0,"lens":null,"applied_filters":{},
        "scope":{"authorized":false},"invariant":"queue == projection · never engine"}
prev → identical
```

So `count: 0` alone cannot distinguish two different causes. **Look at `scope`
in the production Response body:**

| `scope` value | Meaning | Fix |
|---|---|---|
| `{"authorized": false}` | the request was **anonymous** — the bearer token was not attached | auth/session, **not** data. Re-login; check `nvx_token` in `localStorage` for `xdr.nivxforge.com` |
| `{"authorized": true, …}` + populated `applied_filters` | authenticated correctly; the production DB genuinely holds **0** incident documents | **no fix — this is correct.** Complete collector enrolment |

Evidence favouring the second row: the production shell and MSS Dashboard
rendered authenticated content with `admin@nivxray.com` in the header. Had the
token been missing or expired, the 401 interceptor in
`apps/nivxray-xdr/src/lib/api.js:36-41` would have cleared it and bounced to
`/login`. I am ~95% confident the answer is "authenticated, genuinely zero",
but I will not assert it without the field.

## Smallest proposed fix

**No code change. No data change.**

1. Owner reads `scope` from the production response (above).
2. If `authorized: true` → nothing to fix. The zero state is correct and the
   real remedy is the work already in flight: finish the `nivx-prod-1`
   collector enrolment so genuine auditd telemetry produces genuine incidents
   when VEEE actually crosses `INCIDENT_MIN_SCORE`.
3. If `authorized: false` → a session/token fix only; still no data change.

Rejected outright: copying, seeding or migrating the preview dataset.

## Awaiting owner approval before applying anything

---

## CONFIRMED by owner's request-header capture (2026-06) — ROOT CAUSE CLOSED

The missing datum arrived. The production request carries:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…
Origin:        https://xdr.nivxforge.com
Sec-Fetch-Mode: cors
```
with `admin@nivxray.com` and `ALL CUSTOMERS` in the shell header.

So the request **is authenticated**. `resolve_tenant_scope()` therefore returns
`authorized: true`, and the anonymous branch
(`scope: {"authorized": false}`) is **ELIMINATED**.

### FINAL ROOT CAUSE
`GET /api/incidents` on production is authenticated, correctly scoped, and
returns `count: 0` because **the production database genuinely contains zero
incident documents**. The 351 in preview live only in the pod-local Mongo
(`mongodb://localhost:27017` · `test_database`), which production has never
been connected to and — by locked policy — has never been copied into.

Confirmed NOT the cause: backend deployment/version (both now run `e9978291`),
Mongo/collection target (`workspace_cases` in both), tenant scope
(`ALL CUSTOMERS` / authorized), environment configuration, incident
query/projection, frontend, CORS, connectivity, auth.

### SMALLEST FIX: none. There is no defect to fix.
Production is displaying the truth — "NO INCIDENTS MATCH THIS FILTER — honest
empty state" is the intended behaviour for a console with no ingested
telemetry. The remedy is the work already in flight: finish the `nivx-prod-1`
collector enrolment so real auditd telemetry produces real incidents when VEEE
crosses `INCIDENT_MIN_SCORE`.

**Still rejected:** copying/seeding/migrating the preview dataset. 67 of the
351 belong to `p0f-*` throwaway proof tenants, 4 are named test fixtures
("R33/R35/R37/R38.2"), 344 have no `name`, and their subject host is
`agent-env-630704a1-621f-478b-9b86-a321772d01bf` — the Emergent dev container.

### Two unrelated observations, logged not acted on
1. The production Incidents queue defaults to a **`Last 7 days`** window. Moot
   at `count: 0`, but once telemetry flows, incidents older than 7 days will be
   hidden by default.
2. Production's Incidents sub-nav lacks the **Detections** entry that preview
   has — expected, because the production XDR SPA is the `21:16:47Z` build that
   predates it. It will appear when the frontend is next published.

NOTHING APPLIED. NOTHING DEPLOYED. Awaiting owner instruction.
