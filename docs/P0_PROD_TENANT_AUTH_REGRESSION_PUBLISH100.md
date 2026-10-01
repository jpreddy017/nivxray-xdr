# P0 PRODUCTION REGRESSION — EDR TENANT AUTHORIZATION AFTER PUBLISH 100

2026-09-29. Read-only. No repair applied. No replay. No republish. No rollback.
No endpoint/sensor/Sysmon/outbox change. Tenant authorization NOT weakened.

`B5_EID5_END_TO_END = HOLD_PRODUCTION_AUTH_REGRESSION`

## FINAL OUTPUT

```
CURRENT_PROD_PUBLISH          = Publish 100 (0aba534) — pending deployer confirmation
CURRENT_SOURCE_COMMIT         = 9ba45bce9dc9599568266e43ee39dcde350bedac (expected)

TENANT_EXISTS                 = NOT_PROVEN (production read pending)
ENDPOINT_EXISTS               = NOT_PROVEN (production read pending)
RAW_EVENTS_EXIST              = NOT_PROVEN (production read pending)
CANONICAL_EVIDENCE_EXISTS     = NOT_PROVEN (production read pending)
LATEST_TELEMETRY              = NOT_PROVEN (production read pending)
  ↑ last authoritative prod measurement, 2026-09-29 pre-Publish-100:
    endpoint ep_1989031c8c1d0085812f EXISTS · 116,012 edr_raw_events ·
    last_telemetry_at 2026-09-29T15:28:33Z · tenant ten_e759b7288598bd882e3dcac49d

PRINCIPAL                     = admin@nivxray.com
ROLE                          = admin (production value pending confirmation)
INTERNAL_VALIDATION_GRANTED   = NO (demonstrated by the refusal itself; the
                                production users document is pending read)

STORE_CONTINUITY              = NOT_PROVEN (production read pending)

SERVER_SIDE_REPRODUCTION      = PENDING (production log read dispatched)

ROOT_CAUSE                    = PUBLISH 100 CONTAINS COMMIT 730ec4f5 (P0-FIX-6B-2,
                                2026-09-28T07:31) WHICH RETIRED ROLE-DERIVED TENANT
                                BREADTH. THE PRODUCTION `users` DOCUMENT FOR
                                admin@nivxray.com WAS NEVER GIVEN THE EXPLICIT
                                REPLACEMENT AUTHORITY (`authority_scope = "PLATFORM"`),
                                BECAUSE THE DESIGNATION SCRIPT ONLY EVER RAN AGAINST A
                                NON-PRODUCTION STORE. THE NEW BUILD THEREFORE FAILS
                                CLOSED — CORRECTLY.
                                (source-level: PROVEN · production data: confirmation pending)

DATA_LOSS                     = NO (for the console symptom). The refusal is raised
                                BEFORE any evidence query runs, so it cannot indicate
                                missing data. Final confirmation pending the prod read.

SENSOR_RECEIVE                = NOT_PROVEN on the current publish (dispatched).
                                ACTIVE as of 2026-09-29T15:33:23Z on Publish 99.

REPAIR_CLASS                  = GRANT_RESTORE
                                (restore the explicit PLATFORM designation / grant in the
                                PRODUCTION auth store — data + bootstrap continuity.
                                NOT a code fix, NOT a rollback, NOT a broadening.)

TENANT_ISOLATION_INVARIANT    = PRESERVED (the boundary is working; it is the grant
                                that is missing)

B5_EID5_END_TO_END            = HOLD_PRODUCTION_AUTH_REGRESSION
```

## ROOT CAUSE — DEMONSTRATED IN SOURCE

Publish 99 (built from `fdb9c05a`, 2026-09-27T09:37) —
`backend/services/dashboard_lenses.py :: resolve_tenant_scope`:

```python
_CROSS_TENANT_ROLES = frozenset({"admin", "platform_admin",
                                 "soc_manager", "mssp_operator"})
...
if role in _CROSS_TENANT_ROLES:
    return {"authorized": True, "all_tenants": True, "role": role}
```

`admin@nivxray.com` carries `role: "admin"`, so **role alone produced
`all_tenants: True`**. Every tenant — including `ten_e759b7288598bd882e3dcac49d` —
was authorized implicitly. That is why the console worked.

Publish 100 contains commit **`730ec4f5`** (2026-09-28T07:31, *"FIX 6B-2 COMPLETE —
role-based tenant breadth retired; grants + explicit PLATFORM scope enforced"*). The
same function is now:

```python
# P0-FIX-6B-2 · these role names are NO LONGER AUTHORITY. They once made
# `all_tenants: True` by themselves, which meant a free-text role string on a
# user document granted every customer tenant.
_LEGACY_ROLE_BREADTH_RETIRED = frozenset({...})   # read by no decision

def authority_scope(user):
    raw = (user or {}).get("authority_scope")
    if isinstance(raw, str) and raw.strip() == "PLATFORM":
        return "PLATFORM"
    return "CUSTOMER"        # least-authority default
...
return {"authorized": True, "authority_scope": scope,
        "all_tenants": scope == "PLATFORM",
        "tenant_ids": tenants, "role": role}
```

and `services/session_context.py :: authorize_requested_tenant` then refuses with the
exact string the console is displaying:

```python
if requested:
    if all_tenants or requested in authorized:
        return requested, "EXPLICIT_REQUEST_TENANT"
    raise ScopeDenied("TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL",
                      "principal is not authorized for the requested "
                      "tenant; naming a tenant never authorizes one",
                      "NOT_AUTHORIZED", requested)
```

**The replacement authority was never applied to production.** The designation is
performed by `scripts/fix6b1b_platform_designation.py`, whose own header states:

> *"Owner-approved 2026-06. Exactly ONE field on exactly ONE principal:
> `users.authority_scope = "PLATFORM"` for `admin@nivxray.com`."*

and whose third line of code is:

```python
load_dotenv("/app/backend/.env")
db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
```

— i.e. it binds to whatever store `backend/.env` points at. In this workspace that is
the container-local preview mongod, **never** the production Atlas store. Verified in
the preview store just now (reference only, NOT production evidence):

```
admin@nivxray.com → role "admin", tenant_ids ["default", "nivx-live"],
                    authority_scope "PLATFORM"
authority_scope holders in preview: exactly 1 (admin@nivxray.com)
```

Two things follow, and they are the whole regression:

1. Production almost certainly has **no** `authority_scope` on that principal (the
   designation never ran there) → class CUSTOMER → breadth gone.
2. `ten_e759b7288598bd882e3dcac49d` is **not** in the grant list either — even in
   preview the grants are `["default", "nivx-live"]`. Access to Internal Validation was
   working *purely* through the retired role-derived breadth.

So: **role-derived breadth carried production, the explicit designation replaced it in
code, and the production data was never migrated.** Fail-closed did the rest.

This is a *good* security outcome expressed as an outage: the new build refuses rather
than silently honouring a free-text role string. Nothing was deleted, nothing moved
tenants, and the sensor path is a different code path entirely.

## CODE CHANGED IN THE AUTHORIZATION PLANE BETWEEN PUBLISH 99 AND 100

```
backend/routers/edr_tenancy.py      | 179 +++++++++++++++++++---
backend/server.py                   |  19 ++++
backend/services/session_context.py | 119 +++++++++++++---
backend/services/tenant_registry.py | 142 +++++++++++++-------
```

P0-FIX-1 (authorization before registry on every EDR route), P0-FIX-2 (non-disclosing
refusal), P0-FIX-5A (unconditional registry validation) and P0-FIX-6B-2 (role breadth
retired) all landed AFTER the Publish 99 build. 6B-2 is the one that changes the
*outcome* for this principal; the others change ordering and disclosure.

Classification against the owner's list: **(B) lost a required production
environment/config binding** — more precisely, a required production DATA designation
that the new code depends on. Not (A) different store, not (C) changed principal
identity, not (F) code regression. (A) and (C) remain formally NOT_PROVEN until the
production read returns.

## WHY THIS IS NOT DATA LOSS

`edr_tenant()` raises the 403 in the FastAPI dependency, before any handler body runs.
No `edr_raw_events` / `edr_endpoints` / evidence query is ever issued on a refused
request. The Events screen even renders both messages at once — the refusal banner AND
the generic "no events in this window" copy — which is a presentation artifact of the
refusal, not two independent findings. Last authoritative production measurement
(Publish 99, 2026-09-29T15:28-15:33Z): endpoint present, 116,012 raw events,
telemetry arriving 200 OK every 1-3 s.

## MINIMUM CORRECT REPAIR — PROPOSED, NOT IMPLEMENTED

`REPAIR_CLASS = GRANT_RESTORE`

Intended end state, unchanged from the owner-approved design:

```
admin@nivxray.com = the explicit PLATFORM Super Admin
  → may name any tenant, which the authoritative registry then validates
every other principal = CUSTOMER, limited to its explicit tenant_ids[]
```

The repair is to make the PRODUCTION auth store carry the explicit designation that the
new code requires — one field, one principal, idempotent:
`users.authority_scope = "PLATFORM"` for `admin@nivxray.com`.

Three candidate mechanisms, for the owner to choose (none executed):

1. **Idempotent bootstrap designation from an explicit server-side env var** — e.g.
   `NIVX_PLATFORM_PRINCIPAL=admin@nivxray.com` read at startup, writing
   `authority_scope = "PLATFORM"` for exactly that one principal if absent, logging the
   write. Authority stays explicit and server-side, never client-supplied. Requires a
   small code addition + one production secret + a deploy.
2. **Run the existing `scripts/fix6b1b_platform_designation.py` against production** —
   zero new code, already owner-approved and idempotent, refuses unless the expected
   grants are intact. Requires production Mongo access, which I do not have; note its
   `EXPECTED_GRANTS = ["default", "nivx-live"]` guard would need to match the real
   production grants or it will refuse (by design).
3. **Grant the tenant explicitly instead of PLATFORM** — add
   `ten_e759b7288598bd882e3dcac49d` to that principal's `tenant_ids[]`. Narrowest
   possible authority, but it makes the Super Admin a two-tenant CUSTOMER principal and
   will need repeating for every future customer.

I did **not** consider, and will not implement: arbitrary tenant IDs, default-tenant
fallback, trusting a frontend-supplied tenant, bypassing the registry, granting all
tenants to all authenticated users, weakening Customer Admin isolation, disabling the
refusal code, changing fail-closed behaviour, hardcoding the tenant in the frontend, or
touching telemetry.

**Rollback is NOT recommended and was NOT performed.** Publish 100 carries the EID5
foundation and the four P0 tenant-authority fixes; rolling back would reinstate
role-string breadth — the very defect 6B-2 closed.

## PRODUCTION CONFIRMATION — DISPATCHED, NOT YET RETURNED

A read-only deployer diagnose was dispatched (mutation and rollback explicitly
forbidden) requesting: current publish/commit; tenant `ten_e759b7288598bd882e3dcac49d`
existence/state/name; endpoint `ep_1989031c8c1d0085812f`; raw-event and canonical
counts + newest timestamps; the production `users` document for `admin@nivxray.com`
(`role`, `tenant_id`, `tenant_ids`, `authority_scope`, `status` only — never the hash);
how many production principals hold a non-null `authority_scope`; P99↔P100 evidence and
auth store continuity plus whether the `MONGO_URL`/`DB_NAME` secret values changed
(without printing them); the 403 log/audit rows for the EDR read routes and any
`[edr.tenant_authority] refusal normalised` lines; and — separately — whether
`/api/edr/agent/telemetry` from DESKTOP-A9HGFJJ is still 200 on the current publish.

It runs asynchronously and has not reported yet. No production value is assumed above;
every unconfirmed item is marked NOT_PROVEN.

STOP FOR OWNER REVIEW. REPAIR NOT APPLIED.
