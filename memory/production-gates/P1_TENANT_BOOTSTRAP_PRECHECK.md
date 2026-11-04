# P1 · PRODUCTION TENANT BOOTSTRAP PRECHECK — READ-ONLY

Date: 2026-06 · Mode: strictly read-only · Production DB writes: **0**

Source of truth: current working tree (`git HEAD 92ea4f31`, the
reconciliation commit on top of `f7a2518`) **and** the live production
OpenAPI at `https://nivxray.nivxforge.com/api/openapi.json` (862 paths).
Every contract below was confirmed against the **deployed** schema, not
documentation.

---

## VERDICT

```
P1 PRODUCTION TENANT BOOTSTRAP PRECHECK: BLOCKED
```

Not blocked by a defect. Blocked by a **contract fact** that contradicts
the owner decision as written:

1. **`tenant_id` cannot be chosen.** The deployed `POST /api/xdr/tenants`
   body (`CreateTenantBody`) has exactly four required fields —
   `organization_id`, `slug`, `display_name`, `kind` — and **no
   `tenant_id`**. The id is minted server-side as
   `ten_` + `secrets.token_hex(13)` (`tenant_registry.new_tenant_id`).
   A tenant whose `id` is the literal string `nivx-machines` is **not
   creatable through any deployed route.**
2. **A tenant cannot be the first object.** `create_tenant` requires an
   existing **ACTIVE organization**. The first production write is
   therefore `POST /api/xdr/organizations`, not the tenant. Two
   administrative writes, in order.

Everything else the owner asked to verify is PASS or honestly reported
below.

---

## PROPOSED TENANT · reconciled against the implementation

| Owner intent | Deployed reality |
|---|---|
| `TENANT_ID: nivx-machines` | **not possible** — server-minted `ten_<26 hex>`. `nivx-machines` is expressible only as the **`slug`** (immutable-by-convention label, never an authorization key) |
| `DISPLAY_NAME: NivX Machines` | ✔ exactly, `display_name`, ≤120 chars |
| one org/workspace, products under it | ✔ matches the model: `organizations` (1) → `tenants` (n), `products` is a free-text label list on the tenant |

`services/tenant_registry.py:22-24` states the design intent explicitly:
*"the security identifier is opaque and immutable (`org_…` / `ten_…`).
Slug and display name are mutable labels and are never an authorization
key."* The owner's naming requirement and the implementation agree on
substance and disagree only on which field carries the human name.

Three owner options (all require owner choice, none taken here):

| Option | Effect | Code change |
|---|---|---|
| **A · accept opaque id** | `id = ten_<hex>`, `slug = nivx-machines`, `display_name = NivX Machines`. Consoles show `display_name`; the id appears only in `X-Tenant-Id` | **none** |
| B · literal `nivx-machines` id | would require exposing `tenant_id` on the create route (today reachable only by `adopt_legacy()`, which **has no route**) | yes — forbidden this task |
| C · adopt as legacy | `adopt_legacy()` preserves a supplied id, but is designed for pre-existing tenant strings and is not routed | yes — forbidden this task |

Option A is the only one executable under the current guardrails.

---

## A · AUTHORITATIVE TENANT REGISTRY

| | |
|---|---|
| Source | `backend/services/tenant_registry.py` (286 lines) |
| Router | `backend/routers/xdr_tenancy.py` — `organizations_router`, `tenants_router` |
| Registered | `backend/server.py:358-361` |
| Service layer | the registry module itself (no separate service) |
| Persistence | MongoDB, sync pymongo via `deps.sync_collection` |
| Collections | `organizations`, `tenants` |
| Tenant model | plain dict, not a Pydantic document model: `id`, `organization_id`, `slug`, `display_name`, `kind`, `state`, `products[]`, `created_at`, `updated_at`, `created_by` |
| Identifier field | `id` (`ten_` + 26 hex) |
| Display-name field | `display_name` |
| Lifecycle field | `state` ∈ `ACTIVE` / `SUSPENDED` / `ARCHIVED` |
| Kind field | `kind` ∈ `INTERNAL_VALIDATION` / `CUSTOMER` / `LAB` / `LEGACY_ADOPTED` |
| Unique constraints | **application-level only** (see ATOMICITY) |
| Indexes | **none beyond `_id_`** — verified by reading live index metadata on the preview DB: `tenants` and `organizations` each carry only `_id_`, `unique=False` |
| Audit integration | `routers.xdr_audit_log.emit_audit`, HMAC chain in `xdr_audit_log` |
| Authorization integration | `routers.xdr_rbac.require_permission` |

**Shared XDR/EDR authority: YES — single authority, proven.**
`grep` for any second tenant store returns nothing: only
`tenant_registry` touches `organizations` / `tenants`. The EDR planes
call the same module — `routers/edr_tenancy.py:36` imports
`services.tenant_registry` and both `edr_tenant()` (analyst plane) and
`sensor_tenant()` (sensor plane) call `tenant_registry.authoritative()`.
XDR control-plane routes reach it through
`xdr_rbac.authorize_tenant()` → `tenant_registry.authoritative()`.
No conflicting authority found. **No reconciliation needed.**

---

## B · EXACT TENANT CREATE API

Two operations, in this order.

### B.1 · Organization (FIRST production write)

```
HTTP METHOD:  POST
API PATH:     https://nivxray.nivxforge.com/api/xdr/organizations
CONTENT TYPE: application/json
AUTH:         Authorization: Bearer <admin JWT>
```

Request body that WOULD be sent (schema field names confirmed from the
deployed `CreateOrganizationBody`):

```json
{
  "slug": "nivx-machines",
  "display_name": "NivX Machines",
  "kind": "CUSTOMER"
}
```

`kind` must be one of `VENDOR` / `CUSTOMER` / `MSSP` — **owner choice**,
not derivable. `VENDOR` = NivX's own organization; `CUSTOMER` = a
customer organization; `MSSP` = a managed-service operator.

Returns `{"ok": true, "data": {...}, "audit_ref": "aud_…"}` where
`data.id` is the `org_<26 hex>` needed by B.2.

### B.2 · Tenant (SECOND production write)

```
HTTP METHOD:  POST
API PATH:     https://nivxray.nivxforge.com/api/xdr/tenants
CONTENT TYPE: application/json
AUTH:         Authorization: Bearer <admin JWT>
```

```json
{
  "organization_id": "org_<returned by B.1>",
  "slug": "nivx-machines",
  "display_name": "NivX Machines",
  "kind": "CUSTOMER",
  "products": ["xdr", "edr"]
}
```

`products` is **a label only** — grep confirms its sole consumer is the
audit payload at `xdr_tenancy.py:109`. It gates nothing. Recorded as
fact, not as capability.

**NOT SENT. Neither request was executed.**

---

## C · AUTHENTICATION

| | |
|---|---|
| Mechanism | `require_permission` accepts exactly two principals: a **verified JWT bearer** (`deps.get_current_user`) or an **`X-XDR-API-Key` + `X-Tenant-Id`** machine pair. Presenting both → `ambiguous-credentials`, refused (`xdr_rbac.py:919-920`) |
| Session/token type | HS256 JWT, `sub` = user email (`deps.py:281`) |
| Identity source | the verified JWT **only**. `xdr_rbac.py:930-950` records that the previous implementation resolved identity from client headers and was fixed under P0-SEC; client headers can no longer establish identity |
| Server-side principal resolution | `get_current_user(JWT)` → `users` document → `role` → `resolve_tenant_scope(email)` |
| Browser-asserted tenant authority | **not trusted.** `verified_actor()` parks any `X-Principal-Id` on `request.state.principal_claim` marked `"used": False` and consults it for nothing (`xdr_rbac.py:813-823`) |
| Tenant from authenticated context | for the create route, tenant identity is **irrelevant** — creation is a platform-tier act gated by permission, not by tenancy. For every *subsequent* tenant-scoped call, the named tenant is resolved through the registry and then intersected with the principal's authorized set |
| Expiration | JWT `exp`; expired → 401, absent → 403 |
| Failure behaviour | fail-closed. Verified live, unauthenticated, read-only: `GET /api/xdr/tenants` → `403 {"code":"ACCESS_DENIED","permission":"tenants.read","reason":"unauthenticated"}`; same for `/api/xdr/organizations` |

---

## D · AUTHORIZATION / RBAC

| | |
|---|---|
| REQUIRED PERMISSION | `tenants.manage` (read side: `tenants.read`) |
| Vocabulary | `xdr_rbac._RESOURCES["tenants"] = {"actions": ["read","manage"], "group": "Platform"}` |
| CHECK LOCATION | route dependency — `xdr_tenancy.py:55` (org), `:94` (tenant): `Depends(require_permission("tenants.manage"))` |
| REQUIRED ROLE | `platform_admin` (builtin, `permissions: ["*.*"]`), **or** any role whose grant expands to `tenants.manage`. `tenant_admin` does **not** include it |
| Short-circuit | `xdr_rbac.py:959-960` — `if role == "admin": return True`. A user document with `role == "admin"` satisfies every non-console permission |
| DENIAL BEHAVIOUR | `403 {"code":"ACCESS_DENIED","permission":"tenants.manage","reason":...}`, and `_audit_denial` writes an `ACCESS_DENIED` audit row |

**CURRENT ADMIN AUTHORITY (`admin@nivxray.com`): IMPLEMENTED — NOT YET
PROVEN in production.**

- Code-level: `deps.seed_admin()` writes the seeded admin with
  `"role": "admin"` and never re-sets an existing password. With that
  role, `require_permission("tenants.manage")` returns `True` at
  `xdr_rbac.py:960`, and `resolve_tenant_scope` classifies `admin` as a
  cross-tenant role (`dashboard_lenses.py:154-156`), so the principal is
  `all_tenants: True`.
- Production: proving it requires either the successful mutation itself
  or an authenticated `GET /api/xdr/tenants` (200 vs 403). The read-only
  proof needs a production admin bearer token, which this task did not
  obtain and did not ask for.

```
AUTHORITY: NOT YET PROVEN  (read-only proof available on request:
           one authenticated GET /api/xdr/tenants — 200 = tenants.read
           held; 403 = not held. It is a read, not a mutation.)
```

No credential was requested, read, logged or inspected.

---

## E · TENANT ISOLATION

Traced creation → resolution → EDR/XDR consumption.

| Check | Result | Evidence |
|---|---|---|
| Server-side authority | ✔ | one call, `tenant_registry.authoritative()` |
| `"default"` fallback | **conditional — see below** | `tenant_registry.py:133-161` |
| First-tenant fallback | ✖ none | no `find_one({})` / `[0]` selection anywhere |
| Global tenant fallback | ✖ none | — |
| Email-domain inference | ✖ none | `resolve_tenant_scope` reads only the `users` doc's `role` / `tenant_id` / `tenant_ids` |
| Hostname / Origin / Referer inference | ✖ none | no header other than `X-Tenant-Id` is consulted |
| Browser-state authority | ✖ none | `apps/nivxray-xdr/src/lib/tenant.js` returns `null` with no selection and documents "no `default` fallback, no hardcoded tenant id, no registry lookup — that is the server's decision" |
| Client-controlled override | ✖ none (narrows only) | `edr_tenancy.edr_scope()` and `xdr_rbac.authorize_tenant()` both intersect; naming an unheld tenant → `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, never a silent downgrade |
| Preview / test tenant fallback | ✖ none | — |

### The one `"default"` path — reported, not fixed

`tenant_registry.authoritative()` has two modes, gated by the
**non-secret** env flag `NIVX_TENANT_REGISTRY_ENFORCE`:

- **enforcement ON** — no tenant → `403 TENANT_REQUIRED`; unregistered →
  `TENANT_NOT_FOUND`; non-ACTIVE tenant or non-ACTIVE organization →
  refused. `"default"` is unreachable; the docstring states the flag
  "can only make the platform stricter".
- **enforcement OFF** — `compat_default="default"` **is returned** for a
  request naming no tenant (`tenant_registry.py:143-147`), and an
  unregistered tenant string is passed through with a log line.

So the literal `"default"` is production-reachable **if and only if the
flag is off in the production runtime.**

```
PREVIEW  (/app/backend/.env)            NIVX_TENANT_REGISTRY_ENFORCE=true   (read directly)
PRODUCTION                              INFERRED ON — not read this session
```

Basis for the inference: the production consoles returned
`TENANT_REQUIRED` (recorded in `MASTER_WORK_RECONCILIATION.md §2`), and
`TENANT_REQUIRED` is raised **only** on the enforcing branch
(`tenant_registry.py:163-167`). With the flag off, the same request
would have returned `200` scoped to `"default"`. That is strong
behavioural evidence, **not** a direct read of the production
environment.

```
RESULT: PASS — conditional on NIVX_TENANT_REGISTRY_ENFORCE being ON in
        the production runtime. Owner confirmation requested; an
        authenticated GET /api/xdr/tenants also returns
        data.enforcing (xdr_tenancy.py:119) and proves it read-only.
```

### Two honest observations (no fix applied)

1. `services/session_context.py:50-51` — `list_customers()` groups
   incident documents with `{"$ifNull": ["$tenant_id", {"$ifNull":
   ["$user_email", "default"]}]}`. This is a **read-side grouping
   label**, not a tenancy authority: it never reaches
   `authoritative()`, never writes, and grants nothing. Its only effect
   is cosmetic — a row literally named `default` could appear in the XDR
   customer list if unattributed incident documents exist. Production
   holds zero incidents today.
2. The same function is why §M below matters: the XDR customer list is
   derived from incident data, not from the registry.

---

## F · DUPLICATE / COLLISION BEHAVIOUR

| Collision | Status | Error | Mutation |
|---|---|---|---|
| `tenant_id` already exists (`ten_…`) | `409` | `TENANT_EXISTS` | none — checked before insert (`tenant_registry.py:242-244`) |
| `slug` already exists **in the same organization** | `409` | `TENANT_SLUG_EXISTS` | none (`:236-240`) |
| `slug` exists in a **different** organization | **allowed** | — | creates a second tenant with the same slug |
| organization `slug` already exists | `409` | `ORGANIZATION_SLUG_EXISTS` | none (`:204-207`) |
| `display_name` collision | **allowed** | — | creates |

```
DISPLAY NAMES: NON-UNIQUE — no check exists at any layer.
```

Consequence worth naming: two tenants may both display **"NivX
Machines"**, distinguishable only by opaque id. The EDR CustomerPicker
renders `display_name` and falls back to `slug`, then `id`
(`CustomerPicker.jsx`), so a duplicate display name is an operator
ambiguity, not a security boundary failure.

---

## G · ATOMICITY

```
STATUS: NOT GUARANTEED
```

Proof (all three legs are facts, not inference):

1. The check is **read-then-write**, not conditional-write:
   `find_one({organization_id, slug})` → `find_one({id})` →
   `insert_one(...)` (`tenant_registry.py:236-250`). Classic TOCTOU
   window.
2. There is **no unique index to catch the race**. A repository-wide
   grep for `create_index` finds none for `tenants` or `organizations`,
   and reading the live index metadata on the preview DB confirms both
   collections carry only `_id_` (`unique=False`).
3. There is **no transaction and no retry** wrapper.

Behaviour of two concurrent `POST /api/xdr/tenants` with
`organization_id` + `slug=nivx-machines`: both `find_one` calls can
return `None`, both inserts succeed, and the result is **two tenants,
two distinct `ten_…` ids, the same slug** — two tenancies presenting as
one customer. Serial requests are safe; concurrent requests are not.

Practical mitigation for the bootstrap, requiring no code change:
**issue the create exactly once, serially, and verify with §L before any
retry.** Never retry a create whose outcome is unknown; read first.

Reported, not modified.

---

## H · IDEMPOTENCY

```
STATUS: NON-IDEMPOTENT
```

- No idempotency key exists — not in the route, the body schema, the
  headers, or the registry.
- A repeated create does **not** return the existing tenant; it returns
  `409 TENANT_SLUG_EXISTS`. Duplicate **rejection** is a uniqueness
  guard, and it is not the same property as idempotency. Stated
  honestly per the owner's instruction.
- `adopt_legacy()` **is** idempotent (returns the existing tenant when
  the id is already present, `:279-281`) but has **no route** and is
  reachable only from code.

No idempotency was added.

---

## I · EXPECTED PRODUCTION DATABASE WRITES

For **B.1 · organization**:

| | |
|---|---|
| DATABASE | production Mongo, `DB_NAME` from the production env (never read here) |
| COLLECTION | `organizations` — **1 DIRECT WRITE** |
| DOCUMENT | `{id: org_<26hex>, slug, display_name, kind, state:"ACTIVE", created_at, updated_at, created_by}` |
| INDEX EFFECTS | none — no index exists to update beyond `_id_` |
| AUDIT RECORD | `xdr_audit_log` — **1 DIRECT WRITE**, `ORGANIZATION_CREATED` |

For **B.2 · tenant**:

| | |
|---|---|
| COLLECTION | `tenants` — **1 DIRECT WRITE** |
| DOCUMENT | `{id: ten_<26hex>, organization_id, slug, display_name, kind, state:"ACTIVE", products[], created_at, updated_at, created_by}` |
| INDEX EFFECTS | none |
| AUDIT RECORD | `xdr_audit_log` — **1 DIRECT WRITE**, `TENANT_CREATED` |
| RELATED OBJECTS | **none** |
| DEFAULT POLICY CREATION | **NO WRITE** — verified: nothing in `create_tenant` or the route touches policies |
| DEFAULT ROLE CREATION | **NO WRITE** — builtin roles are static constants, not documents |
| DEFAULT CUSTOMER/WORKSPACE CREATION | **NO WRITE** — the "customer" concept is a derived read (§M) |
| ENROLMENT TOKEN | **NO WRITE** — minting is a separate authenticated act |
| ENDPOINT | **NO WRITE** |
| DERIVED / ASYNC WRITE | **none.** Both handlers are plain `def` (synchronous), no background task, no queue, no event emission, no hook |
| OTHER SIDE EFFECTS | none |

```
TOTAL: 4 documents across 3 collections. 2 organizations/tenants rows,
       2 audit rows. No preview/test data copy. No synthetic endpoint.
       No enrolment token. No provisioning cascade.
```

### One ordering defect found — reported, not fixed

`xdr_tenancy.py:93-110` inserts the tenant **first** and emits the audit
record **second**, and `emit_audit` is fail-closed (`503` when audit
storage is unavailable, `xdr_audit_log.py:107-110`). If the audit write
fails, the tenant **already exists** while the caller receives an error
and no audit row was written. There is no compensating delete. The
probability is low (production booted, which proves
`XDR_AUDIT_MASTER_SECRET` is configured — `assert_production_ready()`
runs at startup and refuses to serve without it), but the window is
real. Mitigation: if the create returns a non-2xx, **run §L before
retrying** — the tenant may exist regardless.

---

## J · AUDITABILITY

From `emit_audit()` (`xdr_audit_log.py:95-138`) and the call site:

| Field | Value |
|---|---|
| EVENT NAME | `TENANT_CREATED` (org: `ORGANIZATION_CREATED`) |
| ACTOR | `principal_id` = `verified_actor(request)` = the JWT `sub`, i.e. the admin's email. `principal_kind: "user"`. Client-supplied attribution is never used |
| TARGET | `resource_kind: "tenant"`, `resource_id: ten_<hex>` |
| TENANT | `tenant_id` = the newly created tenant's own id (org event: the org id) |
| TIMESTAMP | `at`, `datetime.now(timezone.utc).isoformat()` |
| REQUEST/CORRELATION ID | `correlation_id`, defaulting to the event id `aud_<20hex>`. **No inbound request-id header is propagated** |
| RESULT | `outcome: "SUCCESS"` (the row is written only on success — a failed create raises before `emit_audit`; denials are audited separately by `_audit_denial`) |
| SOURCE | `"xdr-admin"` |
| AFTER | `{organization_id, slug, kind, products}` |
| INTEGRITY | per-tenant HMAC chain: `prev_sig` + `sig`, `prev_sig="genesis"` for the tenant's first row; `sig_key_id` names the signing key inside the signed payload |
| SECRET REDACTION | ✔ by construction — the payload carries no credential field, and `secret_policy` never returns or logs a value |

Who / what / when / through-which-operation / success-or-failure: **all
present.** Not present: a client-supplied correlation id, and any audit
row for a create that succeeded while its audit write failed (§I).

---

## K · TENANT LIFECYCLE

| | |
|---|---|
| SUPPORTED STATES | `ACTIVE`, `SUSPENDED`, `ARCHIVED` (`tenant_registry.STATES`) |
| DEACTIVATION | `PUT /api/xdr/tenants/{tenant_id}/state` with `{"state":"SUSPENDED"}` (or `ARCHIVED`), `tenants.manage`, audited as `TENANT_STATE_CHANGED`. Effect: `authoritative()` then refuses every request naming that tenant with `403 TENANT_NOT_ACTIVE` — including sensors, whose tenant is validated from their session |
| Organization-level | `PUT /api/xdr/organizations/{org_id}/state` — suspending the org refuses every tenant under it (`ORGANIZATION_NOT_ACTIVE`) |
| DELETED state | **not supported** — `DELETED` is not in `STATES` |
| Hard deletion | **no route exists.** No `DELETE` on `/api/xdr/tenants` in the 862-path production OpenAPI, and the registry has no `delete_*` function |
| RISK | **LOW, and in the safe direction.** Rollback is `SUSPENDED`/`ARCHIVED` — reversible, audited, and it does not rewrite persisted `tenant_id` values (which the registry documents as forbidden because they are part of the ingest-dedupe and EDR raw-event digests). The residual consequence of a mistaken create is one inert `tenants` document plus its audit row, both permanent. Nothing was deleted. |

---

## L · POST-CREATE READ-ONLY VERIFICATION PLAN

To be executed **only after** owner approval and a successful create.
All calls are `GET`. `$TOKEN` = production admin bearer;
`$TEN` = the returned `ten_…`; `$ORG` = the returned `org_…`.

```bash
API=https://nivxray.nivxforge.com
H="Authorization: Bearer $TOKEN"

# 1 · exists exactly once · 2 · id · 3 · display_name · 7 · no second tenant
#     also returns data.enforcing → proves §E's enforcement flag read-only
curl -s "$API/api/xdr/tenants?limit=500" -H "$H"
#   EXPECT count == 1; tenants[0].id == $TEN; slug == "nivx-machines";
#          display_name == "NivX Machines"; state == "ACTIVE";
#          kind == <chosen>; enforcing == true

curl -s "$API/api/xdr/tenants/$TEN" -H "$H"
#   EXPECT 200, the same single document

curl -s "$API/api/xdr/organizations?limit=200" -H "$H"
#   EXPECT count == 1, id == $ORG, state == "ACTIVE"

# 6 · no "default" tenant was created
curl -s "$API/api/xdr/tenants/default" -H "$H"
#   EXPECT 404 {"code":"TENANT_NOT_FOUND"}

# 5 · EDR resolves the SAME authority (this is the EDR CustomerPicker's
#     own source of truth — /api/xdr/tenants — so it is proven above;
#     this call proves the EDR plane accepts the tenant as authoritative)
curl -s "$API/api/edr/endpoints" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT 200 with an EMPTY endpoint list (not 403)

# 4 · XDR scope — see §M: this is EXPECTED to remain empty
curl -s "$API/api/xdr/scope/authorized" -H "$H"
#   EXPECT cross_tenant_role == true, tenants == []  (derived from
#          incidents, not from the registry — empty is CORRECT here)

# 8 · no endpoint was created
curl -s "$API/api/edr/enrollment/endpoints" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT empty

# 9 · no enrolment token was created
curl -s "$API/api/edr/enrollment/tokens" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT empty

# 10 · no telemetry was fabricated
curl -s "$API/api/edr/telemetry/freshness" -H "$H" -H "X-Tenant-Id: $TEN"
curl -s "$API/api/edr/wave0/raw-events/stats" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT zero observations

# 11 · no finding was fabricated
curl -s "$API/api/edr/findings?limit=50" -H "$H" -H "X-Tenant-Id: $TEN"
curl -s "$API/api/edr/findings/evaluation-state" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT empty / NOT_EVALUATED — never CLEAN

# 12 + 13 · response authority still fail-closed, zero actions
curl -s "$API/api/edr/response/actions" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT empty list
#   (no POST is issued; P0-PROD-4 remains closed)

# 14 · tenant isolation remains explicit — the negative controls
curl -s "$API/api/edr/endpoints" -H "$H"
#   EXPECT 403 TENANT_REQUIRED          (no header ⇒ no tenancy)
curl -s "$API/api/edr/endpoints" -H "$H" -H "X-Tenant-Id: ten_doesnotexist"
#   EXPECT 403 TENANT_NOT_FOUND
curl -s "$API/api/edr/endpoints" -H "$H" -H "X-Tenant-Id: default"
#   EXPECT 403 TENANT_NOT_FOUND

# audit proof — who created it, when, and that the chain verifies
curl -s "$API/api/xdr/audit-log?tenant=$TEN&action=TENANT_CREATED" -H "$H"
#   EXPECT 1 event: principal_id == the admin email, principal_kind "user",
#          resource_kind "tenant", resource_id == $TEN, outcome SUCCESS,
#          prev_sig == "genesis", sig_key_id present
curl -s "$API/api/xdr/audit-log/verify/chain" -H "$H" -H "X-Tenant-Id: $TEN"
#   EXPECT valid
```

Nothing in this plan mutates. No `POST`, `PUT`, `PATCH` or `DELETE`.

---

## M · EXPECTED CONSOLE RESULT

This is where documentation and implementation diverge, so it is stated
precisely.

**EDR console (`edr.nivxforge.com`) — WILL show the tenant.**
`nivxforge/components/CustomerPicker.jsx` reads
`GET /api/xdr/tenants?limit=500` — the **registry** — filters to
`state === "ACTIVE"`, and renders `display_name`. Its own header comment
says the list comes from the registry "not from whichever tenants happen
to already hold evidence: a newly provisioned customer with zero
computers is exactly the one an operator needs to select". So **"NivX
Machines" appears immediately**, with zero computers. Selecting it calls
`setActiveTenant(id)` → `localStorage["nvx_tenant"]` → every request
carries `X-Tenant-Id`, and `TENANT_REQUIRED` disappears for that
session. The browser stores a **selection**; the server still decides
existence, state and authorization on every call.

**XDR console (`xdr.nivxforge.com`) — WILL NOT show the tenant yet.**
`XdrClientManagementPage.jsx` and `XdrScopeNavigator.jsx` read
`GET /api/xdr/scope/authorized`, whose `tenants` field is
`session_context.tenant_context()["customers"]` =
`list_customers(email)`, **a `$group` aggregation over the
`workspace_cases` incident collection** (`session_context.py:40-63`).
It lists tenants **that already hold incidents**, not registered
tenants. With zero incidents in production, the XDR client list stays
empty after tenant creation, and that is the **current implementation's
correct behaviour, not a bug introduced by the bootstrap.**

```
XDR:  customer list remains EMPTY until the first incident exists.
      The XDR admin surfaces that use lib/tenant.js (API keys,
      collectors, integrations, assets) will accept the selected tenant
      immediately, because they send X-Tenant-Id like the EDR console.
EDR:  CustomerPicker shows "NivX Machines" immediately.
```

If the owner expects the XDR client list to show a registry tenant with
no incidents, that is a **separate UI change** (point it at
`/api/xdr/tenants`, or union the two) — not part of this bootstrap, and
not done here.

No frontend default-tenant selection exists and none would be added:
`lib/tenant.js` returns `null` with no operator selection, deliberately.

---

## N · NEXT UNBLOCKED STEP

The **single** next supported operation after an approved, verified
tenant:

```
POST /api/xdr/organizations        ← actually first (B.1)
POST /api/xdr/tenants              ← the tenant itself (B.2)
   └─ then, and only then, the next operation is:

      POST /api/edr/enrollment/tokens
        Authorization: Bearer <admin JWT>
        X-Tenant-Id: ten_<new tenant id>
      (TENANT_SCOPED per edr_tenancy.ROUTE_CLASSIFICATION:86)
```

That mints a short-lived, single-use enrolment token (P0-PROD-2,
CLOSED). It is a **production DB write** and requires its own owner
approval. Everything after it — token consumption
(`POST /api/edr/agent/enroll`), endpoint identity, endpoint credential,
`/agent/session`, `/agent/heartbeat`, `/agent/policy`,
`/agent/policy-ack`, `/agent/telemetry`, server-side detection, durable
finding, investigation — is `SENSOR_SCOPED` and requires a real host.
Response and independent verification remain gated behind **P0-PROD-4**.

**No part of this chain was executed.**

---

## O · EDR_AUTH_PEPPER

Owner statement accepted as configuration evidence: the production
`EDR_AUTH_PEPPER` was generated fresh during production secret
configuration and was not copied from preview.

Actions taken on it: **none.** Not displayed, read, hashed, compared,
logged, returned, copied, rotated or requested. Secret storage was not
inspected. The only fact used is boot-derived and value-free:
`assert_production_ready()` runs at startup and refuses to serve when
any of `MANDATORY_PRODUCTION_SECRETS` (which includes
`EDR_AUTH_PEPPER`) is absent, blank or a placeholder — and production
answers `/api/health` with `200`. That proves *configured*, nothing
about the value.

`MASTER_WORK_RECONCILIATION.md §24.7` (pepper freshness UNKNOWN) is
answered by owner attestation and moves to
**OWNER_ATTESTED · BEHAVIOURALLY_UNVERIFIED**, to be closed by the first
real production enrolment.

---

## P · SECURITY ARCHITECTURE INVARIANTS

Verified intact, in the owner's own order:

```
User/Operator
  → authoritative backend authentication     deps.get_current_user (JWT only)
  → server-side principal                    verified_actor / users document
  → server-side tenant resolution            tenant_registry.authoritative()
  → RBAC / permission                        require_permission("tenants.manage")
  → tenant-scoped resource validation        authorize_tenant / edr_scope (narrow-only)
  → operation
  → immutable/auditable evidence             emit_audit, per-tenant HMAC chain
```

- Client-controlled tenant authority: **not present.** A request may
  *name* a tenant; `edr_scope()` and `authorize_tenant()` both then
  require the authenticated principal to hold it, refusing rather than
  downgrading.
- `tenant_id` supplied by the browser is treated as a **request**, never
  as authority — stated in code at `xdr_rbac.py:842` and
  `edr_tenancy.py:206-213`.
- Sensors never name their own tenancy: `sensor_tenant()` reads the
  tenant from the authenticated endpoint session and never from a
  header.

No boundary was weakened. No code was changed.

---

## Q · RESPONSE AUTHORITY

```
RESPONSE AUTHORITY: FAIL-CLOSED — unchanged
```

`XDR_RESPONSE_SERVICE_URL` was not configured, not read and not
inspected. P0-PROD-4 was not started. Endpoint isolation, process kill,
quarantine, containment and remote execution remain unreachable. Tenant
bootstrap touches none of this: the create path has no response-plane
coupling of any kind.

---

## R · GUARDRAIL LEDGER

```
PRODUCTION DB WRITES        0
TENANTS CREATED             0
TENANTS MODIFIED            0
TENANTS DELETED             0
ORGANIZATIONS CREATED       0
ENDPOINTS CREATED           0
ENROLLMENT TOKENS CREATED   0
ENDPOINTS ENROLLED          0
POLICIES MODIFIED           0
EXCLUSIONS MODIFIED         0
FINDINGS MODIFIED           0
RESPONSE ACTIONS            0
SECRET VALUES ACCESSED      0
CODE CHANGES                0
COMMITS                     0
PUSHES                      0
DEPLOYMENTS                 0
VERCEL CHANGES              0
BACKGROUND WORKERS ENABLED  0
MIGRATIONS RUN              0
DIRECT MONGO WRITES         0
```

Reads performed: repository source; the live production
`/api/openapi.json` and `/api/health`; two **unauthenticated** `GET`s to
`/api/xdr/tenants` and `/api/xdr/organizations` (both `403`, expected);
`index_information()` + `count_documents({})` on the **preview**
database's `tenants` / `organizations` / `xdr_audit_log` (index metadata
and counts only — needed for §G, and the production database was never
contacted). One non-secret env flag name was read from
`backend/.env`; no value of any secret was read or printed.

---

## S · TRUTHFULNESS CLASSIFICATION

| Claim | Grade |
|---|---|
| Single shared XDR/EDR tenant authority | **IMPLEMENTED · VERIFIED (source)** |
| `POST /api/xdr/organizations` then `POST /api/xdr/tenants` is the only create path | **IMPLEMENTED · VERIFIED against the deployed OpenAPI** |
| `tenant_id` is server-minted and not choosable | **IMPLEMENTED · VERIFIED (deployed schema)** |
| Tenant creation writes exactly 2 docs + 2 audit rows | **EXPECTED** — from source reading; not executed |
| `tenants.manage` gates creation; `role=="admin"` satisfies it | **IMPLEMENTED · VERIFIED (source)** |
| `admin@nivxray.com` holds that authority in production | **NOT VERIFIED** — needs one authenticated read |
| No default/first/global/domain/host/browser tenant fallback | **IMPLEMENTED · VERIFIED**, conditional on the enforcement flag |
| `NIVX_TENANT_REGISTRY_ENFORCE=true` in production | **INFERRED** from the observed `TENANT_REQUIRED` refusal — not read |
| Atomicity | **NOT GUARANTEED** — no unique index, no transaction; stated as a gap, not claimed |
| Idempotency | **NOT IMPLEMENTED** — duplicate rejection is not idempotency |
| Auditability of tenant creation | **IMPLEMENTED · VERIFIED (source)**; the write-then-audit ordering gap is reported |
| EDR console will show the new tenant | **EXPECTED** — same registry endpoint the picker already calls |
| XDR client list will show the new tenant | **NOT IMPLEMENTED** — that list is incident-derived; it will stay empty |
| `EDR_AUTH_PEPPER` freshness | **OWNER-ATTESTED · BEHAVIOURALLY UNVERIFIED** |
| Response authority | **FAIL-CLOSED · UNCHANGED** |

Nothing discovered during this precheck was silently fixed. Three items
are reported and left alone: the missing unique index (§G), the
write-then-audit ordering (§I), and the incident-derived XDR customer
list (§M).

---

## EXACT BLOCKERS

1. **`TENANT_ID: nivx-machines` is not creatable.** Owner must choose
   Option A (opaque `ten_…` id, `slug=nivx-machines`) or authorize a
   code change (Option B/C) — which this task is forbidden to make.
2. **`organization_id` does not exist yet.** The first write is the
   organization; owner must confirm its `kind`
   (`VENDOR` / `CUSTOMER` / `MSSP`) and that a single org is intended.
3. **Tenant `kind` is an owner decision** — `CUSTOMER` /
   `INTERNAL_VALIDATION` / `LAB` (`LEGACY_ADOPTED` is not appropriate
   for a new tenant).
4. **Authorization for the first two production DB writes** — explicit,
   per-write.
5. *(Optional, read-only)* confirm `admin@nivxray.com` holds
   `tenants.read` / `tenants.manage` in production, and confirm
   `enforcing == true`, via one authenticated `GET /api/xdr/tenants`.

---

## STOP POINT

Stopped for owner review. The tenant create request was **not**
executed. Nothing was created, modified, deployed, enrolled, rotated,
enabled or dispatched.
