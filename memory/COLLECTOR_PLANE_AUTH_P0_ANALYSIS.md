# COLLECTOR PLANE AUTHENTICATION / RBAC — P0 ANALYSIS + REMEDIATION PLAN

Analysis only. **Nothing implemented.** No production republish. No production
data mutation. No collector, connector, API key, enrolment token or endpoint.
No W1 / Sysmon telemetry. `C:\NivX\forwarder` untouched. No Tenant Picker, no
Unattributed Evidence View. W1 Phase 3 HELD.

Accepted: `ab6be4a9` is the platform packaging commit for the approved code
baseline `7645b2b1` (diff = one memory document; `backend`, `apps`, `frontend`
byte-identical).

**Probe discipline honoured:** every production probe in this analysis was a
read-only `GET`. **No anonymous POST/PUT/PATCH/DELETE was issued against
production or preview.** All mutation findings below are derived from reading
the deployed source, and are labelled as such.

---

## 1 · THE GAP, STATED PRECISELY

```
apps/nivxray-xdr-collector/routes/*.py
  grep get_current_user | Depends | require_permission | Authorization  ->  0 hits
backend/routers/xdr_collector_landing.py:167-173
  app.include_router(<7 routers>, prefix="/api/xdr/collector")   <- no dependencies=[...]
```
Seven routers, 22 operations, mounted into the core with **no authentication
dependency of any kind**. Your framing is exactly right: the tenant convergence
answered *which customer*, and nothing answers *who* or *what may they do*.
A tenant id is an identifier, not a credential — and `ten_*` ids are returned
by `GET /api/xdr/tenants`, so they are not secrets either.

## 2 · THE 22-OPERATION MATRIX

`ANON-MUTATE` = anonymously reachable state change (source-derived).
`ANON-LEAK` = anonymously readable sensitive information (GET-verified on production).

### 2a · `routes/connectors.py` — 10 operations
| op | class | today | sensitivity |
|---|---|---|---|
| `GET /source-types` | PRODUCT_METADATA | anon | static catalogue · not sensitive |
| `GET /connectors` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-LEAK** integration topology (credentials are `***` via `store.redacted()`) |
| `POST /connectors` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-MUTATE** creates a connector; on the live build with no header it lands under `"default"` |
| `GET /connectors/{cid}` | HUMAN_CONTROL | anon | **ANON-LEAK** per-connector config |
| `PATCH /connectors/{cid}` | HUMAN_CONTROL | anon | **ANON-MUTATE** rewrites config **incl. credentials** |
| `DELETE /connectors/{cid}` | HUMAN_CONTROL | anon | **ANON-MUTATE** destroys an integration |
| `POST /connectors/{cid}/test` | HUMAN_CONTROL | anon | **ANON-MUTATE** outbound request as the tenant · SSRF surface |
| `POST /connectors/{cid}/start` | HUMAN_CONTROL | anon | **ANON-MUTATE** starts collection |
| `POST /connectors/{cid}/stop` | HUMAN_CONTROL | anon | **ANON-MUTATE** **silences a security data source** |
| `POST /connectors/{cid}/inject` | TEST_PLANE | anon + `X-Debug-Inject: 1` | **ANON-MUTATE · WORST** injects a synthetic payload through parser→dedup→**delivery**. A header the caller sets is not a control. This is fabricated evidence entering the canonical pipeline |

Note `PATCH` accepts a full `config` including `credentials`, while `GET`
redacts them — so the write path is more dangerous than the read path.

### 2b · `routes/collectors.py` — 2
| op | class | today | sensitivity |
|---|---|---|---|
| `GET /collectors` | HUMAN_CONTROL | anon | **ANON-LEAK** — production returns `collector_id`, version, `python-3.11.14`, **host** |
| `GET /collectors/{collector_id}` | HUMAN_CONTROL | anon | same |

### 2c · `routes/outbox.py` — 5
| op | class | today | sensitivity |
|---|---|---|---|
| `GET /outbox/health` | HUMAN_CONTROL | anon | **ANON-LEAK** ingest config state (`url_set`, `token_set`, `auth_mode`), queue depth |
| `GET /outbox` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-LEAK** undelivered **envelope contents** = raw telemetry |
| `GET /outbox/{rid}` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-LEAK** single envelope |
| `POST /outbox/{rid}/replay` | HUMAN_CONTROL | anon | **ANON-MUTATE** requeues a dead letter |
| `POST /outbox/drain-once` | HUMAN_CONTROL | anon | **ANON-MUTATE** forces a delivery tick |

### 2d · single-operation routers — 5
| op | class | today | sensitivity |
|---|---|---|---|
| `GET /data-sources` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-LEAK** configured sources |
| `GET /telemetry-health` | HUMAN_CONTROL · tenant-scoped | anon | **ANON-LEAK** which transports are connected — a reconnaissance oracle for blind spots |
| `POST /ingest-preflight` | HUMAN_CONTROL | tenant-gated on the candidate | on the candidate anon+tenant still delivers one synthetic envelope |
| `POST /webhooks/{secret_id}` | **MACHINE (vendor)** | HMAC-verified | **CORRECT AS-IS.** `conn.verify(body, headers)` → 401 on bad signature. Public by design; per-connector shared-secret auth. **Do not put a JWT in front of it** |
| `GET /api/xdr/collector/landing` | PRODUCT_METADATA | anon | mount topology · low, but no reason to be public |

### 2e · Classification totals
```
HUMAN_CONTROL (JWT + permission + explicit tenant)   17
MACHINE (per-connector HMAC, already correct)         1   POST /webhooks/{secret_id}
TEST_PLANE (must be authenticated + gated)            1   POST /connectors/{cid}/inject
PRODUCT_METADATA (authenticated, tenant-independent)  3   /source-types, /landing, (+/telemetry-health if reclassified)
--------------------------------------------------------------
ANON-MUTATE operations today                          9
ANON-LEAK operations today                            9
```
**There is no legitimate machine/collector consumer of this plane other than
the inbound webhook.** The forwarder and collectors deliver telemetry to
`POST /api/xdr/ingest/telemetry` with `X-XDR-API-Key`, which is already
authenticated. So this is a **human control plane with one public webhook** —
which makes the closure small.

## 3 · EXISTING PRIMITIVES ARE SUFFICIENT — NO SECOND AUTHORITY NEEDED

Everything required already exists and is already the authority elsewhere:

- **`routers.xdr_rbac.require_permission(perm)`** (`:724`) — dual-principal by
  design: `USER` via verified JWT (`deps.get_current_user` + `xdr_users` /
  `xdr_user_roles`), or `MACHINE` via `X-XDR-API-Key` + `X-Tenant-Id` against
  the SHA-256 digests in `xdr_api_keys`. Presenting both is rejected as
  ambiguous; **no credential at all fails closed**. This is exactly the
  contract the collector plane is missing.
- **`collectors` is already a first-class RBAC resource** (`xdr_rbac.py:136`)
  with actions `read, create, update, delete, enroll, revoke, test, enable,
  disable, rotate`. `tenant_admin` already holds `collectors.*`; `auditor` and
  `read_only`-adjacent roles already hold `collectors.read`. **No new
  permission string and no role change is required.**
- **`services.tenant_registry.authoritative()`** — already wired into this
  plane by the accepted closure. Preserved untouched.
- **`framework.webhook.verify()`** — the correct machine credential for the one
  public route. Keep.

So: no collector-specific identity, no second tenant authority, no new role,
no new permission. Reuse only.

## 4 · TARGET CONTRACT

```
Human/Admin  ->  JWT (get_current_user)  ->  require_permission("collectors.<action>")
             ->  edr/xdr tenant registry (explicit X-Tenant-Id)  ->  operation
Machine      ->  X-XDR-API-Key (xdr_api_keys, scope-checked)  ->  credential-bound tenant  ->  operation
Vendor       ->  per-connector HMAC (webhooks only)  ->  connector-bound tenant  ->  ingest
```
Fail-closed ladder, in this order — **authentication before authority before
capability**:
```
no credential                  -> 403 (require_permission's existing fail-closed)
authenticated, wrong role      -> 403 ACCESS_DENIED
missing tenant (tenant-scoped) -> 403 TENANT_REQUIRED
unknown tenant                 -> 403 TENANT_NOT_FOUND
inactive tenant                -> 403 TENANT_NOT_ACTIVE
```
A valid tenant must never satisfy the authentication step. The accepted tenant
fixes are preserved exactly; auth is added *in front of* them.

## 5 · PROPOSED PERMISSION PER OPERATION

| operation(s) | permission |
|---|---|
| `GET /connectors`, `/connectors/{cid}`, `/collectors`, `/collectors/{id}`, `/data-sources`, `/telemetry-health`, `/outbox`, `/outbox/{rid}`, `/outbox/health` | `collectors.read` |
| `POST /connectors` | `collectors.create` |
| `PATCH /connectors/{cid}` | `collectors.update` |
| `DELETE /connectors/{cid}` | `collectors.delete` |
| `POST /connectors/{cid}/test`, `POST /ingest-preflight` | `collectors.test` |
| `POST /connectors/{cid}/start` | `collectors.enable` |
| `POST /connectors/{cid}/stop` | `collectors.disable` |
| `POST /outbox/{rid}/replay`, `POST /outbox/drain-once` | `collectors.update` |
| `POST /connectors/{cid}/inject` | `collectors.test` **+** keep `X-Debug-Inject: 1` **+** refuse unless an explicit non-production flag is set |
| `GET /source-types`, `GET /landing` | authenticated only (PRODUCT_METADATA) |
| `POST /webhooks/{secret_id}` | **none — HMAC only.** Unchanged |

## 6 · FILES EXPECTED TO CHANGE (7, all small)

1. **`backend/routers/xdr_collector_landing.py`** — the single highest-value
   change: attach `dependencies=[Depends(require_permission(...))]` at
   `include_router` time, per router, with the webhook router deliberately
   excluded. This closes the plane in one place even before per-operation
   granularity lands.
2. **`apps/nivxray-xdr-collector/routes/connectors.py`** — per-operation
   permission + reuse the existing `_tenant()`.
3. **`.../routes/outbox.py`** — permissions; tenant-scope `GET /outbox*`.
4. **`.../routes/collectors.py`** — `collectors.read`.
5. **`.../routes/data_sources.py`**, **`.../routes/telemetry_health.py`** —
   `collectors.read` + tenant scope.
6. **`.../routes/preflight.py`** — add `collectors.test` in front of the
   already-correct tenant gate.
7. **`apps/nivxray-xdr/src/xdr/admin/collectorApi.js`** — this client sends
   **no `Authorization` header at all** (its own axios instance). Add the same
   bearer attachment the interceptor already does for the tenant. Without this
   the Integrations UI breaks the moment auth lands.

A standalone-deployment shim is needed for `require_permission` mirroring the
existing `ImportError` pattern in `_tenant()` — and in standalone mode it must
**fail closed**, not open.

## 7 · TESTS REQUIRED

- **Route-table coverage gate**, same shape as `ROUTE_CLASSIFICATION`: every
  live `/api/xdr/collector/*` operation must appear in a
  `COLLECTOR_ROUTE_CLASSIFICATION` map, so a new route is failed-closed by
  default. This is the clause that would have caught this gap.
- **Anonymous refusal, all 21 non-webhook operations** → 401/403. Mutating ops
  asserted refused *and* asserted to have created nothing.
- **Authenticated-but-unauthorised** (`read_only` principal) → 403 on every
  write op; 200 on reads.
- **Ladder order**: an anonymous request with a *valid* tenant must be refused
  for **authentication**, not answered — proving a tenant cannot substitute for
  a credential.
- **Webhook unchanged**: valid HMAC accepted without a JWT; bad HMAC → 401.
- **Machine principal**: `X-XDR-API-Key` accepted where scoped; JWT + key
  together → ambiguous-credentials 403 (existing behaviour).
- **`inject` regression**: refused anonymously, refused without the debug
  header, refused in production mode even when authenticated.
- **No regression** to the accepted tenant contract: the P6 A–I set plus the
  collector `TENANT_REQUIRED` / `TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE` set.

## 8 · SHOULD THE REPUBLISH HAPPEN BEFORE OR AFTER THIS CLOSURE?

**Recommendation: republish `ab6be4a9` NOW, then close auth, then publish
again.** Reasoning, and the trade-off stated plainly:

- **Today's live exploit needs ZERO knowledge.** `POST /api/xdr/collector/connectors`
  with **no headers at all** succeeds and lands under `"default"`, because the
  live build still has `x_tenant_id or "default"`. Same for `PATCH`, `DELETE`,
  `stop` and `inject`.
- **On the frozen candidate the same caller is refused `TENANT_REQUIRED`.** To
  mutate anything they would first have to learn a registered `ten_*` id — and
  `GET /api/xdr/tenants` is authenticated, so anonymously they cannot. That is
  a large, immediate reduction in exploitability of 9 anonymous-mutate
  operations.
- Holding the republish to bundle both changes keeps the zero-knowledge
  anonymous-mutate path live for the whole duration of the auth work.

Cost of publishing now: one extra publish and one extra acceptance cycle.
Benefit: the trivially-exploitable path closes today. I judge that trade
clearly worth it — but it is your risk call, and if you prefer a single
combined publish the analysis above is unchanged.

**Either way, W1 stays HELD until authentication lands.** The candidate makes
the plane tenant-safe, not authenticated, and creating a real collector for a
real Windows endpoint on an unauthenticated control plane is exactly the
sequence you rejected.

## 9 · STATUS
```
analysis                     DONE · 22 operations classified
anonymous mutate operations  9  (source-derived; no POST probe issued)
anonymous leak operations    9  (GET-verified on production)
new authority required       NONE - reuse require_permission + tenant_registry
new permissions required     NONE - `collectors` resource already defines them
files expected to change     7
implementation               NOT STARTED - awaiting owner approval
production republish         NOT PERFORMED - recommendation in section 8
W1                           HELD
```
