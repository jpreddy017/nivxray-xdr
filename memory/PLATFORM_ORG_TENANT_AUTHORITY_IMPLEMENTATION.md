# PLATFORM ORG / TENANT AUTHORITY — IMPLEMENTATION

**IMPLEMENTED · TESTED · NOT YET DEPLOYED · NOT YET BOOTSTRAPPED · W1 STILL PAUSED**

Date 2026-09-17 · preview only. No production object created, no republish, no
Vercel change, no Windows action, no telemetry, `_COLLECTED_PRODUCTS` still
`{"linux"}`.

---

## 1 · WHAT WAS BUILT

### New files
| file | role |
|---|---|
| `backend/services/tenant_registry.py` | the single tenancy authority: id generation, lookup, `authoritative()` resolution, administrative create/state, legacy adoption, enforcement flag |
| `backend/routers/xdr_tenancy.py` | control plane: `/api/xdr/organizations`, `/api/xdr/tenants` |
| `backend/tests/test_b4b5_tenant_registry_authority.py` | 20 adversarial tests (B4, B5, flag semantics, migration safety) |

### New collections
`organizations`, `tenants`. Created on first write. **Never seeded at
startup**; nothing is created by a deployment.

### New routes (5)
```
POST /api/xdr/organizations                  tenants.manage
GET  /api/xdr/organizations                  tenants.read
PUT  /api/xdr/organizations/{org_id}/state   tenants.manage
POST /api/xdr/tenants                        tenants.manage
GET  /api/xdr/tenants                        tenants.read
GET  /api/xdr/tenants/{tenant_id}            tenants.read
PUT  /api/xdr/tenants/{tenant_id}/state      tenants.manage
```
(7 operations over 5 paths.) `tenants.read` / `tenants.manage` already existed
in the RBAC vocabulary (`xdr_rbac._RESOURCES["tenants"]`) with no route behind
them; they now have one. Preview OpenAPI: **790 → 795 paths**.

### Data model (as approved)
```
organizations  id=org_<26 hex>  slug  display_name  kind=VENDOR|CUSTOMER|MSSP
               state=ACTIVE|SUSPENDED|ARCHIVED  created_at/by  updated_at
tenants        id=ten_<26 hex>  organization_id  slug  display_name
               kind=INTERNAL_VALIDATION|CUSTOMER|LAB|LEGACY_ADOPTED
               state=ACTIVE|SUSPENDED|ARCHIVED  products[]  created_at/by
```
Identifiers are `secrets.token_hex(13)` — opaque, unguessable, derived from
nothing. `slug` and `display_name` are mutable labels and are never an
authorization key. No billing, quota or metering fields; `products` is the
entitlement extension point.

---

## 2 · AUTHORITY FLOW (implemented)

```
request (JWT | nvx_ key | EDR session | body tenant on security-state)
  → authenticated principal                      (existing, unchanged)
  → requested tenant                             (header / key binding / body)
  → services.tenant_registry.authoritative()     ← NEW single authority
        unknown tenant        → TENANT_NOT_FOUND         403
        blank / absent tenant → TENANT_REQUIRED          403
        tenant not ACTIVE     → TENANT_NOT_ACTIVE        403
        org not ACTIVE        → ORGANIZATION_NOT_ACTIVE  403
  → existing RBAC / tenant-isolation checks      (unchanged)
  → tenant-scoped operation
```

### Converged call sites
| file | function | purpose label |
|---|---|---|
| `routers/xdr_collectors.py` | `_principal()` | `xdr.collectors` |
| `routers/xdr_api_keys.py` | `_principal()` + `create_key()` | `xdr.api_keys` |
| `routers/xdr_audit_log.py` | `_principal()` | `xdr.audit` |
| `routers/xdr_ingest.py` | `_principal()` | `xdr.ingest` |
| `routers/edr_enrollment.py` | `_tenant()` (admin) / `_agent_tenant()` (sensor) | `edr.enrollment` / `edr.agent` |
| `security_state/routers/router.py` | `evaluate_security_state()` | `security_state.evaluate` |

One resolver, six call sites, **no duplicated registry logic**. EDR endpoint
ownership and EDR response authority both derive from the endpoint record whose
tenant is now registry-validated at enrolment, so they inherit the same
`ten_*` without a second code path.

Deliberately NOT changed: `services/tenant_authority.py` (D14),
`services/source_routing.py` (D15), `services/ingest_idempotency.py`, every
DSM, `detection_content/**`, `edr_plane/response.py`, the EDR credential
mechanism (`edr_plane/enrollment/security.py` — HMAC + `EDR_AUTH_PEPPER`
untouched: this was authority convergence, not credential consolidation).

---

## 3 · B4 — CLOSED (proof)

Before: `POST /api/xdr/collectors` took `X-Tenant-Id` verbatim, wrote the
document, and that document then satisfied `_tenant_is_known()` so a key could
be minted — tenancy created as a side effect of a data-plane write.

After (enforcement on), proven by test:
- `test_collector_creation_cannot_create_tenancy` → **403**, and both
  `tenants` and `xdr_collectors` contain nothing for the typo tenant.
- `test_api_key_creation_cannot_create_tenancy` → refused, no key row.
- `test_allow_new_tenant_is_refused_when_enforcing` → refused
  (`ALLOW_NEW_TENANT_DEPRECATED` when the caller is otherwise authorised).
- `test_telemetry_cannot_create_tenancy` → **403 TENANT_NOT_FOUND** with a
  valid API key bound to an unregistered tenant; no tenant created.
- `test_registry_never_seeds_a_default_tenant` → `get_tenant("default")` is
  `None`.

`allow_new_tenant` is **deprecated, not deleted**: the field still parses, the
docstring says so, and it is refused only when enforcement is on. Physical
removal stays a separate auditable cleanup.

---

## 4 · B5 — CLOSED (proof)

Before: `routers/edr_enrollment._tenant(user) = (user or {}).get("customer")
or "default"`, and **no code anywhere writes `customer`** onto a user
document, so every NivXForge EDR enrolment token was minted into the literal
tenant `"default"`.

After: the tenant comes from the same explicit `X-Tenant-Id` header the XDR
control plane uses, resolved through the one registry; the `customer` read
remains only as a documented compatibility fallback reachable with enforcement
off. The sensor surface (`/api/edr/agent/enroll`, `/api/edr/agent/session`)
validates the presented `tenant_id` against the registry before the
tenant-scoped token/credential match.

Proven by test:
- `test_edr_admin_plane_no_longer_falls_back_to_default` → `TENANT_REQUIRED`
  for a real user document (which has no `customer` field).
- `test_edr_enrollment_cannot_create_tenancy` → refused, no tenant created.
- `test_edr_and_xdr_resolve_the_same_authority` → `edr_enrollment._tenant`,
  `edr_enrollment._agent_tenant` and the XDR collector resolution all return
  the **same `ten_*`**.

---

## 5 · TEST RESULTS

**New suite — 20 passed** (`tests/test_b4b5_tenant_registry_authority.py`):
opaque/prefixed ids · id accepted by the existing `_TENANT_RE` header pattern ·
slug/display_name mutable while identity is not · unknown tenant denied ·
missing tenant denied and never defaulted · inactive tenant denied · inactive
organization denies its ACTIVE tenant · active tenant resolves · collector
cannot create tenancy · API key cannot create tenancy · `allow_new_tenant`
refused · telemetry cannot create tenancy · EDR enrolment cannot create
tenancy · EDR admin no longer defaults · EDR and XDR resolve one authority ·
flag off preserves legacy behaviour exactly · flag on strictly stricter ·
legacy adoption preserves the existing string and is idempotent ·
`event_identity()` semantics unchanged · no `default` tenant is ever seeded.

**Regression with the flag OFF (default) — 275 passed / 15 skipped**
(`d14_tenant_authority`, `d15_declared_source_routing`, `d21_routing_visibility`,
`w1_sysmon_field_preservation`, `w1_forwarder_source_gate`,
`dcr1_detection_content_recovery`, `p0sec_rbac_fail_closed`,
`collector_api_key_auth`, `p0_ingest_idempotency`, plus the new suite).
Previous baseline was 255 passed / 15 skipped → **+20 new, zero regressions.**

**EDR suites — 62 passed, 1 pre-existing failure**
(`tests/edr/test_cross_tenant.py::test_v11_body_tenant_id_never_trusted`).
Proven pre-existing: with my changes stashed the test fails identically. It
asserts the response body mentions the tenant, but the request carries no
credential so P0-SEC refuses it earlier with `403 unauthenticated`. Untouched
by this change and NOT fixed here.

**Live control-plane smoke (preview only)**
`POST /api/xdr/organizations` → `org_330348bceeaba422e46aafc865` ·
`POST /api/xdr/tenants` → `ten_813aa3160190401f7723ce1c4e` ·
`GET /api/xdr/tenants?organization_id=…` → 1, `enforcing: false` ·
audit refs emitted (`ORGANIZATION_CREATED`, `TENANT_CREATED`) ·
`created_by` = `admin@nivxray.com` read from the **verified** JWT ·
anonymous `GET /api/xdr/organizations` → **403**, anonymous
`POST /api/xdr/tenants` → **403**. Both smoke objects were then set to
`ARCHIVED` so preview carries no stray ACTIVE tenancy.

---

## 6 · ENFORCEMENT FLAG BEHAVIOUR — PROVEN BOTH WAYS

`NIVX_TENANT_REGISTRY_ENFORCE` is read **per call**, never cached.

- **OFF (default, and the current state everywhere):** resolution is
  observational. Behaviour is byte-identical to the pre-registry code path,
  including the historical `"default"` fallback; every deviation
  (unregistered / inactive tenant) is logged as "would be refused when on".
  Evidence: 275 passed / 15 skipped, and
  `test_flag_off_preserves_the_legacy_behaviour_exactly`.
- **ON:** all four refusal codes fail closed. There is no branch in which
  enforcement becomes permission — the flag can only make the platform
  stricter, which is why it cannot create a fail-open condition.

**Measured consequence of switching it on before bootstrap** — run honestly and
reported rather than hidden: with the flag ON,
`tests/test_collector_api_key_auth.py` + `tests/test_d15_declared_source_routing.py`
returned **81 passed, 6 failed**. All six failures are positive-path tests that
use the *unregistered* tenant string `p0f-keyauth-test`
(`test_valid_key_authorizes_read`, `test_wildcard_scope_is_honoured`,
`test_global_wildcard_scope_is_honoured`, `test_last_used_is_stamped`,
`test_unexpired_key_is_accepted`, `test_jwt_admin_path_still_works`). That is
**correct enforcement**, not a defect, and it states the operational rule
precisely: **every tenant in use must be registered/adopted BEFORE the flag is
switched on in any environment.** Existing suites were deliberately not
rewritten in this change.

---

## 7 · COMPATIBILITY · DATA · MIGRATION

- **No existing `tenant_id` value is read, rewritten or renamed anywhere.**
  `services/ingest_idempotency.event_identity()` is untouched and asserted
  unchanged by test; the EDR raw-event dedupe digest is untouched.
- Legacy strings are handled by `tenant_registry.adopt_legacy()`: it inserts a
  `tenants` document whose `id` **is** the existing string with
  `kind:"LEGACY_ADOPTED"`, is idempotent, and is never automatic — it is an
  explicit administrative call, never a startup hook.
- Production is a clean slate (0 collectors, 0 keys, 0 incidents), so
  production needs **no adoption pass at all** — its first tenant can be a
  clean generated `ten_*`. Preview holds legacy strings and would be adopted
  before its flag is switched on.
- Nothing is migrated by deploying: code deployment and tenancy bootstrap stay
  separate, auditable operations.
- **Rollback:** unset `NIVX_TENANT_REGISTRY_ENFORCE` (instant, behaviour
  returns to the legacy path) or roll back the build. The two new collections
  are inert when enforcement is off; no data is destroyed in either direction.

---

## 8 · PROPOSED PRODUCTION BOOTSTRAP (owner-driven, after review)

1. Republish production with this build through the existing controlled process
   (flag **OFF** — behaviour identical to today, five new routes appear).
2. Verify: `/api/` 200 · `/api/health` 200 · OpenAPI **795** paths ·
   the 5 tenancy paths present · anonymous `GET /api/xdr/organizations` 403 ·
   anonymous ingest 403 · unknown key 401 · `GET /api/xdr/tenants` returns
   `count: 0, enforcing: false`.
3. Owner creates the authority (one JWT, no key, no telemetry):
   `POST /api/xdr/organizations {slug:"nivxmachines", display_name:"NivXMachines", kind:"VENDOR"}`
   → records `org_*`; then
   `POST /api/xdr/tenants {organization_id, slug:"internal-validation", display_name:"Internal Validation", kind:"INTERNAL_VALIDATION", products:["XDR","EDR"]}`
   → records `ten_*`. Both ids are platform-generated and immutable; neither is
   secret.
4. Confirm `GET /api/xdr/tenants` shows exactly one ACTIVE tenant under one
   ACTIVE organization, and that no collector, key or endpoint exists yet.
5. Set `NIVX_TENANT_REGISTRY_ENFORCE=true` in the production secrets and
   restart. Re-run step 2 plus: collector create with an unregistered tenant
   → 403 `TENANT_NOT_FOUND`; ingest with an unregistered tenant → 403.
6. **Only then** resume W1 Phase 3.1 under the generated `ten_*`: one
   collector (`protocol=rest`, `authorized_sources=["microsoft-sysmon"]`), one
   scoped key (`collectors.enroll`, short expiry, **no** `allow_new_tenant`),
   then the bounded 5-event transmission.

---

## 9 · BACKLOG AFTER THIS CHANGE

- **B3 — OPEN (unchanged).** `xdr_ingest._principal()` still prefers
  `X-Principal-Id` / `X-Principal-Kind` for machine-path AUDIT attribution.
  Authority unaffected. The new `xdr_tenancy._actor()` already demonstrates the
  target pattern (verified-token identity, client header ignored).
- **B4 — CLOSED** (implemented + tested; `allow_new_tenant` removal pending as
  a separate cleanup).
- **B5 — CLOSED** (implemented + tested).
- **B6 — NEW, OPEN, not fixed here.** `POST /api/v2/security-state/evaluate`
  (and its sibling security-state routes) have **no authentication dependency
  at all** and take `tenant_id` from the request body. This change adds registry
  validation of that tenant, so an unregistered/inactive tenant can no longer
  acquire security state, but the missing authentication is a separate security
  item and was deliberately left untouched.

---

## 10 · PRESERVED INVARIANTS

Tenant isolation, declared-source routing, canonical evidence provenance,
D14/D15, DCR-1 semantics, ACCEPTED ≠ EXECUTED ≠ CONTAINED ≠ VERIFIED,
PID ≠ process identity, IP ≠ endpoint identity, correlation ≠ attribution,
missing evidence ≠ permission to infer, replay PASS ≠ live-source PASS,
parser support ≠ telemetry availability — all unchanged and covered by the
275-test regression run.

**STOP — owner review required before republish and before bootstrap.**

---

# B6 SECURITY CLOSURE — `/api/v2/security-state/*`

**B6 CLOSED.**

## Files changed
| file | change |
|---|---|
| `security_state/routers/router.py` | router-level `dependencies=[Depends(require_permission("incidents.read")), Depends(_authorized_tenant)]` + new `_authorized_tenant()`; the inline registry call added earlier inside `evaluate` removed as superseded |
| `routers/xdr_rbac.py` | new `authorize_tenant()` — the shared principal↔tenant authorization contract |

No analytical semantics were altered: not one engine call, threshold, ledger
write or response shape changed.

## Authentication flow — before / after
```
BEFORE   any caller (no credential at all)
           → tenant_id read from request body or query
           → engines + persistence           ← any tenant, no authority

AFTER    require_permission("incidents.read")     (JWT or nvx_ key; else 403)
           → _authorized_tenant()
               tenant from query or body          = a REQUEST
               tenant_registry.authoritative()    exists + ACTIVE + org ACTIVE
               authorize_tenant()                 principal may act there
           → engines + persistence
```
All **14** security-state operations are covered by the router-level
dependency — `evaluate`, `{case_id}`, `history`, `transitions`, `causality`,
`capabilities`, `reachability`, `counterfactual`, `interventions/plan`,
`response/verify`, `ledger`, `streaming/status`, `provenance`,
`interventions/stage` — not `evaluate` alone.

## Tenant-authority rules implemented (`xdr_rbac.authorize_tenant`)
| principal | rule |
|---|---|
| machine (`nvx_` key) | may act ONLY in the tenant the credential is bound to; naming another → `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` |
| human, cross-tenant role (`admin`, `platform_admin`, `soc_manager`, `mssp_operator`) | permitted, exactly the authority `resolve_tenant_scope()` already grants elsewhere |
| human, tenant-scoped | permitted only for tenants in their VERIFIED user record |
| unauthenticated / forged token | `403 ACCESS_DENIED` |
| unknown / inactive tenant / inactive org | `403 TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE` / `ORGANIZATION_NOT_ACTIVE` |

No security-state-specific authority was invented; no client identity header is
trusted anywhere in this path.

## B6 proof (tests, enforcement ON)
- `test_b6_security_state_denies_unauthenticated` — `evaluate`, `{case_id}`,
  `streaming/status`, `interventions/stage` all **401/403** with no credential.
- `test_b6_security_state_denies_unregistered_tenant` — a VALID key cannot
  reach an unregistered tenant → **403 TENANT_NOT_FOUND**.
- `test_b6_security_state_denies_inactive_tenant` → **403 TENANT_NOT_ACTIVE**.
- `test_b6_machine_principal_cannot_name_another_tenant` → **403
  TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL**, while the same credential on its own
  tenant returns **200**.
- `test_b6_cross_tenant_human_principal_is_authorized` — verified token grants
  the tenant; the accompanying spoofed `X-Principal-Id` changes nothing.
- `test_b6_tenant_scoped_human_principal_cannot_reach_another_tenant` — own
  tenant permitted, sibling tenant refused.

---

# B3 SECURITY CLOSURE — machine-path audit attribution

**B3 CLOSED.**

## Files changed
| file | change |
|---|---|
| `routers/xdr_rbac.py` | new `verified_actor()` — the single actor-resolution mechanism |
| `routers/xdr_ingest.py` | `_principal()` now takes the actor from `verified_actor()` |
| `routers/xdr_tenancy.py` | `_actor()` delegates to `verified_actor()` (no second implementation) |

## Audit actor — before / after
```
BEFORE  pid = X-Principal-Id   or state.principal_id or "system@ingest"
        pkd = X-Principal-Kind or state.principal_kind or "system"
        → a client could choose the recorded actor on the machine path

AFTER   pid, pkd = verified_actor(request)
          1. request.state.principal_id/kind  (set by authenticate_api_key)
          2. `sub` of a bearer token verified with deps.JWT_SECRET/JWT_ALG
          3. otherwise (None, None) → the caller's own honest default
        X-Principal-Id / X-Principal-Kind are recorded on
        request.state.principal_claim as {"used": false} metadata and
        influence nothing.
```
Invariant now holds: **AUDIT ACTOR = VERIFIED AUTHENTICATED PRINCIPAL**.

## B3 proof (tests)
- `test_b3_verified_actor_ignores_client_claim_headers` — header-only request →
  `(None, None)`, claim recorded with `used=False`.
- `test_b3_verified_actor_prefers_machine_principal_state` → `apikey:key_real`
  even when a different `X-Principal-Id` is supplied.
- `test_b3_verified_actor_reads_only_a_verified_bearer_token` — valid token →
  its `sub`; forged token → `(None, None)`.
- `test_b3_ingest_actor_is_never_the_client_claim` — spoofed headers alone →
  `system@ingest`/`system`; with a real machine principal →
  `apikey:key_real`/`api_key`.

---

# REGRESSION RESULTS (after B6 + B3)

## Enforcement OFF (default)
`test_b4b5_tenant_registry_authority` (30) · `d14_tenant_authority` ·
`d15_declared_source_routing` · `d21_routing_visibility` ·
`w1_sysmon_field_preservation` · `w1_forwarder_source_gate` ·
`dcr1_detection_content_recovery` · `p0sec_rbac_fail_closed` ·
`collector_api_key_auth` · `p0_ingest_idempotency` ·
`edr/test_security_state_isolation` · `edr/test_cross_tenant` ·
`edr/test_p0_a2_enrollment` · `edr/test_p0_f5_response_identity`
→ **341 passed · 15 skipped · 0 errors · 1 failure**, the single failure being
the pre-existing `edr/test_cross_tenant::test_v11_body_tenant_id_never_trusted`
assessed below.

Two anomalies seen in an intermediate run (a `p0sec` failure and 10
`Event loop is closed` setup errors in `p0_ingest_idempotency`) were traced to
MY OWN test fixture: it had bound Motor outside a persistent event loop, which
poisoned sibling suites sharing an xdist worker. The fixture was corrected
(machine-principal HTTP tests only; human-principal authority asserted directly
against `authorize_tenant`) and both anomalies disappeared. **No production
code was changed to make tests pass.**

## Enforcement ON
- `test_b4b5_tenant_registry_authority` — **30 passed** with
  `NIVX_TENANT_REGISTRY_ENFORCE=true` (the suite registers its own tenants
  through the registry, as required).
- `collector_api_key_auth` with the flag ON: first run 27 passed / 6 failed,
  all six refused with `TENANT_NOT_FOUND` for the unregistered fixture tenant.
  The tenants were then **properly adopted** via `reg.adopt_legacy()` (correct
  registration, not a code change) → **32 passed / 1 failed**.
- The one remaining flag-ON failure is `test_jwt_admin_path_still_works`, and it
  is **correct enforcement, reported rather than papered over**: the test
  performs `GET /api/xdr/collectors` with an admin JWT and **no
  `X-Tenant-Id`**, so the answer is `403 TENANT_REQUIRED` — there is no default
  tenant. See B7 below; this is a production prerequisite, not a code defect.
- Note for reproduction: `backend/conftest.py` sets
  `DB_NAME=nivxray_ci_local`, so tenants must be adopted in **that** database
  for flag-ON runs, not in `test_database`.

## Suites with PRE-EXISTING failures (proven, unrelated)
`tests/test_xdr_api_keys.py` (7 failed) and `tests/test_xdr_rbac_enforcement.py`
(21 setup errors): identical results with every change of mine stashed
(`git stash` A/B). They send header-only identity and are refused by the
P0-SEC fail-closed gate. Not fixed here; out of scope.

---

# PRE-EXISTING EDR FAILURE — ASSESSMENT

`tests/edr/test_cross_tenant.py::test_v11_body_tenant_id_never_trusted`

**Verdict: the test expectation is STALE. There is no remaining defect.**
- Its first assertion — the request must be refused (`400/403/422`) —
  **passes**: the platform answers `403 ACCESS_DENIED / unauthenticated`.
- Its second assertion additionally requires the response text to contain the
  foreign tenant id or the string `TENANT_ISOLATION`. That was written when an
  unauthenticated header-only request still reached the tenant-isolation
  branch. Since P0-SEC (2026-09-09) `require_permission` fails closed **before**
  any tenant reasoning, so the refusal is earlier and the response
  deliberately does not echo tenant identifiers back — strictly less leakage.
- **Authentication order was NOT changed to make it green.** Recommended (not
  performed): accept `ACCESS_DENIED` as a valid refusal in that assertion and
  add a credentialed variant to exercise the isolation branch — which is
  already covered by `test_d14_tenant_authority`,
  `test_collector_api_key_adversarial_regression` and the new B4/B6 tests.

---

# REMAINING BLOCKERS TO PRODUCTION REPUBLISH

1. **B7 (NEW, owner decision, no code written).** With enforcement ON, every
   tenant-scoped control-plane call must name a tenant — a cross-tenant admin
   listing "all collectors" has no tenant to name and receives
   `403 TENANT_REQUIRED`. Before enforcement is enabled in production the owner
   must accept ONE of: (a) callers/UI always send `X-Tenant-Id` (the W1
   enrolment runbook already does), or (b) a future explicit cross-tenant
   listing contract is added. This does not block the republish itself, because
   the flag ships **OFF**.
2. **Preview-only tenant adoption** before preview's flag is switched on
   (production is a clean slate and needs none).
3. No other blocker. The build is otherwise ready: contract additions only,
   no migration, no new mandatory secret, rollback = unset the flag.

---

# FINAL STATUS

```
B4  CLOSED
B5  CLOSED
B6  CLOSED
B3  CLOSED
B7  OPEN  (owner decision, enforcement-on prerequisite, no code written)
NOT DEPLOYED
NOT BOOTSTRAPPED
W1 STILL PAUSED
```
