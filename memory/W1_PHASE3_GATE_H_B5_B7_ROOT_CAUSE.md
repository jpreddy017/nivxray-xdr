# GATE H ROOT-CAUSE REPORT — B5/B7 EDR CONTROL-PLANE TENANT BYPASS

Investigation only. No code edited. No production mutation. No tenant created
or adopted. Enforcement not weakened. No republish. W1 remains paused.

Production: publish 100 / build `8833215` · `NIVX_TENANT_REGISTRY_ENFORCE=true`
Build identity re-proved: prod OpenAPI == OpenAPI generated from the code in
this pod (795 paths, `prod_only=[]`, `cand_only=[]`, path-hash
`a0ca692d8710c7ff`, 0 schema bodies differing). The code analysed below IS the
code running in production.

---

## 0 · ROUTE IDENTITY CORRECTION (material to the diagnosis)

There are **two different** EDR endpoint-listing routes, and they have
different authority models:

| route | file | tenant authority |
|---|---|---|
| `/api/edr/enrollment/endpoints` | `routers/edr_enrollment.py:114` | **B5-converged** — `_tenant(user, request)` → `X-Tenant-Id` → `tenant_registry.authoritative()` |
| `/api/edr/endpoints` | `routers/edr.py:630` | **NOT converged** — `Depends(get_current_user)` only; no tenant parameter, no registry call |

The frozen Gate H probe targeted `/api/edr/enrollment/endpoints`. The observed
failure (`host ENG-42`, `source v2_shadow_observations`,
`tenant_attribution UNATTRIBUTED_LEGACY_OBSERVATION`) is the response shape of
`/api/edr/endpoints` — `routers/edr.py:630` merged with
`services/edr/device_identity.list_devices()`. `/api/edr/enrollment/endpoints`
returns `enrollment_state / credential_state / sensor_state` rows and a
`transport` block, and cannot produce that output.

This does not reduce the finding. `/api/edr/endpoints` is an authenticated EDR
control-plane read that **violates the approved B7 Option A contract**, and it
is reachable in production right now. It simply means the defect is in a route
the B5 work never touched, not a regression inside the converged route.

**Still to be confirmed by the owner:** the raw request line of the failing
Gate H call, so the record states exactly which URL produced
`NO_TENANT_RESULT : UNEXPECTED SUCCESS`.

---

## 1 · WHY THE ROUTE ACCEPTS A REQUEST WITHOUT EXPLICIT TENANT SCOPE

`routers/edr.py:630`
```python
@router.get("/endpoints")
async def list_endpoints(user=Depends(get_current_user)):
    q = _case_scope(user)
```
The signature has **no `Request`, no `X-Tenant-Id`, and no tenant argument**.
`routers/edr.py` does not import `services.tenant_registry` at all
(`grep -c tenant_registry routers/edr.py` → **0**).

Scope comes from `_case_scope(user)` / `_is_cross_tenant(user)`
(`routers/edr.py:37` and `:57`), both of which call
`services/dashboard_lenses.resolve_tenant_scope(user.email)`. That function
answers a different question:

- `resolve_tenant_scope` = *"which tenants is this principal authorised for?"*
- `tenant_registry.authoritative` = *"which single registered tenant is this
  request acting in?"*

A cross-tenant role returns `{"all_tenants": True}`, which the route treats as
"no filter". So for an owner/cross-tenant principal the route is a **global**
projection, and the absence of `X-Tenant-Id` is not an error state — it is
simply never read.

**Therefore `X-Tenant-Id` is silently ignored on this route.** The Gate H
"scoped" call was never scoped; it returned the identical global projection as
the unscoped call. Silent ignoring is worse than rejection: the caller
believes it asked a tenant-scoped question and got a tenant-scoped answer.

## 2 · DOES IT USE THE CONVERGED AUTHORITATIVE RESOLVER REQUIRED BY B5?

**No.** `routers/edr.py` never calls `tenant_registry`. Enforcement
(`NIVX_TENANT_REGISTRY_ENFORCE=true`) has **zero effect** on this route,
because enforcement is implemented inside `tenant_registry.authoritative()`
and that function is never reached. This is why enabling enforcement did not
close the hole and why no anonymous probe could have detected it.

## 3 · WHY AN EXPLICITLY SCOPED AUTHORITATIVE TENANT SEES `UNATTRIBUTED_LEGACY_OBSERVATION`

`services/edr/device_identity.py:31` states the substrate contract:
`v2_shadow_observations` **carries no `tenant_id`**.

`_attribute()` (`device_identity.py:148`) therefore labels such a row
`UNATTRIBUTED_LEGACY_OBSERVATION` with `tenant_id = None` — it refuses to
invent an owner. `list_devices()` (`device_identity.py:176`) then filters:

```python
if not all_tenants:
    out = [r for r in out
           if r["tenant_attribution"].startswith("ATTRIBUTED")
           and r["tenant_id"] in allowed]
```

So unattributed rows are released **only** to `all_tenants` principals. This
is the documented `EDR_TENANT_BOUNDARY` doctrine in
`services/session_context.py:28-38`: *"Observations that carry no owner stay
UNATTRIBUTED_LEGACY_OBSERVATION and are released to cross-tenant roles only;
they are never assigned to a customer by inference."*

The row was returned because the caller is a **cross-tenant principal**, not
because it was attributed to `ten_e759b7288598bd882e3dcac49d`. The row's
`tenant_id` is correctly empty and its label correctly says "no owner".

## 4 · IS THIS CROSS-TENANT DATA EXPOSURE, OR AN INTENTIONAL GLOBAL LEGACY PROJECTION?

**Intentional global legacy projection — with a real authority defect layered
on top.** Assessed separately:

| question | answer | basis |
|---|---|---|
| Can a tenant-scoped analyst see another tenant's device? | **No** | `list_devices` filters to `ATTRIBUTED*` rows whose `tenant_id ∈ allowed` |
| Can a tenant-scoped analyst see unattributed legacy rows? | **No** | same filter requires `ATTRIBUTED*` |
| Was unattributed evidence attributed to `ten_e759…`? | **No** | `tenant_id` empty, label `UNATTRIBUTED_LEGACY_OBSERVATION` |
| Does the route require an explicit tenant? | **No — DEFECT** | no tenant parameter exists |
| Does supplying `X-Tenant-Id` narrow the answer? | **No — DEFECT** | header never read |
| Does a wrong/unknown `X-Tenant-Id` get refused? | **No — DEFECT** | header never read, so no `TENANT_NOT_FOUND` is possible |

So: no confirmed cross-tenant *leak*, but a confirmed **B7 contract
violation** and a confirmed **silent-scope-ignoring** defect. The correct
verdict on Gate H is **FAIL**, and the owner's stop was correct.

### 4a · Secondary defect found while tracing (not the Gate H cause)
`services/dashboard_lenses.py:183`
```python
if not tenants:
    tenants = [str(user.get("tenant_id") or "default")]
```
A user document with no `tenant_id`/`tenant_ids` is still scoped to the
literal string **`"default"`**, entirely outside the registry. This is a
surviving remnant of the same class of defect as B5, on the authorisation
path rather than the authority path. It cannot fabricate tenancy (it only
filters), but it means "default" still exists as a scope concept in code.
Reported, not fixed.

### 4b · Separate P0 data-provenance question: `ENG-42`
`ENG-42` is a pre-existing, non-tenanted observation in the **production**
`v2_shadow_observations` collection. Under the Production Data Policy
("production must never contain seeded, fake, or demo data") a hostname of
that shape needs its origin established. This is a data question, not an
authority question, and it is **not** part of Gate H. Nothing was read from,
written to, or deleted in production. A read-only owner probe is proposed in
§7 — no deletion is proposed.

## 5 · WHICH TESTS CLAIMED B5 CLOSURE, AND WHY THEY MISSED THIS

`backend/tests/test_b4b5_tenant_registry_authority.py` contains exactly three
EDR assertions:

- `test_edr_enrollment_cannot_create_tenancy` → `POST /api/edr/agent/enroll`
- `test_edr_admin_plane_no_longer_falls_back_to_default` → calls
  `edr_enrollment._tenant()` **directly as a function**
- `test_edr_and_xdr_resolve_the_same_authority` → calls
  `edr_enrollment._tenant()` / `_agent_tenant()` **directly as functions**

Three reasons they could not catch it:

1. **Scope**: every assertion is about `routers/edr_enrollment.py`. B5 was
   defined and verified as "the *enrolment* plane converges on the registry",
   while the accepted contract as written to you was the broader "EDR
   control-plane access requires an explicit tenant". `routers/edr.py`
   (14 routes), `routers/edr_response.py` (8), `routers/edr_wave0.py` (10)
   were never in the test scope — **0 of those 32 routes import
   `tenant_registry`**.
2. **Unit, not route**: testing `_tenant()` as a function proves the resolver
   is correct; it cannot prove which routes call it. A route that never calls
   it is invisible to that style of test.
3. **No negative route test for the class**: there is no test of the form
   "for every tenant-scoped EDR route, a request without `X-Tenant-Id` returns
   `TENANT_REQUIRED`". That is the test that would have failed, and it does
   not exist.

## 6 · WHICH OTHER EDR READ ROUTES SHARE THE SAME BYPASS

`grep -c tenant_registry` per router: `edr.py` **0** · `edr_response.py` **0**
· `edr_wave0.py` **0** · `edr_enrollment.py` 6.

**`routers/edr.py` — 14 routes, all `get_current_user` only, none tenant-scoped:**
`/detections`, `/endpoint-detections`, `/process-tree`, `/campaign-story`,
`/observation-narrative`, `/file-trajectory`, `/fleet-spread-index`,
`/telemetry/freshness`, `/endpoints`, `/endpoints/{id}/trajectory`,
`/device-trajectory`, `/context`, `/endpoints/{id}/linked-incidents`,
`/endpoints/{id}/trajectory/focus`.

`/fleet-spread-index` (`edr.py:598`) is the most exposed of the set: it takes
no scope argument at all, not even `resolve_tenant_scope`.

**`routers/edr_response.py` — 8 routes**, including the **write/response**
surface `POST /actions`, `PUT /isolation-policy`. These use
`resolve_tenant_scope` but not the registry, so response actions are also not
bound to an explicit registered tenant. This is the highest-severity item in
the sweep because it is a *response* plane, not a read plane.

**`routers/edr_wave0.py` — 10 routes**, capability/sensor/contract metadata.
Mostly product-level metadata rather than tenant evidence; needs a
classification pass rather than an assumption.

## 7 · MINIMUM FAIL-CLOSED REMEDIATION PROPOSAL (for approval — NOT implemented)

Deliberately narrow. No new authority, no new store, no refactor.

**R1 — converge `/api/edr/endpoints` (closes Gate H).** Add `request: Request`
and resolve the tenant with the existing resolver already used by the
enrolment plane:
`tenant_registry.authoritative(request.headers.get("X-Tenant-Id"), purpose="edr.endpoints")`.
Missing → `TENANT_REQUIRED`. Unknown/inactive → `TENANT_NOT_FOUND` /
`TENANT_NOT_ACTIVE`. Then pass the resolved tenant into `_case_scope` and
`list_devices` as an additional narrowing filter **intersected with**
`resolve_tenant_scope` — never replacing it. Authority narrows; it never
widens. A cross-tenant principal naming `ten_e759…` gets `ten_e759…` only.

**R2 — unattributed legacy rows are never returned under an explicit tenant.**
Once R1 lands, an explicitly scoped request must exclude
`UNATTRIBUTED_LEGACY_OBSERVATION` / `TENANT_CONFLICT_FAILED_CLOSED` /
`TENANT_MISMATCH_FAILED_CLOSED`, because a request that names a tenant is
asking a tenant question and unowned evidence is not an answer to it. Keep
them visible only on an explicit, separately-named unattributed view so the
evidence is never hidden — just never mis-attributed. This closes the
`ENG-42`-under-`ten_e759…` observation without deleting any data.

**R3 — one shared dependency, applied per route deliberately.** Introduce a
single `edr_tenant()` FastAPI dependency wrapping `tenant_registry`, then
apply it route-by-route with an explicit classification of each of the 32
routes as `TENANT_SCOPED` or `PRODUCT_METADATA`. No blanket router-level
dependency: that would silently change the 10 `edr_wave0` metadata routes.
Priority order: `edr_response.py` (write/response) → `edr.py` evidence reads →
`edr_wave0.py` metadata classification.

**R4 — the test that would have caught this.** A route-level contract test
that enumerates the FastAPI route table, takes the routes classified
`TENANT_SCOPED`, and asserts for each: no `X-Tenant-Id` → `TENANT_REQUIRED`;
unregistered `X-Tenant-Id` → `TENANT_NOT_FOUND`; registered+ACTIVE → success.
Table-driven off the route table, so a **new** route is failed-closed by
default and must be explicitly classified. Plus a unit test for R2.

**R5 — retire the `"default"` remnant** at `dashboard_lenses.py:183`
(§4a). Smallest possible change: no implicit `"default"` scope; an
unassigned user gets an honest empty scope.

Invariants preserved by all of the above: missing explicit tenant →
`TENANT_REQUIRED` · unknown tenant → `TENANT_NOT_FOUND` · cross-tenant
authority ≠ implicit tenant · unattributed legacy evidence is never
attributable to the requested tenant · authority narrows, never widens.

**Read-only owner probes proposed (no mutation), for the record only:**
- the raw failing Gate H request line (§0)
- the raw Gate F output (§8)
- `GET /api/edr/endpoints` with a deliberately unregistered `X-Tenant-Id`, to
  record on the record that the header is ignored rather than refused
- `ENG-42` provenance: `GET /api/edr/endpoints/ENG-42/trajectory` +
  `GET /api/edr/fleet-spread-index` to establish origin. **No deletion.**

## 8 · GATE F — NOT REPRODUCIBLE AS DESCRIBED (kept separate, as instructed)

`/api/v2/security-state/streaming/status` **is present** in the deployed
production OpenAPI (`publish 100 / build 8833215`) — verified directly against
`https://nivxray.nivxforge.com/api/openapi.json`. It is one of **14**
`/api/v2/security-state/*` operations present. Its `get` declares a
**required query parameter `tenant_id`**.

It is correctly wired for B6: `security_state/routers/router.py:89` applies
router-level `dependencies=[Depends(require_permission("incidents.read")),
Depends(_authorized_tenant)]`, and `_authorized_tenant` (`:65`) resolves the
tenant via `routers.xdr_rbac.authorize_tenant(..., purpose="security_state")`.
My anonymous probe confirms it is live and fail-closed: `403 ACCESS_DENIED
incidents.read / unauthenticated` for the bare path, for
`?tenant_id=default`, and for `?tenant_id=ten_e759…`.

So the route is **not absent**. Most likely causes of the Gate F observation,
in order: (a) a required-parameter rejection (`422`) read as "absent", (b) a
path-spelling difference, (c) a `404` from an unrelated URL. I have **not**
invented a substitute route and have **not** re-run Gate F. Please paste the
raw Gate F output/status code and I will classify it. Gate F is
**INCONCLUSIVE — evidence pending**, not BLOCKED-by-absence.

## 9 · STATUS

```
A  PASS
B  PASS
C  PASS
D  PASS
E  PASS
F  INCONCLUSIVE - route present + correctly wired; raw owner output needed
G  PASS (no side effect; tenant_count still 1)
H  FAIL - /api/edr/endpoints has no tenant authority at all (routers/edr.py:630)
I  NOT RUN - hard stop honoured
```
Root cause: **B5 convergence was scoped to `routers/edr_enrollment.py` only.
32 further EDR routes across `edr.py` / `edr_response.py` / `edr_wave0.py`
never call `tenant_registry`, so enforcement cannot reach them.** Not a
regression, not an enforcement failure, not a data-authority failure — a
coverage gap in the convergence, proven by production behaviour.

Nothing implemented. Awaiting owner approval of R1–R5 scope.
W1 Phase 3 stays paused.
