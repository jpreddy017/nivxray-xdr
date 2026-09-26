# PLATFORM ORG / TENANT AUTHORITY DESIGN — INSPECTION & DESIGN ONLY

Date 2026-09-17 · Backend inspected at HEAD (contract-identical to the build
now live in production). **Nothing implemented. No org, no tenant, no
collector, no key, no telemetry, no DB write, no deploy.** W1 Phase 3.1 stays
paused. Sections are labelled **[PROVEN]**, **[RECOMMENDATION]**, **[FUTURE]**.

---

## 1 · REPOSITORY / PRODUCT DEPENDENCY MAP **[PROVEN]**

Classification: **A** shared platform/control-plane · **B** NivXRay XDR only ·
**C** NivXForge EDR only · **D** Workspace/company-facing · **E** deployment.

| Component (file) | Class | Tenant behaviour observed |
|---|---|---|
| `routers/auth.py` (`/api/auth/login|me|change-password`) | **A** | Issues the only human bearer token. Token carries `email` only — **no tenant, no org** (`create_token(body.email)`, line 61). |
| `deps.py::seed_admin` (`users` collection) | **A** | Seeds `{email, password, role:"admin", must_change_password}` — **no `tenant_id`, no `tenant_ids`, no `customer`** (lines 373-379). |
| `services/dashboard_lenses.py::resolve_tenant_scope` | **A** (consumed by B and D) | Reads `users.role/tenant_id/tenant_ids`. `_CROSS_TENANT_ROLES = {admin, platform_admin, soc_manager, mssp_operator}` → `all_tenants=True`, no `tenant_ids`. Otherwise falls back to the literal `"default"` (line 183). |
| `services/session_context.py` | **A** (consumed by B and C) | `customers` is an **aggregation over `workspace_cases` incidents**, not a registry (lines 46-63). `active_customer=null` for cross-tenant roles. |
| `routers/xdr_rbac.py` (`xdr_users`, `xdr_roles`, `xdr_groups`, assignments) | **A** | Control-plane RBAC store, tenant from `X-Tenant-Id` header else `"default"`. **Separate store from the `users` login collection.** |
| `routers/xdr_api_keys.py` | **A** (used by B today) | Machine credentials. `_principal()` → header else `"default"`; `_tenant_is_known()` over `xdr_users/xdr_roles/xdr_collectors/xdr_api_keys`; `confirm_tenant_id` + `allow_new_tenant`. |
| `routers/xdr_collectors.py` | **B** | `tenant_id` taken verbatim from `X-Tenant-Id` (else `"default"`), **no existence check, no format check** → B4. |
| `routers/xdr_ingest.py` + `services/source_routing.py` | **B** | Runtime chain: key tenant == header tenant == envelope tenant == collector tenant, else 403. Declared-source allowlist fail-closed. |
| `services/tenant_authority.py` (D14) | **A** (used by every DSM) | Suppresses payload tenant CLAIMS; records them as evidence. **It is not a tenant registry** — it only guarantees "authenticated tenant wins, no `default` fallback". |
| `services/ingest_idempotency.py::event_identity` | **B** | `tenant_id` is **inside the canonical identity digest** (line 139-145) and inside the Mongo indexes (line 122). |
| `detection_content/**` (DSMs, rules, DCR-1) | **B** | Consume the resolved tenant; never choose one. |
| `services/multi_evidence_incident.py`, `routers/incidents.py`, `workspace_cases` | **B**+**D** | Incidents carry `tenant_id`; the same collection backs Workspace cases (shared collection, separated by `doc_type`). |
| `edr_plane/enrollment/{store,identity,security,transport}.py` | **C** | Every store function takes `tenant_id` explicitly and filters on it. Machine secrets = HMAC-SHA-256 with `EDR_AUTH_PEPPER`, prefixes `enr`/`eak`/`est`. **A second machine-credential mechanism, independent of `xdr_api_keys`.** |
| `routers/edr_enrollment.py` | **C** | **`_tenant(user) = (user or {}).get("customer") or "default"` (lines 39-40).** No code anywhere writes `customer` onto a user document → **today every EDR enrolment token is minted into the literal tenant `"default"`.** Agent surface takes `tenant_id` from the request body, bound only by the tenant-scoped one-time token. |
| `edr_plane/response.py`, `edr_plane/isolation_policy.py`, `routers/edr_response.py` | **C** | `REQUESTED→DISPATCHED→EXECUTED→VERIFIED`; tenant carried from the authenticated endpoint record. |
| `edr_plane/canonical_bridge.py`, `edr_plane/raw_events.py` | **C→B** | EDR raw events dedupe on `sha256(tenant_id · source · payload)` (raw_events.py:110-122) and bridge into XDR canonical evidence carrying that tenant. |
| `security_state/**` (`/api/v2/security-state`) | **B** | Own `AuthenticatedPrincipal{principal_id, tenant_id, transport_mechanism}` derived from transport credentials (`streaming/auth.py`). **A third tenant-derivation rule.** |
| `apps/nivxray-xdr` (Vite) | **B**+**C** UI | Deployed to Vercel `xdr.nivxforge.com`; reads tenant from the session-context endpoint. |
| `apps/nivxray-xdr-collector`, `apps/nivxray-xdr-response` | **B** runtimes | Not deployed. `routes/preflight.py` **sends a synthetic envelope** — must never be used on a real-source path. |
| `frontend/` (CRA, incl. `src/nivxforge`) | **D** | The Workspace app; this is what the Emergent deployment serves at `/`. |
| Emergent deployment (backend + `frontend/`), Vercel projects, `scripts/refuse-root-deployment.sh` | **E** | One backend, three frontend deployment targets. |

### Blast radius of a tenant-authority change **[PROVEN]**
- **XDR:** `xdr_collectors`, `xdr_api_keys`, ingest authority chain, canonical
  identity digest + indexes, detections, correlation, incidents, audit log,
  `security_state`.
- **EDR:** enrolment tokens/credentials/sessions/endpoints, raw-event dedupe
  digest, response commands, isolation policy, the canonical bridge.
- **Workspace (NivXMachines-facing):** `workspace_cases` is shared with the
  XDR incident plane and `session_context.customers` is computed from it, so a
  change to how tenants resolve is visible in the Workspace surfaces too.
- **Not affected:** detection content authorship metadata (`organization` in
  `detection_content/**` is a rule-author field, unrelated to tenancy).

---

## 2 · CURRENT TENANT AUTHORITY / DATA FLOW **[PROVEN]**

```
human bearer token (email only, no tenant)
   ├─ XDR control plane   → X-Tenant-Id header ─────────────► else "default"
   ├─ XDR incident plane  → users.role/tenant_id/tenant_ids ► else "default"
   ├─ EDR admin plane     → users["customer"] ──────────────► ALWAYS "default" today
   └─ security_state      → transport credential principal

machine credentials
   ├─ XDR  nvx_ key (xdr_api_keys, SHA-256)  → tenant fixed at mint
   └─ EDR  enr/eak/est (HMAC + pepper)       → tenant fixed at enrolment

ingest → tenant_authority.resolve() → payload claims recorded, never used
       → event_identity(tenant_id, collector_id, source, source_event_id, sha256(raw))
       → canonical evidence → detection → incident (workspace_cases.tenant_id)
```

**Four independent tenant-resolution rules, three different `"default"`
fallbacks, two machine-credential systems, two user stores (`users` for login,
`xdr_users` for RBAC), and no object anywhere that says "this tenant exists and
is active".**

---

## 3 · THE EXACT WEAKNESS B4 EXPOSES **[PROVEN]**

1. Tenancy is **implied by the first write**, not asserted by an authority.
   `POST /api/xdr/collectors` accepts any `X-Tenant-Id` string; the document it
   writes then makes `_tenant_is_known()` true, which in turn satisfies the
   key-minting guard. A typo bootstraps a real, usable tenant.
2. The guard asymmetry is backwards: the **credential** path validates tenant
   evidence, the **resource** path does not.
3. `"default"` is reachable by *omission* on three planes — the weakest
   possible way to acquire an authority.
4. `tenant_id` is inside the canonical identity digest and the EDR dedupe
   digest, so a wrong tenant is not a label mistake — it **partitions evidence
   into a different identity space**, and correcting it later changes those
   digests.
5. EDR today resolves to `"default"` unconditionally, so a Windows XDR
   collector enrolled into `nivx-prod-win-1` and an EDR sensor enrolled from
   the same console would land in **different tenants** with no error.

---

## 4 · INDUSTRY PATTERN COMPARISON (principles only) **[RECOMMENDATION]**

| Platform | Principle we take | Principle we reject |
|---|---|---|
| Cisco XDR | An **Organization** object exists before any device/integration; integrations are *granted* to an org | Their UI/entitlement specifics |
| Cortex XDR / XSIAM | Parent/child tenant hierarchy for MSSP; child data isolated, parent gets read-across | Their multi-tenant console internals |
| Microsoft Defender XDR | Tenant identity comes from the **identity provider**, not from telemetry; multitenant views are an *authorisation overlay*, never a data merge | Entra-specific graph model |
| CrowdStrike Falcon | Immutable opaque **CID** as the permanent security identifier; human names are display-only | Their sensor grouping semantics |
| Sophos Central | Enterprise → sub-estate, sub-estate remains the data boundary | Their licensing model |

**Common invariant in all five:** the tenant/organization exists
*independently* of telemetry, collectors, endpoints, detections and incidents,
is created by an explicit administrative act, has an immutable identifier and a
lifecycle state, and every data-plane write is *validated against* it.
Our platform currently satisfies none of those five properties.

---

## 5 · RECOMMENDED MODEL: `Organization → Tenant` **[RECOMMENDATION]**

Not "Organization = Tenant". Two levels, introduced now, because:
- NivXMachines itself is an **organization that owns tenants**, not a tenant —
  exactly the distinction the owner stated;
- the internal production-validation environment (this Windows laptop) must be
  a **tenant of the NivXMachines organization**, isolated from any future
  customer tenant, without pretending to be a customer;
- MSSP / parent-child / enterprise sub-estate all collapse into
  "organization owns N tenants" with no third level;
- a single-tenant customer is just an organization with one tenant, so the
  simple case costs one extra document, not a new code path;
- collapsing to one level later is impossible; adding the parent later means
  rewriting every authorization call site.

Hierarchy depth is fixed at two. Nested organizations are **[FUTURE]** and
deliberately out of scope.

---

## 6 · MINIMAL DATA MODEL **[RECOMMENDATION]**

```
organizations                         tenants
  id            org_<26-char ulid>      id             ten_<26-char ulid>
  slug          nivxmachines            organization_id org_...
  display_name  NivXMachines            slug           prod-win-1
  kind          VENDOR|CUSTOMER|MSSP    display_name   Production Windows Validation
  state         ACTIVE|SUSPENDED|       kind           INTERNAL_VALIDATION|CUSTOMER|LAB
                ARCHIVED                state          ACTIVE|SUSPENDED|ARCHIVED
  created_at/by                         products       ["XDR","EDR"]   <- entitlement stub only
                                        created_at/by
```
Two collections. No billing, no quotas, no usage metering, no invoicing —
those are **[FUTURE]** extension points hanging off `tenants.products`.

`principal_tenant_grants` is **[FUTURE]**: for now the existing
`_CROSS_TENANT_ROLES` + `xdr_users.tenant_id` continue to answer "may this
principal act in this tenant?", so RBAC is not rewritten in the same step as
tenancy.

---

## 7 · IMMUTABLE IDENTIFIER STRATEGY **[RECOMMENDATION]**

- `tenants.id = "ten_<opaque>"` — never a hostname, customer name, product
  name or operator string. Immutable for life; renames touch `display_name`
  and `slug` only.
- **The existing `tenant_id` field keeps carrying the value** — it is already
  a free-form string 1-128 chars in every collection and index, so
  `tenant_id = "ten_01J..."` requires **no schema replacement**. This is the
  decisive compatibility fact: because `tenant_id` participates in
  `event_identity()` and in the EDR dedupe digest, the value must never be
  rewritten in place for existing evidence. Existing tenant strings are
  therefore **adopted as legacy tenants, not renamed** (see §11).
- `slug` is unique per organization and mutable; it is a lookup convenience,
  never an authorization key.

---

## 8 · AUTHORITY / RBAC FLOW **[RECOMMENDATION]**

```
request (bearer JWT | nvx_ key | EDR session | transport credential)
   → resolve authenticated principal
   → resolve requested tenant   (header / key binding / endpoint record)
   → LOOKUP tenants.id          ── unknown  → 404/403 TENANT_NOT_FOUND   (fail closed)
   → verify tenants.state=ACTIVE ── else     → 403 TENANT_NOT_ACTIVE      (fail closed)
   → verify organizations.state=ACTIVE
   → verify principal may act in that tenant ── else → 403 ACCESS_DENIED
   → tenant-scoped operation
```
One resolver (`services/tenant_registry.py`, new) called by **all four**
existing resolution sites, replacing three independent `"default"` fallbacks.
Invariants to enforce:
- collector creation, key creation, endpoint enrolment **must not** create
  tenancy;
- telemetry and incident creation **must never** establish tenancy;
- omission of `X-Tenant-Id` is a refusal, not `"default"`.

**`allow_new_tenant` should be deprecated** once the registry exists: it is a
bootstrap escape hatch whose only purpose was to compensate for the absent
registry. Keep it for exactly one release as a no-op that logs, then remove.
Bootstrap moves to an explicit `POST /api/xdr/organizations` +
`POST /api/xdr/tenants` pair requiring a new `tenants.manage` permission
(the permission vocabulary already reserves `tenants: [read, manage]`,
`xdr_rbac.py:125`, currently backed by no route).

---

## 9 · PROPOSED BOOTSTRAP + ENROLMENT FLOW **[RECOMMENDATION]**

```
platform_admin
  → POST /api/xdr/organizations {slug:"nivxmachines", kind:"VENDOR"}      → org_...
  → POST /api/xdr/tenants {organization_id, slug:"prod-win-1",
                           kind:"INTERNAL_VALIDATION", products:["XDR","EDR"]} → ten_...
  → POST /api/xdr/collectors      X-Tenant-Id: ten_...   (tenant must already exist)
  → POST /api/xdr/api-keys        confirm_tenant_id: ten_...  (no allow_new_tenant)
  → POST /api/edr/enrollment/tokens  X-Tenant-Id: ten_...  (replaces users["customer"])
  → sensor/forwarder authenticates → tenant comes from the credential, never the body
```
Same `ten_...` identity for the XDR collector, the EDR sensor, the canonical
evidence, the detection, the incident and the response verification. **No
XDR↔EDR translation table** — there is nothing to translate.

---

## 10 · FILES / ROUTES / COLLECTIONS THAT WOULD CHANGE **[RECOMMENDATION]**

New: `services/tenant_registry.py`, `routers/xdr_organizations.py`,
`routers/xdr_tenants.py`, collections `organizations`, `tenants`.

Modified (authority call sites only — no business logic):
`routers/xdr_collectors.py::_principal/create_collector` (validate + drop the
`"default"` fallback) · `routers/xdr_api_keys.py::_principal/create_key`
(validate; deprecate `allow_new_tenant`; keep `confirm_tenant_id`) ·
`routers/xdr_audit_log.py::_principal` · `routers/edr_enrollment.py::_tenant`
(**the `users["customer"]` bug — replace with the registry-backed resolution**)
· `services/dashboard_lenses.py::resolve_tenant_scope` (remove the `"default"`
fallback) · `services/session_context.py` (report registry tenants, keep the
incident-derived customer counts as a separate field) ·
`security_state/streaming/auth.py` (validate the principal's tenant against the
registry) · `server.py` (router registration).

Untouched by design: every DSM, `services/tenant_authority.py`,
`services/source_routing.py`, `services/ingest_idempotency.py`,
`detection_content/**`, `edr_plane/response.py`.

---

## 11 · EXISTING DATA / MIGRATION / ROLLBACK **[RECOMMENDATION]**

- **Additive only.** Create `organizations` + `tenants`; for every distinct
  `tenant_id` already present in `xdr_collectors`, `xdr_api_keys`, `xdr_users`,
  `edr_endpoints`, `workspace_cases`, `xdr_canonical_evidence`, insert a
  `tenants` document **whose `id` is that existing string** and
  `kind:"LEGACY_ADOPTED"`, owned by the NivXMachines organization.
- **No value is rewritten**, therefore `event_identity()` digests, the EDR
  dedupe digests and every index stay byte-identical. This is the only safe
  option and it is the reason the design reuses `tenant_id`.
- Production is a clean slate (0 collectors, 0 keys, 0 incidents), so the
  adoption pass there is expected to insert **zero or one** legacy tenant;
  preview will adopt its existing strings.
- **Rollback:** the registry lookup is feature-flagged
  (`NIVX_TENANT_REGISTRY_ENFORCE=false` → log-only). Rollback = flip the flag,
  or roll back the Emergent build; the two new collections are inert when not
  enforced. No data is destroyed at any point.

---

## 12 · REQUIRED TESTS **[RECOMMENDATION]**

Security/fail-closed: unknown tenant → refusal on collector create, key mint,
EDR token mint, ingest; `SUSPENDED` tenant → refusal on all four; omitted
`X-Tenant-Id` → refusal, never `"default"`; cross-org tenant access → refusal;
tenant rename changes `display_name` only and leaves `event_identity()`
unchanged; collector/key/endpoint/telemetry/incident creation each proven
**not** to create a tenant.
Regression (must stay green, unchanged): `test_d14_tenant_authority`,
`test_d15_declared_source_routing`, `test_d21_routing_visibility`,
`test_w1_sysmon_field_preservation`, `test_w1_forwarder_source_gate`,
`test_dcr1_detection_content_recovery`, `test_p0sec_rbac_fail_closed`,
`test_collector_api_key_auth`, `test_p0_ingest_idempotency` (today 255 passed /
15 skipped), plus the EDR enrolment/response suites.

---

## 13 · IMPLEMENTATION SEQUENCE **[RECOMMENDATION]**

1. `organizations` + `tenants` collections, `services/tenant_registry.py`,
   read-only resolution, flag **off**. No behaviour change.
2. `POST/GET /api/xdr/organizations`, `POST/GET /api/xdr/tenants` behind the
   existing `tenants.manage` / `tenants.read` permissions.
3. Legacy adoption pass (additive, idempotent, no value rewrite).
4. Enforcement at the four resolution sites behind the flag; fail-closed tests.
5. Fix `edr_enrollment._tenant` (**closes the `"default"` EDR defect**).
6. Deprecate `allow_new_tenant`; require an existing tenant for collector and
   key creation (**closes B4**).
7. Enable enforcement in preview, run the full gate set, then production.

---

## 14 · CAN W1 RESUME IMMEDIATELY? **[RECOMMENDATION]**

**Two honest options — owner's choice:**

- **Option 1 · resume W1 now, tenant-registry later.** Enrol the Windows
  collector under one deliberately chosen tenant string that will later be
  *adopted* as a legacy tenant (no rename, no digest change). Cost: the tenant
  is still implied by the first write (B4 remains open) and the EDR side would
  still land in `"default"` until step 5. Benefit: first genuine Windows
  telemetry this week; nothing has to be undone afterwards.
- **Option 2 · steps 1-6 first, then enrol.** W1 Phase 3.1 waits for a
  backend change plus a production republish. Benefit: the very first
  production tenant is created by a real authority and B4 + the EDR `"default"`
  defect are closed before any endpoint exists.

Either way the *identifier* must be chosen deliberately now, because it is
immutable in practice. If the registry is built first, that identifier becomes
`ten_<opaque>` and no legacy adoption is needed for it at all — which is the
cleaner outcome and the one this report recommends.

---

## 15 · BACKLOG STATUS

- **B3 — OPEN.** `routers/xdr_ingest.py::_principal()` prefers
  `X-Principal-Id` / `X-Principal-Kind` headers for machine-path AUDIT
  attribution. Authority unaffected. Fix: derive from
  `request.state.principal_id` set by `authenticate_api_key()` and ignore the
  client headers on the machine path. Independent of this design; small.
- **B4 — OPEN, closure defined.** Closed by steps 1, 2, 4 and 6 above
  (registry exists → collector create validates → `allow_new_tenant` removed).
- **B5 — NEW, OPEN.** `routers/edr_enrollment.py:39-40`
  `_tenant(user) = user["customer"] or "default"` while no code ever writes
  `customer` → **all EDR enrolment today is tenant `"default"`**. Proven from
  code, not inferred. Closed by step 5.

---

## 16 · PRESERVED INVARIANTS

Nothing in this design weakens tenant isolation, declared-source routing,
canonical evidence provenance, D14/D15, DCR-1 semantics, or
ACCEPTED ≠ EXECUTED ≠ CONTAINED ≠ VERIFIED · PID ≠ process identity ·
IP ≠ endpoint identity · correlation ≠ attribution · missing evidence ≠
permission to infer · replay PASS ≠ live-source PASS · parser support ≠
telemetry availability. The design only makes the tenant an *asserted* rather
than an *implied* authority, and it never rewrites an existing identity value.
