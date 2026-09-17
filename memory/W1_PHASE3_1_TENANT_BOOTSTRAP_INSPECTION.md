# W1 PHASE 3.1 · TENANT BOOTSTRAP INSPECTION — READ ONLY

Verified 2026-09-17 against the aligned code now live in production
(`8e473e4`, contract-identical to accepted HEAD). Nothing created, nothing
modified, `default` not used, no tenant invented, no telemetry.

## 1 · There is NO tenant/customer entity in this platform

Searched the whole backend: there is no `tenants` or `customers` collection,
no `/api/xdr/tenants*` and no `/api/xdr/customers*` router. `"tenants"` exists
only as an RBAC permission vocabulary entry (`xdr_rbac.py:125`), which grants
authority over an object kind that has no CRUD surface.

`tenant_id` is a **string attribute carried by documents**, not a row in a
tenant table: `xdr_users`, `xdr_roles`, `xdr_collectors`, `xdr_api_keys`,
`xdr_audit_log`, `workspace_cases`, canonical evidence, `edr_endpoints`.

## 2 · Why session-context looks "empty" — it is CORRECT, not broken

`services/session_context.py:40-63` — `customers` is **derived from real
incidents**, not from a customer registry:

```
_cases = sync_collection("workspace_cases")
q = _scope({}, email)                       # doc_type == "xdr_incident"
$group by $ifNull[$tenant_id, $ifNull[$user_email, "default"]]
```

So `customers = []` means exactly one thing: **production has no XDR incident
documents yet**. It does not mean a bootstrap object is missing.

`services/dashboard_lenses.py:159-185` — a cross-tenant role returns
`{"authorized": True, "all_tenants": True}` and deliberately carries **no**
`tenant_ids`. `session_context.py:82-83` then refuses to pick one:
`active_customer = null`, `basis = CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`.

That is the designed answer for a platform admin: the platform will not invent
an active tenant for a principal authorised for all of them. **Conclusion:
`/api/xdr/rbac/session-context` is the wrong instrument for choosing an
enrolment tenant, and the owner was right to stop.**

## 3 · Is `default` a real tenant?

No. `default` appears only as a **fallback literal** in three places:
`_principal()` in the control-plane routers (`xdr_collectors.py:80-81`,
`xdr_api_keys.py:55-56`, `xdr_audit_log.py:330`), the `$ifNull` chain of the
customer aggregation, and `resolve_tenant_scope`'s single-tenant fallback.
Nothing seeds a tenant named `default`; no document is created with it unless
a caller omits `X-Tenant-Id`. Using it would mean accepting a fallback as an
authority — correctly refused.

## 4 · What actually establishes an authoritative tenant

**The first control-plane object minted with that `tenant_id`.** There is no
other mechanism, and the code states it explicitly:
`xdr_api_keys.py:86-100` — `_TENANT_EVIDENCE = ("xdr_users", "xdr_roles",
"xdr_collectors", "xdr_api_keys")`; `_tenant_is_known()` returns True as soon
as ONE of those holds a document with that tenant. `create_key` refuses with
`UNKNOWN_TENANT` (line 146-153) unless the tenant is already evidenced or the
operator sets `allow_new_tenant=true`, whose docstring is literally
"Explicitly acknowledge minting the first-ever credential for a tenant that
has no users, roles, collectors or keys yet" (line 110-112).

Ordering consequence: **create the collector first** — it becomes the tenant's
first evidence object, after which the key mints WITHOUT `allow_new_tenant`.

`allow_new_tenant=true` on key creation is a guard override, **not** a
bootstrap of anything else: `create_key` writes one document into
`xdr_api_keys` and nothing more (lines 163-191). It creates no customer, no
tenant record, no RBAC binding. Answer to the owner's question: it is intended
to bootstrap a tenant only in the sense of "mint the first credential for one";
it does NOT produce a complete authoritative tenant/customer object, because
no such object type exists.

## 5 · Orphan risk — REAL, and asymmetric (finding)

`create_collector` (`xdr_collectors.py:352-407`) takes `tenant_id` verbatim
from `X-Tenant-Id` with **no existence check and no format validation**. A
typo therefore silently creates a collector in a tenant nobody will ever look
at — the `_tenant_is_known` guard exists only on the key path. Mitigations
that already exist:
- everything is tenant-scoped on read (`GET /api/xdr/collectors` filters
  `{"tenant_id": ten}`), so the mistake is visible only by querying the same
  wrong tenant;
- `DELETE /api/xdr/collectors/{cid}` (line 654) is tenant-scoped and can
  remove it;
- `COLLECTOR_CREATED` is audit-logged with the tenant.
Operational rule for 3.1A: the `X-Tenant-Id` header and a re-read of the
created document must be checked character-for-character before the key is
minted.

## 6 · Tenant identifier format

No regex, no catalog, no reserved list. Only constraint in code:
`confirm_tenant_id` is 1-128 chars (`xdr_api_keys.py:109`). `_NAME_RE`
(line 173 of the collectors router) constrains the collector NAME, not the
tenant. Format is therefore an operator convention, and this workspace already
has an owner-approved precedent:
`memory/PRODUCTION_COLLECTOR_ENROLMENT_nivx-prod-1.md` chose the dedicated
tenant `nivx-prod-1` (lowercase, hyphenated, deliberately isolated from the
login tenant) with `allow_new_tenant: true`.

## 7 · Must the tenant exist before collector creation?

No — and it cannot, since there is nothing to pre-create. The correct order is
collector -> key, because the collector supplies the tenant evidence the key
guard demands. The ingest path then enforces the chain at runtime
(`xdr_ingest.py`): key tenant == `X-Tenant-Id` == every envelope `tenant_id`
== `xdr_collectors.tenant_id`, otherwise `403 TENANT_ISOLATION_VIOLATION`.

## 8 · Can an existing legitimate tenant be discovered read-only?

**No enumeration endpoint exists.** Audit-log listing is per-tenant
(`xdr_audit_log.py:175-177` — `tenant = tenant or ten`, then
`{"tenant_id": tenant}`), collectors/keys/users/groups all filter by the
resolved tenant. There is no `distinct("tenant_id")` anywhere in the codebase.

So existence can only be PROBED per candidate, read-only, owner-side:

```powershell
foreach ($t in @('default','nivx-prod-1')) {
  $h = @{ Authorization="Bearer $tok"; 'X-Tenant-Id'=$t }
  $c = (Invoke-RestMethod -Uri "$Api/api/xdr/collectors" -Headers $h).data.count
  $k = (Invoke-RestMethod -Uri "$Api/api/xdr/api-keys"   -Headers $h).data.count
  $u = (Invoke-RestMethod -Uri "$Api/api/xdr/rbac/users" -Headers $h).data.count
  $a = (Invoke-RestMethod -Uri "$Api/api/xdr/audit-log?limit=5&tenant=$t" -Headers $h).data.count
  "{0}: collectors={1} keys={2} rbac_users={3} audit={4}" -f $t,$c,$k,$u,$a
}
```
These are GETs only; reading a tenant is not using it. If every candidate
returns zeros, production genuinely holds no control-plane tenant yet and the
Windows tenant will be the first one — which is the normal state of a fresh
install, not a defect.

## 9 · How session-context will look AFTER a correct bootstrap

Unchanged, and that is expected:
- `all_tenants` stays `true` and `tenant_ids` stays `[]` for a cross-tenant
  admin (by design, `dashboard_lenses.py:179-180`);
- `customers` stays `[]` until the first **incident document** exists for that
  tenant — creating a collector or a key will NOT populate it;
- `active_customer.basis` stays `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`.
The customer pill will only light up after Windows telemetry becomes canonical
evidence, fires a detection and is promoted to an incident carrying that
`tenant_id`. That is the honest acceptance signal for W1, not a config step.

## 10 · The one safe zero-write authority proof (use this, not preflight)

`POST /api/xdr/ingest/telemetry` with `{"envelopes":[]}` returns
`400 "empty batch"` (`xdr_ingest.py:700-701`) **after** authentication, tenant
authority, scope and rate-limit checks and **before** any write. That is the
sanctioned way to prove the credential/tenant/collector triple without
creating a single row — the same proof already used in the `nivx-prod-1`
runbook.

DO NOT use `/api/xdr/collector/ingest-preflight`. That route belongs to the
separate collector runtime (`apps/nivxray-xdr-collector/routes/preflight.py`)
and it DELIVERS A SYNTHETIC ENVELOPE. Synthetic evidence must never enter the
real-source path.

## 11 · Exact existing bootstrap procedure (owner-side, unchanged code)

1. Choose a dedicated tenant identifier for this Windows host, in writing,
   e.g. `nivx-prod-win-1`. Do not use `default`. The agent will not invent it.
2. Probe it read-only (§8) and confirm all four counts are 0 — proving it is
   genuinely new and not colliding with an existing tenant.
3. `POST /api/xdr/collectors` with `X-Tenant-Id: <that tenant>` — this is the
   tenant-establishing act (state `ADOPTED`, counters 0,
   `authorized_sources: ["microsoft-sysmon"]`).
4. Re-read `GET /api/xdr/collectors/{id}` with the same header and verify
   `tenant_id` character-for-character.
5. `POST /api/xdr/api-keys` with `confirm_tenant_id: <that tenant>`,
   `scopes: ["collectors.enroll"]`, short `expires_at`. `allow_new_tenant`
   should now be unnecessary — if the API still demands it, step 3/4 did not
   land in the tenant you think it did. That is a designed tripwire; stop and
   re-check rather than overriding it.
6. Zero-write authority proof (§10) → expect `400 empty batch`.

There IS a safe existing bootstrap path; it requires one owner decision (the
tenant identifier) and no code change.

## 12 · Not done / not recommended

No tenant or customer created, no collector, no key, `default` not used, no
tenant identifier invented, no telemetry, no database write, no auth/RBAC
change, no code change, no republish. Production data was not read by the
agent (no production credential is held); §8 is the owner-side read-only
procedure.

Separately tracked: **B3** (machine-path audit attribution must derive from the
authenticated machine identity rather than `X-Principal-*` headers) and, newly
recorded, **B4** (collector creation accepts an unvalidated, unevidenced
`X-Tenant-Id` while key creation requires tenant evidence — the asymmetry in
§5). Neither is being changed now.
