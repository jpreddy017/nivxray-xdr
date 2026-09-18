# FROZEN PRODUCTION CANDIDATE — `7645b2b16db8bcbb2995a660f492f66cbaa8f99a`

**NOT REPUBLISHED.** Production remains `publish 100 / build 8833215`.
No production data mutation. No collector, connector, API key, endpoint or
enrolment token created. No Sysmon telemetry. No Tenant Picker. No
Unattributed Evidence View. W1 Phase 3 paused.

---

## 1 · THE FREEZE IS ALREADY DONE — AND THE SHA IS NOT WHAT I LAST REPORTED

Important correction. The Emergent platform commits at the end of each step, so
the 7 files I described as "uncommitted" were committed automatically when that
step closed. I did not — and should not — run `git commit` myself; for explicit
git write actions the platform's **Save to Github** control is the path.

```
Frozen candidate  7645b2b16db8bcbb2995a660f492f66cbaa8f99a   (short 7645b2b1)
Previous commit   0fc9be8a  (frontend tenant contract + P6 preview A-I)
git status --short  CLEAN   (no modified, no untracked, excluding node_modules)
```
So `0fc9be8a` was **never** the deployable identity — your objection was
correct, and the authoritative candidate SHA to publish from is
**`7645b2b1`**. Nothing was added or cleaned up in this step; the only
non-code files in that commit are the three memory documents.

## 2 · SCOPE REVIEW OF THE FROZEN COMMIT — ALL 7 CODE FILES BELONG

Read line by line against the approved closure. No feature, no drive-by
cleanup, no unrelated edit.

| file | change | approved under |
|---|---|---|
| `nivxray-xdr-collector/framework/identity.py` | `NIVX_TENANT_ID or "default"` → `or ""` | telemetry cannot self-label `default` |
| `nivxray-xdr-collector/routes/connectors.py` | `_tenant()` → registry-resolved; absent refused | collector creation cannot infer/create tenancy |
| `nivxray-xdr-collector/routes/preflight.py` | `_preflight_tenant()` added; resolved **before** the runtime/config check; `x_tenant_id or "preflight"` deleted | preflight cannot invent tenancy · authority before capability |
| `nivxray-xdr-collector/tests/test_preflight.py` | +2 refusal tests; 2 conformance headers | test coverage of the above |
| `nivxray-xdr/src/xdr/admin/collectorApi.js` | `requireTenant()` / `NO_TENANT_CONTEXT`; per-instance `X-Tenant-Id` interceptor; both `= "default"` defaults deleted | the original `collectorApi.js:77,85` ask |
| `nivxray-xdr/src/xdr/admin/IntegrationsBody.jsx` | wizard tenant field `"default"` → `activeTenant() \|\| ""` | no hardcoded `"default"` |
| `nivxray-xdr/src/xdr/design/_WizardLegacyBridge.jsx` | same | no hardcoded `"default"` |

Accepted behaviour, all present in this commit: missing tenant →
`TENANT_REQUIRED` · unknown → `TENANT_NOT_FOUND` · inactive →
`TENANT_NOT_ACTIVE` · collector creation cannot infer/create tenancy ·
preflight cannot invent tenancy · collector telemetry cannot self-label
`"default"` · authority evaluated before capability/runtime checks.

## 3 · RE-RUN FROM THE FROZEN CLEAN COMMIT — REPRODUCES THE ACCEPTED RESULTS

Backend restarted against the clean tree (`/api/health` → 200).

| check | result |
|---|---|
| `test_edr_route_tenant_authority` + `test_b4b5_tenant_registry_authority` + `test_d14_tenant_authority` | **258 passed / 0 failed** |
| `apps/nivxray-xdr-collector/tests` (12 files) | **105 passed / 0 failed** |
| `yarn build` on `apps/nivxray-xdr` (clean `dist/`) | **exit 0** |
| **OpenAPI path count** | **795** — unchanged |
| `/api/xdr/collector/connectors` present | yes |
| `/api/edr/endpoints` present | yes |

Two extra artifact checks on the freshly built bundle:
- `nvx_tenant` is present in `dist/assets/index-qoYrX1-C.js` → the active-tenant
  module is really in the shipped build, and `X-Tenant-Id` appears in the admin
  chunk → the header attachment is compiled in, not just in source.
- `grep -rl "ten_e759" dist/` → **empty**. No production tenant id is baked
  into the frontend artifact.

## 4 · PRODUCTION REPUBLISH — WHAT I NEED FROM YOU

I cannot press Republish; that lever is yours. **Publish from
`7645b2b16db8bcbb2995a660f492f66cbaa8f99a` only.** Do not change any secret,
do not touch `EDR_AUTH_PEPPER`, leave `NIVX_TENANT_REGISTRY_ENFORCE=true` as
already configured. Tell me the new publish number and build id when the
deployment is green.

## 5 · PRODUCTION ACCEPTANCE I WILL RUN AFTER REPUBLISH (read-only + refused negatives)

Frozen now so it is not invented later. Nothing is created at any point.

**A–I** as before, against `ten_e759b7288598bd882e3dcac49d`:
A registry authority + `enforcing=True` · B tenant ACTIVE under
`org_55f6dc202dbf8995369db989ad` with the expected XDR/EDR products ·
C explicit scope reads, collectors and API keys still **0** · D unknown →
`TENANT_NOT_FOUND` · E missing → `TENANT_REQUIRED` · F security-state:
authoritative 200 and `default` → `TENANT_NOT_FOUND` · G collector-create
against a nonexistent tenant refused, tenant count still exactly **1** ·
H **Gate H** — `/api/edr/endpoints` scoped 200 / unscoped `TENANT_REQUIRED`,
plus `/edr/enrollment/endpoints` and `/edr/response/isolation-policy` ·
I `X-Principal-Id: attacker@evil.test` → 0 attributed audit rows.

**Plus the collector-plane authority set (new this round):**
`/api/xdr/collector/connectors` GET+POST and
`/api/xdr/collector/ingest-preflight` — each with no tenant, an unknown
tenant, and a non-ACTIVE tenant → `TENANT_REQUIRED` /`TENANT_NOT_FOUND` /
`TENANT_NOT_ACTIVE`. **No POST with a valid tenant**, so no connector is ever
created.

**Plus "no `default` resurrection":** `GET /api/xdr/tenants` count stays 1 and
`default` is absent from the production registry; `default` is refused on
security-state, EDR and the collector plane.

**Plus frontend/console verification:** confirm the deployed production bundle
contains the active-tenant module and no baked tenant id, then load
`?tenant=ten_e759b7288598bd882e3dcac49d` and confirm
`GET /api/edr/context` returns `all_tenants: false`,
`tenant_ids: ["ten_e759b7288598bd882e3dcac49d"]`,
`explicit_tenant` matching, and `basis = EXPLICIT_REQUEST_TENANT`.

**Object counts to report:** organizations, tenants, collectors, API keys,
endpoints, enrolment tokens — all expected to be unchanged, with collectors,
API keys, endpoints and tokens at **0**.

If any production security gate fails: **STOP**, no compensating tenant
creation or adoption, no enforcement weakening, no automatic rollback, and
**W1 does not begin**.

## 6 · STATUS
```
candidate frozen            7645b2b1 · git status CLEAN
scope review                PASS (7/7 code files in approved scope)
re-run from frozen commit   258 + 105 passed · build exit 0 · OpenAPI 795
production republish        AUTHORIZED BY OWNER, FROM 7645b2b1 ONLY - NOT PERFORMED
production A-I + collector  NOT PERFORMED (awaiting green deployment)
W1 collector / key / 5 events  NOT STARTED
```
