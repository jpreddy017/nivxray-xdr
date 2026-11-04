# P0 TENANT AUTHORITY · FIX 6B-0 — LIVE GRANT PLAN (read-only)

Owner decision recorded: **OPTION B — explicit per-principal tenant grants.**
No `platform_authority` bypass. Role = what you may do; explicit grants =
where you may do it.

This step is READ-ONLY: no `tenant_ids[]` written, no account modified, no
code, no frontend, no audit write, no deploy. `git status` clean.

---

## LIVE_MULTI_TENANT_PRINCIPALS (4)

Every live `users` document whose role currently yields role-based
`all_tenants` (`_CROSS_TENANT_ROLES`):

| # | principal | role | account nature |
|---|-----------|------|----------------|
| 1 | `admin@nivxray.com` | `admin` | the real owner/operator account (created 2026-07-16) |
| 2 | `a05-admin-37051a53@nivxray.test` | `admin` | **test-fixture residue** from `tests/test_a05_tenant_scope_contract.py` (`U_ADMIN = f"a05-admin-{SUF}@nivxray.test"`) |
| 3 | `approver@nivxray.com` | `admin` | preview fixture · EDR exclusion second approver (`scripts/seed_edr_approver.py`, documented in `memory/test_credentials.md`) |
| 4 | `p0a-approver@nivxray.com` | `soc_manager` | preview fixture · P0-A response approval authority (separation of duties) |

## CURRENT_TENANT_DATA

| principal | `tenant_id` | `tenant_ids[]` | organization relationship |
|-----------|-------------|----------------|---------------------------|
| `admin@nivxray.com` | — | — | none recorded on the user document |
| `a05-admin-37051a53@nivxray.test` | — | — | none |
| `approver@nivxray.com` | — | — | none |
| `p0a-approver@nivxray.com` | **`default`** | — | `default` → `org_529e0c37d097e270d0647e101f` |

Reference points (not grants): the ONLY live user carrying `tenant_ids[]` is
`a05-mdr-37051a53@nivxray.test` → `["a05-acme-37051a53",
"a05-contoso-37051a53"]` (an MSSP-shaped precedent, also fixture residue), and
`analyst@nivx-live.com` is the single-tenant principal (`tenant_id:
nivx-live`) used for the Fix 4A/4B proofs.

Organization context for the two real tenants:

```
org_529e0c37d097e270d0647e101f · slug nivxmachines-preview
  display "NivXMachines (Preview)" · kind VENDOR · ACTIVE
    ├─ tenant default    "Preview Runtime (legacy default)"      LEGACY_ADOPTED · ACTIVE
    └─ tenant nivx-live  "Preview Live Sources (legacy nivx-live)" LEGACY_ADOPTED · ACTIVE
```

## CURRENT_USAGE_EVIDENCE (from existing authoritative data only)

**`admin@nivxray.com`** — 714 `xdr_audit_log` rows as principal, spread over
42 distinct `tenant_id` values:

| tenant | rows | what the tenant is |
|--------|------|--------------------|
| `unresolved` | 371 | refusal/denial records with no tenant — **not access evidence** |
| `default` | 100 | real preview runtime tenant (VENDOR org) |
| `p0f-collector-auth-proof` (+`-other`) | 55 | test-suite fixture tenants |
| `nivx-live` | 8 | real preview live-sources tenant (VENDOR org) |
| 37 further tenants | 1–17 each | `gate-*`, `rbac-*`, `p0sec-*`, `lolbas-*`, `wh-*`, `ten_*` — created by `gate`, `test-suite`, `secrets`, `auditlog`, `webhooks`, `lolbas` |

Operational (non-audit) evidence: `edr_endpoints` 318/321 in `default`;
20,000/20,000 sampled `edr_raw_events` in `default`; `workspace_cases` —
19 rows with `user_email = admin@nivxray.com` in `default`, 1 assigned case in
`default`; 945 `default` cases overall. `edr_enrollment_tokens` = 0,
`edr_response_actions` = 0, `edr_saved_views` = 1 (no tenant).

**`a05-admin-37051a53@nivxray.test`** — 0 audit rows, 0 cases, 0 assignments,
0 EDR artifacts. No usage evidence of any kind.

**`approver@nivxray.com`** — 0 audit rows, 0 cases, 0 EDR artifacts. Its only
documented purpose (`memory/test_credentials.md`, Gate 5/7/11 live-proof
scripts) is approving EDR exclusions on `X-Tenant-Id: default`.

**`p0a-approver@nivxray.com`** — 0 audit rows, 0 cases. Carries
`tenant_id: default` on its own document and is documented as the
`response.approve` counterpart to `admin@nivxray.com` on `default`.

## PROPOSED_GRANT_PLAN — **NOT APPLIED**

| PRINCIPAL | ROLE | CURRENT TENANT DATA | PROPOSED EXPLICIT TENANT GRANTS | EVIDENCE/BASIS | CONFIDENCE | ACCESS CLASS |
|-----------|------|---------------------|---------------------------------|----------------|-----------|--------------|
| `admin@nivxray.com` | `admin` | none | `["default", "nivx-live"]` | 100 + 8 audit rows as principal; 318 endpoints, all sampled raw events, 945 cases and 20 own/assigned cases in `default`; both tenants belong to the same ACTIVE **VENDOR** org "NivXMachines (Preview)"; `nivx-live` is the tenant the Fix 4A/4B console proofs resolve | HIGH (`default`) · MEDIUM-HIGH (`nivx-live`) | **VENDOR INTERNAL** |
| `p0a-approver@nivxray.com` | `soc_manager` | `tenant_id: default` | `["default"]` | its own persisted `tenant_id`; documented as the approval authority for response actions requested on `default`; no evidence of any other tenant | HIGH | **CUSTOMER-SPECIFIC** (`default`) |
| `approver@nivxray.com` | `admin` | none | `["default"]` *(owner confirmation requested)* | no telemetry/audit evidence; documented purpose is the Gate 7 second-approver on `X-Tenant-Id: default`. Grant proposed from *documented purpose*, not from observed access | MEDIUM | **VENDOR INTERNAL** (fixture) |
| `a05-admin-37051a53@nivxray.test` | `admin` | none | **UNRESOLVED** | zero evidence; the name matches the `a05-*` fixture family seeded per-run with a random suffix, so this is residue from one historical run. Granting `a05-acme-37051a53`/`a05-contoso-37051a53` would preserve nothing (the suite re-seeds fresh users each run) | — | **UNKNOWN / fixture residue** |

Explicitly **not** proposed: the 40 remaining tenants in
`admin@nivxray.com`'s audit trail. They are gate/test fixtures, and current
breadth is not evidence of intended authorization.

## EVIDENCE_PER_PROPOSED_GRANT

- `admin → default` — `xdr_audit_log` (100 rows, principal_id match),
  `edr_endpoints` (318), `edr_raw_events` (20k sampled), `workspace_cases`
  (19 `user_email` + 1 `incident_assignee`), `tenants.default` ACTIVE under
  ACTIVE VENDOR org.
- `admin → nivx-live` — `xdr_audit_log` (8 rows), same ACTIVE VENDOR org,
  and it is the tenant the console resolves in the accepted Fix 4B live proof.
  *(Weaker than `default`; flagged rather than assumed.)*
- `p0a-approver → default` — persisted `users.tenant_id = "default"` plus the
  documented separation-of-duties pairing with `admin@nivxray.com`.
- `approver → default` — documentation only (`test_credentials.md`,
  `scripts/gate5_7_11_live_proof.py` use `X-Tenant-Id: default`). No
  observed access. **Owner sign-off needed or it becomes UNRESOLVED.**

## UNRESOLVED_GRANTS

1. `a05-admin-37051a53@nivxray.test` — recommend **no grants**. Cleaning up
   the residue row would be a data change and is NOT requested here.
2. `approver@nivxray.com` — MEDIUM confidence, documentation-based only.
3. `admin@nivxray.com → nivx-live` — include or exclude? Excluding it means
   the owner account cannot open the live-sources tenant after Fix 6B.

## CONFIRMED DECISIONS (recorded, not yet implemented)

| Item | Decision |
|------|----------|
| SOC_MANAGER_DECISION | **EXPLICIT_GRANTS_ONLY** — role loses automatic all-tenant breadth |
| MSSP_OPERATOR_DECISION | **EXPLICIT_GRANTS_ONLY** (no live user holds this role; it is not even an RBAC catalog role) |
| AUTHORIZED_COUNT_DECISION | **GRANT_DERIVED** — never "customers with incidents" |
| PICKER_SOURCE_DECISION | **AUTHORIZED_TENANTS** (grants ∩ registry ACTIVE); queue stays evidence-derived `customers[]`; divergence is correct |
| MSSP_ORG_KIND_DECISION | **NON_AUTHORITATIVE** — `organization.kind` is eligibility/context only |
| G6_7_STATUS | **DEFERRED_FOR_SEPARATE_REVIEW** (`xdr_rbac.authorize_tenant`, XDR/security-state parity) |
| AUDIT_MODEL | reuse `xdr_audit_log`; `TENANT_CONTEXT_SWITCHED` added later, not in 6B-0; no separate Refusal Audit Trail product |
| DATA_CHANGED | **NO** |
| CODE_CHANGED | **NO** |

## FIX 6B DEPENDENCY THE OWNER SHOULD KNOW BEFORE APPROVING

`tests/test_a05_tenant_scope_contract.py` seeds `U_ADMIN` with role `admin`
and **no** tenant grants, then asserts cross-tenant outcomes (e.g.
`authorize_requested_tenant(U_ADMIN, T_ACME) == (T_ACME,
"EXPLICIT_REQUEST_TENANT")`, `/api/xdr/scope/authorized`, the incident queue
breadth). Under grants-first those fixtures must seed explicit
`tenant_ids[]` — a **test-fixture** change that preserves the assertions'
intent (a multi-tenant principal), not a product weakening. Other suites that
seed role-only admins may need the same one-line fixture change. This will be
reported per-suite during Fix 6B rather than assumed now.

## NEXT_MINIMUM_IMPLEMENTATION_STEP

**Fix 6B-1 (on owner approval of the table above):** write the approved
`tenant_ids[]` onto the approved accounts ONLY (idempotent, one script,
no other field touched, no credential created), then re-read and report the
resulting scope for each of the four principals — still with NO authority-code
change. Grants-first `resolve_tenant_scope()` / `authorize_requested_tenant()`
and the audited switch become **Fix 6B-2**, so the data and the enforcement
never change in the same step.

## PERMANENT REQUIREMENT (unchanged)

The moment Tenant Authority closes, return immediately to the Cisco Secure
Endpoint / AMP Device Trajectory operational-clone target — the real publicly
observable Cisco-class UI/UX, process/relationship/time interaction and
analyst operational functionality, implemented independently on real
NivXForge evidence. Not generic trajectory, not merely AMP-inspired.
