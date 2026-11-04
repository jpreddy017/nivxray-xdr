# NIVX MACHINES PRODUCTION VALIDATION TENANT BOOTSTRAP — PRE-WRITE STATE

Mode: authenticated **READ-ONLY**. **No write was performed.** Zero organizations created,
zero tenants created, zero tokens, zero endpoints, zero response actions. The admin password
was used only to obtain a JWT held in memory; it was never written to any file, log, report or
screenshot.

RESULT: **BOOTSTRAP: PASS BY REUSE — owner authorised reuse of the existing tenant; zero writes.**

## Owner decision (recorded)
- Q1 → **Reuse `ten_e759b7288598bd882e3dcac49d` as-is.** No rename, no new tenant.
- Q2 → **Stop for owner review; mint the single-use Windows enrollment token only after explicit go.**

Final read-back after the decision confirms nothing changed: **1 organization, 1 tenant**,
`enforcing: true`, reuse target still `ACTIVE`.

```
VALIDATION ESTATE (accepted):
  ORGANIZATION  org_55f6dc202dbf8995369db989ad  VENDOR  ACTIVE
  TENANT        ten_e759b7288598bd882e3dcac49d  INTERNAL_VALIDATION  ACTIVE  products ["XDR","EDR"]
  ENDPOINTS     0
```

## The decisive finding: production is NOT clean

The handoff stated the production database was "entirely clean (zero tenants, zero endpoints)".
An authenticated read of the authoritative registry shows that is **false** — a NivX Machines
organization **and** an INTERNAL_VALIDATION tenant were already created on **2026-09-17** by
`admin@nivxray.com`:

```
ORGANIZATION (1 total)
  id            org_55f6dc202dbf8995369db989ad
  slug          nivxmachines
  display_name  NivXMachines
  kind          VENDOR
  state         ACTIVE
  created_at    2026-09-17T05:43:24Z   created_by admin@nivxray.com

TENANT (1 total)
  id               ten_e759b7288598bd882e3dcac49d
  slug             internal-validation
  display_name     Internal Validation
  kind             INTERNAL_VALIDATION
  state            ACTIVE
  organization_id  org_55f6dc202dbf8995369db989ad   ← the org above
  products         ["XDR","EDR"]
  created_at       2026-09-17T05:45:00Z   created_by admin@nivxray.com

ENDPOINTS on that tenant: 0  (telemetry/freshness → NO_ENROLLED_ENDPOINTS)
```

## Why I stopped instead of creating

The owner's idempotency rule is: *"Confirm no existing organization already represents NivX
Machines"* and *"do NOT create duplicate organization / duplicate tenant."*

- A **literal slug** check passes (no org slug is exactly `nivx-machines`, no tenant slug is
  exactly `nivx-machines`), which would say "create".
- But the **intent** check fails hard: `org_55f6dc202dbf8995369db989ad` (**NivXMachines,
  VENDOR, ACTIVE**) already *is* the NivX Machines vendor organization, and it already owns an
  **INTERNAL_VALIDATION** tenant with `products ["XDR","EDR"]` — exactly the validation
  fixture this bootstrap was meant to create.

Creating a second org + tenant would produce a de-facto **duplicate NivX Machines
organization** and a **second internal-validation tenant**, which the authorization explicitly
forbids and which the registry (no unique index) would not stop. So this is exactly the
"ambiguous / already-present → read state, do not write" case.

## The differences vs the requested identity (owner decision needed)

| Field | Requested | Already in production |
|---|---|---|
| Org slug | `nivx-machines` | `nivxmachines` |
| Org display | NivX Machines | NivXMachines |
| Org kind | VENDOR | VENDOR ✓ |
| Tenant slug | `nivx-machines` | `internal-validation` |
| Tenant display | NivX Machines | Internal Validation |
| Tenant kind | INTERNAL_VALIDATION | INTERNAL_VALIDATION ✓ |
| Tenant products | ["xdr","edr"] | ["XDR","EDR"] (case differs) |
| Tenant id | backend `ten_…` | `ten_e759b7288598bd882e3dcac49d` ✓ opaque |

Kinds match; only slugs/display/casing differ. The existing tenant is **fully usable** for the
first Windows enrollment as-is.

## Options for the owner

1. **REUSE** `ten_e759b7288598bd882e3dcac49d` — no write at all; proceed straight to minting one
   enrollment token when authorised. (Cleanest; zero new production writes.)
2. **RENAME** — if the exact `nivx-machines` slug/display matters, that needs a registry
   update path (slug changes are sensitive and were not part of this authorization). Requires a
   separate, explicit owner decision; not performed.
3. **CREATE NEW ANYWAY** — only on an explicit owner instruction acknowledging it will be a
   parallel NivX Machines org/tenant alongside the existing one. Not recommended.

I have made **no** change. The JWT remains in memory only for this session.

## Counters

```
ORGANIZATIONS CREATED: 0   TENANTS CREATED: 0   TOKENS CREATED: 0
ENDPOINTS ENROLLED: 0      TELEMETRY INGESTED: 0   RESPONSE ACTIONS: 0
DB MIGRATIONS: 0   DB BACKFILLS: 0   SECRETS CHANGED: 0   DEPLOYMENTS: 0
DUPLICATE ORGANIZATIONS: 0   DUPLICATE TENANTS: 0
RESPONSE AUTHORITY: FAIL-CLOSED (unchanged)
PASSWORD PERSISTED ANYWHERE: NO
```
