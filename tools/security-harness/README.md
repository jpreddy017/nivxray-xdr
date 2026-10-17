# Security-suite test harness

**Test-only.** Nothing here runs in production, ships in an image, or is
imported by application code.

## Why it exists

Several security suites were unrunnable outside a fully provisioned pod — not
because the controls were missing, but because the suites need preconditions
nothing supplied: a database, a signed-audit key, an admin credential, and for
the live-HTTP suites a reachable backend with provisioned principals. The
effect was that the controls those suites exist to prove were never exercised
by any release gate.

## What it supplies, and nothing more

- an ephemeral `mongod` on a free port with a throwaway dbpath,
- per-run generated secrets (`JWT_SECRET`, `XDR_AUDIT_MASTER_SECRET`,
  `XDR_SECRETS_MASTER_SECRET`, `XDR_ROOT_KEY`, `EDR_AUTH_PEPPER`, admin and
  analyst passwords) — random every run, so a suite that passed because a key
  was guessable fails here,
- `NIVXRAY_REPO_ROOT`, because `routers/benchmark.py` inserts
  `$NIVXRAY_REPO_ROOT/backend` and `.../backend/tests` into `sys.path` at
  application import time and defaults that root to `/app`. Without it a suite
  run from a checkout imports its helpers from the **deployed** tree and
  silently audits the wrong source,
- for `--tier 2`, a backend on a free port plus the principals those suites
  expect to already exist.

## What it must never do

- weaken, skip or relax a control,
- grant a permission a suite needs to be refused,
- use a credential this repository knows,
- report a skipped test as a pass.

`SecretPolicyError` refusing an unkeyed or repository-known value is the
control **working**. It is never something to configure around.

## Usage

```bash
python3 tools/security-harness/run.py --tier 1          # in-process suites
python3 tools/security-harness/run.py --tier 2          # live-HTTP suites
python3 tools/security-harness/run.py --suite tests/test_xdr_webhooks.py
python3 tools/security-harness/run.py --tier 1 --junitxml evidence/tier1.xml
```

First start on a blank database costs about four minutes of index
initialisation before any test runs. That is the application's startup cost,
not the harness's.

## Provisioning, and why each step is legitimate

`--tier 2` creates one organization, one tenant, and two principals:

| Step | Why it is not a bypass |
|---|---|
| register organization + tenant | the registry fails closed on an unregistered tenant; an operator registers it |
| `authorize_tenants(admin, tenant)` | an explicit grant, the narrower of the two facts `authorize_requested_tenant()` accepts. **Not** `authority_scope = PLATFORM` |
| `provision_rbac_principal(tenant, admin, "platform_admin")` | the RBAC API is gated by `users.create`, which needs a principal already provisioned in that tenant, so the first one cannot be created through the API |
| analyst with role `read_only` | `read_only` holds no `collectors.*` permission, so the refusal the suite asserts is a real authorization decision, not an absent account |

Registry validation, RBAC resolution, tenant authorization, scope checks and
the audit chain all run unchanged afterwards. The harness supplies state; the
server still makes every decision.
