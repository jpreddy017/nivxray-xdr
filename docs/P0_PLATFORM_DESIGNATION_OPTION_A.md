# P0 — OPTION A · CONTROLLED PLATFORM DESIGNATION REPAIR

2026-09-29. Repair implemented and tested. Production republish dispatched.
Post-deploy proof pending (deploy is asynchronous).

## FINAL STATUS

```
PLATFORM_REPAIR_CODE              = PASS (implemented + tested locally)
TESTS                             = 22 new + 83 tenant-authority + 51 cross-tenant/isolation
                                    + 72 A05 scope contract  = 228 passed, 0 failed
                                    (1 unrelated teardown ERROR — see §5)
COMMIT_SHA                        = pending this step's platform auto-commit on
                                    branch feature/rc2-alignment
PROD_DEPLOY                       = DISPATCHED (async; not yet confirmed)
PRODUCTION_PRINCIPAL              = admin@nivxray.com
AUTHORITY_SCOPE_BEFORE            = ABSENT (production; 0 of 1 users carried any)
AUTHORITY_SCOPE_AFTER             = NOT_PROVEN (read-back requested post-deploy)
COMPUTERS_ACCESS                  = NOT_PROVEN (post-deploy)
EVENTS_ACCESS                     = NOT_PROVEN (post-deploy)
DEVICE_TRAJECTORY_ACCESS          = NOT_PROVEN (post-deploy)
INTERNAL_VALIDATION_ACCESS        = NOT_PROVEN (post-deploy)
DESKTOP_A9HGFJJ_VISIBLE           = NOT_PROVEN (post-deploy)
SENSOR_RECEIVE                    = ACTIVE (pre-deploy, 2026-09-29T16:42:28Z)
LATEST_TELEMETRY                  = 2026-09-29T16:42:28Z (pre-deploy)
TENANT_ISOLATION_NEGATIVE_CONTROL = PASS (§4)
DATA_LOSS                         = NO
B5_EID5_END_TO_END                = HOLD: production authorization proof pending
```

## 1. IMPLEMENTATION

New file `backend/services/platform_designation.py`, called from the existing FastAPI
startup in `backend/server.py` immediately after `seed_admin`:

```python
await seed_admin(log)
# P0 · explicit PLATFORM designation. Fix 6B-2 retired role-derived tenant
# breadth, so the Super Admin needs `authority_scope = "PLATFORM"` written
# explicitly; without it every tenant is (correctly) refused. Idempotent,
# server-side only, refuses on any ambiguity, and never a startup crash —
# the authorization path stays fail-closed on its own.
from services.platform_designation import designate_platform_principal
await designate_platform_principal(db.users, log)
```

It runs against the SAME auth database the backend itself uses (`db.users`), so there
is no second connection string and no possibility of hitting the wrong store.

Behaviour, exactly as specified:

| Condition | Outcome | Writes? |
|---|---|---|
| `NIVX_PLATFORM_PRINCIPAL` unset/empty | `NOT_CONFIGURED` — silent, backend serves normally | no |
| value malformed (not an email, whitespace, embedded space) | `REFUSED_MALFORMED_PRINCIPAL`, ERROR log | no |
| zero principals match (normalized, case-insensitive exact email) | `REFUSED_PRINCIPAL_NOT_FOUND`, ERROR log | no |
| more than one matches | `REFUSED_PRINCIPAL_AMBIGUOUS`, ERROR log | no |
| `authority_scope` absent | **`UPDATED`** → `$set {authority_scope: "PLATFORM"}`, then read back and verified | one field, one doc |
| `authority_scope == "PLATFORM"` | `ALREADY_CONFIGURED` (verification, per the migration guard) | no |
| `authority_scope` holds any other value | `REFUSED_CONFLICTING_AUTHORITY_SCOPE`, ERROR log | no |
| auth store unreachable | `REFUSED_AUTH_STORE_UNREACHABLE`, ERROR log | no |
| read-back does not equal `"PLATFORM"` | `REFUSED_DESIGNATION_NOT_VERIFIED`, ERROR log | no |

The update is literally `{"$set": {"authority_scope": "PLATFORM"}}` on one `_id` — a
test asserts that exact payload, so the blast radius is machine-enforced.

Configuration added to `backend/.env`:
```
NIVX_PLATFORM_PRINCIPAL=admin@nivxray.com
```

### Migration guard
When the variable IS configured, startup always ends in a verified state or a loud,
machine-readable `REFUSED_*` ERROR line — never a silent downgrade and never a fallback
to role-derived authority. When it is NOT configured, the module returns
`NOT_CONFIGURED` and writes nothing: general backend availability never depends on an
optional PLATFORM principal. A refusal does not crash the API either — converting an
access-control condition into a total outage would be strictly worse, and the
authorization path is independently fail-closed (absent designation ⇒ CUSTOMER), so
refusing to write is already the safe state.

### What it does NOT touch
role · password/hash · `tenant_ids` · customer membership · endpoint records · tenant
registry · evidence · telemetry · sensor config · Sysmon · outbox · response
authorization · frontend authorization. `_CROSS_TENANT_ROLES` is NOT reintroduced;
`role == "admin"` still confers nothing; no wildcard or default-tenant fallback exists.
Nothing is logged but the principal email and the before/after scope words.

## 2. LIVE PROOF THAT THE CODE PATH RUNS (preview runtime, NOT production evidence)

Backend restarted in this workspace; startup emitted:

```
{"level":"INFO","logger":"nivxray",
 "msg":"[platform-designation] result=ALREADY_CONFIGURED principal=admin@nivxray.com"}
```

`ALREADY_CONFIGURED` is the correct outcome here — this store was designated back in
June by the old script — and it demonstrates the idempotent branch against a real
MongoDB, not just a stub. `/api/health` → `{"status":"ok","service":"nivxray-api"}`.

## 3. TESTS — A THROUGH J

`backend/tests/edr/test_p0_platform_designation.py` → **22 passed**

| Req | Test |
|---|---|
| A | `test_configured_principal_receives_platform_authority`, `test_the_designated_principal_then_resolves_platform` |
| B | `test_second_execution_is_a_no_op` (one update recorded across two runs), `test_case_insensitive_configuration_still_finds_one_principal` |
| C | `test_role_admin_without_designation_gets_no_breadth`, `test_the_retired_role_set_is_not_reintroduced` (asserts `_CROSS_TENANT_ROLES` is GONE) |
| D | `test_customer_admin_stays_customer_scoped` |
| E | `test_customer_analyst_stays_customer_scoped` |
| F | `test_naming_a_tenant_never_authorises_it` (real `ScopeDenied` from `session_context`) |
| G | `test_unknown_configured_principal_fails_closed`, `test_ambiguous_principal_fails_closed`, `test_malformed_configuration_fails_closed` |
| H | `test_conflicting_authority_scope_fails_closed` (and the conflicting value still resolves CUSTOMER) |
| I | `test_no_tenant_ids_are_ever_added`, `test_existing_grants_are_preserved_untouched` |
| J | `test_the_write_touches_only_authority_scope`, `test_only_the_designated_principal_is_touched`, `test_role_and_password_are_preserved_untouched`, `test_unreachable_auth_store_is_a_refusal_not_a_crash`, `test_unconfigured_env_writes_nothing_and_is_not_a_failure`, `test_only_the_env_var_names_the_principal` |

## 4. EXISTING TENANT-AUTHORITY REGRESSION — NO SECURITY REGRESSION

| Suite | Result |
|---|---|
| `test_p0_tenant_authority_fix6b2.py` + `fix1` + `fix2` | **83 passed** |
| `test_cross_tenant.py` + `test_trajectory_tenant_isolation.py` | **51 passed** |
| `test_a05_tenant_scope_contract.py` | **72 passed**, 1 teardown ERROR (§5) |

`TENANT_ISOLATION_NEGATIVE_CONTROL = PASS`.

## 5. ONE UNRELATED TEARDOWN ERROR, DISCLOSED

`tests/test_a05_tenant_scope_contract.py::test_the_guard_is_not_vacuous` — the TEST
PASSES; the error is raised in the module-scoped `_seed` fixture teardown, and is a
litellm/LLM artifact: `APIConnectionError: cannot schedule new futures after
interpreter shutdown`. Reproducible when running that single test in isolation, on a
code path this repair does not touch (the repair performs one Mongo field write at
startup). Not in any RC4/RC5 gate step list. Flagged, not fixed, not hidden.

## 6. DEPLOY

The production republish has been dispatched with explicit instructions: do not roll
back Publish 100, do not touch routing/domain/registry/telemetry/endpoint/sensor, do not
replay, do not weaken any check — and one hard requirement called out to the pipeline:

> **`NIVX_PLATFORM_PRINCIPAL=admin@nivxray.com` must exist in the production
> environment for the new run.** Without it the designation is a documented NO-OP
> (`result=NOT_CONFIGURED`) and the 403s persist.

Post-deploy read-only proof requested: new run id + health; presence (not value) of the
new env var; the verbatim `[platform-designation]` log line; a read-back of the
production `users` document (`role`, `authority_scope`, `tenant_ids`, `status` only) with
`authority_scope == "PLATFORM"` confirmed and exactly one authority holder; the status
codes now returned on the EDR read routes for `ten_e759b7288598bd882e3dcac49d`; sensor
route health + newest ingest timestamp; startup errors; and `edr_raw_events >= 117,904`
to prove nothing was lost across the republish.

Deploys are asynchronous — none of that is confirmed yet, so every post-deploy line in
the status block is `NOT_PROVEN` rather than assumed.

## 7. B5

`B5_EID5_END_TO_END = HOLD` until the production authorization proof returns. No EID5
replay. B5 not marked PASS. No E3. No UI change.

STOP FOR OWNER REVIEW.
