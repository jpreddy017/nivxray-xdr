# A1_SECURITY_TEST_HARNESS_REPORT

Date: 2026-06
Branch: `engineering/a1-security-harness` (isolated worktree — **not merged**)
Baseline: `cd2b8b92d785bee2f88432d3202367bbd51508c0` / tree `15a13aa6a5fe562895efaecabc11b4e434c8505f`
Candidate: `3db07b18625d01205592009cdbe17ac293d96220` / tree `2284f5e2c0a43c0a45e5a1666deafe05fc9239f9` (code commit `0ee630f5`, docs commit on top)

## FINAL STATUS: **PARTIAL**

PASS on every acceptance criterion for harness readiness. PARTIAL because two
failure families remain after the harness is removed as a variable, and both
are application-side questions A1 is forbidden to touch. They are reported,
not fixed, and not reclassified as passes.

---

## Step 1 · Baseline verified

```
HEAD      cd2b8b92d785bee2f88432d3202367bbd51508c0
tree      15a13aa6a5fe562895efaecabc11b4e434c8505f
status    0 modified files
```

Matches the A0 baseline exactly. Work was done in a separate worktree
(`git worktree add -b engineering/a1-security-harness`), so
`engineering/e3-stage2b-package` was never checked out or modified.

Existing release gates recorded before any change:
`boundaries` 136 · `tenant` 104 · `response` 39 · `decoder` 147 (6 skipped) ·
`command` 372 — **798 tests, 0 failures**.

## Step 2 · Failures reproduced and classified

Baseline run of the eight target suites, bare `pytest`, on `cd2b8b92`:

```
112 tests collected · 7 failed · 13 errors · 0 skipped
```

Two suites never collected at all — `test_collector_plane_auth.py` and
`test_edr_route_tenant_authority.py` raised `KeyError:
'NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_003'` at import, so roughly a hundred
assertions were silently absent from every count ever reported.

| Observed failure | Classification | Evidence |
|---|---|---|
| `KeyError: NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_003/010/011` at import | **missing test configuration** | 60 test files read the credential contract from the environment — the P0-PROD-1 pattern, deliberately not committed |
| `SecretPolicyError: XDR_AUDIT_MASTER_SECRET is not configured…` | **expected security rejection** | `security/secret_policy.py:171` refusing to derive a key from an unkeyed or repository-known value. Not a defect; the harness supplies a generated key instead |
| `test_p0prod1_secret_policy` auditing `/app/backend/tests/...` | **invalid test fixture** | six hardcoded paths pointed at the deployed pod, so the suite audited a tree that was not under test |
| `ImportError: cannot import name 'authorize_tenants' from 'tests._verified_session' (/app/backend/tests/…)` | **invalid test fixture (environment coupling)** | `routers/benchmark.py:26-27` inserts `$NIVXRAY_REPO_ROOT/backend{,/tests}` into `sys.path` at import, defaulting to `/app` — helpers resolved from the **deployed** tree |
| `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` on webhook/collector suites | **expected security rejection + invalid test fixture** | the A0.5 contract is working; the suites register a tenant but never grant the principal authorization for it |
| `403 ACCESS_DENIED reason=user-not-provisioned` | **invalid test fixture** | `deps.seed_admin()` writes the authentication record only; the tenant-scoped `xdr_users` record is never created |
| `401 Invalid credentials` for `analyst@default.com` (62 failures) | **missing test configuration** | the live-HTTP suites log in as principals that exist only in the long-lived preview database |
| `test_rc5_source_never_imports_v2_unwrapped` | **GENUINE APPLICATION DEFECT** | 27 unwrapped `v2` imports — see Step 5 |
| `test_human_control_refuses_an_unknown_tenant` ×16 | **expected security rejection, different code** | server answers 403 `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, suite expects 403 `TENANT_NOT_FOUND` — see Step 5 |

## Step 3 · Changes made — test harness only

| File | Change | Lines |
|---|---|---|
| `tools/security-harness/run.py` | **new** · ephemeral mongod, generated per-run secrets, optional backend, tier-2 provisioning, junit output, guaranteed teardown | +307 |
| `tools/security-harness/README.md` | **new** · what it supplies, what it must never do, why each provisioning step is legitimate | +— |
| `backend/tests/_verified_session.py` | `authorize_tenants()` and `provision_rbac_principal()` | +66 |
| `backend/tests/test_p0prod1_secret_policy.py` | repository-relative `BACKEND` root; explicit skip when no `.env` exists | +24/−9 |
| `backend/tests/test_xdr_webhooks.py` | authorize + provision the principal; provision **after** the fixture's own purge; authorize the second tenant so the isolation test reaches data isolation | +15 |
| `backend/tests/test_collector_api_key_auth.py` | register, authorize and provision the suite tenant | +9 |

No application file, no runtime configuration, no staging file was touched.

Two notes on judgement calls:

- `provision_rbac_principal()` **raises** when the RBAC store is unavailable.
  An earlier version returned silently, which would have let the harness
  "provision" nothing and then report the resulting 403s as security results.
- The administrator is given an **explicit tenant grant**, not
  `authority_scope = "PLATFORM"`. Both were tried: PLATFORM breadth makes the
  suite's own `GET /api/xdr/tenants` discovery fail with `TENANT_REQUIRED` and
  produced **67** failures, against **16** with the narrow grant. The narrower
  privilege is both more faithful and better evidence.

## Step 4 · Validation

### Existing gates — no regression

| Gate | Tests | Result |
|---|---|---|
| boundaries | 136 | 0 failures |
| tenant | 104 | 0 failures |
| response | 39 | 0 failures |
| decoder | 147 | 0 failures, 6 skipped |
| command | 372 | 0 failures |
| **Total** | **798** | **identical to baseline** |

### Target suites — before and after

| | Baseline | After A1 |
|---|---|---|
| Tests executed | 112 | **221** |
| Errors (collection/config) | **13** | **0** |
| Failed | 7 | 17 |
| Skipped | 0 | 10 |
| Suites that could not collect | 2 | **0** |

`tier1.xml` — 108 tests, 1 failure, 1 skip.
`tier2.xml` — 113 tests, 16 failures, 9 skips.
Evidence: `/app/rocket-evidence/a1/{baseline,tier1,tier2}.xml`, `gates/*.xml`.

The failure count rose because **a hundred previously-absent assertions now
run**. `test_xdr_webhooks` went from 9 failures to **9/9 passing**, so webhook
authentication, HMAC secret handling, DLQ replay, tenant isolation and audit-
chain validity are now genuinely exercised. `test_p0prod1_secret_policy`,
`test_d11_ingest_provenance`, `test_collector_api_key_auth` and
`test_phase2_1_tenant_isolation` all pass against the repository under test.

Required demonstrations:

- previously runnable tests still pass — 798 gate tests, unchanged;
- suites execute without environment-related collection errors — 13 → 0;
- expected rejections still enforced — `SecretPolicyError` still fires on an
  unkeyed value; `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` still refuses an
  unauthorized selector; `read_only` is still refused the collector plane;
- no production credential used — every secret is generated per run;
- no tenant isolation check disabled — none touched;
- no assertion weakened or deleted — `git diff` shows additions and path
  resolution only;
- no application code or runtime configuration changed;
- staging package untouched — see below.

## Step 5 · Genuine findings for owner review

### F1 · 27 unwrapped `v2` imports — deletion-safety contract broken

`tests/test_v2_isolation.py::test_rc5_source_never_imports_v2_unwrapped`
fails on real source, including production routers:

```
routers/xdr_ingest.py          from v2.ingestion.telemetry_bridge import …
routers/report_writer.py       from v2.report_writer import …
routers/auto_investigate.py    from v2.jobs.pipeline import …
routers/auto_investigate_jobs.py, routers/decoded_artifacts.py
engine/orchestrator.py, edr_plane/{file_identity,canonical_bridge,
  windows_eventlog,file_content_acquisition}.py, edr_trajectory/*,
services/decoder/powershell_constants.py, canonical/iue/adapters/*
```

The contract exists so the `v2` tree can be deleted without breaking the
application. Today deleting it would break ingest, reporting and auto-
investigation at import time. **A1 did not fix this.**

### F2 · Unknown tenant returns an authorization code, not a registry code

16 failures: the server answers 403 `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` for
`ten_definitely_not_registered_0000`; the suite expects 403 `TENANT_NOT_FOUND`.
Both are fail-closed 403s. Answering "not authorized" before "does not exist"
is arguably **better** — it discloses nothing about which tenants exist. The
open question is which contract is authoritative. Needs an owner decision;
changing either side is out of A1 scope.

### F3 · Application code mutates `sys.path` at import time

`routers/benchmark.py:26-27` inserts `$NIVXRAY_REPO_ROOT/backend` and
`.../backend/tests`, defaulting to `/app`. Any test run from a checkout
resolves helpers from the deployed tree unless the variable is set. The
harness sets it; the application-side fix needs owner review.

### F4 · No supported path to provision the first principal in a tenant

`POST /api/xdr/rbac/users` requires `users.create`, resolved against
`xdr_users` for that tenant, so the first principal cannot be created through
the API. `deps.seed_admin()` writes only the `users` authentication record.
The harness writes the two rows directly; an operator has no documented path.

## Staging package impact — **none, and it cannot be merged as-is**

`prepare.py --verify-only` **refuses** the A1 commit:

```
ValueError: Candidate includes changes outside staging packaging
```

That is the admission control working. Checked file by file with
`prepare.included()`, **not one** of the changed files enters the build
context:

```
excluded  backend/tests/_verified_session.py
excluded  backend/tests/test_collector_api_key_auth.py
excluded  backend/tests/test_p0prod1_secret_policy.py
excluded  backend/tests/test_xdr_webhooks.py
excluded  tools/security-harness/run.py
any included: False
```

So the image contents would be byte-identical; only the commit SHA differs.
Consequences, stated plainly:

- The Hetzner package is **untouched**. Pin `593b3e9f`, bundle SHA-256
  `98e4adba…fdfa`, branch `engineering/e3-stage2b-package` — all unchanged,
  and `prepare.py --verify-only` still passes there.
- A1 **cannot be merged** into the staging branch without re-pinning
  `source.json`, rebuilding the bundle and re-issuing the checksum.
- Therefore A1 stays on its own branch until the Hetzner run completes or the
  owner authorises a re-pin.

## Remaining harness blockers

| Blocker | Impact |
|---|---|
| `test_edr_route_tenant_authority.py` skips at module level | needs `TEST_ANALYST_NIVXLIVE_PASSWORD` plus tenants `default`, `nivx-live` and a specific ARCHIVED tenant id that exist only in the preview database. The suite refuses to invent accounts — correctly. Synthesising that environment is an owner decision, not harness readiness |
| 8 machine-key skips in `test_collector_plane_auth.py` | require an enrolled collector identity |
| ~4 minutes of index initialisation per fresh database | the application's startup cost; makes per-suite iteration slow |
| 316 hardcoded `/app/...` literals remain in other test files | only the secret-policy suite was repaired; others may silently audit the deployed tree |

## Recommended A3 scope

1. Add a `security` gate running the **tier-1** set through the harness —
   proven: 108 tests, 0 errors, one known application defect (F1).
2. Treat F1 as a **release blocker candidate** and schedule its own task; do
   not gate until it is decided, or the gate lands red on day one.
3. Get an owner ruling on F2, then align one side.
4. Keep tier-2 **out** of the mandatory gate until the live-environment
   question is settled; run it as a pre-release check against a provisioned
   staging database.
5. Fix F3 and F4 as separate small tasks — both are application changes and
   both will require re-pinning the staging package.

**IMPLEMENTATION BEYOND THE TEST HARNESS: NONE.** No merge, no push, no
deployment, no migration, no package regeneration, no weakened control. All
security HOLDs preserved. Release status **NO-GO**.
