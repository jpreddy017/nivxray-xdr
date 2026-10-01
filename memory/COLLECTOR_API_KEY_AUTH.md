# Collector API-Key Authentication (machine principal) — 2026-06

**Status: IMPLEMENTED + TESTED IN PREVIEW. NOT deployed to production. No
production collector enrolled.**

## Why
`require_permission()` resolved identity ONLY from a verified user JWT. The
docs claimed collectors authenticate with a scoped API key carrying
`collectors.enroll`, but that path did not exist — a collector presenting a
perfectly valid key was rejected 403. This blocked the first real telemetry
collector without handing it an admin JWT.

## Design (owner-approved choices)
- Hashed lookup only. `xdr_api_keys` has **always** persisted just
  `hash = sha256(plaintext)`; there is no plaintext column, so **no migration
  and no plaintext compatibility fallback exists or was added.**
- Headers: `X-XDR-API-Key: nvx_<48 lowercase hex>` **plus** `X-Tenant-Id`,
  which must equal the key document's `tenant_id`.
- Permissions come from the key's own `scopes` (wildcard-expanded through the
  same `_expand_wildcard` the RBAC roles use). A key never inherits a user's
  role set.

## Code — `backend/routers/xdr_rbac.py`
- `authenticate_api_key(request, raw_key, permission)` — sha256 digest lookup
  on `xdr_api_keys.hash`, `hmac.compare_digest`, then revoked → disabled →
  expiry → tenant → scope checks, then best-effort `last_used_at` /
  `last_used_ip` / `$inc use_count` stamping (telemetry never gates a valid
  request). Sets `request.state.principal_kind = "api_key"`.
- `require_permission()` now takes `creds = Depends(HTTPBearer(auto_error=False))`:
  1. bearer **and** key present → `401 ambiguous-credentials`
     (so an invalid JWT can never fall through to key auth)
  2. key only → machine path
  3. neither → `403 unauthenticated` (identical to the pre-change HTTPBearer)
  4. bearer only → `await _deps_current_user(creds)`, then the untouched
     `check_access()` user path
- New helpers: `_c_api_keys()`, `_API_KEY_RE`, `_TENANT_RE`,
  `_machine_denied()`, `_key_effective_permissions()`, `_audit_machine_denial()`.

## Fail-closed matrix (all DENY)
missing credential · malformed key · unknown digest · revoked · disabled ·
expired · **malformed expiry (never means never-expires)** · tenant mismatch ·
scope not granted · empty scopes · missing `X-Tenant-Id` · store unavailable (503).
`expires_at: null` intentionally means never-expires.

## Tests
- `backend/tests/test_collector_api_key_auth.py` — 33 tests, in-process.
- `backend/tests/test_collector_api_key_adversarial_regression.py` — 18 tests
  over HTTP against the preview URL (empty header value, header-case variants,
  spoofed principal headers, cross-tenant envelope, `expires_at: null`).
- `backend/tests/test_p0sec_rbac_fail_closed.py` — 21 tests; the source-guard
  test was updated to assert the new invariants (`_deps_current_user(creds)`,
  `authenticate_api_key(...)`, `ambiguous-credentials` present; `_principal(request)`
  and the tenant-count bypass still absent).
**72/72 in-scope tests pass.** P0-SEC fail-closed guarantees unchanged.

## Pre-existing failures — NOT caused by this change (verified by stashing
`xdr_rbac.py` and re-running)
- `test_xdr_api_keys.py`: 8 failed before → 7 after (this change repaired one).
- `test_xdr_rbac_enforcement.py`: 21 fixture ERRORS before and after.
- Root cause for both: those suites seed identity through the legacy
  `X-Tenant-Id` / `X-Principal-Id` headers that the P0-SEC fix deliberately
  stopped honouring, so the seeding requests 403 and `resp.json()["data"]`
  raises `KeyError`. Fixing them means migrating those fixtures to real JWTs.

## Known gap (report-only, deferred)
`POST /api/xdr/ingest/telemetry` with a valid enroll-scoped key and an envelope
for a different tenant returns **422** (body shape validation) rather than a
distinct `403 TENANT_ISOLATION_VIOLATION`. The auth gate behaved correctly and
no cross-tenant write occurred; this is a defence-in-depth ergonomics gap only.

## Next (blocked on owner approval)
1. Preview-only collector-auth proof: mint a key with `collectors.enroll`, send
   real telemetry, confirm it reaches the incident pipeline.
2. Only then: deploy to production and enroll the first webhook collector in a
   dedicated tenant (e.g. `p0f-firstproof`).
