# P0-PROD-2 · SECURE ENDPOINT ENROLMENT

Gate: **P0-PROD-2 — token-based endpoint enrolment**
Date: 2026-06
Status: **PASS** (implementation gate only — nothing deployed)

---

## 1 · EXECUTIVE RESULT

**PASS.**

The production sensor bootstrap no longer requires an
administrator/operator/analyst credential to exist on the endpoint. A
Linux or Windows endpoint bootstraps with a short-lived, single-use,
tenant-bound enrolment token, receives its own endpoint-scoped credential,
and uses that identity — never a console identity — for every subsequent
request.

Two honest qualifications, stated rather than hidden:

1. **Most of the cryptographic enrolment machinery already existed**
   (P0-A.2): CSPRNG 256-bit tokens, keyed-digest-only storage, atomic
   single-use consumption, endpoint-scoped credentials, short-lived
   sessions. P0-PROD-2 closed the genuine remaining gaps rather than
   rebuilding what was already correct:
   - unused-token **revocation** did not exist,
   - the token **state model** was `PENDING/USED/EXPIRED` and had no
     revoked state,
   - the enrolment **lifecycle audit** store did not exist,
   - the **Linux supervised launcher** logged in with
     `ADMIN_EMAIL`/`ADMIN_PASSWORD` to mint its own token.
2. Credential-at-rest protection on the endpoint is **filesystem
   permissions only** (`0600` on Linux, SYSTEM+Administrators ACL on
   Windows). There is no TPM/DPAPI/keyring binding. See §25.

---

## 2 · ARCHITECTURE IMPLEMENTED

```
Authenticated console principal (JWT + X-Tenant-Id)
  → tenant resolved SERVER-SIDE via services/tenant_registry.authoritative()
  → POST /api/edr/enrollment/tokens
  → 256-bit CSPRNG token, keyed-HMAC digest stored, PLAINTEXT RETURNED ONCE
  → operator provisions it to the endpoint (env var or token file)
        ↓
Endpoint (no console credential anywhere)
  → POST /api/edr/agent/enroll { tenant_id, enrollment_token, machine attrs }
  → tenant must be registered+ACTIVE (generic 401 if not — no oracle)
  → endpoint_id MINTED BY THE PLATFORM from durable machine attributes
  → token matched+burned in ONE find_one_and_update
      (tenant_id + token_hash + used_at:None + revoked_at:None + not expired)
  → endpoint record + endpoint-scoped credential (eak_…) issued ONCE
        ↓
  → POST /api/edr/agent/session (eak_ → est_, short TTL)
  → heartbeat / telemetry / policy fetch / policy ACK / response commands
    all authenticate with the SESSION, whose tenant is an OUTPUT of
    authentication, never an input
```

The enrolment token is bootstrap authority only: it is burned at first
use and never becomes the durable credential.

---

## 3 · EXACT FILES CHANGED

| File | Change |
|---|---|
| `backend/edr_plane/enrollment/audit.py` | **NEW.** Append-only `edr_enrollment_audit` with a code-enforced redaction guard. |
| `backend/edr_plane/enrollment/store.py` | Token docs gain `revoked_at/revoked_by/revoke_reason`; `revoke_enrollment_token()`; `token_state()`; consumption now excludes revoked tokens; `used_by_endpoint_id` recorded; audit hooks on mint/enrol; `list_tokens()` state vocabulary; `token_id` unique index. |
| `backend/routers/edr_enrollment.py` | `POST /edr/enrollment/tokens/{token_id}/revoke`; `ENROLLMENT_REJECTED` audit on both rejection paths. |
| `backend/routers/edr_audit.py` | `ENROLMENT` category now also reads `edr_enrollment_audit`. |
| `scripts/nivxforge_sensor_supervise.py` | Token-first bootstrap (`NIVXFORGE_ENROLLMENT_TOKEN` / `..._TOKEN_FILE`, file deleted after read); the operator-credential path is unreachable under `NIVX_DEPLOYMENT_ENV=production`; `backend/.env` is not read at all in production. |
| `backend/tests/edr/test_p0prod2_enrollment_hardening.py` | **NEW.** 25 focused tests. |
| `backend/tests/edr/test_p0_a2_enrollment.py` | One assertion updated for the new state vocabulary (`USED` → `CONSUMED`, plus `legacy_state`/`usable`). |

Unchanged because already compliant: `agents/nivxforge-windows/Install-NivXForgeSensor.ps1`
(takes `-EnrollmentToken`, has no credential parameter), both sensors
(`enrol --token` only), `edr_plane/enrollment/security.py`.

---

## 4 · API CONTRACT

| Method | Route | Auth | Purpose |
|---|---|---|---|
| POST | `/api/edr/enrollment/tokens` | console JWT + tenant | mint (plaintext returned once, with `token_id`) |
| GET | `/api/edr/enrollment/tokens` | console JWT + tenant | metadata + truthful state; never plaintext or digest |
| POST | `/api/edr/enrollment/tokens/{token_id}/revoke` | console JWT + tenant | **NEW** — revoke an unused token |
| POST | `/api/edr/agent/enroll` | token (bootstrap) | consume + issue endpoint credential |
| POST | `/api/edr/agent/session` | endpoint credential | short-lived session |
| POST | `/api/edr/agent/heartbeat` · `/telemetry`, GET `/policy`, `/whoami` | session | endpoint identity only |

Error contract (agent surface): every token failure — unknown, malformed,
expired, consumed, revoked, wrong tenant, unregistered tenant — returns
the **same** `401 ENROLLMENT_TOKEN_INVALID` with the same reason string.
Proven by `test_no_oracle_between_unknown_expired_used_and_foreign`.
The admin surface, where the caller has already proven who they are, is
specific: `404 ENROLLMENT_TOKEN_NOT_FOUND`, `409
ENROLLMENT_TOKEN_NOT_REVOCABLE`.

No CRUD was added beyond mint / list / revoke / enrol.

---

## 5–8 · TOKEN GENERATION, STORAGE, LIFECYCLE, TTL

- Generation: `secrets.token_urlsafe(32)` → 256 bits, prefixed `enr_`
  (`edr_plane/enrollment/security.py`). No UUIDs, hostnames, tenant ids,
  timestamps or sequences as secret material.
- Storage: **keyed HMAC-SHA-256 with a server-side pepper**
  (`EDR_AUTH_PEPPER`, environment-only, absent ⇒ hard `RuntimeError`, never
  an unkeyed digest). Only the digest is written. A database-only
  compromise cannot verify candidate tokens offline.
- Plaintext lifetime: the mint response body, once. Never in Mongo, never
  in a GET, never in audit, never in a log.
- Lifecycle fields: `token_id`, `tenant_id`, `created_at`, `issued_by`,
  `expires_at` (+`expires_at_dt`), `ttl_seconds`, `used_at`,
  `used_by_endpoint_id`, `revoked_at`, `revoked_by`, `revoke_reason`.
- States: `ACTIVE · CONSUMED · EXPIRED · REVOKED` via `store.token_state()`.
  Precedence REVOKED > CONSUMED > EXPIRED > ACTIVE — facts outrank the
  clock. A malformed/missing expiry resolves to **EXPIRED, never ACTIVE**
  (`test_a_malformed_token_document_is_never_active`).
- TTL: `EDR_ENROLLMENT_TOKEN_TTL_SECONDS` (900 s default in the pod),
  per-mint override bounded `60 ≤ ttl ≤ 86400`. Expiry is evaluated
  against **server** time on every read; the Mongo TTL index is cleanup
  only, never authorisation.

---

## 9 · REVOCATION SEMANTICS

`revoke_enrollment_token()` is a conditional update carrying
`used_at: None, revoked_at: None`, so it cannot half-happen against a
racing enrolment. Only an unused token is revocable.

Enrolment-token revocation and endpoint-identity revocation are kept
**distinct**: revoking a consumed token is refused with `409` and an
explicit pointer to `POST /edr/enrollment/endpoints/{id}/revoke`, and the
already-issued credential keeps working
(`test_consumed_token_is_not_revocable_and_identity_survives`).

---

## 10–12 · ATOMICITY, REPLAY, TENANT ISOLATION (proofs)

- **Atomic single use**: 25 concurrent enrolments on one token →
  **exactly one** success and exactly one credential document
  (`test_concurrent_consumption_yields_exactly_one_success`). The match
  and the burn are one `find_one_and_update`; there is no read-then-write
  window.
- **Replay**: a spent token is permanently unusable; the replay mints no
  credential, creates no endpoint, returns no original credential, and is
  audited (`test_enrollment_consumes_the_token_and_replay_is_refused`,
  plus live `HTTP 401` below).
- **Tenant isolation**: a Tenant-A token presented as Tenant B fails and
  creates nothing in Tenant B — and does not burn the token for its
  rightful owner (`test_token_cannot_enroll_into_another_tenant`). The
  endpoint credential is equally tenant-bound
  (`test_endpoint_credential_is_tenant_bound`). On the telemetry leg the
  tenant is an output of `resolve_session()`, never a caller input.

---

## 13–15 · ENDPOINT IDENTITY, CREDENTIAL SCOPE, PRIVILEGE BOUNDARY

`endpoint_id` is minted by the platform from durable machine attributes
(hardware id > machine GUID > device IID > hostname); an agent cannot
name itself. `AuthenticatedEndpoint` is frozen and carries exactly
`tenant_id, endpoint_id, credential_id, session_id, auth_method,
device_iid, authenticated_at` — no role, permission, scope, email or
approval authority
(`test_endpoint_identity_carries_no_console_authority`). No agent route
depends on `get_current_user`
(`test_agent_routes_never_depend_on_a_platform_user`).

Live privilege-boundary probe with a valid session token:

```
/api/edr/audit                   HTTP 401
/api/auth/me                     HTTP 401
/api/edr/enrollment/endpoints    HTTP 401
/api/edr/enrollment/tokens       HTTP 401
/api/edr/response/actions        HTTP 401
```

---

## 16–17 · WINDOWS AND LINUX BOOTSTRAP

**Windows** — already compliant, verified and locked by test:
`Install-NivXForgeSensor.ps1` takes `-EnrollmentToken`, has no
`$AdminPassword`/`$Credential`/`auth/login`, and runs
`nivxforge_sensor.py enrol --token`. State dir ACL is SYSTEM +
Administrators.

**Linux** — the real defect, now fixed.
`scripts/nivxforge_sensor_supervise.py` previously did
`POST /api/auth/login` with `ADMIN_EMAIL`/`ADMIN_PASSWORD` read out of
`backend/.env` and minted its own token. It now:
1. reads a provisioned token from `NIVXFORGE_ENROLLMENT_TOKEN` or
   `NIVXFORGE_ENROLLMENT_TOKEN_FILE` (the file is **deleted after
   reading** — a spent bearer secret does not stay on disk),
2. under `NIVX_DEPLOYMENT_ENV=production` with no token: **exits** with a
   stated reason and does **not** fall back to any credential path, and
   does not read `backend/.env` at all,
3. keeps the operator-credential mint as an explicitly labelled
   NON-PRODUCTION lab convenience, which is unreachable in production.

Failure is never silent: the launcher exits and the console keeps
reporting the endpoint as blind — the truth.

---

## 18 · LEGACY ADMIN BOOTSTRAP REJECTED IN PRODUCTION (proof)

`test_production_launcher_refuses_admin_credential_bootstrap` **runs the
launcher** as a subprocess with `NIVX_DEPLOYMENT_ENV=production` and with
`ADMIN_EMAIL`/`ADMIN_PASSWORD` deliberately present in the environment.
It asserts a non-zero exit, the `REMOVED`/production message, and that no
operator login was attempted. `test_launcher_admin_path_is_gated_behind_
the_production_check` additionally asserts the production guard appears
**before** the first `ADMIN_PASSWORD` reference in the source.

Console/admin authentication was not touched. This is sensor bootstrap
only.

Out of scope, reported: `scripts/p0_3_sensor_recovery_proof.py` and
`scripts/p0_b_sensor_proof.py` are development proof harnesses that still
log in as an operator. They are not an installation path and never run on
an endpoint.

---

## 19–20 · AUDIT AND REDACTION

New authoritative store `edr_enrollment_audit`, surfaced through the
existing `GET /api/edr/audit?category=ENROLMENT` aggregator (no second
truth). Events: `TOKEN_CREATED`, `TOKEN_REVOKED`,
`ENROLLMENT_SUCCEEDED`, `ENROLLMENT_REJECTED`, each with
`tenant_id, at, actor, outcome, token_id, endpoint_id, reason_code,
source_ip, secret_fingerprint, detail`.

Redaction is **enforced in code, not promised**: `_assert_no_secret()`
walks every value and raises `AuditRedactionError` if anything carries an
`enr_` / `eak_` / `est_` prefix, before the write
(`test_audit_store_refuses_to_write_secret_material`). Rejected attempts
store a 16-char non-reversible fingerprint so repeated abuse correlates
without the platform ever holding the token.

On the unauthenticated rejection path the audit append uses
`record_safe()`, which never raises: the authoritative security signal is
already in `edr_rejected_telemetry`, and letting an audit hiccup turn a
correct `401` into a `500` would itself be an oracle. Redaction
violations still raise.

Live leak scan: the full plaintext token was grepped against
`/var/log/supervisor/backend.{out,err}.log` → **0 occurrences**; a pattern
scan for `enr_[A-Za-z0-9_-]{20,}` across both logs → **no matches**; the
audit API response contains no secret prefix. P0-PROD-1 audit signing and
`key_id` semantics were not touched.

---

## 21 · PERFORMANCE / CRITICAL PATH

Enrolment is a one-time path. Routine sensor traffic (heartbeat,
telemetry, policy fetch/ACK) verifies a **session** via one indexed
keyed-digest lookup plus one credential lookup and an epoch comparison —
the expensive token path is not re-entered. Revocation remains an
immediate indexed lookup because the digest is deterministic. The new
work per mint/enrol is a single extra audit insert, off the telemetry
path. **No new synchronous external dependency was introduced anywhere in
the sensor critical path.**

---

## 22 · TEST COUNTS

```
tests/edr/test_p0prod2_enrollment_hardening.py        25 passed
tests/edr/ (whole EDR suite, incl. P0-A.2)           see below
tests/edr + test_b4b5_tenant_registry_authority.py
          + test_edr_onboarding_v1.py       536 passed · 3 skipped · 8 failed
```

All 8 failures are present in the frozen baseline (§23).

Live end-to-end proof against the preview backend:

```
mint              → token_id tok_… , single_use True
revoke (unused)   → 200 state REVOKED
enrol w/ revoked  → 401 ENROLLMENT_TOKEN_INVALID
re-revoke         → 409 ENROLLMENT_TOKEN_NOT_REVOCABLE
mint w/o auth     → 403
happy path        → endpoint ep_3d73be4ce10f1e09ff46, credential prefix eak_,
                    distinct from the token, sensor_state
                    ENROLLED_NEVER_REPORTED (enrolment is not visibility)
session           → est_…
heartbeat         → CONNECTED
policy fetch      → 200
replay of token   → 401
audit             → TOKEN_CREATED / TOKEN_REVOKED / ENROLLMENT_SUCCEEDED /
                    ENROLLMENT_REJECTED, no secret prefix in the response
```

---

## 23–24 · FROZEN-BASELINE COMPARISON · NEW REGRESSIONS

Compared against
`memory/production-gates/BASELINE_PYTEST_PRE_P0PROD2.json`.

**NEW REGRESSIONS: NONE.**

Two failures appeared during development and were both closed before this
report:

1. `test_b4b5_tenant_registry_authority::test_edr_enrollment_cannot_create_tenancy`
   — a strict audit append on the unauthenticated rejection path turned a
   correct `401` into a `500` under a fixture that does not initialise
   `deps.db`. **Real defect, fixed** with `audit.record_safe()`.
2. `test_p0_a2_enrollment::test_no_route_returns_a_token_digest_or_plaintext`
   — asserted the old `USED` state word. **Contract change required by
   this gate**; the assertion was updated to `CONSUMED` and strengthened
   with `legacy_state == "USED"` and `usable is False`. No assertion was
   weakened, skipped or deleted.

No whole-suite 48-minute rerun was performed: the change surface is the
EDR enrolment plane, and the affected suites were run in full. No
unrelated baseline debt was touched, and no Harness Debt Sweep was run.

---

## 25 · REMAINING RISKS (stated, not hidden)

1. **Credential at rest is filesystem-permission protected only.** No
   TPM, DPAPI, keyring or hardware binding. An attacker with SYSTEM/root
   on the endpoint can read `identity.json` and impersonate that endpoint
   until the credential is revoked or rotated.
2. **Token delivery is out of band.** The platform mints the token; how
   an operator/MDM gets it onto the endpoint is outside this gate. A
   token pasted into a shared channel is as exposed as the channel.
3. **No mTLS yet.** Transport security is TLS + bearer secrets.
   `AuthenticatedEndpoint` was designed so an mTLS authenticator can
   produce the same object, but that work is not done.
4. **No enrolment rate limiting / lockout** on the bootstrap route beyond
   the generic 401 and the rejection feed. Guessing a 256-bit token is
   not a realistic threat, but a flood is an availability question that
   P0-PROD-7 should measure.
5. **Windows `-ReEnroll` requires a new token** (correct), but a
   re-enrolment legitimately re-issues the credential for the same
   `endpoint_id`; delivery history is preserved by design (P0-3 fix).
6. Development proof harnesses still use operator credentials (§18).

---

## 26 · EXACT P0-PROD-3 DEPENDENCIES DISCOVERED

To make the latest EDR backend plane real in production, P0-PROD-3 must
account for:

1. **Routes that must exist in the production build**: `/api/edr/agent/*`
   (enroll, session, heartbeat, telemetry, policy, whoami),
   `/api/edr/enrollment/*` (tokens, tokens/{id}/revoke, endpoints,
   rotate, revoke, rejections), `/api/edr/policy*`, `/api/edr/exclusions*`,
   `/api/edr/findings`, `/api/edr/audit`, `/api/edr/response/*`.
2. **Environment variables the enrolment plane hard-requires** (absent ⇒
   refuse, by design): `EDR_AUTH_PEPPER`,
   `EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_AGENT_SESSION_TTL_SECONDS`,
   plus the P0-PROD-1 six and `NIVX_DEPLOYMENT_ENV=production`.
   `EDR_AUTH_PEPPER` is a **purpose-separated production secret** — it
   must be generated fresh for production and must NOT be copied from
   preview, because copying it would make preview-issued credentials
   verifiable in production.
3. **Indexes**: `store.ensure_indexes()` + `rejection.ensure_indexes()` +
   the new `audit.ensure_indexes()` must run at production startup
   (`edr_enrollment_audit` is a new collection — a clean create, not a
   migration).
4. **Tenant registry**: production needs its own registered, ACTIVE
   tenant(s). Enrolment deliberately cannot create tenancy, so an
   unregistered production tenant makes every enrolment fail closed with
   a generic 401 — which will look like a token problem if this is
   forgotten.
5. **Response authority still depends on the local response service**
   (P0-PROD-4). Destructive response must stay fail-closed in production
   until that gate closes.
6. Background/replica-sensitive jobs remain gated by P0-PROD-6.

---

## 27 · PRODUCTION MIGRATION CONSIDERATIONS

- `edr_enrollment_audit` is created empty. **No data migration.** Preview
  enrolment tokens, credentials and sessions must **not** be copied:
  their digests are peppered with the preview `EDR_AUTH_PEPPER` and would
  either be unverifiable or, worse, grant preview endpoints production
  standing.
- Pre-existing token documents (preview) lack `revoked_at`;
  `token_state()` treats a missing value as "not revoked", so old
  documents keep behaving correctly. No backfill is required.
- Real endpoints must enrol fresh in production with production-minted
  tokens.

---

## 28 · COMPLETION STATUS

```
P0-PROD-2 STATUS:                          PASS
ADMIN-CREDENTIAL SENSOR BOOTSTRAP IN PROD: REMOVED
WINDOWS TOKEN ENROLMENT:                   PASS (already compliant, now locked by test)
LINUX TOKEN ENROLMENT:                     PASS
SINGLE-USE / REPLAY:                       PASS
ATOMIC CONCURRENCY:                        PASS (25 concurrent → exactly 1)
TENANT ISOLATION:                          PASS
ENDPOINT IDENTITY:                         PASS
ENDPOINT PRIVILEGE BOUNDARY:               PASS
SECRET REDACTION:                          PASS
FOCUSED TESTS:                             25 new (all pass); 536 passed in the
                                           affected EDR/tenant/onboarding suites
NEW REGRESSIONS VS FROZEN BASELINE:        NONE
PRODUCTION DEPLOYMENT:                     NOT PERFORMED
PRODUCTION DB:                             NOT MODIFIED
VERCEL:                                    NOT DEPLOYED
P0-PROD-3:                                 NOT STARTED
P0-PROD-4:                                 NOT STARTED
P0-PROD-6:                                 NOT STARTED
```

**STOPPING FOR OWNER REVIEW.**
