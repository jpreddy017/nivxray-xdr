# P0 — PRODUCTION PLATFORM AUTHORITY REPAIR

2026-09-29. Phase 1 CONFIRMED. Phase 3 mutation **NOT APPLIED** — see the mechanism
blocker in §3. Nothing was changed in production. Tenant authority not weakened.

## REQUIRED OUTPUT

```
PRODUCTION_PRINCIPAL             = admin@nivxray.com
ROLE                             = admin
AUTHORITY_SCOPE_BEFORE           = ABSENT (field not present on the document;
                                   0 of 1 production users carry any authority_scope)
TENANT_IDS_BEFORE                = ABSENT (field not present on the document)

INTERNAL_VALIDATION_TENANT_EXISTS = YES — `tenants`, display_name "Internal Validation",
                                    status ACTIVE, id ten_e759b7288598bd882e3dcac49d
ENDPOINT_EXISTS                   = YES — ep_1989031c8c1d0085812f / DESKTOP-A9HGFJJ,
                                    REPORTING, under that tenant
EVIDENCE_EXISTS                   = YES — edr_raw_events 117,904 · canonical_evidence
                                    45,355 · fresh to 2026-09-29T16:40-16:41Z
SENSOR_RECEIVE_BEFORE_REPAIR      = ACTIVE — agent session/policy/telemetry all 200,
                                    latest 2026-09-29T16:42:28Z

ROOT_CAUSE_CONFIRMED             = YES

REPAIR_APPLIED                   = NO
REPAIR_SCOPE                     = intended: users.authority_scope = "PLATFORM" for
                                   exactly one principal (admin@nivxray.com) in the
                                   production auth store. NOT EXECUTED — no available
                                   write path (§3).

AUTHORITY_SCOPE_AFTER            = unchanged / ABSENT

COMPUTERS_ACCESS                 = FAIL (403, pre-repair — unchanged)
EVENTS_ACCESS                    = FAIL (403, pre-repair — unchanged)
DEVICE_TRAJECTORY_ACCESS         = NOT_ACCESSIBLE (403, pre-repair — unchanged)

TENANT_ISOLATION                 = PASS (boundary intact and enforcing; 40/40 negative
                                   controls green — §4)
DATA_LOSS                        = NO

PROD_REPUBLISH_REQUIRED          = YES: a production DATA write requires an app-side
                                   write path, and none exists today. Either add the
                                   one-time designation path and deploy once, OR the
                                   owner executes the existing script against the
                                   production store directly (no deploy). Owner's
                                   choice — see §3.

B5_EID5_END_TO_END               = HOLD: production tenant authorization not yet
                                   restored (repair blocked on mechanism, not on
                                   diagnosis)
```

## 1. PHASE 1 — PRODUCTION CONFIRMATION (store: `greeting-app-5782-test_database`, live run `0aba534a`)

All four Phase-2 conditions are proven:

| Condition | Evidence | Verdict |
|---|---|---|
| 1. `admin@nivxray.com` is the intended NivX PLATFORM / Super Admin | `scripts/fix6b1b_platform_designation.py` header: *"Owner-approved 2026-06. Exactly ONE field on exactly ONE principal: `users.authority_scope = "PLATFORM"` for `admin@nivxray.com`"*; it is the only principal in the production auth store | YES |
| 2. it currently lacks `authority_scope = "PLATFORM"` | production `users` document has **neither** `authority_scope` **nor** `tenant_ids`; **0 of 1** production users carry any `authority_scope` | YES |
| 3. tenant / endpoint / evidence still exist | tenant ACTIVE "Internal Validation"; endpoint REPORTING; 117,904 raw events; 45,355 canonical evidence; fresh to 16:40–16:41Z | YES |
| 4. the 403 is caused by that missing designation | **29 × 403** reproduced server-side post-16:31 rollout on `/api/edr/onboarding/computers`, `/events`, `/events/facets`, `/telemetry/freshness`, `/endpoints`, `/saved-views`, `/endpoint-detections`, all tagged `tenant_id=ten_e759b7288598bd882e3dcac49d`, while `/api/xdr/rbac/session-context` returns **200** (login itself is fine) | YES |

Also established: `STORE_CONTINUITY = PASS` — Publish 99 (`d85f3698`) and Publish 100
both resolve `DB_NAME = greeting-app-5782-test_database`, and no secret change ran
between them. Publish 100 startup logs are clean: no migration or tenant-registry
errors. So this is not a store swap, not a config loss, and not a code defect.

`REPAIR_REQUIRED = EXPLICIT_PLATFORM_DESIGNATION`

**Why the field was never there.** `deps.py :: seed_admin` — the bootstrap that created
this principal — writes exactly five fields:

```python
await db.users.insert_one({
    "email": ADMIN_EMAIL, "password": hash_password(ADMIN_PASSWORD),
    "role": "admin", "must_change_password": _ADMIN_FORCE_PW_CHANGE,
    "created_at": ...,
})
```

No `tenant_ids`, no `authority_scope`. Under Publish 99 that was survivable because
`role: "admin"` alone conferred `all_tenants: True`. Publish 100 retired that, and the
replacement designation lives only in a script bound to `/app/backend/.env` — a
non-production store. Hence: 0 authority-bearing principals in production.

## 2. PHASE 2 — DECISION

`REPAIR_REQUIRED = EXPLICIT_PLATFORM_DESIGNATION`, exactly as the owner's Phase-2 gate
specifies. The old behaviour is NOT restored; `role: "admin"` will continue to imply
nothing about tenant breadth.

## 3. PHASE 3 — CONTROLLED REPAIR: **BLOCKED ON MECHANISM, NOT ON AUTHORITY**

The owner's approval is understood and accepted. I could not execute it, and I will not
pretend otherwise. Three independent facts close every write path I have:

1. **I have no production database credentials.** The production `MONGO_URL` is a
   deployment secret; the diagnose can confirm its *presence* only. `backend/.env` in
   this workspace points at the container-local preview mongod — and the owner's own
   constraint ("do not use `/app/backend/.env` if it points to preview") correctly
   forbids using it.
2. **The deployer diagnose capability is read-only for production data by design.** It
   reads pod runtime, logs, secret presence and DB binding. It cannot write a document.
   Its own returned guidance says the corrective action "lives in prod DATA … Owner
   decides whether/how to execute; nothing was changed here."
3. **No existing production API route can set this field.** I checked every
   user-mutating endpoint:
   - `PUT /api/xdr/rbac/users/{user_id}` — writes the tenant-scoped RBAC user
     collection, and accepts only `display_name`, `groups`, `enabled`. It cannot reach
     `users.authority_scope`, and it is itself tenant-scoped (so it would need the very
     authorization that is broken).
   - `POST /api/xdr/access/users/{user_id}/grants` and `/restrictions` — data-scope
     grants, a different store; not `users.authority_scope` or `users.tenant_ids`.
   - `routers/auth.py` — only `/auth/login` and `/auth/change-password`; the sole write
     is the password field.
   - `routers/admin.py` — reads users; no user-mutating route.

   Grep confirms the ONLY writers of the auth `users` collection anywhere in the backend
   are `auth.py` (password) and `deps.py :: seed_admin` (insert-if-absent).

So the approved one-field mutation has no vehicle today. Two ways to give it one — the
owner picks; I have implemented neither:

**Option A — one-time designation in the existing startup bootstrap (needs one deploy).**
Extend the already-present `seed_admin` path with a separate, explicit, idempotent
designation driven by a production secret, e.g. `NIVX_PLATFORM_PRINCIPAL=admin@nivxray.com`:
reads the env var, and if that exact principal exists and lacks the field, sets
`authority_scope = "PLATFORM"` and logs before/after. Authority stays explicit and
server-side; nothing is inferred from role; absent env var = no write; unknown principal
= refuse and log. Idempotent on every subsequent boot. This contradicts the owner's
"do not republish merely for this data repair" — flagged deliberately, because the
alternative is Option B.

**Option B — owner executes the existing script against production (no deploy).**
`scripts/fix6b1b_platform_designation.py` is already owner-approved, idempotent, writes
exactly one field, records before/after, prints a fingerprint of every
`authority_scope` holder, and refuses on unexpected state. It needs (a) the production
connection string, which only the owner can supply, and (b) one caveat: its guard
`EXPECTED_GRANTS = ["default", "nivx-live"]` will **REFUSE** against production, because
the production document has no `tenant_ids` at all. That guard would need to be relaxed
to "absent grants are acceptable" — a one-line change to a script, not to the
authorization boundary.

**Option C — narrower alternative.** Add `ten_e759b7288598bd882e3dcac49d` to
`tenant_ids[]` instead of granting PLATFORM. Least authority, but it makes the Super
Admin a single-tenant CUSTOMER principal and must be repeated for every future customer.
Same mechanism problem as A/B.

Nothing in any option weakens `authorize_requested_tenant()`, reinstates
`_CROSS_TENANT_ROLES`, adds a default-tenant fallback, trusts a client-supplied tenant,
or touches roles, passwords, evidence, endpoints or the tenant registry.

## 4. PHASE 4 — AUTHORIZATION VERIFICATION

Positive verification (Computers / Events / Trajectory as PLATFORM) **cannot be run
until the designation exists**. Reported as FAIL/NOT_ACCESSIBLE above rather than
skipped, and it will be re-run server-side immediately after the repair.

Negative security behaviour, proven now without altering any principal:
`tests/edr/test_p0_tenant_authority_fix6b2.py` → **40 passed**. It asserts, among
others, that a CUSTOMER principal naming another tenant is refused
`TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, that `role` confers no breadth, that
`authority_scope` must be the exact string `"PLATFORM"` (not `"platform"`, not a role
name, not a truthy value), and that `X-Tenant-Id` never authorizes itself. No production
principal was modified to manufacture this proof.

`TENANT_ISOLATION = PASS` — the boundary is working correctly. This outage is the
boundary doing its job against a principal whose explicit authority was never written.

## 5. PHASE 5 — DATA / INGEST CHECK (pre-repair, production)

```
DESKTOP-A9HGFJJ    = PRESENT in the production store (not visible in the console only
                     because of the 403)
ENDPOINT           = ep_1989031c8c1d0085812f · REPORTING
EVENTS             = PRESENT · edr_raw_events 117,904 · canonical_evidence 45,355
SENSOR_RECEIVE     = ACTIVE
LATEST_TELEMETRY   = 2026-09-29T16:42:28Z (agent routes 200; session/policy/telemetry
                     all unaffected by the console regression)
DEVICE_TRAJECTORY  = NOT_ACCESSIBLE (403 authorization, not missing data)
```

Note the raw-event count **rose** from 116,012 (15:32Z) to 117,904 (16:40Z) across the
Publish 100 rollout: the new build is ingesting normally. The regression is confined to
the browser principal's authorization; the sensor path was never affected.

No telemetry loss is inferred from the authorization refusal.

## 6. PHASE 6 — B5

`B5_EID5_END_TO_END = HOLD` (authorization not yet restored). No EID5 replay performed.
B5 is not marked PASS. It resumes the moment the console is authorized again.

STOP FOR OWNER REVIEW. NO PRODUCTION CHANGE MADE.
