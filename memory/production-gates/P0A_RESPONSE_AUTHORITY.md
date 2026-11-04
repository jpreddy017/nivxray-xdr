# P0-A · EDR RESPONSE AUTHORITY — EVIDENCE PACKAGE

Slice: **P0-A only.** Owner directive *OWNER DECISION — P0-A RESPONSE
AUTHORITY*. Closed 2026-09-26. P0-B was **not** started.

## PRECONDITION

Audit finding C3: `POST /api/edr/response/actions` required only an
authenticated, tenant-authorised session. No action-level permission, no
approver distinct from the requester, no replay protection. 82 real
commands already existed. `edr_plane/response.py` self-authorised
containment from `requested_by`.

## ARCHITECTURAL INVARIANT IMPLEMENTED

    user / EDR console
      → authoritative backend identity + RBAC   (routers/xdr_rbac.py)
      → response-engine approval authority       (/api/respond/*)
      → validated exact-action approval          (edr_plane/authority.py)
      → NivXForge EDR adapter                    (framework/nivxforge_edr.py)
      → endpoint → execution result → independent verification

NivXForge EDR **issues no approvals**, stores no approval authority and
defines no roles. It resolves permissions through the platform's existing
resolver and validates an artifact the authority already produced.

## EXACT AUTHORIZATION FLOW (`POST /api/edr/response/actions`)

1. `get_current_user` — authenticated principal (401 otherwise).
2. `edr_tenant` — server-side tenant resolution from the registry; there
   is no default tenant (403 `TENANT_REQUIRED`).
3. `edr_scope(tenant, user)` — the principal must hold that tenant
   (403 `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`).
4. `_canonical_endpoint_id` — the endpoint reference is resolved inside
   the caller's scope only.
5. `authority.authorize(...)`:
   a. `permissions_for` → requester must hold **`response.execute`**
      (403 `RESPONSE_EXECUTE_NOT_AUTHORIZED`, basis disclosed).
   b. `RELEASE_ISOLATION` → permission-only, `approval_required: False`,
      basis `RESTORATIVE_ACTION_PERMISSION_ONLY`.
   c. otherwise `action_spec(action_id)` from the **authority's own**
      action catalogue decides `approval_required` (503 if the authority
      is unreachable/unconfigured, or does not declare the action).
   d. `validate_approval` binds the artifact: exists · status
      `approved` · action matches · tenant matches · endpoint matches
      (from the artifact's own parameters) · requester matches the
      artifact's invoker · approver recorded · approver ≠ requester ·
      approver holds **`response.approve`** · approval age within the
      bounded window (`EDR_APPROVAL_MAX_AGE_SECONDS`, default 900 s).
6. `resp.request_action(..., authority=decision)` — records the command,
   stamps the authority block, and refuses a reused approval at the store
   (409 `APPROVAL_ALREADY_CONSUMED`, unique partial index).
7. Dispatch → endpoint execution → sensor result → independent
   verification. Unchanged: `REQUESTED ≠ AUTHORIZED ≠ DISPATCHED ≠
   EXECUTED ≠ VERIFIED`.

No break-glass path, no platform-admin bypass, no EDR-side approval UI.

## CODE CHANGED

| File | Change |
|---|---|
| `backend/edr_plane/authority.py` | **NEW** — the gate: permission resolution, authoritative requirement lookup, approval binding, freshness, fail-closed transport |
| `backend/edr_plane/response.py` | `request_action(..., authority=...)`; authority block stamped on every command; `APPROVAL_VALIDATED` history entry; unique partial index `cmd_approval_ref_unique`; `APPROVAL_ALREADY_CONSUMED`; idempotent release (`NO_ACTIVE_ISOLATION` / replay of the existing record); `INTERNAL_AUTHORITY` label for the in-process auto-release |
| `backend/routers/edr_response.py` | gate on `POST /actions`; `approval_ref` field; gate on `PUT /isolation-policy` (it decides what stays reachable during containment); requester identity aligned with the authority's invoker id |
| `backend/routers/xdr_respond_boundary.py` | client-supplied `approval_ref` / `approved_by` / `approved_at` are **stripped** on intake — the engine treated them as a pre-approval, which allowed self-pre-approval |
| `apps/nivxray-xdr-response/framework/executor.py` | adapter ctx carries the approval block; the execution read discloses `parameters` + `canonical_target` so an approval is **independently verifiable** by the product that must act on it |
| `apps/nivxray-xdr-response/framework/nivxforge_edr.py` | forwards `approval_ref` = the **execution id** (the fetchable artifact) and the authoritative `X-Tenant-Id` (without it the orchestrated dispatch was rejected `TENANT_REQUIRED` — a pre-existing defect) |

## TESTS

**Added** — `backend/tests/edr/test_p0a_response_authority.py` (27,
deterministic; only the authority *transport* is stubbed, every binding
rule is real) and `backend/tests/edr/test_p0a_response_authority_live.py`
(8, the wired path on the preview host with two real operators).

**Changed** — `backend/tests/edr/test_p0_f10_live_api.py`:

| | OLD | NEW |
|---|---|---|
| `test_isolate_action_carries_authorized_step` → `test_isolate_action_requires_an_authoritative_approval` | direct isolate → `AUTHORIZED` | direct isolate without an authoritative approval → **403 `APPROVAL_REQUIRED`**, nothing recorded |
| `test_kill_action_still_two_step_no_authorisation` → `test_kill_action_requires_an_authoritative_approval` | direct kill → `REQUESTED` (or any refusal) | direct kill without an authoritative approval → **403 `APPROVAL_REQUIRED`** naming `endpoint.kill_process` |

This is an intentional security-contract change, not a regression.

## ACTUAL RESULT

`tests/edr/test_p0a_response_authority.py` · **27 passed**
`tests/edr/test_p0a_response_authority_live.py` · **8 passed**
`apps/nivxray-xdr-response/tests` · **27 passed**
Full EDR regression `tests/edr` · **460 passed · 1 skipped · 0 failed**
(baseline 425/1/0; +35 = the new security tests. The one skip is
`test_iteration_82_activation.py:213`, a corpus precondition, unchanged.)

### Negative coverage proven

| Case | Refusal | Where |
|---|---|---|
| requester lacks `response.execute` | 403 `RESPONSE_EXECUTE_NOT_AUTHORIZED` | deterministic + live |
| missing approval | 403 `APPROVAL_REQUIRED` (+ workflow named) | deterministic + live |
| nonexistent approval | 403 `APPROVAL_NOT_FOUND` | deterministic |
| pending / rejected / absent status | 403 `APPROVAL_NOT_APPROVED` | deterministic (3 cases) |
| wrong action | 403 `APPROVAL_ACTION_MISMATCH` | deterministic + live |
| wrong endpoint | 403 `APPROVAL_ENDPOINT_MISMATCH` | deterministic |
| wrong tenant | 403 `APPROVAL_TENANT_MISMATCH` | deterministic |
| artifact discloses no target | 403 `APPROVAL_TARGET_NOT_DISCLOSED` | deterministic |
| approval requested by someone else | 403 `APPROVAL_REQUESTER_MISMATCH` | deterministic |
| requester == approver | 403 `SELF_APPROVAL_REFUSED` | deterministic + **live, end to end** |
| approver lacks `response.approve` | 403 `APPROVER_NOT_AUTHORIZED` | deterministic |
| no approver recorded | 403 `APPROVER_NOT_RECORDED` | deterministic |
| approval too old | 403 `APPROVAL_EXPIRED` | deterministic |
| approval time unusable | 403 `APPROVAL_AGE_UNKNOWN` | deterministic |
| consumed / replayed approval | 409 `APPROVAL_ALREADY_CONSUMED` | deterministic + **live** |
| authority unreachable | 503 `RESPONSE_AUTHORITY_UNAVAILABLE` | deterministic |
| authority unconfigured | 503 `RESPONSE_AUTHORITY_NOT_CONFIGURED` | deterministic |
| action not in the authority's catalogue | 503 `ACTION_NOT_IN_AUTHORITATIVE_CATALOGUE` | deterministic |
| cross-tenant response | 403/404 | live |
| unauthenticated response | 401/403 | live |
| release without `response.execute` | 403 `RESPONSE_EXECUTE_NOT_AUTHORIZED` | deterministic + live |
| release of an uncontained endpoint | 409 `NO_ACTIVE_ISOLATION`, nothing recorded | deterministic |
| repeated release | `idempotent_replay: true`, same `command_id`, ONE record | deterministic |
| isolation-policy write without permission | 403 `RESPONSE_EXECUTE_NOT_AUTHORIZED` | live |

### Positive coverage proven

* Approved isolate, end to end on the preview host: admin requests →
  `WAITING_APPROVAL` → a *second* real operator (`soc_manager`, holds
  `response.approve`, not `response.execute`) approves → the engine
  dispatches into EDR → EDR validates and records exactly ONE command.
  The record carries `authority.approval_ref`, `authority.approved_by`,
  `authority.principal`; `proof.success_claimed` is `false`;
  `executed_at` and `verified_at` are `null`.
* Approved kill (deterministic): accepted and still bound to the observed
  process start identity — `observed_start_ticks` unchanged.
* Internal auto-release is labelled `INTERNAL_POLICY_AUTOMATION`, never
  presented as operator-authorised.

## NO CIRCULARITY

EDR validates the authority's **execution record**, which is `approved`
and names its approver *before* the engine dispatches. The read is a
stable prior authorization artifact, addressed by execution id, and does
not depend on the dispatch it authorises completing. The engine's
internal minted `approval_ref` is deliberately NOT what travels, because
it is not independently fetchable.

## REMAINING RISKS

1. **No EDR-console approval-request UI** (deliberate, per directive). An
   EDR-only operator cannot start the authoritative workflow from the EDR
   console yet — recorded as a later usability slice. The authority stays
   backend-owned.
2. **Approval expiry is an EDR-side control.** The artifact carries no
   `expires_at`; EDR enforces a 900 s freshness window and discloses that
   basis. Adding a real expiry to the authority artifact is the better
   long-term fix.
3. **The approver's permission is re-resolved by email.** A principal with
   no granular assignment and no platform user record resolves to zero
   permissions (fail closed), which is safe but will refuse federated
   approvers until they are provisioned.
4. **`edr_findings` remains empty and exclusions still destroy
   evidence** — P0-B and P0-C, untouched by this slice.
5. **The response-engine execution store is SQLite** on the engine's own
   volume. An approval artifact is only as durable as that file.
6. `tests/test_edr_route_tenant_authority.py` has **146 pre-existing
   failures** caused by routes added in the previous session having no
   probe in its `SAMPLES` map (`KeyError`, plus its own coverage
   assertion). None mention any response or authority code path; it is
   the known stale-contract debt, not a P0-A regression.
