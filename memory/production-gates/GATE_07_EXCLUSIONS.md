# GATE 7 · Exclusions & declared protection blind spots — EVIDENCE

Status: **PASS (server-side enforcement proven)** · 2026-09-26
Endpoint-side enforcement is DELIVERABLE through the policy authority
and reports its real state; the released connector does not declare the
capability, so it is never claimed.

## What was built

`backend/edr_plane/exclusions/`:

* `contracts.py` — six types, five match kinds, three engines, six
  truth states, approval states, `lifecycle_state()`, `matches()` and
  `in_scope()`. Every owner-required field is mandatory by
  construction: tenant, scope, type, value, reason (min 10 chars),
  creator, approval, affected engines, policy version bindings,
  effective time, expiry, review, audit.
* `store.py` — `edr_exclusion_sets`, `edr_exclusions`. Nothing is
  deleted; revocation is a recorded event.
* `enforcement.py` — the gate (`NOT_EVALUATED_DUE_TO_EXCLUSION` before
  an analyzer runs), the suppressor (`EXCLUDED` for findings that
  already existed) and `endpoint_truth_state()`.

Surfaces: `routers/edr_exclusions.py`,
`pages/EdrExclusionsPage.jsx`.

## The owner correction, implemented

Truth is NOT collapsed into one token. Two axes are reported
separately:

* **what happened to the evidence** — `EXCLUDED` (a finding existed and
  was suppressed, with `suppressed_by`) vs
  `NOT_EVALUATED_DUE_TO_EXCLUSION` (the engine was bypassed before it
  ran).
* **where enforcement happened** — `SERVER_EXCLUSION_APPLIED`,
  `ENDPOINT_EXCLUSION_APPLIED`, `EXCLUSION_PENDING_POLICY`,
  `EXCLUSION_NOT_SUPPORTED_BY_ENGINE`.

`GET /api/edr/exclusions/enforcement-proof` returns both per example
(`evidence_truth_state`, `enforcement_truth_state`).

## Live proof — a Mongo record alone is a FAIL

`GET /api/edr/exclusions/enforcement-proof?sample=400` executes the
registered deterministic analyzer over real persisted evidence twice,
with and without the gate. Read-only.

| Assertion | Result |
|---|---|
| the fabric produces real findings before any exclusion | PASS · `FINDINGS=2` |
| an **UNAPPROVED** exclusion changes nothing | PASS · `bypassed=0`, `consulted=0` |
| self-approval is refused (`SELF_APPROVAL_REFUSED`, 409) | PASS |
| a second operator can approve | PASS |
| the approved exclusion is consulted by the engine | PASS |
| the exclusion **actually bypassed the engine** | PASS · `bypassed=3`, `findings_suppressed=2` |
| both evidence truth states are preserved | PASS · `{EXCLUDED, NOT_EVALUATED_DUE_TO_EXCLUSION}` |
| server enforcement reports `SERVER_EXCLUSION_APPLIED` | PASS |
| endpoint enforcement is NOT claimed | PASS · `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` |
| revoking the exclusion restores the engine | PASS · `bypassed=0` |

The exclusion value used by the proof is **derived from real matched
evidence in the environment** (`PATH = /usr/bin/bash` in this run), so
the proof can never be tuned to a hardcoded string.

## Inertness is a code path, not a policy statement

`store.enforceable_for_endpoint()` is the only function the fabric
calls, and it filters on `approval_state == APPROVED`,
`revoked_at is None`, an enforceable lifecycle state and scope. An
unapproved exclusion is therefore unreachable by any engine.

## Known limit

`endpoint.prevention` / `endpoint.collection` are declared as delivery
targets. Release 0.1.0 does not declare `endpoint_exclusions`, so those
engines honestly report `EXCLUSION_NOT_SUPPORTED_BY_ENGINE`. When a
release declares the capability, the state flips to
`EXCLUSION_PENDING_POLICY` and then to `ENDPOINT_EXCLUSION_APPLIED`
once the endpoint acknowledges a policy version carrying the set —
which is why the policy-version binding is recorded now.
