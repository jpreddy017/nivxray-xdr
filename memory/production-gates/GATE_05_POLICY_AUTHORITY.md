# GATE 5 · Policy Authority & Enforcement — EVIDENCE

Status: **PASS (server-side lifecycle)** · 2026-09-26
Endpoint-side *enforcement* of policy settings remains a connector
capability gap and is declared, not claimed.

## What was built

One authority, `backend/edr_plane/policy/`:

* `contracts.py` — the nine states, the `PolicyConfig` (`extra=forbid`),
  the config digest, `unsupported_settings()` driven by the connector
  release's declared capability, and `derive_endpoint_state()` — the
  single derivation of an endpoint's policy truth.
* `store.py` — `edr_policies`, immutable `edr_policy_versions`,
  `edr_policy_endpoint_state`, append-only `edr_policy_audit`; group and
  endpoint assignment; delivery and acknowledgement recording.

Surfaces: `routers/edr_policies.py` (admin + connector),
`pages/EdrPoliciesPage.jsx`.

The platform default policy is now written **through the same
authority** (`edr_onboarding.ensure_default_placement`), so there is no
second policy model.

## The invariant

`ASSIGNED != DELIVERED != ACKNOWLEDGED != APPLIED != VERIFIED`.
State is **computed** from recorded facts, never stored as a headline,
so it cannot drift from its own evidence.

## Live proof

`scripts/gate5_7_11_live_proof.py` against the preview host — **all
assertions PASSED**:

| Assertion | Result |
|---|---|
| new policy starts at `CREATED` | PASS |
| assignment reports `ASSIGNED` and nothing more | PASS |
| before any fetch the endpoint is `PENDING_DELIVERY` | PASS |
| fetching the policy reports `DELIVERED` | PASS |
| delivered version carries the exact config digest | PASS |
| `DELIVERED` is NOT reported as applied (`confirmed_by_endpoint=false`) | PASS |
| an ACK for a digest never delivered → `RECORDED_OUT_OF_SYNC`, state stays `DELIVERED` | PASS |
| a correct ACK → `RECORDED_APPLIED` → `APPLIED` | PASS |
| `APPLIED` carries `confirmed_by_endpoint=true` | PASS |
| a later independent ACK → `RECORDED_VERIFIED` → `VERIFIED` | PASS |
| a new version makes the endpoint `OUT_OF_SYNC` | PASS |
| a reported apply failure → `FAILED`, never `APPLIED` | PASS |

The proof drives the real connector surfaces: it mints a deployment,
enrols a new endpoint, opens an authenticated session, fetches the
policy and acknowledges it. No database was edited to reach a state.

## Regression

`tests/edr` — **400 passed, 1 skipped, 0 failed**.
`EndpointRecord` gained `deployment_id`, `policy_source`,
`policy_assigned_at`, `policy_assigned_by` (the model forbids extras by
design; the missing fields were caught by the existing adversarial
suite and fixed).

## Declared, not claimed

The released connector 0.1.0 declares `endpoint_prevention: false`,
`file/network/registry collection: false` and
`endpoint_exclusions: false`. A policy requesting any of them is
recorded as requested and reported with
`state: NOT_SUPPORTED_BY_CONNECTOR` and a reason. The per-computer
`policy_lifecycle.enforced` stays `false`: a policy can be `VERIFIED`
and still enforce nothing, because `DETECT_ONLY` is what it asked for.

## Route classification

All nine admin routes and both connector routes are registered in
`routers/edr_tenancy.ROUTE_CLASSIFICATION`. The R4 regression gate
walks the live route table and fails closed on an unclassified EDR
route; 75 EDR routes, 0 unclassified.
