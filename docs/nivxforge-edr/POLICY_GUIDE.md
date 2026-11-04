# NivXForge EDR · Policy Guide

## The invariant

```
ASSIGNED  !=  DELIVERED  !=  ACKNOWLEDGED  !=  APPLIED  !=  VERIFIED
```

Five different facts about who has done what. The product never
collapses them, and **delivery alone can never produce APPLIED**.

## The authority chain

```
Tenant → Group → Policy → Policy Version → Endpoint Assignment
  → Delivery → Acknowledgement → Applied → Verified
```

One authority (`edr_plane.policy`) serves the console, the exclusion
plane and the connector. There is no second policy model and no second
delivery mechanism.

## Objects

| Object | Collection | Mutability |
|---|---|---|
| Policy | `edr_policies` | name, description and `current_version` pointer |
| Policy version | `edr_policy_versions` | **immutable** — a change is a new version |
| Group | `edr_groups` | carries `policy_id` |
| Per-endpoint state | `edr_policy_endpoint_state` | delivery / ack / apply record |
| Audit | `edr_policy_audit` | append-only |

Every version carries a **config digest** (`cfg_…`) computed from the
canonicalised configuration. The digest is what an endpoint must
acknowledge, which is what makes "the endpoint applied *this*
configuration" checkable rather than asserted.

## Configuration surface

`extra="forbid"` on the config model is the point: a setting no
connector honours cannot be smuggled into a policy and then rendered as
protection.

| Setting | Honoured by release 0.1.0 |
|---|---|
| `mode` (`DETECT_ONLY` / `PREVENT`) | `DETECT_ONLY` only |
| `prevention_enabled` | **no** |
| `report_interval_seconds` (10–3600) | yes |
| `heartbeat_interval_seconds` (10–3600) | yes |
| `collect_process_events` | yes |
| `collect_file_events` | **no** |
| `collect_network_events` | **no** |
| `collect_registry_events` | **no** |
| `exclusion_set_ids` | **no** (server-side enforcement only) |

Anything requested but not declared by the release appears in
`not_enforced[]` with `state: NOT_SUPPORTED_BY_CONNECTOR` and a reason.

## Assignment precedence

1. an explicit **endpoint override**
2. the endpoint's **group** policy
3. the placement written at **enrolment**
4. nothing → `POLICY_UNASSIGNED`

`POLICY_UNASSIGNED` is not a lifecycle state. It is the honest answer
for a computer that no policy resolves to.

## The nine states

| State | Recorded fact |
|---|---|
| `CREATED` | a policy version exists in the authority |
| `ASSIGNED` | an endpoint resolves to this version, but is not currently eligible to receive it (no active credential) |
| `PENDING_DELIVERY` | the endpoint is enrolled with an active credential and will receive it at its next check-in |
| `DELIVERED` | the platform handed the exact version to the endpoint's authenticated session |
| `ACKNOWLEDGED` | the endpoint confirmed RECEIPT of that exact version and digest |
| `APPLIED` | the endpoint confirmed it APPLIED that exact digest |
| `VERIFIED` | a LATER, independent check-in re-reported the same running digest |
| `FAILED` | the endpoint reported it could not apply it, with its reason |
| `STALE` | the endpoint stopped checking in before the state could be confirmed (the underlying state is preserved) |
| `OUT_OF_SYNC` | the endpoint holds a different version than the one now assigned |

Every row also carries `confirmed_by_endpoint` — true only for
`APPLIED` and `VERIFIED` — and the server's `basis` sentence.

## The connector surfaces

### `GET /api/edr/agent/policy`

Authenticated connector session. **Fetching is delivery.** Returns the
policy id, version, config, config digest and the resolved exclusions,
and records `DELIVERED`. Nothing more.

### `POST /api/edr/agent/policy-ack`

```json
{ "policy_id": "pol_…", "version": 2,
  "config_digest": "cfg_…", "applied": true,
  "running_config_digest": "cfg_…",
  "connector_version": "0.1.0-windows",
  "failure_reason": null }
```

* The acknowledgement must name the **currently assigned** policy id,
  version and digest. An acknowledgement for anything else is
  **recorded** — it is real endpoint truth — as `OUT_OF_SYNC`, and can
  never produce `APPLIED`.
* `applied: true` with a matching `running_config_digest` → `APPLIED`.
* A **later** acknowledgement repeating the same running digest →
  `VERIFIED`. An apply acknowledgement can never verify itself.
* `applied: false` with a `failure_reason` → `FAILED`.

## Authoring workflow

1. `Policies → New policy` — creates the policy and immutable
   version 1.
2. Assign to a group (or a single endpoint as an override).
3. Publishing a change → **New version**. Every endpoint holding the
   previous version immediately reads `OUT_OF_SYNC` until it
   acknowledges the new one. Nothing is silently rewritten.

## Reading the console honestly

* `Awaiting confirmation` counts `ASSIGNED + PENDING_DELIVERY +
  DELIVERED + ACKNOWLEDGED`. Those computers are **not** known to be
  running the policy.
* `Applied` column reads `NOT CONFIRMED` rather than showing the
  assigned version when the endpoint has not acknowledged it.
* `enforced` in the per-computer protection block is `false` for the
  released connector. That is a capability fact and is deliberately
  separate from the delivery lifecycle: a policy can be `VERIFIED` and
  still enforce nothing, because `DETECT_ONLY` is what it asked for.

## API summary

| Method | Path |
|---|---|
| `GET` | `/api/edr/policies` |
| `POST` | `/api/edr/policies` |
| `GET` | `/api/edr/policies/{policy_id}` |
| `POST` | `/api/edr/policies/{policy_id}/versions` |
| `POST` | `/api/edr/policies/{policy_id}/assign` |
| `GET` | `/api/edr/policies/deployment[?policy_id=]` |
| `GET` | `/api/edr/policies/audit` |
| `GET` / `POST` | `/api/edr/groups` |
| `GET` | `/api/edr/agent/policy` (connector) |
| `POST` | `/api/edr/agent/policy-ack` (connector) |

All admin routes require an explicit `X-Tenant-Id`. Connector routes
take the tenant from the authenticated endpoint session and never read
a header.
