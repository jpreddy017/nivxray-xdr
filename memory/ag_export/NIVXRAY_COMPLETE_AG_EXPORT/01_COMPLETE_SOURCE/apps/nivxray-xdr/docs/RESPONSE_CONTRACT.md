# NivXRay XDR — Response Contract

**Status:** Response Execution Integration slice · v0.2 · 2026-02-10.

The Response plane is a standalone service:
`/app/apps/nivxray-xdr-response/`. Every invocation surface —
Playbook Designer Run, Automation Rules, Analyst Response Drawer,
Visual Execution Studio — sends a single canonical request to
`POST /api/respond/execute` and reads state back from
`GET /api/respond/executions/{id}`.

## 1 · Execution State Machine

```
QUEUED
  ├── (no approval needed)     ─→ RUNNING ─→ EXECUTING ─→ FORWARDING_EVIDENCE
  │                                                            ├── SUCCEEDED
  │                                                            └── FAILED_FORWARDING
  ├── (approval needed)        ─→ WAITING_APPROVAL
  │                                 ├── approve ─→ EXECUTING ─→ FORWARDING_EVIDENCE ─→ …
  │                                 └── reject  ─→ FAILED_APPROVAL
  └── (validation error)       ─→ REJECTED / FAILED_TARGET
```

Every state transition is persisted to the Response Engine's own
SQLite DB (`executions.db`) BEFORE any external side effect.

- **Restart recovery**: any row stuck in `RUNNING` / `EXECUTING` /
  `FORWARDING_EVIDENCE` on engine boot is flipped to
  `FAILED_RECOVERED` — the operator sees where the crash happened
  rather than the engine silently re-firing a vendor call.

## 2 · Approval Workflow

Approval-required actions do NOT return 403 synchronously. They
transition into `WAITING_APPROVAL` and the caller receives an
`execution_id`. A peer decides:

- `POST /api/respond/approve/{execution_id}` → resumes the same
  execution (never a duplicate).
- `POST /api/respond/reject/{execution_id}` → terminates with
  `FAILED_APPROVAL`.

Approval decisions are immutable — `409 invalid_state_for_approval`
on any second decision.

Legacy pre-approved path is preserved: if the initial `execute` call
carries `authorization.approval_ref` + `authorization.approved_by`,
the engine treats the action as pre-approved and runs straight
through. This keeps the Playbook Simulator dry-run path frictionless.

## 3 · Idempotency

Key: `(tenant_id, invoker_kind, invoker_id, execution_id)`.

- Duplicate POSTs return the prior response verbatim with
  `idempotent_replay: true`.
- Terminal executions replay identically. A duplicate approve on a
  terminal execution returns 409.

## 4 · Evidence-First Invariants

An execution reaches `SUCCEEDED` **only when both**:

1. `adapter_result.ok == True` (real vendor call reported success),
2. Evidence Forwarder produced `evidence_ref` + `audit_ref` +
   `timeline_ref` (or `forwarding_state == "not_wired"` if the base
   endpoint URL is intentionally unset in this deployment).

If (1) holds but (2) fails → `FAILED_FORWARDING`.
The engine never claims success while the evidence chain is broken.

## 5 · Invoker Kinds

- `playbook`         — Playbook Designer Run.
- `automation_rule`  — WHEN → IF → THEN.
- `analyst`          — Analyst Response Drawer.
- `simulator`        — Visual Execution Studio Debug mode (dry-run).

The engine trusts none of these individually — every request MUST
carry `authorization.scopes` covering the action's
`required_permissions`. Missing scopes → HTTP 403 `authorization_failed`.

## 6 · Response Action Registry

18 canonical actions across `endpoint`, `identity`, `network`,
`email`, `nivxray` providers. Each carries:

- `action_id`, `provider`, `capability`, `label`
- `parameters` (typed, with `required` markers)
- `required_permissions` (role + scope)
- `approval_required`, `reversible`, `destructive`
- `adapter_status`: `AVAILABLE` / `NOT_CONNECTED` / `NOT_IMPLEMENTED`
  / `NOT_AUTHORIZED` — Phase 1 ships every action as `AVAILABLE`
  with `simulation_only: true` because adapters are deterministic
  stubs. Phase C wires real CrowdStrike / Defender / SentinelOne /
  Cisco SEP adapters without changing the execution model.

## 7 · Target Resolution

The engine resolves parameters into a canonical target:

- `host_id`  → `asset:<host_id>`
- `user_id`  → `identity:<user_id>`
- `ip`       → `indicator:ip:<ip>`     (regex-validated)
- `domain`   → `indicator:domain:<domain>`
- `hash`     → `indicator:hash:<hash>`

If a target cannot be resolved → `FAILED_TARGET`.

## 8 · Frontend Surfaces

- **Playbook Designer** (`/xdr/respond/playbooks/:id`) — Design
  view is authoring only. Visual Execution Studio button opens the
  debug/live simulator.
- **Visual Execution Studio** — Full walker with breakpoints, pause,
  resume, step-over, step-into, force TRUE / FALSE branch, animated
  node highlighting, per-node evidence panel. Two modes: `debug`
  (dry-run through Response Engine's `/simulate-playbook` +
  per-action `/execute` with `constraints.dry_run=True`) and `live`
  (persisted state machine, real approvals).
- **Automation Rules Editor** — WHEN / IF / THEN with two run
  buttons: `Simulate` (design-time only; client-side condition
  eval) and `Live Run` (dispatches through the Response Engine
  using the same execution contract as everything else).
- **Analyst Response Drawer** — Right-side drawer on
  `/xdr/incidents/:id`. `invoker.kind = "analyst"`. Peer-approval
  enforced — the analyst who requested an action cannot approve it.

## 9 · Evidence Forwarding to Base

Every terminal execution POSTs an envelope to
`POST /api/xdr/response-evidence` on the base backend and receives
back `{ evidence_ref, audit_ref, timeline_ref }`. See
`RESPONSE_INGEST_CONTRACT.md` for the wire shape and the
authoritative invariants written on the base side.
