# NivXRay Response Engine · Contract (LOCKED, unimplemented)

**Status:** contract-only. No executor exists yet.
**Owner:** NivXRay backend team (execution) + NivXRay XDR team (invocation).
**Consumers:** Playbook Designer, Automation Rules, analyst-initiated
manual actions from Incidents.

This document is the mirror of `INGEST_CONTRACT.md`. Where the ingest
contract carries data INTO the platform, this one carries **response
actions OUT** — always through a single authoritative endpoint so
response actions become part of the evidence record, never an opaque
SOAR blob.

---

## 1 · Architectural rule (owner-locked)

```
Incident / Alert
      ↓
Automation Rule  ─── or ───  Analyst
      ↓                        ↓
Playbook                Manual Response
      ↓                        ↓
      └──────── Response Contract ────────┐
                                            ↓
                                POST /api/respond/execute
                                            ↓
                                     Response Engine
                                            ↓
                    Vendor SDK (Endpoint / Identity / Network / Email)
                                            ↓
                                       Result
                                            ↓
                    Evidence (append to authoritative NivXRay evidence)
                                            ↓
                    Incident timeline + Audit log
```

Every response execution MUST produce:

| Artefact | Purpose |
| --- | --- |
| `execution_id` | Unique key referenced by the invoker (playbook / rule / analyst). |
| `evidence_ref` | Pointer to the appended NivXRay evidence row. |
| `audit_entry` | Immutable audit log entry. |
| `timeline_entry` | Incident timeline record analysts see in Investigation. |

A response action is not "done" until all four are written. No opaque
automation.

---

## 2 · Endpoint

| | |
| --- | --- |
| **Method** | `POST` |
| **Path**   | `POST {NIVX_RESPOND_URL}` — e.g. `https://nivxray.example.com/api/respond/execute` |
| **Auth**   | `Authorization: Bearer {NIVX_RESPOND_TOKEN}`. The token's scopes MUST include every `required_permissions` entry of the action. |
| **Content-Type** | `application/json` |
| **Idempotency** | Required on `(tenant_id, invoker_kind, invoker_id, execution_id)`. Retrying with the same `execution_id` MUST NOT execute the action twice; return the prior result. |
| **Timeout** | Server-side hard cap 60 s per action. Longer-running actions must return `status = "in_progress"` + a follow-up `GET /api/respond/executions/{id}` handle. |

### 2.1 Request body

```json
{
  "execution_id":  "exec-<uuid>",
  "tenant_id":     "acme",
  "invoker": {
    "kind": "playbook | automation_rule | analyst",
    "id":   "pb-abc123 | rule-xyz789 | user:alice@acme.com",
    "context": {
      "incident_id":       "INC-2026-00192",
      "playbook_node_id":  "n-04",
      "rule_id":           "rule-xyz789"
    }
  },
  "action": {
    "action_id":   "endpoint.isolate",
    "provider":    "endpoint",
    "capability":  "isolate_endpoint",
    "parameters":  { "host_id": "THEBORG-PHX" }
  },
  "authorization": {
    "approved_by": "user:alice@acme.com",
    "approval_ref": "approval-abc123",
    "reason":       "Confirmed lateral movement · IR playbook step 3"
  },
  "constraints": {
    "max_duration_seconds": 30,
    "dry_run":              false
  }
}
```

### 2.2 Response body (synchronous)

```json
{
  "execution_id":   "exec-<uuid>",
  "status":         "succeeded | failed | in_progress | rejected",
  "started_at":     "2026-02-10T09:12:33Z",
  "completed_at":   "2026-02-10T09:12:35Z",
  "duration_ms":    2137,
  "result": { "isolated": true, "vendor_ref": "cs-abc" },
  "evidence_ref":   "evidence-91237",
  "audit_ref":      "audit-88712",
  "timeline_ref":   "timeline-33091",
  "reversal": {
    "reversible":   true,
    "reversal_id":  "exec-rev-<uuid>",
    "expires_at":   "2026-02-11T09:12:33Z"
  },
  "error":          null
}
```

`in_progress` responses MUST include an `execution_id` retrievable via
`GET /api/respond/executions/{id}`.

### 2.3 Status codes

| Code | Meaning | Invoker action |
| --- | --- | --- |
| `202` | Accepted, async execution. Poll `GET /executions/{id}`. | Show "in progress" in the invoker; poll. |
| `200` | Completed synchronously. | Read `status` for outcome. |
| `400` | Malformed body. | Fatal — do not retry. |
| `401` / `403` | Auth or approval failure. | Fatal for the caller; surface the specific approval requirement. |
| `409` | Duplicate `execution_id`. | Read the prior result via `GET /executions/{id}`. |
| `422` | Semantic validation failure (unknown action_id, bad parameters, unresolved target). | Fatal. |
| `429` | Rate limited. | Backoff + retry. |
| `5xx` | Backend fault. | Backoff + retry. |

---

## 3 · Authorization & approval

- Every action carries `required_permissions` in the Response Action
  Registry. The Response Engine MUST verify the caller's bearer
  token scopes include all of them.
- Every `approval_required: true` action MUST include an
  `authorization.approval_ref` that resolves to an
  `approved` approval record. Missing / stale approvals → `403`.
- `dry_run: true` MUST NOT touch any vendor system. It exercises the
  target resolution + parameter validation + evidence write and
  returns `status: "succeeded"` with `result.dry_run: true`.

---

## 4 · Target resolution

Actions MUST resolve their target into a canonical NivXRay entity
BEFORE dispatching to the vendor SDK.

- `host_id` → `asset:{host_id}` (must exist in Asset Inventory).
- `user_id` → `identity:{user_id}` (must exist in Identity graph).
- Any target that fails resolution → `422 unresolved_target`.

The resolved canonical entity is what gets written to
`evidence_ref` — not the raw vendor id — so an analyst investigating
in NivXRay always sees a stable target.

---

## 5 · Idempotency & retry

- Callers generate `execution_id` client-side (UUID recommended).
- The engine records `(tenant_id, invoker_kind, invoker_id, execution_id)` in a de-dup index.
- Retrying with the same tuple returns the prior result verbatim.
- The Playbook Designer and Automation Rule invoker MUST NOT rewrite
  `execution_id` on retry — they persist it with the node/rule and
  reuse it.

---

## 6 · Reversal

Actions with `reversible: true` in the registry MUST return a
`reversal.reversal_id`. A caller may reverse within `reversal.expires_at`
by:

```
POST /api/respond/reversals
{ "reversal_id": "exec-rev-<uuid>", "reason": "…" }
```

Reversals themselves create their own `execution_id` + evidence.

---

## 7 · Evidence, audit, timeline

Every completed execution MUST write:

- **Evidence row** in the authoritative canonical evidence table,
  with `provenance.kind = "response_action"`. Analysts see this in
  Investigation → Evidence just like a detection would appear.
- **Audit row** — immutable, WORM if the tenant policy requires it.
- **Timeline row** on the incident (`incident_timeline.appended`)
  so the response is visible in Investigation → Attack Story.

No response action is considered complete until all three writes
succeed. If any of them fails, the engine MUST roll the whole
execution to `status = "failed"` with a descriptive `error`.

---

## 8 · What this contract deliberately does NOT include (yet)

- Streaming / WebSocket variants — Phase E.
- Bulk / batch execution — Phase E. For now, one action per POST.
- Response DAGs — playbooks handle sequencing; the engine executes
  one action at a time.
- Automatic reversal on failure — the caller is responsible for
  ordering `reversal` invocations if it wants transactional-style
  playbooks.

---

## 9 · Implementation checklist (base backend team)

- [ ] `POST /api/respond/execute` with the request/response shape above.
- [ ] `GET /api/respond/executions/{execution_id}` for polling.
- [ ] `POST /api/respond/reversals` for reversal.
- [ ] Idempotency index on `(tenant_id, invoker_kind, invoker_id, execution_id)`.
- [ ] Approval-record resolver.
- [ ] Target-resolution against Asset Inventory + Identity graph.
- [ ] Evidence writer with `provenance.kind = "response_action"`.
- [ ] Audit writer.
- [ ] Incident-timeline appender.
- [ ] Vendor SDK adapters (start with the same priority order as
  Phase C: CrowdStrike, Defender, SentinelOne, Cisco SEP).
- [ ] Per-action `dry_run` path.
- [ ] `NIVX_RESPOND_URL` + `NIVX_RESPOND_TOKEN` deploy vars.

Once these ship, the Playbook Designer's Run button, the Automation
Rules invoker, and the Incident manual-action drawer can all light up
in a single frontend release — because they all speak this one
contract.
