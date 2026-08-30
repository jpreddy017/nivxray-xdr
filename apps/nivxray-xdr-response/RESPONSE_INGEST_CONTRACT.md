# NivXRay Response Engine → Base · Evidence / Audit / Timeline Ingest

**Status:** LOCKED contract, unimplemented on the base backend.
**Consumer:** the standalone Response Engine (`/app/apps/nivxray-xdr-response/`).
**Producer of writes:** the base NivXRay backend.

## 1 · Purpose

Every completed response execution MUST leave three artefacts on the
authoritative NivXRay backend so response becomes part of the
investigation record — never an opaque SOAR blob:

| Ref | Written into | Meaning |
| --- | --- | --- |
| `evidence_ref` | Canonical Evidence table with `provenance.kind = "response_action"` | An analyst investigating in NivXRay sees this alongside detection evidence. |
| `audit_ref` | Immutable audit log | Compliance / DFIR chain-of-custody. |
| `timeline_ref` | Incident timeline (`incident_timeline`) | The response appears in Investigation → Attack Story. |

If any of the three writes fails the Response Engine MUST report the
execution as `status = "failed"` with `forwarding_state = "failed_forwarding"`.
Reporting `succeeded` while the evidence chain is broken is forbidden.

## 2 · Endpoint

| | |
| --- | --- |
| **Method** | `POST` |
| **Path** | `POST {NIVX_RESPONSE_EVIDENCE_URL}` — e.g. `https://nivxray.example.com/api/xdr/response-evidence` |
| **Auth** | `Authorization: Bearer {NIVX_RESPONSE_EVIDENCE_TOKEN}` |
| **Idempotency** | Required on `execution_id`. Repeat POSTs return the same refs. |
| **Timeout** | ≤ 10 s. On 5xx / timeout the engine retries with backoff and holds the execution in `failed_forwarding` until success. |

## 3 · Request body

```json
{
  "execution_id":     "exec-<uuid>",
  "tenant_id":        "acme",
  "invoker": {
    "kind": "playbook | automation_rule | analyst | simulator",
    "id":   "pb-abc | rule-xyz | user:alice@acme.com",
    "context": { "incident_id": "INC-…", "playbook_node_id": "n-04" }
  },
  "action": {
    "action_id": "endpoint.isolate",
    "provider":  "endpoint",
    "capability": "isolate_endpoint"
  },
  "parameters":       { "host_id": "THEBORG-PHX" },
  "canonical_target": { "asset": "asset:THEBORG-PHX" },
  "adapter_result":   { "isolated": true, "vendor_ref": "cs-abc" },
  "adapter_ok":       true,
  "started_at":       "2026-02-10T09:12:33Z",
  "completed_at":     "2026-02-10T09:12:35Z",
  "dry_run":          false,
  "authorization": {
    "approved_by":  "user:alice@acme.com",
    "approval_ref": "approval-abc123",
    "reason":       "Confirmed lateral movement · IR playbook step 3"
  }
}
```

## 4 · Response body

```json
{
  "evidence_ref": "evidence-91237",
  "audit_ref":    "audit-88712",
  "timeline_ref": "timeline-33091"
}
```

If any of the three could not be created return the appropriate
partial refs and a non-2xx status. The engine's forwarder considers
the whole batch failed until all three are present.

## 5 · Attribution invariants (owner-locked)

- Every evidence row MUST carry `provenance.execution_id` referencing
  the response engine's execution — so an analyst can trace evidence
  → response → invoker → approval trail.
- Every timeline row MUST carry `execution_id` + `action_id` + a
  human label like `"Isolate Endpoint · WS-123 · by alice@acme.com"`
  so Attack Story reads cleanly.
- Every audit row MUST carry the full `authorization` block verbatim.
- `dry_run: true` executions still generate all three artefacts but
  MUST be tagged `simulation = true` — the base MAY choose to hide
  them from Investigation views while retaining them for compliance.

## 6 · Deploy variables

| Var | Purpose |
| --- | --- |
| `NIVX_RESPONSE_EVIDENCE_URL` | Full URL of the base endpoint above. |
| `NIVX_RESPONSE_EVIDENCE_TOKEN` | Bearer token. |
| `NIVX_RESPONSE_EVIDENCE_TIMEOUT` | Delivery timeout (seconds). Default 10. |

When unset, the Response Engine still records executions locally
(SQLite `executions.db`) and returns synthetic local refs with
`forwarding_state = "not_wired"` so callers get a deterministic
outcome, but the execution is honestly flagged as un-forwarded.

## 7 · Base backend implementation checklist

- [ ] `POST /api/xdr/response-evidence` per the request/response shape above.
- [ ] Idempotency on `execution_id`.
- [ ] Evidence writer with `provenance.kind = "response_action"` and
  `provenance.execution_id`.
- [ ] Timeline appender bound to the invoker's `context.incident_id`
  (nullable — analyst-initiated actions on assets not tied to an
  incident still write to a per-asset timeline).
- [ ] Audit writer.
- [ ] Tenant + RBAC enforcement mirroring the rest of the base API.

Once implemented, every response action — whether triggered by
Playbook Run, Automation Rule, or Analyst Response Drawer — becomes
first-class evidence in NivXRay's investigation record.
