# NivXRay Response Engine → Base · Evidence / Audit / Timeline Ingest

**Status:** IMPLEMENTED — base backend accepts response evidence on
`POST /api/xdr/response-evidence`. Every completed Response Engine
execution forwards a canonical evidence envelope here.

**Consumer:** the standalone Response Engine
(`/app/apps/nivxray-xdr-response/`).
**Producer of writes:** the base NivXRay backend
(`/app/backend/routers/xdr_response_evidence.py`).

## 1 · Purpose

Every completed response execution MUST leave three artefacts on the
authoritative NivXRay backend so response becomes part of the
investigation record — never an opaque SOAR blob:

| Ref | Written into | Meaning |
| --- | --- | --- |
| `evidence_ref` | `xdr_response_evidence` collection with `provenance.kind = "response_action"` | An analyst investigating in NivXRay sees this alongside detection evidence. |
| `audit_ref` | `xdr_response_audit` (immutable audit trail) | Compliance / DFIR chain-of-custody. |
| `timeline_ref` | `xdr_response_timeline` (per-incident timeline) | The response appears in Investigation → Attack Story. |

If any of the three writes fails the Response Engine MUST report the
execution as `state = "FAILED_FORWARDING"`. Reporting `SUCCEEDED` while
the evidence chain is broken is forbidden.

## 2 · Endpoint

| | |
| --- | --- |
| **Method** | `POST` |
| **Path** | `POST {NIVX_RESPONSE_EVIDENCE_URL}` — e.g. `https://nivxray.example.com/api/xdr/response-evidence` |
| **Auth** | `Authorization: Bearer {NIVX_RESPONSE_EVIDENCE_TOKEN}` (base backend authentication mirrors the rest of the `/api` surface) |
| **Idempotency** | Required on `execution_id`. Repeat POSTs return the same refs and `idempotent_replay: true`. |
| **Timeout** | ≤ 10 s. On 5xx / timeout the engine retries with backoff and holds the execution in `FAILED_FORWARDING` until success. |

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
  },
  "provenance": {
    "kind":         "response_action",
    "execution_id": "exec-<uuid>"
  }
}
```

If `provenance` is omitted, the base backend stamps
`provenance.kind = "response_action"` and echoes back `execution_id`.

If `provenance.kind` is present and is **not** `"response_action"`, the
endpoint returns `400 invalid_provenance`.

## 4 · Response body

```json
{
  "evidence_ref": "evidence-91237a12ee31",
  "audit_ref":    "audit-88712dee00c1",
  "timeline_ref": "timeline-33091ff220ab",
  "idempotent_replay": false
}
```

On idempotent replay `idempotent_replay: true` is included and the
three refs are identical to the original write.

## 4b · Tenant authority (P0.1 · 2026-06)

`tenant_id` in the request body is an **assertion**, never authority. The
stored tenant is resolved server-side from authoritative context:

| Context | Authority |
| --- | --- |
| `invoker.context.incident_id` present | the incident's server-resolved tenant (the incident is addressed through the incident authority; out of scope ⇒ `404`, existence never disclosed) |
| no resource anchor, single-tenant principal | the principal's one tenant |
| no resource anchor, multi/all-tenant principal | **DENY** `403 tenant_authority_denied` — being authorized for tenant B does not prove this evidence belongs to B |

A presented `tenant_id` that disagrees with the resolved authority fails
closed with `403 tenant_authority_denied`; the refusal never echoes the
authoritative tenant. `tenant_id` may therefore be omitted entirely.

Idempotency on `execution_id` is evaluated **within the resolved tenant**, so
the same `execution_id` in two tenants can neither collide nor be used to
harvest the other tenant's ref triple.

Rows written before P0.1 do not carry this guarantee: their `tenant_id` was
the value the writer presented. They are left untouched — response evidence is
audit material and is not rewritten to conform to a later contract.

## 5 · Attribution invariants

- Every evidence row carries `provenance.execution_id`, `provenance.kind`,
  `tenant_id`, and the full `invoker`/`action`/`authorization` blocks.
- Every row written after P0.1 carries
  `provenance.tenant_authority = { source: "incident" | "principal_scope",
  tenant_id, asserted_tenant_id }` — a RECORD of how the tenant was
  resolved; it is never consulted as authority.
- Every timeline row is tagged `incident_id` from `invoker.context` (nullable
  — analyst-initiated actions on assets not tied to an incident still write
  to a per-asset timeline).
- Every audit row carries the full `authorization` block verbatim.
- `dry_run: true` executions still generate all three artefacts but are
  tagged `simulation = true` — Investigation views MAY choose to hide
  them.

## 6 · Base backend read surface

`GET /api/xdr/response-evidence/{execution_id}?tenant_id=acme` returns
the ref triple for the execution. 404 on unknown or mis-tenanted id.

## 7 · Boundary invariant

This endpoint is the **only** base-backend write path that the standalone
Response Engine invokes. The endpoint never mutates SSOT, Verdict, IKG,
Incident state, or detection logic. It writes to dedicated collections:

- `xdr_response_evidence`
- `xdr_response_audit`
- `xdr_response_timeline`
- `xdr_response_executions`  (dedup index on `execution_id`)

The Response Engine's execution store (own SQLite DB at
`/app/apps/nivxray-xdr-response/data/executions.db`) is authoritative for
the execution lifecycle and approval decisions; the base backend is
authoritative for evidence, audit, and timeline. These two authoritative
truths are joined through the ref triple.

## 8 · Deploy variables

| Var | Purpose |
| --- | --- |
| `NIVX_RESPONSE_EVIDENCE_URL` | Full URL of the base endpoint above. |
| `NIVX_RESPONSE_EVIDENCE_TOKEN` | Bearer token. |
| `NIVX_RESPONSE_EVIDENCE_TIMEOUT` | Delivery timeout (seconds). Default 10. |

When unset, the Response Engine still records executions locally
(SQLite `executions.db`) and returns synthetic local refs with
`forwarding_state = "not_wired"` so callers get a deterministic
outcome, but the execution is honestly flagged as un-forwarded.
