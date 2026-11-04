# P0.1 · Response-Evidence WRITE Tenant Authority (2026-06)

## Defect
`POST /api/xdr/response-evidence` stored `body.tenant_id` — the value the
WRITER presented — as the tenant of the evidence / audit / timeline /
dedup rows. Response evidence is audit material, so a writer could stamp
another customer's tenant onto it. Idempotency on `execution_id` was also
looked up globally, making the ref triple a cross-tenant side channel.

## Contract now enforced (owner-approved)
`body.tenant_id` is an ASSERTION that may be CHECKED, never authority.

| Context | Authority | Outcome |
| --- | --- | --- |
| `invoker.context.incident_id` present | incident's server-resolved tenant (`authorized_incident`) | accept; out-of-scope incident ⇒ 404, no disclosure |
| no anchor, single-tenant principal | the principal's one tenant | accept |
| no anchor, multi/all-tenant principal | none | 403 `ambiguous_tenant_authority_without_resource_anchor` |
| assertion ≠ authority | — | 403 `tenant_authority_denied` (authoritative tenant never echoed) |

- Idempotency lookup is `{execution_id, tenant_id: resolved}` → same
  `execution_id` in two tenants yields distinct triples, no replay, no
  ref disclosure.
- `provenance.tenant_authority = {source, tenant_id, asserted_tenant_id}`
  RECORDS the decision; it is never consulted as authority.
- `tenant_id` is now optional in the wire model.

## Technical debt (explicitly accepted)
Pre-P0.1 rows lack the tenant-authority guarantee: their `tenant_id` was
client-supplied. No backfill, no migration, no rewrite, and no blanket
"unverified" labelling — audit history is not rewritten to conform to a
later contract. Revisit only if an authoritative legacy-validation
mechanism is built.

Longer term: the Response Engine should derive tenant from the
authenticated dispatch/execution context, not from a body assertion.

## Files
- `/app/backend/routers/xdr_response_evidence.py`
  (`_resolve_write_tenant_authority`, `response_evidence`)
- `/app/backend/tests/test_p01_response_evidence_write_tenant_authority.py`
- `/app/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md` (§4b)
- `/app/scripts/p01_response_evidence_write_tenant_authority.py`

## Proof (2026-06, backend only — no screenshots, no testing agent)
`pytest tests/test_p01_response_evidence_write_tenant_authority.py
tests/test_xdr_response_evidence.py
tests/test_p0_response_execution_tenant_scope.py` → 35 passed.

Matrix proven:
single-tenant/no incident → own tenant ACCEPT ·
single-tenant/foreign assertion → DENY ·
multi-tenant/incident-owned tenant → ACCEPT ·
multi-tenant/incident-vs-assertion mismatch → DENY ·
multi/all-tenant/no anchor + body tenant only → DENY ·
single-tenant/foreign incident → 404 no disclosure ·
same `execution_id` across tenants → no collision, no ref harvest ·
same-tenant replay → still idempotent.
