# NivXRay XDR Response Engine

Standalone, independently-deployable **response plane** for NivXRay XDR.

## Boundary (owner-locked)

- Owns: response action execution, action registry, adapters,
  idempotency, approval + authorization, target resolution,
  execution state, evidence/audit/timeline forwarding.
- Does NOT own: SSOT, Verdict, IKG, incidents, investigation
  state. Those remain authoritative on the base NivXRay backend.
- Every completed execution MUST produce `evidence_ref`,
  `audit_ref`, and `timeline_ref` via the base ingest contract
  (`RESPONSE_INGEST_CONTRACT.md`). No opaque SOAR blobs.

## Endpoints

| Verb | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/respond/execute` | Execute one action per `RESPONSE_CONTRACT.md`. |
| `POST` | `/api/respond/simulate-playbook` | Walk a whole playbook via dry_run adapters and return the execution trace. |
| `GET`  | `/api/respond/executions/{execution_id}` | Fetch a prior execution (idempotent replay). |
| `GET`  | `/api/respond/actions` | List the registered action catalogue. |
| `GET`  | `/health` | Liveness. |

## Environment

| Var | Purpose |
| --- | --- |
| `NIVX_RESPONSE_EVIDENCE_URL` | Base backend endpoint that receives evidence/audit/timeline. |
| `NIVX_RESPONSE_EVIDENCE_TOKEN` | Bearer token for the base endpoint. |
| `NIVX_RESPONSE_EVIDENCE_TIMEOUT` | Delivery timeout (seconds). Default `10`. |
| `XDR_RESPOND_STATE_DIR` | Persistent state dir for `executions.db` (SQLite). Falls back to `:memory:` for tests. |
| `XDR_RESPOND_CORS_ORIGINS` | Comma-separated allow-list. Default `*`; tighten in production. |

## Local

```bash
cd /app/apps/nivxray-xdr-response
pip install -r requirements.txt
uvicorn main:app --reload --port 8085
python -m pytest tests/ -q
```

## Guarantees

- Idempotent on `(tenant_id, invoker_kind, invoker_id, execution_id)`.
- No fake success: `succeeded` requires adapter ok + evidence forwarding ok.
- Restart recovery: `in_progress` rows flip to `failed_recovered` on boot;
  they are NOT silently retried against external systems.
- Phase 1 adapters are deterministic stubs that never call vendor SDKs.
  Phase C replaces them with CrowdStrike / Defender / SentinelOne /
  Cisco SEP adapters WITHOUT changing the execution model.

## Contracts

- `RESPONSE_CONTRACT.md` — external wire spec every invoker speaks
  (Playbook Designer, Automation Rules, Analyst Response Drawer).
- `RESPONSE_INGEST_CONTRACT.md` — how the engine posts evidence,
  audit, and timeline back to the base NivXRay backend.
