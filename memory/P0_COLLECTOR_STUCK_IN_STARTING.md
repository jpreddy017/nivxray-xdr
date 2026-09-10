# P0 — Collector stuck in STARTING (2026-06)

## Root cause
`start_collector()` in `backend/routers/xdr_collectors.py` **only persisted a
requested state**. It called `_admin_transition(..., target="STARTING",
reason="start requested")` and returned. There was **no runtime dispatch of
any kind** — nothing was ever asked to bind a listener, so nothing could ever
move the state on. `STARTING` was a dead end by construction.

The deeper truth behind it: the NivXRay API core is a FastAPI app behind a
Kubernetes HTTPS ingress. **It cannot bind UDP/TCP 514.** A `syslog` transport
is terminated by the *separate* `apps/nivxray-xdr-collector` runtime, which is
**not deployed anywhere today**. So there was no runtime to dispatch to even in
principle, and the UI truthfully reported "start requested" forever.

### Reassurance that matters
The stuck state was **never blocking ingestion**. `xdr_ingest` writes collector
state directly (lines 599-606) and does not go through
`_ALLOWED_TRANSITIONS`, so real telemetry moves any prior state straight to
`CONNECTED`. The approved plan — the auditd forwarder posting to
`POST /api/xdr/ingest/telemetry` — **never needed the collector to "start"**.
`protocol: syslog` is metadata describing the source, not a listener the core
owns.

## Files changed — 1
`backend/routers/xdr_collectors.py` (+`urllib`/`json` imports, new
`_runtime_start()`, `start_collector()` now dispatches). No frontend change,
no state-machine change, no auth/RBAC change, no other product.

## Old → new behaviour
| | Old | New |
|---|---|---|
| Start action | writes `STARTING` / "start requested", returns | resolves `XDR_COLLECTOR_RUNTIME_URL`, POSTs `/collectors/{id}/start`, records the real outcome |
| No runtime configured | **stuck at STARTING forever** | `CONNECTION_FAILED` naming the cause and the remedy |
| Runtime unreachable | stuck at STARTING | `CONNECTION_FAILED` with the transport error |
| Runtime accepts but reports no listener | stuck at STARTING | `CONNECTION_FAILED` — an accepted start is not proof of a bound listener |
| Runtime listening | stuck at STARTING | `STARTING` · "runtime listening on `<bind>` · awaiting telemetry" — a truthful pre-connected state |
| CONNECTED | ingest-only | **unchanged** — ingest-only, evidence-gated |

`CONNECTED` was **not** touched. It still requires
`received > 0 AND parsed > 0 AND normalized > 0` and is still written only by
the ingest path. No admin action can promote to it.

## Acceptance proof (preview, throwaway tenant, all artifacts deleted)
```
collector col_cff8… protocol syslog
BEFORE                     state ADOPTED        reason "created"
START (no runtime)         state CONNECTION_FAILED
  reason: no collector runtime configured (XDR_COLLECTOR_RUNTIME_URL unset) —
          the API core cannot terminate a listening transport; deploy
          apps/nivxray-xdr-collector. HTTP ingest via
          POST /api/xdr/ingest/telemetry does not require this.
START (runtime unreachable, unit-level)  started=False
  reason: runtime unreachable at http://127.0.0.1:9/dead/collectors/col_x/start:
          URLError: [Errno 111] Connection refused

ONE real auditd event through the REAL ingest path:
  duplicates 0 · reasoned 1 · observations_created 1
  collector_state CONNECTED
  collector_state_reason "telemetry received/parsed/normalized: 1/1/1"
AFTER                      state CONNECTED
  rx/parsed/norm/err        1 / 1 / 1 / 0
  last_event_at             2026-09-10T13:21:14Z
```
So: no longer stuck, the failure is truthful and actionable, and `CONNECTED`
still arrives **only** from real telemetry.

Tenant isolation and audit history preserved — every transition still goes
through `_admin_transition`, which emits `COLLECTOR_STATE_CHANGED`; the failure
path adds `COLLECTOR_START_FAILED`.

## What the owner should expect in production
Pressing **Start** on `linux-audit-syslog-prod-1` will now return
`CONNECTION_FAILED` with the "no collector runtime configured" reason. **That
is correct and is not a regression** — it is the honest replacement for an
indefinite `STARTING`. Two valid ways forward:

1. **Approved plan, no Start needed** — point the auditd forwarder at
   `POST /api/xdr/ingest/telemetry`. The collector goes straight to
   `CONNECTED` on the first real event, exactly as proven above.
2. **Later** — deploy `apps/nivxray-xdr-collector` and set
   `XDR_COLLECTOR_RUNTIME_URL`; Start will then bind a real syslog listener.

**Not deployed.** This change is in the workspace only; production still runs
the previous backend until the owner approves a deploy.
