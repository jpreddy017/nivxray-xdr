"""NivXRay AUTO INVESTIGATE — Background Jobs infrastructure.

Turns the synchronous `POST /api/v2/auto-investigate` flow into an
enterprise asynchronous pipeline:

    Client  ──►  POST /jobs           (returns job_id immediately)
              ◄─  { job_id, ws_path }
    Client  ──►  WS   /jobs/{id}/ws   (long-lived stream)
              ◄─  { type:'progress', stage, percent, message }
              ◄─  { type:'command',  binary, status, seconds }
              ◄─  { type:'result',   … full FinalIncidentSummary }

The worker runs OFF the request loop so browser / proxy timeouts never
kill an investigation on 100MB+ incidents.

All modules here follow the RC5-immutable rule: no engine mutation.
The worker reuses helpers from `routers/auto_investigate.py`.
"""
from __future__ import annotations
