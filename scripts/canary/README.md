# B5-GAP-1 disposable Windows canary package

**Nothing here has been run. `CANARY_STARTED = NO`.** Run only on a
disposable host explicitly authorised by the owner. `DESKTOP-A9HGFJJ` is out
of scope: the load generator refuses to start on it.

Full procedure, schemas, scenarios, invariants and rollback:
`docs/B5_GAP_1_CANARY_PLAN.md`.

| File | Role |
|---|---|
| `b5gap1_canary_collector.py` | read-only collector: samples SOURCE -> ACQUISITION -> JOURNAL -> TRANSPORT -> BACKEND -> ACK -> RELEASE into a timestamped CSV, then writes a verdict JSON that evaluates the acceptance invariants |
| `b5gap1_canary_load.ps1` | generates REAL source records on the canary (benign process activity, Security/System/Sysmon), plus the deliberate source discontinuity |
| `b5gap1_canary_impair.py` | transparent TCP relay: `slow` / `down` / `cut` impairment of the delivery path, TLS untouched, no credential held |

Backend per-event cost is **re-used**, not reinvented:
`scripts/b5gap1_ingest_cost_profile.py`. No ingest middleware is added.

```powershell
$env:NIVX_CANARY_READ_TOKEN = '<operator read token>'    # never echoed, never stored
python b5gap1_canary_collector.py --scenario NORMAL --duration 900 --interval 15 `
  --backend https://nivxray.nivxforge.com --tenant <canary_tenant> `
  --endpoint <canary_endpoint_id> --artifact-sha256 <gate0 sha256> `
  --out-dir C:\NivXForgeCanary\normal
```

The collector never writes to the sensor state. It opens the journal
`mode=ro`, or reads an untouched copy when a WAL reader cannot attach, and
reports `NOT_PROVABLE` for anything it cannot measure honestly.

Harness self-proof: `backend/tests/edr/test_b5gap1_canary_harness.py`.
