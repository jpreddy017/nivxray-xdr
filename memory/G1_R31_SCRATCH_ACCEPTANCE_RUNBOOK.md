# G1-R3.1 · Scratch-collector acceptance runbook (bounded, disposable)

**Scope boundary.** This runbook uses a SCRATCH collector state directory and
a LOOPBACK fake destination only. It does not touch `DESKTOP-A9HGFJJ`, does not
touch `C:\ProgramData\NivXForge\state\outbox.db`, does not start the production
Windows collector, and does not involve the preserved 14,868 dead-letter rows.

The driver refuses to run if `XDR_STATE_DIR` looks like NivXForge production
state, or if `NIVX_INGEST_URL` is not loopback.

What this adds over the in-repo harness: a real OS process, a real socket, the
real wall clock, and a real on-disk `outbox.db` — so `Ctrl-C` is an actual
service restart rather than a simulated one.

---

## 0 · Prepare (any machine with the repo + Python 3.11)

### macOS / Linux
```bash
cd apps/nivxray-xdr-collector
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SCRATCH=/tmp/r31-scratch
rm -rf "$SCRATCH" && mkdir -p "$SCRATCH/state"
export XDR_STATE_DIR="$SCRATCH/state"
export NIVX_INGEST_URL="http://127.0.0.1:8099/api/xdr/ingest/telemetry"
export NIVX_INGEST_TOKEN="scratch-disposable"
export NIVX_DELIVERY_GATE_THRESHOLD=3
export NIVX_DELIVERY_GATE_COOLDOWN_SECONDS=15
```

### Windows PowerShell (scratch machine, NOT the production endpoint)
```powershell
cd apps\nivxray-xdr-collector
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:SCRATCH = "$env:TEMP\r31-scratch"
Remove-Item -Recurse -Force $env:SCRATCH -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$env:SCRATCH\state" | Out-Null
$env:XDR_STATE_DIR = "$env:SCRATCH\state"
$env:NIVX_INGEST_URL = "http://127.0.0.1:8099/api/xdr/ingest/telemetry"
$env:NIVX_INGEST_TOKEN = "scratch-disposable"
$env:NIVX_DELIVERY_GATE_THRESHOLD = "3"
$env:NIVX_DELIVERY_GATE_COOLDOWN_SECONDS = "15"
```

> `XDR_STATE_DIR` must NOT be `C:\ProgramData\NivXForge\state`. The driver
> aborts if it is.

---

## 1 · Start the controllable destination (terminal A)

```bash
python scripts/g1_r31_fake_destination.py --port 8099 --flag "$SCRATCH/destination.flag"
```

| Flag file | Destination answers | Meaning |
|---|---|---|
| absent | `200` + `X-Request-ID` | healthy |
| contains `404` | `404`, **no** attribution header | the exact G1 edge failure |
| any other content | `503` + `X-Request-ID` | backend down |

Check it any time: `curl -s http://127.0.0.1:8099/`

---

## 2 · Seed disposable proof events (terminal B)

```bash
python scripts/g1_r31_scratch_driver.py seed --count 8
```

**Expect:** `queued: 8`. These are `r31-scratch-*` events in a scratch tenant.

---

## 3 · HEALTHY → delivery works

```bash
python scripts/g1_r31_scratch_driver.py run --seconds 6
```

**Expect:** ticks with `"delivered": 2`, `"gate": "CLOSED"`.
Stop with `Ctrl-C`.

---

## 4 · Destination unavailable → SUSPECT → OPEN

```bash
echo 404 > "$SCRATCH/destination.flag"        # PowerShell: "404" | Set-Content ...
python scripts/g1_r31_scratch_driver.py run --seconds 10
```

**Expect, in order:**
- a tick with `"gate": "SUSPECT"` before the threshold is reached;
- a tick with `"gate": "OPEN"` at the third destination failure;
- subsequent ticks `"gate_skipped": true`, `"drained": 0`;
- `dead_letter: 0` throughout (R1: an unattributed 404 is retryable).

Stop with `Ctrl-C`, then:

```bash
python scripts/g1_r31_scratch_driver.py status
```

**Expect** `persisted_health_gate.state = "OPEN"`, `consecutive_failures = 3`,
a `cooldown_until_epoch`, and `last_reason` mentioning
`UNATTRIBUTED_FAILURE (no X-Request-ID)`. Note the `attempts` map — only the
rows actually attempted have `attempts >= 1`.

---

## 5 · RESTART while OPEN → stays safely paused (the R3.1 property)

```bash
python scripts/g1_r31_scratch_driver.py run --seconds 6
```

**Expect:**
- `boot_gate.state = "OPEN"`, `boot_gate.restored_from = "OPEN"`,
  `state_load_error = null` — the restart REMEMBERED the outage;
- while `seconds_until_probe > 0`: every tick `gate_skipped: true`,
  `drained: 0`, and **no new request in terminal A's log**;
- `status` afterwards: the `attempts` map is UNCHANGED — the restart cost no
  row any retry budget;
- `delivering: 0` — nothing stranded.

Repeat this step 2-3 times to simulate a crash-loop. The failure run stays at
3 and `opened_count` does not climb per restart.

---

## 6 · Cooldown → HALF_OPEN → exactly ONE bounded probe

Wait until `seconds_until_probe` reaches 0, then run again.

**Expect:** exactly ONE tick with `"probe": true, "drained": 1` — one request
in terminal A's log, not a burst. Since the destination is still down, the gate
re-opens and `cooldown_seconds` doubles (15 → 30 → 60 …, bounded by
`NIVX_DELIVERY_GATE_MAX_COOLDOWN_SECONDS`, default 300).

`status` confirms the escalated `cooldown_seconds` is persisted.

---

## 7 · Destination restored → CLOSED → normal delivery resumes

```bash
rm -f "$SCRATCH/destination.flag"             # PowerShell: Remove-Item ...
python scripts/g1_r31_scratch_driver.py run --seconds 30
```

**Expect:**
- the first probe after cooldown delivers 1 and the gate becomes `CLOSED`;
- subsequent ticks drain normally in batches;
- `status`: `persisted_health_gate.state = "CLOSED"`,
  `cooldown_until_epoch = null`;
- `curl -s http://127.0.0.1:8099/` → `accepted == unique_accepted`
  (**no duplicate acknowledgement**);
- `dead_letter: 0` (**no event loss**), `delivering: 0` (**nothing stranded**).

Rows still inside their per-event backoff remain `retrying` — that is correct,
not loss; they drain on their own schedule.

---

## 8 · Corruption behaviour (optional, 30 seconds)

```bash
sqlite3 "$XDR_STATE_DIR/outbox.db" "UPDATE delivery_health_gate SET state='NOT_A_STATE';"
python scripts/g1_r31_scratch_driver.py run --seconds 4
```

**Expect:** `boot_gate.state = "OPEN"`, `state_load_error` populated,
`last_reason` beginning "persisted delivery-health state was unreadable" —
it fails SAFE (paused, bounded to the base cooldown) and VISIBLY, never
silently into unthrottled traffic.

---

## 9 · Teardown

```bash
# terminal A: Ctrl-C
rm -rf "$SCRATCH"
```

Nothing outside `$SCRATCH` was written.

---

## Acceptance record to report back

| # | Check | Result |
|---|---|---|
| 3 | HEALTHY delivers | |
| 4 | SUSPECT then OPEN at threshold, `dead_letter: 0` | |
| 4 | OPEN persisted with deadline + failure run | |
| 5 | restart restores OPEN, `restored_from: OPEN`, no traffic | |
| 5 | `attempts` map unchanged across restart | |
| 5 | crash-loop does not re-burn the threshold | |
| 6 | exactly ONE probe after cooldown | |
| 6 | escalated cooldown persisted and bounded | |
| 7 | successful probe closes, delivery resumes | |
| 7 | `accepted == unique_accepted` | |
| 7 | `dead_letter: 0`, `delivering: 0` | |
| 8 | corrupt state fails safe and visible | |
