#!/usr/bin/env bash
# G1-R3.1 · scratch acceptance execution (loopback, disposable, non-production)
# Produces the 12-row acceptance table from the runbook.
set -u
cd /app/apps/nivxray-xdr-collector

SCRATCH=/tmp/r31-scratch-run
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH/state"
export XDR_STATE_DIR="$SCRATCH/state"
export NIVX_INGEST_URL="http://127.0.0.1:8098/api/xdr/ingest/telemetry"
export NIVX_INGEST_TOKEN="scratch-disposable"
export NIVX_DELIVERY_GATE_THRESHOLD=3
export NIVX_DELIVERY_GATE_COOLDOWN_SECONDS=10
export NIVX_DELIVERY_GATE_MAX_COOLDOWN_SECONDS=40
FLAG="$SCRATCH/destination.flag"
LOG="$SCRATCH/evidence.txt"

python scripts/g1_r31_fake_destination.py --port 8098 --flag "$FLAG" \
  > "$SCRATCH/dest.log" 2>&1 &
DEST_PID=$!
sleep 1.5

say() { echo -e "\n===== $* =====" | tee -a "$LOG"; }
run() { python scripts/g1_r31_scratch_driver.py "$@" 2>&1 | tee -a "$LOG"; }

say "STEP 2 seed"
run seed --count 8

say "STEP 3 HEALTHY"
run run --seconds 4

say "STEP 4 destination unavailable (unattributed edge 404)"
echo 404 > "$FLAG"
run run --seconds 8
say "STEP 4 status"
run status

say "STEP 5 RESTART while OPEN (x3, crash-loop)"
for i in 1 2 3; do
  echo "--- restart $i" | tee -a "$LOG"
  run run --seconds 2
done
say "STEP 5 status after crash-loop"
run status

say "STEP 6 cooldown elapsed -> ONE bounded probe (still down)"
sleep 10
run run --seconds 2
say "STEP 6 status"
run status

say "STEP 7 destination restored"
rm -f "$FLAG"
sleep 22
run run --seconds 30
say "STEP 7 status"
run status
say "STEP 7 destination ledger"
curl -s http://127.0.0.1:8098/ | tee -a "$LOG"; echo

say "STEP 8 corrupt persisted gate state"
python - <<'PY' 2>&1 | tee -a "$LOG"
import os, sqlite3
db = os.path.join(os.environ["XDR_STATE_DIR"], "outbox.db")
con = sqlite3.connect(db)
con.execute("UPDATE delivery_health_gate SET state='NOT_A_STATE'")
con.commit(); con.close()
print("corrupted persisted gate state")
PY
run run --seconds 2

say "STEP 9 teardown"
kill $DEST_PID 2>/dev/null
echo "evidence: $LOG"
