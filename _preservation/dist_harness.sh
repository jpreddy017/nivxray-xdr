#!/usr/bin/env bash
# Cold/contention distribution harness. Preview only, read-only on data.
set -u
EP=ep_2d57cbe6f80152062109
W='time_start=2026-10-01T00:00:00Z&time_end=2026-10-31T23:59:59Z&lane_start=0&lane_end=100000&limit=500'
cd /app/backend; set -a; . ./.env; set +a
B=http://localhost:8001/api/edr/endpoints/$EP/trajectory

newtok() {
  for a in 1 2 3 4 5; do
    T=$(curl -s --max-time 20 -X POST http://localhost:8001/api/auth/login \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
        | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('access_token',''))
except Exception: print('')" 2>/dev/null)
    [ -n "$T" ] && { echo "$T"; return; }
    sleep 5
  done
  echo ""
}
wait_idle() { for i in $(seq 1 60); do
    l=$(cut -d' ' -f1 /proc/loadavg | cut -d. -f1); [ "$l" -lt 2 ] && return; sleep 5; done; }
wait_up() { for i in $(seq 1 40); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8001/api/health)" = "200" ] && return; sleep 5; done; }

run_n() {  # label n token
  local label=$1 n=$2 T=$3
  for i in $(seq 1 "$n"); do
    echo "$label $(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 120 \
      -H "Authorization: Bearer $T" -H 'X-Tenant-Id: default' "$B?presentation=v3&$W")"
  done
}

OUT=/app/_preservation/dist_results.txt
: > "$OUT"

echo "### A · idle container, 20 samples" | tee -a "$OUT"
wait_up; wait_idle; T=$(newtok)
run_n A 20 "$T" | tee -a "$OUT"

echo "### B · 8 restarts, first read after each" | tee -a "$OUT"
for r in $(seq 1 8); do
  sudo supervisorctl restart backend >/dev/null 2>&1
  wait_up; T=$(newtok)
  [ -z "$T" ] && { echo "B TOKENFAIL" | tee -a "$OUT"; continue; }
  run_n B 1 "$T" | tee -a "$OUT"
done

echo "### C · 10 concurrent v3 reads (same instant), plus health probes" | tee -a "$OUT"
wait_idle; T=$(newtok)
for i in $(seq 1 10); do
  ( curl -s -o /dev/null -w "C %{http_code} %{time_total}\n" --max-time 120 \
      -H "Authorization: Bearer $T" -H 'X-Tenant-Id: default' "$B?presentation=v3&$W" ) >> "$OUT" &
done
for i in $(seq 1 12); do
  echo "H $(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 15 http://localhost:8001/api/health)" >> "$OUT"
  sleep 1
done
wait

echo "### D · v3 while a legacy combined read is executing" | tee -a "$OUT"
wait_idle; T=$(newtok)
( curl -s -o /dev/null -w "LEGACY %{http_code} %{time_total}\n" --max-time 120 \
    -H "Authorization: Bearer $T" -H 'X-Tenant-Id: default' "$B?presentation=combined&$W" ) >> "$OUT" &
sleep 2
run_n D 6 "$T" | tee -a "$OUT"
for i in $(seq 1 8); do
  echo "HD $(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 15 http://localhost:8001/api/health)" >> "$OUT"
  sleep 1
done
wait

echo "### E · v3 under synthetic CPU load (2 busy threads on a 2-CPU cap)" | tee -a "$OUT"
wait_idle; T=$(newtok)
for c in 1 2; do ( timeout 45 python3 -c "
while True: pass" ) & done
sleep 2
run_n E 6 "$T" | tee -a "$OUT"
wait
echo "### DONE" | tee -a "$OUT"
