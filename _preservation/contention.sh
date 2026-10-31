#!/usr/bin/env bash
# Does an abandoned legacy `combined` request inflate concurrent v3 reads
# and health responsiveness? Preview only.
set -u
EP=ep_2d57cbe6f80152062109
W='time_start=2026-10-01T00:00:00Z&time_end=2026-10-31T23:59:59Z&lane_start=0&lane_end=100000&limit=500'
cd /app/backend; set -a; . ./.env; set +a
T=$(curl -s -X POST http://localhost:8001/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
H=(-H "Authorization: Bearer $T" -H 'X-Tenant-Id: default')
B=http://localhost:8001/api/edr/endpoints/$EP/trajectory

echo "=== PHASE A · v3 with an idle worker ==="
for i in 1 2 3; do
  curl -s -o /dev/null -w "    v3 run$i: status=%{http_code} total=%{time_total}s\n" \
    --max-time 120 "${H[@]}" "$B?presentation=v3&$W"
done

echo
echo "=== PHASE B · one legacy combined read (504s at 30s), then probe during it ==="
curl -s -o /dev/null -w "    combined: status=%{http_code} total=%{time_total}s\n" \
  --max-time 120 "${H[@]}" "$B?presentation=combined&$W" &
LEG=$!
sleep 2
for i in 1 2 3; do
  curl -s -o /dev/null -w "    v3 during-legacy run$i: status=%{http_code} total=%{time_total}s\n" \
    --max-time 120 "${H[@]}" "$B?presentation=v3&$W"
done
echo "  -- health during the same window --"
for i in $(seq 1 6); do
  echo "    health t+${i}: $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' --max-time 10 http://localhost:8001/api/health)"
  sleep 1
done
wait $LEG

echo
echo "=== PHASE C · v3 after legacy work drains ==="
sleep 35
for i in 1 2 3; do
  curl -s -o /dev/null -w "    v3 run$i: status=%{http_code} total=%{time_total}s\n" \
    --max-time 120 "${H[@]}" "$B?presentation=v3&$W"
done

echo
echo "=== server-side stage timings ==="
grep -h '\[trajectory\]' /var/log/supervisor/backend.*.log | tail -12 \
  | python3 -c "
import sys,json
for l in sys.stdin:
    try: print('   ',json.loads(l)['msg'].replace('[trajectory] ',''))
    except Exception: pass"
echo "=== 504s logged ==="; grep -h 'server_timeout' /var/log/supervisor/backend.*.log | tail -3
