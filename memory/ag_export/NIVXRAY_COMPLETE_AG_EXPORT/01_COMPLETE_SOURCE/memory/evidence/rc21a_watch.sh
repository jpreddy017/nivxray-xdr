#!/usr/bin/env bash
# RC2.1a — Post-Deploy Production Watch (30-min continuous health probe)
#
# Emits one JSON line per probe to /app/memory/evidence/rc21a_prod_watch.jsonl
# Rollback trigger criteria are enumerated in RC2.1a_ROLLBACK_PLAN.md.
#
# Usage:
#   PROD_ADMIN_PASS='<prod admin password>' bash rc21a_watch.sh
#
# Runs 30 iterations at 60 s intervals = 30 min total wall-clock.
set -eu

PROD="${PROD_URL:-https://nivxray.nivxforge.com}"
ADMIN="${PROD_ADMIN_EMAIL:-admin@nivxray.com}"
PASS="${PROD_ADMIN_PASS:-}"
OUT="${OUT_LOG:-/app/memory/evidence/rc21a_prod_watch.jsonl}"
ITERS="${WATCH_ITERS:-30}"
SLEEP_S="${WATCH_INTERVAL:-60}"

if [ -z "$PASS" ]; then
  echo "ERROR: PROD_ADMIN_PASS env var required" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

login() {
  curl -s -X POST "$PROD/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN\",\"password\":\"$PASS\"}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

probe() {
  local iter="$1"
  local ts; ts=$(date -u +%FT%TZ)
  local health_code plugins_code plugins_count auth_code login_ms analyze_verdict analyze_family analyze_ms

  health_code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$PROD/api/" || echo "000")

  local t_login_start t_login_end
  t_login_start=$(date +%s%3N)
  TOKEN=$(login || echo "")
  t_login_end=$(date +%s%3N)
  login_ms=$((t_login_end - t_login_start))

  if [ -n "$TOKEN" ]; then
    auth_code="200"
    local plugins_json
    plugins_json=$(curl -s -H "Authorization: Bearer $TOKEN" -m 10 "$PROD/api/v2/plugins" || echo "{}")
    plugins_count=$(echo "$plugins_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('count','?'))" 2>/dev/null || echo "?")
    plugins_code="200"

    # Meterpreter smoke — quick check, only every 5 iters to save budget
    if [ $((iter % 5)) -eq 0 ] && [ -f /tmp/payload.json ]; then
      local t0 t1 an_json
      t0=$(date +%s%3N)
      an_json=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
                    -d @/tmp/payload.json -m 15 "$PROD/api/v2/analyze" || echo "{}")
      t1=$(date +%s%3N)
      analyze_ms=$((t1 - t0))
      analyze_verdict=$(echo "$an_json" | python3 -c "import sys,json;d=json.load(sys.stdin).get('report',{});print(d.get('findings',{}).get('verdict','?'))" 2>/dev/null || echo "?")
      analyze_family=$(echo "$an_json" | python3 -c "import sys,json;d=json.load(sys.stdin).get('report',{});print(d.get('findings',{}).get('family',{}).get('family','?'))" 2>/dev/null || echo "?")
    else
      analyze_verdict="skipped"
      analyze_family="skipped"
      analyze_ms="0"
    fi
  else
    auth_code="401_or_5xx"
    plugins_code="skipped"
    plugins_count="?"
    analyze_verdict="skipped"
    analyze_family="skipped"
    analyze_ms="0"
  fi

  # Alarm evaluation
  local alarm="OK"
  if [ "$health_code" != "200" ]; then alarm="HEALTH_FAIL"; fi
  if [ "$auth_code" != "200" ] && [ "$alarm" = "OK" ]; then alarm="AUTH_FAIL"; fi
  if [ "$plugins_count" != "21" ] && [ "$plugins_count" != "?" ] && [ "$alarm" = "OK" ]; then alarm="PLUGINS_COUNT_UNEXPECTED"; fi
  if [ "$analyze_verdict" != "malicious" ] && [ "$analyze_verdict" != "skipped" ] && [ "$alarm" = "OK" ]; then alarm="ANALYZE_VERDICT_UNEXPECTED"; fi

  printf '{"iter":%d,"ts":"%s","alarm":"%s","health":"%s","auth":"%s","login_ms":%d,"plugins":"%s","plugins_count":"%s","analyze_verdict":"%s","analyze_family":"%s","analyze_ms":%s}\n' \
    "$iter" "$ts" "$alarm" "$health_code" "$auth_code" "$login_ms" \
    "$plugins_code" "$plugins_count" "$analyze_verdict" "$analyze_family" "$analyze_ms" \
    | tee -a "$OUT"
}

echo "▶ RC2.1a production watch — $ITERS iterations · every ${SLEEP_S}s · logging to $OUT"
for i in $(seq 1 "$ITERS"); do
  probe "$i"
  if [ "$i" -lt "$ITERS" ]; then
    sleep "$SLEEP_S"
  fi
done

# Final summary
python3 <<'PY'
import json, collections
lines = open("/app/memory/evidence/rc21a_prod_watch.jsonl").read().splitlines()
alarms = collections.Counter()
for L in lines:
    try:
        alarms[json.loads(L).get("alarm", "?")] += 1
    except Exception:
        alarms["parse_error"] += 1
print("=" * 60)
print("RC2.1a Post-Deploy Watch — final summary")
print(f"Probes: {len(lines)}")
for k, v in alarms.most_common():
    print(f"  {k}: {v}")
if alarms.get("OK", 0) == len(lines):
    print("VERDICT: ✅ GREEN — RC2.1a stable across watch window")
else:
    print("VERDICT: ⚠️  ALARM(s) fired — inspect log & consider rollback")
PY
