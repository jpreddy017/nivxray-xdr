#!/bin/bash
# P0-INFRA-1 · external availability probe (read-only). One line per sweep.
URL="https://greeting-app-5782.preview.emergentagent.com"
OUT=/app/memory/availability_probe.log
while true; do
  TS=$(date -u +%H:%M:%S)
  L=""
  for P in "/" "/xdr/control-center" "/edr/computers" "/edr/computers/ep_2d57cbe6f80152062109/trajectory" "/api/health"; do
    C=$(curl -s -o /dev/null -m 20 -w "%{http_code}" "$URL$P")
    L="$L $P=$C"
  done
  UP=$(ps -o etimes= -p 1 | tr -d ' ')
  BU=$(sudo supervisorctl status backend | awk '{print $NF}')
  FU=$(sudo supervisorctl status frontend | awk '{print $NF}')
  echo "$TS pid1_uptime=${UP}s backend_up=$BU frontend_up=$FU$L" >> $OUT
  sleep 20
done
