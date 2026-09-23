#!/usr/bin/env bash
# Chunked backend regression: the whole suite crashes the runner when driven in
# one process, so it is executed in bounded file groups and aggregated.
set -u
cd /app/backend
OUT=${1:-/tmp/regress_after}
rm -rf "$OUT"; mkdir -p "$OUT"

SKIP="test_investigation_quality.py|test_iter62_correlations_e2e.py|test_osint_live_endpoints.py|test_pr212_api_parity.py|test_pr21_canonical_artifact_api.py|test_rule_detection_playbook_expansion.py|test_s2mini_engine_depth_authz.py"

mapfile -t FILES < <(ls tests/test_*.py | grep -Ev "$SKIP")
mapfile -t DIRS < <(ls -d tests/*/ 2>/dev/null)

i=0
CHUNK=()
flush() {
  [ ${#CHUNK[@]} -eq 0 ] && return
  i=$((i+1))
  timeout 900 python -m pytest -q -p no:cacheprovider "${CHUNK[@]}" \
    > "$OUT/chunk_$i.txt" 2>&1
  echo "chunk $i: $(tail -n 2 "$OUT/chunk_$i.txt" | tr '\n' ' ')"
  CHUNK=()
}

for f in "${FILES[@]}"; do
  CHUNK+=("$f")
  if [ ${#CHUNK[@]} -ge 12 ]; then flush; fi
done
flush
for d in "${DIRS[@]}"; do
  CHUNK+=("$d"); flush
done
echo "DONE $OUT"
