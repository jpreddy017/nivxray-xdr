#!/usr/bin/env bash
# NivXForge EDR · pre-deletion backup + verification + DRY RUN
#
#   MONGO_URL='mongodb+srv://…' ./edr_backup_and_dryrun.sh
#
# READ-ONLY against the database: it dumps, verifies the dump, and runs the
# reset script in its default dry-run mode. It contains no delete and never
# arms anything. Safe to re-run.
set -uo pipefail

: "${MONGO_URL:?set MONGO_URL (Manage Publishes -> Database). It is regenerated on every deploy, so copy it fresh.}"
DB="${DB:-greeting-app-5782-test_database}"
OUT="${OUT:-/tmp/edr-predelete.archive.gz}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="${LOG:-/tmp/edr-backup-$STAMP.log}"

say() { printf '\n=== %s\n' "$*" | tee -a "$LOG"; }

say "0 · connectivity (read-only ping)"
if ! mongosh "$MONGO_URL" --quiet --eval 'db.adminCommand({ping:1}).ok' 2>&1 | tee -a "$LOG" | grep -q 1; then
  say "CONNECTION FAILED — see $LOG. If this is 'connection refused' or a DNS/SRV"
  say "failure it is the Atlas IP allowlist for this host, not a credential problem."
  exit 2
fi

say "1 · mongodump · whole database"
# mongodump (100.19.1) has NO --nsInclude: that option belongs to
# mongorestore. Verified by running it. So the dump is whole-database, which
# is also the stronger backup: every collection this cleanup touches plus
# everything it does not.
mongodump --uri="$MONGO_URL" --db="$DB" --gzip --archive="$OUT" 2>&1 | tee -a "$LOG"
[ -s "$OUT" ] || { say "DUMP EMPTY OR MISSING — stop."; exit 3; }

say "2 · archive identity"
ls -l "$OUT" | tee -a "$LOG"
du -h "$OUT" | tee -a "$LOG"
sha256sum "$OUT" | tee -a "$LOG"

say "3 · restore-readiness (dry run · writes nothing)"
mongorestore --uri="$MONGO_URL" --gzip --archive="$OUT" --dryRun \
  --nsInclude="$DB.*" 2>&1 | tail -40 | tee -a "$LOG"

say "4 · per-collection counts dumped (cross-check against the inventory)"
grep -E 'done dumping' "$LOG" | sed 's/^/   /' | tee -a "$LOG"

say "5 · DRY RUN of the reset script (dry by default · writes nothing)"
mongosh "$MONGO_URL" --quiet --file "$HERE/edr_dev_reset.mongosh.js" 2>&1 | tee -a "$LOG"

say "DONE · log $LOG · archive $OUT"
say "Nothing was deleted. The script above ran in DRY RUN mode."
