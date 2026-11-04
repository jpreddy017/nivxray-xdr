#!/usr/bin/env bash
# scripts/run_docs_capture.sh — thin wrapper for the docs-screenshot
# capture, safe to invoke from CI or a cron job.
#
# Env (all optional; defaults are fine for a local run):
#   NIVXRAY_BASE_URL          override REACT_APP_BACKEND_URL
#   NIVXRAY_ADMIN_EMAIL       admin login (default: admin@nivxray.com)
#   NIVXRAY_ADMIN_PASSWORD    admin password (REQUIRED in CI)
#   NIVXRAY_WORKFLOW          single workflow id; if unset → --all
#
# Exit codes:
#   0  success (screenshots written)
#   2  bad args / missing config
#   >0 playwright failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${NIVXRAY_ADMIN_EMAIL:=admin@nivxray.com}"
: "${NIVXRAY_ADMIN_PASSWORD:?NIVXRAY_ADMIN_PASSWORD env is required}"

BASE_URL="${NIVXRAY_BASE_URL:-}"
if [[ -z "$BASE_URL" && -f /app/frontend/.env ]]; then
  BASE_URL="$(grep '^REACT_APP_BACKEND_URL=' /app/frontend/.env | cut -d= -f2- | tr -d '"')"
fi
if [[ -z "$BASE_URL" ]]; then
  echo "error: NIVXRAY_BASE_URL not set and /app/frontend/.env missing" >&2
  exit 2
fi

cd "$BACKEND_DIR"

ARGS=(
  --base-url "$BASE_URL"
  --email    "$NIVXRAY_ADMIN_EMAIL"
  --password "$NIVXRAY_ADMIN_PASSWORD"
)
if [[ -n "${NIVXRAY_WORKFLOW:-}" ]]; then
  ARGS+=(--workflow "$NIVXRAY_WORKFLOW")
else
  ARGS+=(--all)
fi

echo "[capture] backend=$BACKEND_DIR base=$BASE_URL ${NIVXRAY_WORKFLOW:+workflow=$NIVXRAY_WORKFLOW}"
python scripts/capture_docs_screenshots.py "${ARGS[@]}"
echo "[capture] ok · screenshots under $BACKEND_DIR/docs/screenshots/"
