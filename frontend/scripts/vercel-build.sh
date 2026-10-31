#!/usr/bin/env bash
# Workspace-only production build for the nivxmachines-workspace Vercel project.
# Extracted verbatim from frontend/vercel.json "buildCommand" because Vercel
# rejects a buildCommand longer than 256 characters. Semantics unchanged:
# the env vars apply to `yarn build` only, and the build guard runs after it
# and must be able to fail the deployment.
set -euo pipefail

case "${NIVX_WORKSPACE_INTEGRATION_PREVIEW:-0}" in
  0|1) ;;
  *) echo "Invalid Workspace preview flag" >&2; exit 1 ;;
esac
API_ORIGIN=https://nivxray.nivxforge.com
if [[ "${NIVX_WORKSPACE_INTEGRATION_PREVIEW:-0}" == "1" ]]; then
  if [[ "${VERCEL_ENV:-}" != "preview" || "${VERCEL_GIT_COMMIT_REF:-}" != "validation/workspace-preview-backend-2026-10-31" ]]; then
    echo "Workspace integration requires its designated preview branch and preview target" >&2
    exit 1
  fi
  API_ORIGIN=https://greeting-app-5782.preview.emergentagent.com
fi

CI=false \
GENERATE_SOURCEMAP=false \
REACT_APP_BACKEND_URL="$API_ORIGIN" \
REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=disabled \
REACT_APP_NIVX_FLAG_CASE_ENGINE=disabled \
REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=disabled \
yarn build

node scripts/verify-production-build.js
printf '{"product_scope":"workspace","api_origin":"%s","integration_preview":%s}\n' "$API_ORIGIN" "${NIVX_WORKSPACE_INTEGRATION_PREVIEW:-0}" > build/build-info.json
