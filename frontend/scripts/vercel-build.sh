#!/usr/bin/env bash
# Workspace-only production build for the nivxmachines-workspace Vercel project.
# Extracted verbatim from frontend/vercel.json "buildCommand" because Vercel
# rejects a buildCommand longer than 256 characters. Semantics unchanged:
# the env vars apply to `yarn build` only, and the build guard runs after it
# and must be able to fail the deployment.
set -euo pipefail

CI=false \
GENERATE_SOURCEMAP=false \
REACT_APP_BACKEND_URL=https://nivxray.nivxforge.com \
REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=disabled \
REACT_APP_NIVX_FLAG_CASE_ENGINE=disabled \
REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=disabled \
yarn build

node scripts/verify-production-build.js
