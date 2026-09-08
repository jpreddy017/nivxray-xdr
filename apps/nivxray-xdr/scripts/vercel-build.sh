#!/usr/bin/env bash
# XDR production build for the (owner-created) xdr.nivxforge.com Vercel project.
# Kept in a script so vercel.json "buildCommand" stays far below Vercel's
# 256-character schema limit — the defect that blocked Phase 1.
#
# Both variables are passed as REAL environment variables, which vite's
# loadEnv(mode, cwd, "") lets override .env. apps/nivxray-xdr/.env keeps
# pointing at the preview backend, so Preview XDR is unaffected (owner rule:
# "do not destroy the Preview configuration to create the production build").
#
# REACT_APP_PRODUCT_SCOPE=xdr is REQUIRED, not cosmetic. Owner decision 5b
# removed the cross-host `/edr/*` redirects from vercel.json, so the server can
# no longer bounce EDR paths off this hostname. src/productScope.js +
# components/ProductScopeGuard.jsx are then the ONLY thing stopping
# xdr.nivxforge.com/edr/trajectory from rendering NivXForge EDR on the XDR
# hostname. Unset it and the product boundary silently disappears.
set -euo pipefail

API_ORIGIN="${XDR_PROD_API_ORIGIN:-https://nivxray.nivxforge.com}"
SCOPE="xdr"

REACT_APP_NIVXRAY_API_URL="$API_ORIGIN" \
REACT_APP_PRODUCT_SCOPE="$SCOPE" \
yarn run build

# Deployment provenance, written into the artifact itself so the guard checks
# what the build was actually told rather than trusting a source .env.
cat > dist/build-info.json <<JSON
{
  "product": "nivxray-xdr",
  "product_scope": "$SCOPE",
  "api_origin": "$API_ORIGIN",
  "phase": "2",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

node scripts/verify-production-build.js
