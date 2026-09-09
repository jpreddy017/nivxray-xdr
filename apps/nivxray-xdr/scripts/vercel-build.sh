#!/usr/bin/env bash
# Production build for the scoped NivXRay frontends.
#
# ONE script serves BOTH Vercel projects, because both use the same Root
# Directory (apps/nivxray-xdr) and therefore the same vercel.json — so the
# build command must be identical and the product must come from a per-project
# environment variable:
#
#   nivxray-xdr-production   NIVX_PRODUCT_SCOPE unset or "xdr"  → xdr.nivxforge.com
#   (new) EDR project        NIVX_PRODUCT_SCOPE="edr"           → edr.nivxforge.com
#
# The default is "xdr", so the LIVE XDR production build is byte-for-byte the
# behaviour it had before this script was parameterised.
#
# XDR and EDR remain SEPARATE ARTIFACTS by design. REACT_APP_PRODUCT_SCOPE is
# required, not cosmetic: owner decision 5b removed the cross-host /edr/*
# redirects, so src/productScope.js + components/ProductScopeGuard.jsx are the
# ONLY thing stopping xdr.nivxforge.com/edr/trajectory from rendering EDR on
# the XDR hostname. Unset it and the product boundary silently disappears.
#
# Kept in a script so vercel.json "buildCommand" stays far below Vercel's
# 256-character schema limit — the defect that blocked Phase 1.
set -euo pipefail

SCOPE="${NIVX_PRODUCT_SCOPE:-xdr}"
if [[ "$SCOPE" != "xdr" && "$SCOPE" != "edr" ]]; then
  echo "FATAL: NIVX_PRODUCT_SCOPE must be 'xdr' or 'edr' (got '$SCOPE')." >&2
  echo "An unscoped build would let either product render on either host." >&2
  exit 1
fi

API_ORIGIN="${XDR_PROD_API_ORIGIN:-https://nivxray.nivxforge.com}"

# Cross-product origins (public config only — never a credential).
#
# Deliberately EMPTY unless NIVX_CROSS_PRODUCT_ORIGINS=1 is set on the
# project. Baking in a hostname that does not resolve yet would ship dead
# links, and the build guard treats the other product's host as forbidden
# precisely so a half-finished split cannot leak across. Turn this on only
# once BOTH hostnames are live and verified.
XDR_ORIGIN=""
EDR_ORIGIN=""
WORKSPACE_ORIGIN="${NIVX_WORKSPACE_ORIGIN:-}"
if [[ "${NIVX_CROSS_PRODUCT_ORIGINS:-0}" == "1" ]]; then
  XDR_ORIGIN="${NIVX_XDR_ORIGIN:-https://xdr.nivxforge.com}"
  EDR_ORIGIN="${NIVX_EDR_ORIGIN:-https://edr.nivxforge.com}"
  WORKSPACE_ORIGIN="${NIVX_WORKSPACE_ORIGIN:-https://workspace.nivxmachines.com}"
fi

echo "── production build ─────────────────────────────"
echo "  product scope      : $SCOPE"
echo "  api origin         : $API_ORIGIN"
echo "  cross-product URLs : ${NIVX_CROSS_PRODUCT_ORIGINS:-0} (xdr='$XDR_ORIGIN' edr='$EDR_ORIGIN' workspace='$WORKSPACE_ORIGIN')"
echo "─────────────────────────────────────────────────"

# Passed as REAL environment variables, which vite's loadEnv(mode, cwd, "")
# lets override .env. apps/nivxray-xdr/.env keeps pointing at the preview
# backend, so Preview XDR is unaffected (owner rule: "do not destroy the
# Preview configuration to create the production build").
REACT_APP_NIVXRAY_API_URL="$API_ORIGIN" \
REACT_APP_PRODUCT_SCOPE="$SCOPE" \
REACT_APP_XDR_URL="$XDR_ORIGIN" \
REACT_APP_EDR_URL="$EDR_ORIGIN" \
REACT_APP_WORKSPACE_URL="$WORKSPACE_ORIGIN" \
yarn run build

# Deployment provenance, written into the artifact itself so the guard checks
# what the build was actually told rather than trusting a source .env.
cat > dist/build-info.json <<JSON
{
  "product": "nivxray-$SCOPE",
  "product_scope": "$SCOPE",
  "api_origin": "$API_ORIGIN",
  "phase": "2",
  "cross_product_origins": ${NIVX_CROSS_PRODUCT_ORIGINS:-0},
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

NIVX_PRODUCT_SCOPE="$SCOPE" node scripts/verify-production-build.js
