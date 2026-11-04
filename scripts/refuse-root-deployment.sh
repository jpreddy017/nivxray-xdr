#!/usr/bin/env bash
# Repo-root deployment guard.
#
# WHY THIS EXISTS
# ---------------
# The repo root previously carried a full, WORKING vercel.json that built
# apps/nivxray-xdr with a plain `vite build`:
#
#   * no REACT_APP_PRODUCT_SCOPE  -> the product boundary disappears and
#     xdr.nivxforge.com/edr/* would render NivXForge EDR on the XDR host
#   * no REACT_APP_NIVXRAY_API_URL override -> the PREVIEW api origin from
#     apps/nivxray-xdr/.env gets baked into a PRODUCTION bundle
#   * no scripts/verify-production-build.js -> neither mistake is caught
#
# Vercel selects vercel.json by the project's Root Directory. The live XDR
# project uses Root Directory `apps/nivxray-xdr` (proven by the deployed
# artifact: dist/build-info.json reports product_scope=xdr and
# api_origin=https://nivxray.nivxforge.com, and `/` 307-redirects to `/xdr`,
# both of which only apps/nivxray-xdr/vercel.json can produce). So the root
# file was unused — but any NEW project created with the default root would
# have silently shipped that unguarded bundle.
#
# Deleting the root vercel.json is NOT the safe fix: with no config Vercel
# falls back to framework auto-detection and would build something
# unpredictable. Failing loudly is deterministic.
#
# THE CORRECT CONFIGURATION
# -------------------------
#   Root Directory : apps/nivxray-xdr
#   Env            : NIVX_PRODUCT_SCOPE = xdr   (or edr for the EDR project)
#                    XDR_PROD_API_ORIGIN = https://nivxray.nivxforge.com
#
# The Workspace project is unaffected: it uses Root Directory `frontend` and
# its own frontend/vercel.json.
set -euo pipefail

cat >&2 <<'MSG'

================================================================
  DEPLOYMENT REFUSED · WRONG ROOT DIRECTORY
================================================================

This Vercel project is building from the REPOSITORY ROOT, which has no
production build guard. A bundle built from here would ship with no
product scope and with the PREVIEW api origin embedded.

Fix the project settings instead:

  Settings -> General -> Root Directory : apps/nivxray-xdr

  Settings -> Environment Variables:
    NIVX_PRODUCT_SCOPE   = xdr      (XDR project)
                         = edr      (EDR project)
    XDR_PROD_API_ORIGIN  = https://nivxray.nivxforge.com

Then redeploy. Nothing was published.
================================================================

MSG
exit 1
