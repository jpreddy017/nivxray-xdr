# Workspace preview build correction — 2026-11-04

Vercel project nivxmachines-workspace has rootDirectory frontend and a CRA
preset. PR #61 had no frontend/vercel.json; root XDR configuration attempted
cd apps/nivxray-xdr from that frontend directory and failed ENOENT.

Added frontend/vercel.json without modifying root XDR configuration or project
settings. The Workspace commands run in frontend and publish build.

Compatibility policies preserved:
- Project install command: yarn install --production=false.
- Existing production script at ddbb0999d497e1815b1b0a94f4b96233a01f3760 uses
  CI=false for yarn build. This preview uses the same warning policy.
  Compiler errors still fail; CRA warnings are not promoted to errors.
- Preview environment variables are retained. Production's hard-coded backend
  URL and disabled engine flags are not copied into the preview.

Outstanding: frontend/yarn.lock needs reconciliation for frozen installs.
Existing React hook dependency warnings remain to be reviewed separately.
This build correction is not evidence of runtime correctness or release approval.
