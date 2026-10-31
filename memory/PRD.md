# NivXForge EDR — product requirements and release state

Last updated: 2026-10-31

## Original problem statement (owner)

Publish all completed, approved and verified NivXForge EDR updates to
https://edr.nivxforge.com. Production was behind the newer preview
implementations. Inventory everything missing, consolidate the approved work
into one controlled release candidate (never a blind merge of development
branches), verify Device Trajectory, Process Tree, time navigation, evidence
rendering, filtering, investigation workflows, UI/UX, API connectivity and
authentication, run build/regression/integration/security checks, complete the
G0–G6 gates, preserve the current production deployment for rollback, and
present the candidate with evidence for approval before promotion.

### Standing restrictions
- No loss of functionality, evidence or production data (see "Owner-authorised
  exceptions" below — two device-scoped deletions were later authorised).
- Do not modify NivXRay XDR, NivXRay Workspace or NivX Machines.
- No database migrations or backend replacements without separate approval.
- No unverified code or incomplete features.
- Preserve EDR independence and separation requirements.
- Do not ask for credentials that are already valid and configured.

## Topology

| Piece | Where |
|---|---|
| EDR production frontend | Vercel project `nivxray-edr-production` → edr.nivxforge.com |
| XDR production frontend | same repo/root, scope `xdr` → xdr.nivxforge.com |
| Production API | https://nivxray.nivxforge.com (separate Emergent deployment, managed Atlas) |
| Preview API + database | https://greeting-app-5782.preview.emergentagent.com, Mongo `test_database` |
| Preview frontend (port 3000) | supervisor `frontend` = `yarn dev` in /app/apps/nivxray-xdr |
| g4lab backend (port 8101) | supervisor `g4lab`, cwd /root/audit/backend — do not delete /root/audit |
| Repo | jpreddy017/nivxray-xdr, production branch `phase2/edr-production` |

Vercel effective config: root `apps/nivxray-xdr`, build `bash scripts/vercel-build.sh`,
output `dist`, SPA rewrite, host redirect edr.nivxforge.com → /edr. Repo-root
`vercel.json` refuses root deployment. Production API origin defaults to
`https://nivxray.nivxforge.com`; the preview backend pin is reachable ONLY with
`NIVX_EDR_INTEGRATION_PREVIEW=1` + `VERCEL_ENV=preview` + branch
`validation/edr-preview-backend-2026-10-31`.

## Release candidate — ready, not promoted

- Branch `release/edr-production-2026-10-31`, commit
  **`18ccb5ccbc3371242c06f2226244dd32d6385165`** (pushed).
- Baseline / rollback: `35d47cc96352f492bd4c603a2f2f1b65afb4119f`, deployment
  `dpl_GnXW5Y5qwss3858hd1jJdrabxXME`, built 2026-10-28T16:15:44Z.
- 36 commits, all linear descendants of production. Excluded deliberately:
  `reconciliation/edr-local-backend-2026-10-31` (carries a DO-NOT-DEPLOY
  server.py review) and `release/edr-repair-readiness-2026-10-31` (docs only).

### Gate evidence (2026-10-31)
| Gate | Result |
|---|---|
| EDR production build + guard | PASS — api origin nivxray.nivxforge.com, no preview origin in 182 artifacts |
| XDR production build + guard | PASS — shared build script change does not alter XDR |
| Frontend unit suite | 16 files / 286 tests passed |
| EDR node tool harnesses | 8/8 pass (focus-state harness repaired to load the real DeepLinkBanner) |
| Backend, deterministic vs baseline | RC 2900 passed / 7 failed · baseline 2768 passed / 18 failed · 18 fixed · 0 common |
| Backend, actual payload at 18ccb5cc | 2930 passed / 8 failed — 7 iteration_82 + 1 Mongo socket flake (`test_platform_seed::test_mac_is_labelled_fixture_only`, passes alone) |
| Route inventory of the payload | 881 routes; only maintenance surface is the new purge route. dev_reset, transfer_bundle, `_arch`/`_pv` mounts all absent |
| Deployment readiness scan | PASS, no findings |
| Purge route contract | 7/7 pass |
| Gate 16 + Gate 17 + purge | 25 passed |

The 7 remaining backend failures are all
`tests/edr/test_iteration_82_activation.py`: it asserts the preview database's
golden corpus while `backend/conftest.py` pins the suite to `nivxray_ci_local`.
Reproduced by `DB_NAME` alone — passes 10/10 against `test_database`, fails 7
against `nivxray_ci_local`. It only ever passed because another module
overrode `DB_NAME` mid-session, the exact leak PR #28 removed. Test-fixture
conflict, no product impact.

## Preview serving (for browser validation)

Port 3000 is held by supervisor program **`edrpreview`** →
`node /root/spa.js /root/rcapp/apps/nivxray-xdr/dist 3000`, a static server for
the candidate's frontend tree built from `18ccb5cc` with the preview API origin.
Supervisor `frontend` (vite dev on /app source) is **STOPPED**: it was
crash-looping with `ENOSPC: System limit for number of file watchers reached`
(`fs.inotify.max_user_watches=12288`, cannot be raised — sysctl permission
denied in this container). That crash loop is what made port 3000 flap and
stalled the earlier browser runs. `/app/apps/nivxray-xdr` has been restored to
its pre-verification state; snapshot at
`/root/app_apps_nivxray-xdr_snapshot.tar.gz`.

## Corpus-failure matrix (resolved)

| Tree | DB_NAME | Result |
|---|---|---|
| candidate 18ccb5cc | test_database | 10 passed |
| candidate 18ccb5cc | nivxray_ci_local | **the same 7 fail** |
| baseline 35d47cc9 | test_database | 10 passed |
| baseline 35d47cc9 | nivxray_ci_local | **the same 7 fail** (+2 network) |

Same database, same fixtures, same 7 names on both trees — pre-existing, not a
regression. `test_platform_seed::test_mac_is_labelled_fixture_only` remains an
**unresolved intermittent** Mongo socket drop under xdist (passes alone; a
different test drew it in each earlier run) — cause not demonstrated.

### Blockers before promotion
0. **The purge route would be LIVE in production.** `EDR_MAINTENANCE_TOKEN` has a
   live slot, so after the backend deploy the route answers (403 without the
   header, 200 with it). Owner asked for it to stay disabled. Remedy, not yet
   applied because it changes the candidate SHA: require a second explicit
   `EDR_PURGE_ENABLED=1` in `_guard`, or clear the production
   `EDR_MAINTENANCE_TOKEN` before deploying.
1. **Backend first.** The RC changes `backend/edr_trajectory/*`,
   `backend/routers/edr.py`, `backend/v2/*`. A Vercel promotion ships frontend
   only. The production API revision is unverified — frontend-only release
   risks a UI whose paging and deep-link states exceed the live contract.
2. `VERCEL_TOKEN` has no value in this workspace (production slot only), so
   Vercel API/CLI deploys cannot be driven from here. Not needed: merging the
   release branch into `phase2/edr-production` triggers the production build.
3. The configured `GITHUB_TOKEN` can push branches but **cannot open PRs**
   ("Resource not accessible by personal access token"). Open it from
   https://github.com/jpreddy017/nivxray-xdr/pull/new/release/edr-production-2026-10-31
4. Vercel deployment protection is Standard; preview URLs need the bypass
   secret (`VERCEL_AUTOMATION_BYPASS_SECRET`, saved and working).

## Workspace reconciliation (for the Emergent backend publish)

`/app/backend` runtime code now equals the RC. Removed three temporary mounts
from `server.py` that would otherwise have shipped: `transfer_bundle`,
`routers/edr_maintenance` (whole-tenant dev reset) and the `ARCH_DOCS_SHARE`
static mounts of `/app/docs/architecture` and `/app/_preservation`. All three
now 404. Both files remain on disk, unimported. Backup of the previous
server.py: `/root/` (see git history for the exact content).

## Owner-authorised exceptions to "no evidence loss"

- **DESKTOP-A9HGFJJ (preview)** — deleted 2026-10-31: 6,597
  `v2_shadow_observations` + 3,300 `xdr_canonical_evidence` = 9,897 docs, all
  captured 2026-09-22, double-ingested across `ten_3f7f772b…` and
  `ten_f1a5479…`. Backup: `/root/evidence_backup/*__DESKTOP-A9HGFJJ.bson`
  (48.6 MB). No KUSHU markers. Endpoint registry untouched.
- **Production deletions requested, NOT executed**: DESKTOP-A9HGFJJ
  (`ep_1989031c8c1d0085812f`, REVOKED) all logs, and KUSHU
  (`ep_a67be48d5b4e01d4d9e8`, CONNECTED) September 2026 logs. Neither device
  exists in preview; both are production-only. Delivered capability instead —
  see below. Awaiting explicit execute.

## Device-scoped evidence purge (new in this release)

`POST /api/edr/maintenance/purge-device-evidence`
(`backend/routers/edr_device_purge.py`, tests
`backend/tests/edr/test_device_evidence_purge.py`).

- 404 unless `EDR_MAINTENANCE_TOKEN` is set; 403 without the matching
  `X-Maintenance-Token` header.
- `mode=dry` default, reports matched counts and tenants per collection.
- `mode=execute` also requires `confirm=DELETE-DEVICE-EVIDENCE` and a non-empty
  `backup` reference, echoed back for audit.
- Resolves the device from `edr_endpoints`; an ambiguous hostname is refused
  (409 `ENDPOINT_AMBIGUOUS`), never guessed.
- Optional `time_start` / `time_end` window (`captured_at` for shadow,
  `event_time` for canonical).
- Never deletes the endpoint record — the device stays in Computers.

Verified live on preview: dry run on `ep_2d57cbe6f80152062109` with the
September window reported 267,181 + 263,335 matched and deleted nothing.

## Backlog

**P0**
- Deploy the backend to production, then verify `presentation=v3`,
  authenticated trajectory load, pagination and deep links; check shared
  XDR/Workspace compatibility.
- Open and merge the release PR into `phase2/edr-production`; confirm the new
  Vercel deployment is Ready, Production and bound to edr.nivxforge.com.
- Execute the two authorised production purges once the route is live.

**P1**
- Rendered-UI verification of the candidate (date selection, 14:00 centering,
  event details, five filter groups, share, fullscreen, older-event loading).
  Repeatedly interrupted by /tmp and /opt being wiped between turns — only
  /app and /root persist. Build from `git archive` into /root/rcapp.
- Re-point `validation/edr-preview-backend-2026-10-31` (currently `6be37d76`)
  so the EDR preview alias serves the candidate.
- Make `test_iteration_82_activation.py` declare its own database requirement.

**P2**
- Review `backend/transfer_bundle.py` and `backend/routers/edr_maintenance.py`
  for deletion or permanent gating.
- Push `engineering/successor-p0-blocker-repair` and `fix/p0-installer-upgrade`
  to GitHub; their worktrees (937 MB) are the only copies.
- Disk: /app volume is 93% full after reclaiming 467 MB.
