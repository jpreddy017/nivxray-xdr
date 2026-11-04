# PHASE 0 SOURCE PROMOTION — STAGE 1 · POST-PUSH VERIFICATION + DEPLOYMENT-STATE RECONCILIATION

Mode: **READ-ONLY**. No deployment, no retry, no republish, no DB write, no secret access.
All remote facts obtained from the **public GitHub API** (no credentials) and plain HTTPS GETs.

RESULT: **PHASE 0 SOURCE PROMOTION — STAGE 1: PASS**

## 1 · Source promotion

| Fact | Value |
|---|---|
| Remote repo | `github.com/jpreddy017/nivxray-xdr` |
| Remote branch | `feature/rc2-alignment` |
| REMOTE HEAD | `8f370c7d` ("Auto-generated changes", 2026-09-26T17:34:57Z) |
| LOCAL HEAD | `0f6e4c0a` (its parent lineage; `8f370c7d` + `cf62f75b` are the platform's own save commits) |
| `bea8852b` ancestor of remote HEAD | **YES** — remote history: `8f370c7d ← cf62f75b ← 0f6e4c0a ← bea8852b ← 92ea4f31 ← 876d6217 ← 9c1e514d ← f7a25183` |

**PHASE0 SOURCE EQUIVALENCE: PASS** — SHA-256 of every Phase 0 file at remote HEAD
(`raw.githubusercontent.com/.../8f370c7d.../<path>`) equals the local preview-proven file:

```
MATCH backend/edr_plane/windows_eventlog.py
MATCH backend/edr_plane/canonical_bridge.py
MATCH backend/edr_plane/trajectory_window.py
MATCH backend/v2/ingestion/telemetry_bridge.py
MATCH backend/v2/ingestion/canonical.py
MATCH backend/services/edr/telemetry_freshness.py
MATCH backend/detection_content/telemetry/nivxforge_sensor_dsm.py
MATCH apps/nivxray-xdr/src/nivxforge/components/TelemetryFreshness.jsx
MATCH backend/tests/edr/test_phase0_windows_canonical_bridge.py
MATCH backend/tests/edr/fixtures_windows_eventlog.py
```

## 2 · What the automatic integration actually deployed

Authoritative source: `GET /repos/jpreddy017/nivxray-xdr/deployments` (100 records) plus
per-deployment statuses. **Every deployment created from `8f370c7d` is `Preview`.** The only
`Production` deployments that exist at all are:

```
Production – nivxray-edr-production | f7a25183 | 15:58:03Z
Production – nivxray-xdr-production | f7a25183 | 15:55:52Z
Production – nivxray-edr-production | 9fcd53a5 | 15:35:52Z
Production – nivxray-xdr-production | 9fcd53a5 | 15:33:22Z
```

There is **no Production deployment from `8f370c7d`**.

| PROJECT | CHECK RESULT | DEPLOYMENT CREATED | SHA | ENVIRONMENT | URL/HOST | PROD OR PREVIEW | LIVE PROD ALIAS CHANGED | PHASE0 FRONTEND INCLUDED |
|---|---|---|---|---|---|---|---|---|
| `nivxray-edr-production` | success | YES | `8f370c7d` | `Preview – nivxray-edr-production` | `nivxray-edr-production-biymp6qzl-jpreddy017.vercel.app` (Vercel deployment protection → login wall) | **PREVIEW** | **NO** | YES, in that **preview** artifact (source is `8f370c7d`); not inspectable due to protection |
| `nivxray-xdr-production` | success | YES | `8f370c7d` | `Preview – nivxray-xdr-production` | `nivxray-xdr-production-30altptc9-jpreddy017.vercel.app` (login wall) | **PREVIEW** | **NO** | YES (same reasoning) |
| `nivxray-xdr` (legacy) | **failure** | YES (failed) | `8f370c7d` | `Preview – nivxray-xdr` | `nivxray-g7bv4zsoc-jpreddy017.vercel.app`, `dpl_ZXjK1oR2SbmzXqKbEGfbnuCrMppd` | **PREVIEW** | **NO** | N/A — build refused |
| `nivxmachines-workspace` | success | YES | `8f370c7d` | `Preview – nivxmachines-workspace` | `nivxmachines-workspace-9ksbctrgu-jpreddy017.vercel.app` (login wall) | **PREVIEW** | **NO** | N/A — builds Root Directory `frontend`, which Phase 0 never touched |

## 3 · Live production consoles — measured, not inferred

```
https://edr.nivxforge.com/build-info.json → built_at 2026-09-26T15:58:00Z  product nivxray-edr
https://xdr.nivxforge.com/build-info.json → built_at 2026-09-26T15:55:50Z  product nivxray-xdr
```

Those timestamps are the **f7a25183 production deployments**, ~97 minutes *before* the push.
Served entry bundles are unchanged (`index-Dyygw0sM.js` on EDR, `index-DWES00xC.js` on XDR),
and their `TelemetryFreshness-*.js` chunks contain **0** occurrences of
`RAW_ONLY_NOT_INVESTIGABLE` and **0** of `investigability`. The `[object Object]` path is
therefore **still live on both hosts**.

## 4 · Failed check — root cause (READ-ONLY, NOT retried)

`Vercel – nivxray-xdr` → `dpl_ZXjK1oR2SbmzXqKbEGfbnuCrMppd`, state `failure`.

**Root cause: the build is refused on purpose.** That legacy project uses Root Directory =
**repo root**, so Vercel selects `/vercel.json`, whose `buildCommand` is
`bash scripts/refuse-root-deployment.sh` — a guard added in commit `f083b8d7` that exits
non-zero with `DEPLOYMENT REFUSED · WRONG ROOT DIRECTORY`. It exists because a root-directory
build would ship a bundle with **no `REACT_APP_PRODUCT_SCOPE`** (the product boundary
disappears — EDR would render on the XDR host) and **no API-origin override** (the *preview*
backend origin baked into a production bundle), with the build guard bypassed.

Corroboration that this is pre-existing and unrelated to Phase 0: the **same project failed
on the previous push too** — `Preview – nivxray-xdr`, sha `f7a25183`, 15:45:39Z,
`dpl_53QBdDinDfM4auECGJA2Di4WRBRL`. Also note this legacy project's Production Branch is
`main` (per `PHASE1_WORKSPACE_DEPLOYMENT_RUNBOOK.md` §2.0b), which is 1,529 commits stale, so
it can never publish from `feature/rc2-alignment`.

**Correct disposition: leave it failing, or fix the project's Root Directory to
`apps/nivxray-xdr` / delete the redundant project. Do NOT retry — a "successful" root build
is the dangerous outcome, not the failure.**

## 5 · Production backend — determined independently of Vercel

| Check | Result |
|---|---|
| `GET /api/openapi.json` before push | 862 paths, sha256 `8c04168feebf43f0` |
| `GET /api/openapi.json` after push | 862 paths, sha256 `8c04168feebf43f0` — **byte-identical** |
| `GET /api/health` | `{"status":"ok","service":"nivxray-api"}` (unchanged) |
| Emergent publish | still **Publish 100 / build `4e76891`** — Emergent deployments are explicit owner actions and are never triggered by a GitHub push |

**The Phase 0 Python canonical bridge is NOT running in production.** Stage 2 (backend
republish) is still required. The green Vercel checks concern web consoles only.

## 6 · Counters

```
PRODUCTION DB WRITES: 0   ORGANIZATIONS CREATED: 0   TENANTS CREATED: 0
TOKENS CREATED: 0   ENDPOINTS ENROLLED: 0   RESPONSE ACTIONS: 0
SECRETS CHANGED: 0   SECRETS READ: 0 (EDR_AUTH_PEPPER never accessed)
VERCEL RETRIES: 0   DEPLOYMENTS TRIGGERED BY AGENT: 0   CODE CHANGED: 0
```

Response authority remains **FAIL-CLOSED**. The stale tenant test remains
**TEST_ONLY_HARNESS_DEBT**, unmodified; no production code was changed for it.
