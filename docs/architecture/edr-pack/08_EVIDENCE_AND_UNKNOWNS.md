# 08 · Evidence Ledger, Unknowns and Required Follow-up

## 8.1 Confidence ledger

| # | Statement | Evidence | Class |
|---|---|---|---|
| 1 | `edr.nivxforge.com` is a Vercel static SPA, `307 → /edr`, asset `index-Btpjue2F.js` | HTTP probe 2026-10-30 | DEPLOY-VERIFIED |
| 2 | Deployed EDR build: scope `edr`, API origin `https://nivxray.nivxforge.com`, built `2026-10-28T16:15:44Z` | `GET /build-info.json` | DEPLOY-VERIFIED |
| 3 | XDR build: same API origin, built `2026-09-30T17:37:18Z` | `GET /build-info.json` | DEPLOY-VERIFIED |
| 4 | Workspace bundle targets the same API origin | bundle string inspection | DEPLOY-VERIFIED |
| 5 | API origin is Cloudflare-fronted, Emergent-hosted FastAPI (`nivxray-api`) | headers + `/api/health` | DEPLOY-VERIFIED |
| 6 | One app serves 875 paths — 86 EDR, 199 XDR, auth, workspace | `/api/openapi.json` | DEPLOY-VERIFIED |
| 7 | EDR agent plane is fail-closed | `401 SENSOR_UNAUTHENTICATED` | DEPLOY-VERIFIED |
| 8 | Prod / preview / local OpenAPI byte-identical (`md5 a8c5abe0…`) | three fetches | DEPLOY-VERIFIED |
| 9 | `phase2/edr-production` → `35d47cc9…`; `release/xdr-b8-selector-candidate` → `e2f15a25…`; `main` → `752a00ff` | GitHub API | REPO-VERIFIED |
| 10 | 56 branches, 23 open PRs; 15 of 23 marked HOLD/DRAFT/NO-GO | GitHub API | REPO-VERIFIED |
| 11 | `reviewer/g3-clean-pass` tip **is** `d2f8b742…`, full monorepo tree, carries a root `.tok` blob | GitHub API | REPO-VERIFIED |
| 12 | EDR owns 154 of 1,512 backend modules; EDR→non-EDR and non-EDR→EDR edges enumerated | AST parse | SOURCE-VERIFIED |
| 13 | Reverse deps: `nivxforge_sensor_dsm` + `xdr_pipeline` → `edr_plane`; 8 XDR UI files → `src/nivxforge` | AST + grep | SOURCE-VERIFIED |
| 14 | `edrApi.js` calls 4 `/xdr/*` endpoints | source | SOURCE-VERIFIED |
| 15 | Workers start inside the shared API process | `server.py` | SOURCE-VERIFIED |
| 16 | 6 mandatory env keys gate startup | `deps.py` `_REQUIRED_ENV` | SOURCE-VERIFIED |
| 17 | `backend/nivxforge/` is the NivXRay analysis engine, not EDR | import graph | SOURCE-VERIFIED |
| 18 | Design tokens, typography, motion, status vocabulary | `design_guidelines.json` | SOURCE-VERIFIED |
| 19 | 23 `/edr/*` routes, 15 page components, V3/legacy split | `App.jsx` + tree | SOURCE-VERIFIED |
| 20 | Sensor capabilities declare unsupported fields and empty `response_actions` | `nivxforge_sensor.py` | SOURCE-VERIFIED |
| 21 | M1 clean-install contract, config schema, refusal codes | `nivxforge_m1.py` (snapshot) | SOURCE-VERIFIED |
| 22 | 13,845 tracked paths → 7,821 unique blobs; `rocket-p0/` 1.2 GB with 8 tracked files | `git ls-tree`, `du` | SOURCE-VERIFIED |
| 23 | Vercel project `prj_KrtnUHko9…`, deployment `dpl_GnXW5Y5q…`, frontend SHA linkage | baseline v0.1/v0.2 | **INHERITED** |
| 24 | Production database differs from preview (login control) | baseline, 2026-09-08 | **INHERITED** |
| 25 | G4 telemetry volumes, reboot recovery, 28,038 stored events | E3 / operator reports | **INHERITED** |
| 26 | Backend deployment ID, revision, SHA | — | **UNKNOWN** |
| 27 | Production MongoDB host/deployment identity and `DB_NAME` | — | **UNKNOWN** |
| 28 | Production collection counts, index sizes, cross-product reference counts | — | **UNKNOWN** |
| 29 | Effective production value of `VITE_E3_DT_V3` and the `NIVX_FLAG_*` family | — | **UNKNOWN** |
| 30 | Whether the production backend runs parent-era code or another revision | OpenAPI cannot discriminate | **UNKNOWN** |

## 8.2 Why statement 8 does not prove statement 30

The byte-identical OpenAPI document proves the **schema** matches. Frozen candidate `d2f8b742` changes only *response content* — adding `e3_detections` to trajectory payloads — and introduces no new path or model. Any revision whose schema is unchanged is therefore invisible to this test. Identifying the deployed revision requires either an authorized platform read or one authenticated read-only trajectory call.

## 8.3 Open items, in the order that unblocks the most

| # | Item | Next read-only check | Unblocks |
|---|---|---|---|
| 1 | Backend deployment revision | authorized platform read of the production app (deployment ID, image/revision, build log) | isolation step 1; all of A0-03 |
| 2 | Production Mongo identity + `DB_NAME` | read the production deployment's env **key names + `DB_NAME` value only** | data boundary design |
| 3 | `backend/canonical/`, `engine/`, `security_state/` (165 modules) untraced | extend the AST pass | completeness of the dependency chain |
| 4 | Symbol-level detail of the 10 reverse-dependency call sites | enumerate imported symbols | safe interface inversion |
| 5 | Feature-flag effectiveness | read flag defaults in source + served artifacts | UI behaviour claims |
| 6 | Collection reader/writer/worker ownership | source-side matrix first, then name-level production view | database separation |
| 7 | Vercel ledger re-verification | read-only Vercel token | artifact→SHA proof |
| 8 | `.tok` blob in the reviewer repo | scoped credential-hygiene task | import safety |
| 9 | `rocket-p0/` 1.2 GB untracked origin | identify owner before any proposal | accurate split estimates |

## 8.4 Security-sensitive omissions

No connection string, password, token, API key, pepper or secret value appears anywhere in this pack. Only **names** of configuration keys, and the preview-only literal `DB_NAME=test_database`, are recorded. The GitHub read used an existing token whose value was never printed.

## 8.5 Standing verdicts

| Scope | Verdict |
|---|---|
| A0-01 production topology | **PARTIAL** — backend revision and Mongo identity UNKNOWN |
| A0-02 source ownership MRI | **PARTIAL** — 3 packages untraced, flags and symbol-level reverse deps open |
| A0-03 data ownership | **NOT STARTED** |
| Isolation directive position | **step 1, incomplete → HOLD** |
| Production deployment | **HOLD** |
| G3 candidate `d2f8b742` | independently approved; frozen; not deployed anywhere |
| G4 native validation | partially executed on the isolated lab; two-rule probe **not** executed |

## 8.6 What this pack deliberately does not claim

- That the checked-out source is what production runs.
- That a passing build or a green test suite proves functional equivalence.
- That queue depth zero proves lossless ingestion — cardinality must be reconciled by ID.
- That Vercel `READY` says anything about backend health.
- That any duplication found in the working tree is duplicated *engine logic* rather than duplicated *files*.
