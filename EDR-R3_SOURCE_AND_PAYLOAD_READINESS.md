# EDR-R3 — Source & Payload Readiness Report

- **Date:** 2026-10-31
- **Release candidate:** `release/edr-trajectory-2026-10-31` @ **`73e2bfea8d09b269792db92360b902a6b75f7b76`** (full SHA read from the GitHub branch API, not from chat)
- **Result:** **NOT READY — 2 hard blockers.** Backend source parity is *not* achieved, and the off-pod preservation destination cannot safely receive the archive.
- **Actions:** read-only inspection plus one 5 MB non-sensitive storage probe. No data deleted, no `/app` reset, no runtime file moved, no credential exported, no publish, no frontend deployment write.

---

## 0 · Correction to my earlier claim

I previously stated that `f22b74aa` "lacks the latest frontend application changes" and that validating one branch does not validate the other. **That was wrong, and I withdraw it.**

Verified independently here against non-truncated recursive trees: **the backend delta between staged `3bbc5c89` and release `73e2bfea` is ZERO across all 3,425 backend blobs** — `[A] backend delta: 0`, with `truncated=False` on both trees and `[C] in staged but not in release: 0`. This corroborates your finding that divergent ancestry is not divergent application behaviour, and that the preview head carries the on-demand Activity/Grid work.

I also accept and will not re-litigate: EDR and XDR are separate Vercel projects with scoped builds and **can be released separately**; source sharing does not force XDR promotion. My earlier "one bundle, so XDR must be republished" statement applied to the *artifact*, not the *project*, and was misleading as written.

---

## 1 · Staged backend vs release candidate

### 1.1 Branch-to-branch: clean

| Check | Result |
|---|---|
| Backend blobs, release vs staged | **3,425 = 3,425, zero differences** |
| Trees truncated | **No** (both) |
| Paths in staged but absent from release | **0** |

**The three files I staged earlier** — `routers/edr.py`, `v2/decoded_artifacts/__init__.py`, `v2/jobs/pipeline.py` — now match the release head exactly and do **not** appear in any difference list below.

### 1.2 Live `/app/backend` vs release: **10 differences — this is the blocker**

| | Count |
|---|---|
| Identical to release | **3,415** |
| **Differing** | **10** |
| Missing locally | 0 |

All ten report **`clean`** in `git status` — they are **committed local work**, not uncommitted edits. Local is consistently *larger* than release, i.e. `/app` holds code the release branch does not have:

| File | Release → local | Origin |
|---|---|---|
| `edr_trajectory/contracts.py` | 77 → **97** lines | local commits `f9fd38e5` / `0fb1ea41` (2026-10-29) |
| `edr_trajectory/identity.py` | 78 → **128** | same |
| `edr_trajectory/production_adapter.py` | 629 → **633** | same (plus `3ef4b3e6`, 2026-10-04) |
| `edr_trajectory/production_service.py` | 173 → **188** | same |
| `edr_trajectory/providers.py` | 217 → **281** | same |
| `edr_trajectory/v3_presentation.py` | 355 → **395** | same |
| `tests/edr/test_b5_gap1_pre_canary_acceptance.py` | — | pre-existing local |
| `tests/edr_trajectory/test_sd_raw_reference.py` | — | pre-existing local |
| `tests/reports/multilayer_battery.json` | — | pre-existing local artifact |
| `server.py` | 1,194 → **1,222** | mixed (§1.3) |

These are **newer unrelated workspace edits and have been preserved untouched.** Nothing was overwritten.

**Why this blocks release.** The backend builds from the `/app` working tree, **not** from a git ref. So:

- Publishing `/app` does **not** deploy `73e2bfea`'s backend — it deploys local `edr_trajectory/*` code that has **never existed on the release branch** and was never reviewed in this release.
- Conversely, making `/app` match the release branch would **regress six `edr_trajectory` files** by discarding the 2026-10-29 work.

There is no publish action that yields "the release candidate's backend" while preserving local work. Two divergent lineages exist because this workspace **has no git remote**: local holds 2026-10-29 work GitHub never received; GitHub holds 2026-10-30/31 work that only reached `/app` because I copied ten files in by hand.

**This needs a reconciliation decision — but not a branch choice by Janardhan.** The concrete question for you as release owner: should the local 2026-10-29 `edr_trajectory` work be pushed onto the release branch and re-reviewed, or is it superseded?

### 1.3 `server.py` — three additive differences, all publish-relevant

```
+ from transfer_bundle import transfer_router          # pre-existing local, not in release
+ api.include_router(transfer_router)
+ from routers.edr_maintenance import router ...       # pre-existing local, not in release
+ api.include_router(edr_maintenance_router)           # token-gated dev RESET router
+ if os.environ.get("ARCH_DOCS_SHARE") == "1":         # MINE, temporary
+     app.mount("/api/_arch", ...)                     #   documentation download
+     app.mount("/api/_pv/<capability>", ...)          #   preservation download
```

The release branch contains **none** of these (`release hits: 0`, `local hits: 9`).

`routers/edr_maintenance.py` is the router flagged in A0-03 as the **tenant-wide reset touching 13 non-EDR collections**. It is gated behind `EDR_MAINTENANCE_TOKEN` and 404s when unset, but publishing `/app` would place it in the production image. The two `_arch`/`_pv` mounts are mine and must come out before any publish.

### 1.4 Runtime config

`requirements.txt` and all other `backend/` config blobs are **identical** to release (they fall inside the 3,415 matches). `.env` is untracked and not part of either tree — see §4.2.

---

## 2 · Minimum real backend runtime payload, and the exclusion mechanism

### 2.1 Measured

| Scope | Size |
|---|---|
| **Current `/app` build context** (platform rule) | **2.95 GB** |
| `backend/` as-is | 122 MB |
| `backend/` minus `tests/` + `reports/` | **105 MB** |
| Largest inflator inside `backend/` | `backend/docs` **76 MB** |
| `apps/nivxray-xdr` source (Vercel-built, not needed by the backend runtime) | 13 MB |
| `frontend` source (Vercel-built, not needed by the backend runtime) | 31 MB |

A realistic backend runtime payload is **≈30 MB** (`backend/` minus `docs`, `tests`, `reports`, `downloads`, `workspace_recovery`) against the **2.95 GB** shipped today — roughly **1 %**.

### 2.2 Exclusion mechanism — platform evidence, not assumption

Per your instruction I did not assume ignore-file behaviour. The platform's own verified extraction of run `81342093`'s pulled source established:

- Rule is the **whole `/app` working tree verbatim, minus `node_modules` and `.git`**.
- **`.gitignore` is NOT honoured** — gitignored `dist/`, `pip-cache/` and `.vercel/` were present in the extracted context.
- **No `.dockerignore` or `.emergentignore` exists, and neither is consulted.**
- It is a **working-tree snapshot, not `git archive` of HEAD** → untracked and modified files **are** included.
- Measured context size **1.9 GB** at that run (my current measurement is 2.95 GB; the delta is unexplained and is recorded as such, not reconciled).
- `.git` count in the extracted context was **0**, so nested `.git` directories are excluded too. **This corrects my earlier claim** that `rocket-p0/src/.git` and its 22 `.tok`-touching commits would ship — they would **not**.

**Conclusion: the only supported exclusion mechanism is physically removing files from `/app`, or narrowing the image `Dockerfile`'s COPY scope.** No `/app` Dockerfile exists, so COPY scope is platform-template-controlled and remains **BLOCKED** to me. Adding ignore files would be theatre.

---

## 3 · Durable off-pod destination — probed, works, but **cannot safely receive the archive**

### 3.1 Destination established and proven

Emergent Managed Object Storage, probed end-to-end with **5 MB of non-sensitive random bytes**:

| Step | Result |
|---|---|
| `init` | **200**, session storage key acquired |
| `PUT` 5 MB | **200** — `size: 5242880`, ETag returned |
| `GET` round-trip | **200**, 5,242,880 bytes |
| **SHA-256 match** | **TRUE** |
| `list` by prefix | **200**, object visible with size/ETag/last-modified |
| `DELETE` | **405 — unsupported** |

It is genuinely off-pod and durable, access is private (storage-key only, **no presigned or public URLs**), and it survives pod loss — which is precisely the failure that destroyed the earlier archives.

### 3.2 BLOCKER — uploads are irreversible and the archive is secret-bearing

**`DELETE` returns 405: there is no delete API.** An upload is **permanent**.

The archive `ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-31.tar.gz` contains git history with **22 commits touching `.tok` credential-shaped blobs**. Uploading it would place credential material into storage **that can never be removed**, and the credential has **not been rotated**.

I therefore **did not upload it**, and I will not without explicit instruction. Per your directive this is named as the exact blocker rather than reported as cleanup complete.

Three ways out, in order of safety:
1. **Rotate the historical `.tok` credential first**, then upload the archive as-is. History stays complete and the exposed secret is already dead. *Recommended.*
2. Upload a **filtered copy** with the `.tok` blobs stripped, and keep the unfiltered original on-pod — but that abandons the "unique history preserved" guarantee the whole exercise exists to satisfy.
3. Deliver the archive to the owner by authenticated download and hold no cloud copy — durable only once it is actually downloaded, and currently it depends on my temporary `_pv` mount, which must itself be removed before publish.

### 3.3 Current preservation state

| | |
|---|---|
| Archive | `/app/_preservation/ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-31.tar.gz`, 153,418,171 bytes |
| SHA-256 | `f854f520…` (recorded in `SHA256SUMS.txt`, re-verified **OK**) |
| Restore-verified | **YES** — 27/27 refs, 787 loose + 35,992 packed objects exactly matching the original, unique commit `cd2b8b92` present, reflogs and `ORIG_HEAD` preserved, `fsck` clean, `HEAD` resolves |
| Source originals | **intact and untouched** at `/app/rocket-p0/src/.git` (158 MB) |
| Location risk | `/app` is the **only** persistent path. `/var` is actively wiped — proven twice this session, and it is why the original T1/T2 archives were lost |
| Disk | `/app` **92 % full, ~845 MB free** |

**Nothing has been moved or removed, and nothing will be until an off-pod copy is verified.**

---

## 4 · Clean payload plan

### 4.1 Removal set (proposal only — not executed)

Ordered by payload saved. **None of this is a runtime dependency of the backend.** Nothing here is deleted without an off-pod copy first (§3.2 gates the preservation archive specifically).

| Path | Size | Note |
|---|---|---|
| `.worktrees/` | ~937 MB | two duplicate source checkouts |
| `rocket-p0/` | ~753 MB | **contains the unique history — gated by §3.2** |
| `rocket-e2e/` | ~331 MB | includes a live local Mongo data directory |
| `memory/` | ~180 MB | **contains `test_credentials.md`** |
| `agents/` | ~165 MB | **contains `agents/nivxforge-linux/.state/` — a durable agent credential and ~170 MB of raw host telemetry** |
| `rocket-evidence/` | ~118 MB | 154 untracked evidence/log files |
| `_preservation/` | 153 MB | mine — removable **after** off-pod verification |
| `backend/docs/` | 76 MB | not required at runtime |
| 14 `*.bundle`, `*.patch`, `dist/`, `pip-cache/`, `.vercel/`, `NIVXRAY_XDR_SOURCE_EXPORT.html.gz`, a literal `C:\Program Files` entry | ~50 MB | build and export residue |
| `backend/tests/`, `backend/tests/reports/` | 16 MB | optional; keep if you want in-image tests |

Code changes required before publish, independent of size:
- **Remove the `_arch` and `_pv` mounts** from `backend/server.py` (mine).
- **Decide on `edr_maintenance_router`** — a tenant-wide reset router that the release branch does not include.
- **Decide on `transfer_bundle`** — likewise absent from release.

### 4.2 Secret injection — already correct, needs one removal

Production secrets are **injected by the platform as environment variables**, not read from shipped files: `MONGO_URL` is an Emergent-managed Atlas **system secret** resolved from the live environment, and production `DB_NAME` is `greeting-app-5782-test_database` while the shipped `backend/.env` says `test_database`. **The shipped file is already not the source of truth in production.**

So the correct posture is: **`backend/.env` should not ship at all.** It currently does, because the payload is the verbatim working tree. It cannot be excluded by an ignore file (§2.2) and it **must not be deleted** — the preview runtime reads it. **This is an unresolved tension I cannot fix from here:** no supported mechanism excludes a required-locally-but-must-not-ship file. Options are Dockerfile COPY narrowing (platform-controlled, BLOCKED) or a platform-side exclusion rule. Flagging rather than papering over.

Also currently shipping and equally unexcludable: `memory/test_credentials.md`, `agents/nivxforge-linux/.state/identity.json` (agent credential) and `outbox.jsonl` (raw host telemetry). Those **can** be relocated off `/app`, unlike `.env`.

### 4.3 Rollback mapping

| Layer | Rollback target | Mechanism |
|---|---|---|
| **Backend image** | `sha256:be6d97d5a1a44cdad0812ffbd528a7a63cf6c6bee4447c5f8e5f54223d080ac5` (run `81342093-…`, built 2026-10-30 09:22 UTC) | Manage Publishes → Overview → Rollback. Image-only, 2–3 min, no rebuild, last 3 deployments, free |
| **Backend source** | baseline `35d47cc9` copies at `/app/.rollback/pre-repair-35d47cc9/` — blobs `e5dab8b3416a`, `f62001fa9a4c`, `501719b0b388` | file-level restore |
| **Local-only `edr_trajectory` work** | **NO ROLLBACK POINT EXISTS OFF-POD** — commits `f9fd38e5`, `0fb1ea41`, `3ef4b3e6` exist only in this workspace | must be pushed before any destructive step |
| **EDR frontend** | production artifact `built_at 2026-10-28T16:15:44Z`, commit `35d47cc9`, branch `phase2/edr-production` | Vercel — **yours** |
| **Database** | **none** — image rollback does **not** restore data | this change set has no schema change or migration, so image rollback suffices *for it alone* |

---

## 5 · Backend regression scope for shared consumers

The backend is shared, so a backend release must cover **XDR and Workspace consumers**, not only EDR:

- **XDR** — `/api/xdr/*`, RBAC/audit routers, dashboard lenses, MITRE catalog, `services.session_context`.
- **Workspace** — `/api/investigation/*` (24 routes) and `/api/decode/*` (17 routes); **no `/api/workspace/*` exists** (it mounts `workspace_investigation_router` under `/api/investigation`).
- **Shared ingestion** — `v2.ingestion.canonical`, `v2.ingestion.telemetry_bridge`, `detection_content.xdr_pipeline`.
- EDR's own `edrApi.js` still makes **four runtime `/xdr/*` calls**.

Already verified non-regressive in preview: `presentation=combined` is the default, so any client that does not send the parameter is unaffected (HTTP 200, unchanged shape). **Not yet run:** a full XDR/Workspace regression pass against the candidate backend.

---

## 6 · Blockers

| # | Blocker | Severity |
|---|---|---|
| **B-1** | `/app/backend` differs from the release head in **10 committed files**, 6 of them newer local `edr_trajectory` work absent from GitHub. No publish yields the release candidate's backend while preserving local work | **HARD** |
| **B-2** | Off-pod storage has **no delete API** (405); the archive is secret-bearing and the `.tok` credential is unrotated, so upload would be a permanent, irreversible credential placement | **HARD** |
| B-3 | `backend/.env` must ship-exclude but cannot be deleted (preview needs it) and ignore files do not work. Needs platform-side exclusion or COPY narrowing | HIGH |
| B-4 | `memory/test_credentials.md`, agent credential and ~170 MB raw host telemetry currently enter the build context | HIGH |
| B-5 | `edr_maintenance_router` (tenant-wide reset) and `transfer_bundle` are in `/app` but not in the release branch — undecided | HIGH |
| B-6 | My `_arch` / `_pv` mounts remain in `server.py` and must be removed pre-publish | MEDIUM |
| B-7 | Local-only `edr_trajectory` commits have **no off-pod copy** | HIGH |
| B-8 | Image `Dockerfile` COPY scope unknown; cannot confirm which context files reach the final image | MEDIUM |
| B-9 | `/app` at 92 % (~845 MB free) constrains any staging that needs a second copy | MEDIUM |
| B-10 | XDR/Workspace backend regression pass not yet executed against the candidate | MEDIUM |

---

*Read-only. Production untouched. No frontend deployment write performed. Rollout remains on HOLD.*
