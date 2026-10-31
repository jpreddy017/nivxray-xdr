# EDR-R1 — Trajectory Repair: Staging, Validation and Rollout Readiness

- **Date:** 2026-10-31
- **Candidate:** `jpreddy017/nivxray-xdr` @ `3bbc5c89b6c5de2f4339778868e082501c47d052` (branch `repair/edr-trajectory-navigation-2026-10-31`)
- **Baseline:** `35d47cc96352f492bd4c603a2f2f1b65afb4119f`
- **Result:** **STAGED AND VALIDATED IN PREVIEW — NOT DEPLOYED.** Rollout awaits explicit go/no-go.
- **Production state:** unchanged. No publish, redeploy, restart, index change, resource change, timeout change or database mutation.

---

## 1 · Management URL and route

| | |
|---|---|
| Emergent runtime URL (production backend) | `https://greeting-app-5782.emergent.host` |
| Custom domain in front of it | `https://nivxray.nivxforge.com` |
| Preview runtime (separate, local Mongo) | `https://greeting-app-5782.preview.emergentagent.com` |
| Manage Publishes route | **Publish / Republish button → Manage Publishes** → tabs *Overview · Domain · Resources · Database · Secrets* (web app only) |
| Logs | *Overview → View Logs* per deployment version |
| Database viewer | *Database → Go to database* (`mongoview.emergent.host`, in-platform only) |
| `deployment_id` | `96834a37-643a-4d79-aa15-44810db52b06` |
| `job_id` | `486146a0-9a5d-462a-8072-904d27d6c533` |

There is **no console, shell or SSH** to a production pod. Access is the Manage Publishes panel only.

### 1.1 Domain → deployment mapping: VERIFIED by replica fingerprint

Identical health bodies were correctly rejected as insufficient. The mapping was instead proven by **replica fingerprinting**: `/api/health/deep` reports per-pod ephemeral disk, and across 8 samples each host returned **the same two distinct values** — `74,605 MB` and `94,471 MB` — interleaved.

Two separate deployments would each expose their own disjoint value set. The same two-value set on both hostnames establishes a **shared 2-replica backing pool**, i.e. one runtime behind both names.

`greeting-app-5782.preview.emergentagent.com` returns the same health JSON but is the **preview** runtime on local Mongo — not production.

---

## 2 · Source comparison against the serving image

### 2.1 Workspace ↔ production baseline

The serving image records no commit (zip build from `/app`, no VCS metadata), so comparison was done on **content**, not provenance. All **9** files the candidate touches were byte-compared between `/app` and baseline `35d47cc9`:

| File | /app vs baseline `35d47cc9` |
|---|---|
| `backend/routers/edr.py` | **IDENTICAL** |
| `backend/v2/decoded_artifacts/__init__.py` | **IDENTICAL** |
| `backend/v2/jobs/pipeline.py` | **IDENTICAL** |
| `…/nivxforge/NivXForgeConsole.jsx` | **IDENTICAL** |
| `…/nivxforge/device/EdrDevicePage.jsx` | **IDENTICAL** |
| `…/nivxforge/pages/EdrEventsPage.jsx` | **IDENTICAL** |
| `…/nivxforge/pages/EdrTrajectoryResolver.jsx` | **IDENTICAL** |
| `…/trajectory_v3/DeviceTrajectoryPage.jsx` | **IDENTICAL** |
| `…/trajectory_v3/amp/TrajectoryPage.jsx` | **IDENTICAL** |

**No newer or unrelated workspace change existed on any touched file**, so the apply was additive and nothing was reset. `/app` was **not** reset; 162 unrelated dirty paths elsewhere in the workspace were left untouched.

### 2.2 Candidate integrity

Each staged file was verified against the frozen commit's **Git tree blob SHA** (not a transport checksum) before being written:

```
26293efe8b28  backend/routers/edr.py
e41c75a5b7f3  backend/v2/decoded_artifacts/__init__.py
a0b2f0030b33  backend/v2/jobs/pipeline.py
d87c6dfe29b8  apps/.../NivXForgeConsole.jsx
b7ec5f871089  apps/.../device/EdrDevicePage.jsx
c29ba48954c9  apps/.../pages/EdrEventsPage.jsx
134061f5303b  apps/.../pages/EdrTrajectoryResolver.jsx
285a8812e335  apps/.../trajectory_v3/DeviceTrajectoryPage.jsx
57c7dddf987c  apps/.../trajectory_v3/amp/TrajectoryPage.jsx
214e3dec5d7b  apps/.../trajectoryTarget.mjs        (new)
ALL_MATCH = True
```

### 2.3 Backend repair shape

Only **3** backend files change. **`edr_plane/trajectory_window.py` is not modified** — the repair does not optimise the legacy projection, it **stops calling it** when the client asks for the paged contract:

- new query parameter `presentation` ∈ `{combined, v3}`, default `combined` (back-compatible); anything else → **422**.
- `presentation=v3` skips `tw.query_window` entirely and serves the paged E3 contract.
- Aggregate header fields become explicit `null` with `projection.state = V3_PAGED_ONLY`, `aggregates = NOT_REQUESTED` — **never zero**. Endpoint and customer scoping (`res.refs`, `res.predicate`) are unchanged and still applied before any read.

---

## 3 · Validation results (preview, populated tenant-scoped data)

Measured against `ep_2d57cbe6f80152062109` — **360,442 events**, i.e. *larger* than the production endpoint in the original report (`ep_a67be48d5b4e01d4d9e8`, which holds 0 events in preview).

| Gate | Check | Result |
|---|---|---|
| G1 | `presentation=v3` populated read | **PASS** — HTTP 200 |
| G2 | `presentation=combined` regression, small endpoint | **PASS** — HTTP 200, 2.62 s, unchanged shape |
| G3 | invalid `presentation` value | **PASS** — HTTP 422 `unsupported trajectory presentation` |
| G4 | unknown endpoint: unavailable ≠ empty | **PASS** — `ENDPOINT_NOT_RESOLVED` + epistemic note; no fabricated empty result |
| G5 | tenant scoping on the new v3 path | **PASS** — HTTP 403, scoping not bypassed |
| G6 | E3 pagination parity | **PASS** — page 1 and 2 both 200 items, **0 overlap**, both `PAGE_READY`, 1.29 s |
| G7 | detection join integrity | **PASS** — `joined=0 / findings_considered=500`, basis `EXACT_EVIDENCE_REFERENCE_MATCH (no timestamp proximity)`; absence not reported as benign |
| G8 | candidate's own test suites | **PASS** — 19 Python (4 presentation + 6 persistence + 9 artifact-write-ack) and 5 JS component tests |
| G9 | Vercel production build | **PASS** — `vite build` exit 0, 4.93 s |

The 4 `.cjs` component tests initially failed with `Invalid hook call`. Cause was a **duplicate React in the ad-hoc test harness**, not a candidate defect; with a single React resolution all pass. `react-test-renderer` was installed **outside `/app`** so no `package.json` or lockfile was modified.

---

## 4 · Before / after timings

Same endpoint, same 31-day window, same parameters.

| | HTTP | resolve | projection | tail | total |
|---|---|---|---|---|---|
| **Before** (`combined`, via gateway) | **504** | — | — | — | **30.15 s** (cut off) |
| **Before** (`combined`, direct, no gateway) | **504** | — | — | — | **30.17 s** (app middleware) |
| **After** (`v3`, cold, first call post-restart) | **200** | 15.19 s | **0.00 s** | 13.08 s | **28.27 s** |
| **After** (`v3`, second call) | **200** | 7.26 s | **0.00 s** | 6.17 s | **13.43 s** |
| **After** (`v3`, warm) | **200** | 0.60 s | **0.00 s** | 2.19 s | **2.79 s** |
| **After** (`v3`, warm) | **200** | 0.59 s | **0.00 s** | 0.62 s | **1.21 s** |
| **After** (`v3`, warm) | **200** | 0.59 s | **0.00 s** | 0.63 s | **1.22 s** |
| **After** (`v3`, page 2 via cursor) | **200** | — | — | — | **1.29 s** |

- **Warm steady state: 504 at 30 s → 200 at ~1.2 s.**
- `projection` is **eliminated** (0.00 s) — the legacy whole-history materialisation no longer runs.
- Evidence is **not truncated**: 200 items per page under the declared `e3.dt.event.v1` / `e3.dt.prod_cursor.v2` contract, with working forward paging.
- No timeout was raised, no index created, no resource increased.

The app's own 30 s cap in `request_hardening.py` (`asyncio.wait_for(call_next(...))`, `504 server_timeout`) was **left exactly as it is**.

---

## 5 · Deployment plan and rollback reference

### 5.1 Rollback reference

| Asset | Reference |
|---|---|
| **Current production image (roll back to this)** | `sha256:be6d97d5a1a44cdad0812ffbd528a7a63cf6c6bee4447c5f8e5f54223d080ac5` |
| Current run ID | `81342093-10f6-4291-9643-46c538a41d57` |
| Build | Cloud Build `4159f71a-…`, promoted 2026-10-30 09:36 UTC |
| Rollback mechanism | Manage Publishes → Overview → Rollback. Image-only, 2–3 min, no rebuild, last 3 successful deployments, free |
| Baseline source for file-level revert | `/app/.rollback/pre-repair-35d47cc9/` — blobs `e5dab8b3416a`, `f62001fa9a4c`, `501719b0b388` |

**Rollback restores the image only. It does not restore the database.** These repairs introduce no schema change, no migration and no backfill, so an image rollback is sufficient for this change set — but that property does not extend to any other pending work.

### 5.2 Ordered plan

1. Backend first. Publish from this workspace (Redeploy — preserves URL, database, domain, tier and secrets). Record the resulting image digest and run ID.
2. Verify on `greeting-app-5782.emergent.host` **before** touching the frontend: `/api/health`, then `presentation=v3` and `presentation=combined` against a real production endpoint, capturing the `[trajectory]` timing line for each.
3. Confirm `presentation=combined` still answers for existing callers — the parameter defaults to `combined`, so any client that does not send it is unaffected.
4. Only then publish the frontend to `edr.nivxforge.com` from `jpreddy017/nivxray-xdr` @ `3bbc5c89`, root directory `apps/nivxray-xdr`.
5. Re-measure and compare against §4.

**A frontend-only publish cannot deliver these repairs** — `presentation=v3` does not exist until the backend ships, and the UI requesting it would receive the legacy 30 s path.

---

## 6 · Blockers and open risks

**B-1 · Cold-start margin at production scale (HIGH).** Warm reads are ~1.2 s, but the first read after a restart measured **28.27 s against a 30 s cap** on a 360k-event endpoint. The production endpoint holds **2.22 M events**. Cost has moved out of `projection` into `resolve` (15.19 s cold) and `tail` (13.08 s cold). **It is not proven that a cold production read stays under 30 s.** Neither the candidate nor this validation addresses cold-path cost.

**B-2 · T1/T2 preservation archives are GONE (HIGH).** `/var/backups/nivx-preservation/` no longer exists: the Git bundle, the full `.git` tar and the ZIP are all absent. The machine has not rebooted (uptime 9 days), so they were removed by cleanup, not a restart — `/tmp` staging files vanished the same way during this session. The **source is still intact** at `/app/rocket-p0/src/.git` (158 MB), so the history is recoverable, but **the preservation work must be redone and moved off-pod.** This is exactly the custody risk previously flagged and deferred. `/app` is at **90 % (998 MB free)**.

**B-3 · Independent EDR copy unverifiable (MEDIUM).** `nivxforgeedr/nivxforge-edr` returns **404** both unauthenticated and with the workspace token. Commit `21e58614a1f4600d538c5bd11fd4fff8e0d4c595` could not be confirmed to exist, and the independent copy was **not** compared against `3bbc5c89`.

**B-4 · Preview cannot validate the frontend repairs (MEDIUM).** `frontend/src/nivxforge` (preview) does **not contain** the touched files; the deployed EDR console lives only in `apps/nivxray-xdr`. The frontend repairs are therefore evidenced by component tests and a successful production build, **not** by an end-to-end preview render.

**B-5 · Production-scale behaviour unmeasured (MEDIUM).** All timings are from preview against preview data. No measurement was taken against the production database.

**B-6 · Still outstanding from P0-02C.** Database-specific snapshot inventory, PITR state, restore owner and RTO/RPO remain **BLOCKED** (support-only). The deployed backend commit remains structurally unrecorded.

---

## 7 · Corrections accepted

- **`_warm_complete` does use `asyncio.to_thread`.** Verified in this workspace: the coroutine is scheduled with `create_task`, but the heavy work runs via `await asyncio.to_thread(_project_all_sync, …)`. My earlier claim that background warming blocks the event loop is **withdrawn**. The blocking path was the **request** path — `await _projected(...)` inline when `complete=True` — which iterates the full cursor on the loop with only `await asyncio.sleep(0)` yields every 500 documents.
- **VPA-eviction causality is treated as UNVERIFIED.** No pod events were inspected and none are claimed. It is recorded as a reported observation only.
- `"build_id": "1ecec01"` remains static repository text and is not the deployed revision.

---

*Staged and validated. Not deployed. Awaiting go/no-go.*
