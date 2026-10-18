# GitHub publication assessment — N-3A and its dependency stack (READ-ONLY)

Nothing was pushed, merged, deployed, re-pinned or modified. All analysis ran
in a disposable clone at `/app/rocket-evidence/pub/gh`; every validated
worktree is still at its approved commit. **RELEASE STATUS: NO-GO.**

---

## 1 · Closest published source baseline

| | branch | commit | tree | date |
|---|---|---|---|---|
| **Recommended base** | `engineering/stage1-staging-package` | `ce8732ba9c7d0deb1d02825855bfe644550be07b` | `aff5f8e1dd267367e9e1b90461f6050c72c655e5` | 2026-10-13 |
| Alternative | `main` | `752a00ffefee679ba5f8b9c3742dd2df74d5f074` | `e97f9c06fbb524e8af6b62830c1f5ceb388cd848` | 2026-08-31 |

`engineering/stage1-staging-package` is the newest of the 40 published refs and
a strict superset of `engineering/stage1-command-readiness` (its parent, +1
commit). Selected on *backend* proximity to our baseline, which is what the
validated commits touch:

| published ref | differing files under `backend/` vs local `1158afc` |
|---|---|
| **`engineering/stage1-staging-package`** | **993** (A 437 · D 291 · M 265) |
| `engineering/stage1-command-readiness` | 993 — identical set |
| `engineering/monorepo-product-boundaries` | 1063 |
| `main` / `feature/unified-xdr-edr-platform-blueprint` | 1663 |

It is also the only published ref carrying `deploy/stage1-staging/` (15 files)
and `backend/tests/_verified_session.py`, both of which our stack assumes.

## 2 · Source-tree divergence

**The histories are unrelated and that is structural, not accidental.**
`git merge-base` between any local branch and any published ref returns
nothing. The local repository is rooted at a single commit,
`b1240bba "Sanitized history-free Rocket repair snapshot"`, with **24 commits**
on top of it up to N-3A. The published repository never received that snapshot,
and the remote rejects our baselines by SHA (`upload-pack: not our ref` for
both `1158afcc…` and the A3 baseline `62a2c658…`).

Whole-tree comparison, published vs the sanitized root:

| vs published `main` | vs published `stage1-staging-package` |
|---|---|
| 3,798 files differ (A 1,916 · D 1,552 · M 332) | 7,397 files differ |

`main` looks "closer" only because the newer branches restructured into
`apps/`; backend-scoped (§1) the stage1 tip is nearly half the distance. The
1,552 "deletions" against `main` are the sanitized snapshot's deliberate
omissions — `evidence/` (954), `memory/` (321), `test_reports/` (152) — not
lost product code.

Scoped to what actually needs transferring, the picture is much better. Net
diff **A3 baseline → N-3A** = **350 files**:

| | files |
|---|---|
| already byte-identical on the published tip | 110 |
| absent on the published tip (new to publication) | 225 |
| **diverged on the published tip** | **15** |

Those 15 are the entire conflict surface:

```
.gitignore                                        backend/server.py
backend/edr_plane/canonical_bridge.py             backend/services/tenant_registry.py
backend/edr_plane/windows_eventlog.py             backend/tests/edr/test_phase0_windows_canonical_bridge.py
backend/finetune/export_dataset.py                backend/tests/real_world_stress_suite.py
backend/routers/benchmark.py                      backend/tests/test_b4b5_tenant_registry_authority.py
backend/routers/xdr_ingest.py                     backend/tests/test_collector_plane_auth.py
backend/routers/xdr_rbac.py                       backend/tests/test_investigation_quality.py
                                                  backend/tests/test_v2_framework.py
```

Direction matters: across those 15 the published side is **+71 / −714** lines
relative to our base — i.e. our base is ahead almost everywhere. The one
substantive published-only block is 39 lines in
`backend/services/tenant_registry.py`: the `NIVX_TENANT_REGISTRY_ENFORCE`
flag whose **default is observational, preserving the historical `"default"`
tenant fallback**. Local commit `80eb83c4` deliberately retired that flag.
Dropping it is the intended security improvement, not a regression — but it is
the single item an owner must consciously accept.

**F1's namespace retirement is import-complete against the published tree
too.** The published tip still has `backend/v2/` (197 files, a subset of our
A3 base — zero orphan paths) and 140 files that import `v2.*`. Of those, 139
are inside `backend/v2/` itself (deleted by the transfer); the only outside
reference is `backend/docs/assets/NIVXRAY_XDR_SOURCE_EXPORT.html`, a generated
source-export asset already published, which merely contains the text.

## 3 · Transferability — measured, not estimated

Each validated commit was cherry-picked **independently** onto the published
tip in a disposable worktree, conflicts counted, then reverted:

| stage | commit | files | conflicts | blocking reason |
|---|---|---|---|---|
| A1 harness | `0ee630f5` | 5 | **0** | — |
| A1 docs | `3db07b18` | 1 | **0** | — |
| A3 gate | `62a2c658` | 2 | 2 | `tools/rocket-validation/run.py` absent upstream |
| F1 g1 | `04730d9d` | 21 | 8 | published copies of 5 leaves diverge/absent |
| F1 g2 | `7c2bb3c5` | 498 | 11 | `server.py`, EDR tests, 7 `v2` leaves |
| S1+F2+F3(part) | `80eb83c4` | 9 | 2 | `tenant_registry.py`, `xdr_rbac.py` |
| F4 | `7c9fc84a` | 6 | 4 | needs A1's harness first |
| F3 | `d5bceb80` | 21 | 4 | needs the two tool files first |
| N-1 | `e2c96f2e` | 6 | 3 | needs F1's rename first |
| N-1 CI | `09a8c2e8` | 1 | 1 | needs A3's runner |
| N-5 | `113ebfb8` | 1 | 1 | needs S1/F2 |
| N-5 CI | `1158afcc` | 1 | 1 | needs A3's runner |
| **N-3A** | **`38e294c6`** | **2** | **0** | — |

Most "conflicts" are ordering artefacts: a commit that edits a file an earlier
unpublished commit created. The two that are **not** ordering artefacts:

* `tools/rocket-validation/run.py` exists only in the unpublished sanitized
  root (`b1240bba`, blob `3dcb3d9f`, later `d46bc4d6`). Every gate-wiring
  commit (A3, N-1 CI, N-5 CI) edits it, so publishing any gate claim needs
  that file carried in as a new file first. The published tip has 3 files
  under `tools/`; our baseline has 26.
* The 15 diverged files of §2, which need their predecessor state published
  before the F1/N-1/N-5 hunks apply.

**N-3A itself is free of both.** `backend/routers/telemetry.py` is blob
`036d87fdd104` on the published tip, on `main`, on the blueprint branch **and**
on our pre-fix baseline — the file never diverged, so the fix lands exactly as
reviewed.

### Trial: the minimal series on the published base

Applied, committed and **executed** in a throwaway worktree (tagged
`trial/n3a-on-published`, `a21da8a8`, tree `5cef61aa`, never pushed):

```
A1: make the security suites runnable without weakening them   → clean
A1: harness documentation                                      → clean
N-3A: normalise BSON in the telemetry recent response          → clean

8 files changed, 762 insertions(+), 16 deletions(-)
  backend/routers/telemetry.py                      | 68 ++-
  backend/tests/test_n3a_telemetry_bson_serialization.py | 223 +
  backend/tests/_verified_session.py                | 66 +
  backend/tests/test_collector_api_key_auth.py      |  9 +
  backend/tests/test_p0prod1_secret_policy.py       | 24 +-
  backend/tests/test_xdr_webhooks.py                | 15 +-
  tools/security-harness/README.md                  | 66 +
  tools/security-harness/run.py                     | 307 +

python3 tools/security-harness/run.py --suite tests/test_n3a_telemetry_bson_serialization.py
→ 14 passed, 25 warnings in 17.63s
```

The repaired endpoint and its 14 regression tests therefore **pass on
published code**, not only on the local stack.

## 4 · Secrets, generated files, unrelated changes

Scanned the added lines of both candidate transfers (minimal 8-file series and
the full 350-file net diff) for private-key blocks, AWS key ids, GitHub PATs,
OpenAI keys, Slack tokens, JWTs, credential-bearing Mongo URIs, `*.env` files
and quoted `password|secret|api_key|token` assignments. **All counts zero.**
No value is printed in this report and none was found to print.

* Test-only placeholders (`os.environ.setdefault("XDR_AUDIT_MASTER_SECRET",
  "test-master")`) are literal fixtures, not credentials; the harness itself
  generates every real secret per run with `secrets.token_urlsafe(48)`.
* `deploy/stage1-staging/*.env.example` are templates with no values, and are
  not in the minimal series.
* **Generated artefacts** — the net A3→N-3A diff carries exactly one:
  `backend/services/uaie/retirement/v2.investigation…json`, which is audit
  evidence and the subject of N-1 (renamed, not rewritten). Two more appear in
  *intermediate* commits and net out: `backend/tests/reports/phase2_batch2_perf.json`
  (added by F1 g2, removed by N-1) and `backend/xdr_state/outbox.db` (a binary
  SQLite runtime-state file added by F4, removed by F3 — **already tracked on
  the published tip**, so the transfer's net effect is to stop publishing it).
  A commit-by-commit replay publishes both into permanent history; a squash
  would not. Flagged for the owner's choice, not decided here.
* **Unrelated changes**: the minimal series is strictly the repair plus the
  test preconditions it needs. The 11 pre-F1 commits (P1–P5, Stage 2B.x) are
  *not* proposed for transfer; `deploy/stage1-staging/` is untouched in the
  recommendation.

## 5 · Proposed branch structure

```
origin/engineering/stage1-staging-package  (ce8732ba — published, unchanged)
└── publish/n3a-telemetry-bson             ← NEW, 3 commits, 8 files
      3ce3f81e  A1: make the security suites runnable without weakening them
      91ac295b  A1: harness documentation
      a21da8a8  N-3A: normalise BSON in the telemetry recent response
```

Later, and only on separate approval, the remainder stacks beneath it in
dependency order — each its own reviewable branch and PR:

```
publish/a3-security-gate        (needs tools/rocket-validation/run.py carried in)
  └── publish/f1-v2-dependency  (~540 files; 15 diverged files to reconcile)
        └── publish/n1-audit-provenance
              └── publish/n5-tenant-authority
                    └── (N-3A rebased on top, if a single lineage is wanted)
```

## 6 · Three strategies

| | scope | conflicts | reviewable? | risk |
|---|---|---|---|---|
| **S1 · Minimal (recommended)** | A1 + N-3A, 3 commits, 8 files | **0** | yes — 284-line fix + 478-line test harness | lowest; publishes a verified fix with its verification |
| S2 · Full validated stack | A1→A3→F1→N-1→N-5→N-3A, 14 commits, ~560 files | ~37 across 15 real files + 1 missing carrier file | partly — F1 g2 alone is 498 files | medium; needs the tenant-registry flag decision and per-file reconciliation |
| S3 · Snapshot import | publish `b1240bba` as one import commit, then replay all 24 | 0 | **no** — the import is 3,798 files against `main` | highest; an unreviewable commit enters permanent history |

## 7 · Recommendation (for owner approval — not executed)

**Adopt S1.** Create `publish/n3a-telemetry-bson` from the published
`engineering/stage1-staging-package` (`ce8732ba`) carrying the two A1 harness
commits and the N-3A commit, and open the PR against that branch — the base
the owner named (`engineering/n5-ci-gate`) is not published and cannot be a
base. Rationale:

* It is the only option with **zero conflicts**, measured, and with the tests
  **passing on the published base** (§3).
* **Nothing required is lost.** N-3A does not depend on F1, N-1 or N-5: the
  proof is that it cherry-picks cleanly onto a tree that still contains
  `backend/v2/`. The A1 harness is included because without it the published
  repository cannot *run* the 14 tests — publishing a fix nobody can verify is
  the failure mode to avoid.
* F1, N-1, N-5 and the gate wiring stay exactly where they are, locally and
  validated, for a subsequent decision. S2 remains available afterwards; S1
  does not foreclose it (N-3A would be rebased or dropped as a duplicate).
* The 15-file reconciliation and the `tenant_registry` flag retirement are
  real decisions that deserve their own review, not a rider on a 2-file fix.

## 8 · Verification required before and after publication

1. Re-confirm `38e294c6` / tree `a7ff378c` and a clean `/app/rocket-p0/n3a`.
2. On the transfer branch: `tools/security-harness/run.py --suite tests/test_n3a_telemetry_bson_serialization.py` → expect **14 passed** (observed: 17.63s on the published base).
3. Confirm `backend/routers/telemetry.py` parent blob is still `036d87fdd104` on the base at push time (the base branch may move).
4. Confirm the diff is exactly 8 files / +762 / −16 and contains no `.env`, no binary, no generated artefact.
5. The mandatory security gate (126 tests) **cannot** be claimed on this branch: `tools/rocket-validation/run.py` is not published. The gate result stands as local evidence for `38e294c6` only, and the PR must say so rather than implying CI coverage upstream.
6. Push and PR creation still need **write credentials** — `/root/.git-credentials` is empty, no `GH_TOKEN`, no `gh` CLI, no remote on the working repo. Use "Save to Github"; I cannot and did not attempt it.

## 9 · Preservation

* Validated worktrees unchanged and clean: `n3a` `38e294c6`, `n5gate` `1158afc`,
  `n5` `113ebfb8`, `n1gate` `09a8c2e8`, `n1` `e2c96f2e`, `f1` `d5bceb80`,
  `src` `cd2b8b92`.
* **Pre-existing** (not from this assessment): the `a3` worktree is dirty —
  `backend/services/uaie/retirement/v2.…json` modified and an untracked
  `backend/tests/reports/` — residue of the historical N-1 reproduction. The
  commit `62a2c658` itself is intact. Left untouched.
* Frozen staging package untouched; `deploy/stage1-staging/` is not in the
  recommended transfer.
* Trial commits exist only in the disposable analysis clone
  (`/app/rocket-evidence/pub/gh`, tag `trial/n3a-on-published`) and were never
  pushed. The trial worktree has been removed.
* Evidence: `/app/rocket-evidence/pub/` — `transfer_matrix.json`,
  `minimal_series.patch`, `trial-published-base.log`.
