# F1 · LEGACY V2 DEPENDENCY REPAIR — **COMPLETE**

Branch `engineering/f1-v2-dependency` · worktree `/app/rocket-p0/f1`
From A3 `62a2c658f638f118920aad4853c3747eeda801ec` / tree `71a64740…`
Group 1 `04730d9` → Group 2 **`7c2bb3c` / tree `2c004924…`**
(Milestone head after F2/F3/F4: `d5bceb8` / tree `22e59d7b…`)

## Root cause — the contract was false, not the test

`tests/test_v2_isolation.py` enforced a "deletion-safety" contract: RC5 must
import with `backend/v2/` deleted, so any `v2` import had to sit in a
try/except. `server.py:708` wrapped the `v2.routers` include with a comment
saying exactly that.

Meanwhile `server.py` mounted four routers **unconditionally** — 
`auto_investigate` (321), `auto_investigate_jobs` (430), `decoded_artifacts`
(436), `report_writer` (440) — each importing `v2` at module scope. Deleting
the tree would have dropped four live surfaces at import time. **The
documented intent and the wiring disagreed**, and the gate was the only thing
saying so.

Inventory at entry: **27 unwrapped imports across 20 files**; `backend/v2`
was 197 files / 33,740 lines of *production* capability (ingestion, canonical
event model, semantic decoding, investigation, verdict, report).

## Decisions

| Component | Decision | Why |
|---|---|---|
| canonical telemetry, collection schema, PowerShell AST/recovery | **MOVE** to `backend/telemetry/*`, `backend/services/decoder/*` (group 1) | true leaves; dependency now points the correct way |
| old leaf paths | **KEEP as logic-free shims** | the legacy tree's own 30+ importers, many relative, are not worth rewriting |
| `v2.jobs`, `v2.report_writer`, `v2.decoded_artifacts`, `v2.investigation` + the rest | **PROMOTE THE WHOLE TREE** — `git mv backend/v2 backend/nivx_engine` | they are live, unconditionally-mounted features; migrating leaf-by-leaf relocates the same unwrapped import, and declaring them optional would have changed what the platform promises |
| `server.py` engine mount | **MODIFY** — unconditional | `except Exception` swallowed import AND `include_router` failures; a required dependency must fail fast, not silently un-mount |
| `test_v2_isolation` | **STRENGTHEN** | now asserts no `backend/v2` tree exists and no `v2.*` import anywhere — source *and* tests. Not suppressed, not skipped, not weakened |

Rejected: a `sys.modules` aliasing trick that would have made the shims
one-liners — it is the hidden import-path manipulation this work exists to
remove.

## Changes

260 files. The engine package, every import site, `server.py`, and
`telemetry/mitre_map.py` (a latent group-1 break: `telemetry/canonical.py`
kept `from .mitre_map import …` after the module moved out of `v2/ingestion`
— caught by diffing against the A3 baseline, not by the gates).

Four structural guards were anchored to the candidate checkout while here:
`test_phase4_wave1_{shadow,observation_infra}.py` and
`tests/canonical/{executor/test_executor_all,ssot/test_ssot_isolation}.py`
were reading `/app/backend`, i.e. validating the deployed pod.

## Verification

```
tests/test_v2_isolation.py                3 passed      (was 1 failed)
security (mandatory)                    118  0 fail      (was 108, 1 fail)
boundaries 136 · command 372 · decoder 147(+6s) · response 39 · tenant 104   0 fail
frontend  420 passed · vite build OK · tier-2  104 passed, 9 skipped
```

Method note: the 54 engine-touching suites were run and **diffed against the
A3 baseline** rather than read in isolation — 38 of those failures pre-exist
on A3. That diff is what surfaced the `mitre_map` break and the four
`/app`-reading guards. Final delta vs A3: **zero new failures.**

`ruff` clean on every new and edited file; `server.py` unchanged at 113
pre-existing findings.

## Staging

`deploy/stage1-staging` untouched; the frozen pin still verifies from
`/app/rocket-p0/src` (`Pinned source verified`). Unlike A1/A3 this candidate
**does** change the build context (255 backend non-test files), so
`prepare.py --verify-only` refuses it — as designed. Merging needs an
owner-approved re-pin and a fresh bundle; neither was performed.

## Rollback

`git revert 7c2bb3c 04730d9`, or `git reset --hard 62a2c658`. The rename is
history-preserving (`git mv`), so a revert restores `backend/v2` exactly.

**RELEASE STATUS: NO-GO** — see `ENGINEERING_REGISTER.md` for what remains.
