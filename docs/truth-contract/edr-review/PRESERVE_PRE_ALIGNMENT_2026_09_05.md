# PRESERVATION SNAPSHOT · POD state at 2026-09-05 (Steps 1–2 of Owner-Authorized Alignment)

## Purpose
This file marks the exact POD state that must be preserved as the rollback anchor **BEFORE any AG-file import (Step 3) is attempted**. Owner-authorized tag name: **`preserve-pre-alignment-2026-09-05`**.

## POD state at snapshot time

- Local branch: `feature/rc2`
- Local HEAD commit SHA (Emergent pod): `7fe9fcd8…` (short) — full 40-char SHA determined by the Save-to-Github push
- Truth Contract v1 (immutable) present at `docs/truth-contract/`:
  - `NIVXRAY_CURRENT_STATE_TRUTH.md`  SHA-256 `061fd851f954f84c22f3e30b486e8222eac64f81f4dad7855961ece6439403dc`
  - `NIVXRAY_CURRENT_STATE.json`      SHA-256 `295d1e7003e775b24c229f3fd87c586011e9ccc69872f07f6f6bc56bf2dcec32`
- Gate 0.5 review artifacts staged in `docs/truth-contract/edr-review/` (12 files) + `docs/truth-contract/edr-review/alignment/alignment_index.json`
- Gate 0.5 code additions on POD:
  - `backend/routers/truth_inventory.py` (new)
  - `backend/tests/edr/__init__.py`, `backend/tests/edr/test_cross_tenant.py` (new)
  - `backend/server.py` (+3 additive lines)

## What "Save to GitHub" WILL commit at this snapshot
- Everything in `docs/truth-contract/edr-review/` (10 review MDs + Master-reconciliation + branch-alignment + Truth v2 + Truth v3)
- `docs/truth-contract/edr-review/alignment/alignment_index.json` (D-1 machine-readable diff)
- Gate 0.5 backend code additions (already committed locally per `git log`)
- This file

## What "Save to GitHub" WILL NOT commit
- `/app/memory/**` (not in commit scope by platform policy)
- `/app/memory/ag_export/ag.zip` (master AG export — remains outside git per owner rule)

## Owner tag creation (post-push)
After Save-to-Github completes, use GitHub UI or a local clone to create the lightweight tag on the pushed commit:

```
git tag preserve-pre-alignment-2026-09-05 <FULL_40_CHAR_SHA>
git push origin preserve-pre-alignment-2026-09-05
```

## Do-not rules honoured
- ✅ AG master export unchanged (SHA `ba06f99d…aa1f`).
- ✅ Truth v1 SHAs preserved.
- ✅ No application source touched at this step.
- ✅ No AG files imported.
- ✅ No Phase 1 kicked off.
