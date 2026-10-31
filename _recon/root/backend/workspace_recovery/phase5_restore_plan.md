# Phase 5 · Minimal Restore Plan — for owner approval

**Evidence anchors (proven by runtime bisect):**
- Window A first-bad: `26099be990` (Jul 20 17:42 UTC) · last-good `8baa7aa467`
- Window B first-bad: `069bd23f77` (Jul 29 04:20 UTC) · last-good `194d6ca8e9`

Total behavioural-code-carrying files across both culprits: **9**.
Nothing else needs to move to reach 11/11 corpus PASS.

---

## Window B restore set (heals S01..S10 — 9 broken samples)

| File | Change in `069bd23f77` | Layer | Restore action |
|---|---|---|---|
| `backend/engine/orchestrator.py` | +62 lines | **Decode orchestration** | `git checkout 194d6ca -- backend/engine/orchestrator.py` |
| `backend/engine/models.py` | +1 line | Decoder schema | `git checkout 194d6ca -- backend/engine/models.py` |
| `backend/rc22_adapter.py` | +4 lines | **Decoder adapter** (blast-radius) | `git checkout 194d6ca -- backend/rc22_adapter.py` |
| `backend/v2/semantic/ps_semantic.py` | +7 lines | **PS semantic layer** | `git checkout 194d6ca -- backend/v2/semantic/ps_semantic.py` |
| `backend/v2/investigation/analyst_report/builder.py` | +14 lines | Intelligence Layer | **Do NOT restore** — decoder must not depend on Intelligence per Contract. If corpus fails after the four decoder-only restores, revisit. |
| `backend/v2/investigation/verdict/__init__.py` | +40 lines | Intelligence Layer | **Do NOT restore** for the same reason. |
| tests + fixtures + frontend + PRD | assorted | non-behavioural | skip |

Expected result after Window B restore set applied: **S01..S10 = 10/10 PASS**. S001 still FAIL (unrelated regression).

## Window A restore set (heals S001)

`26099be990` (Jul 20 17:42) introduced two brand-new decoder files that unconditionally fire on any `powershell.exe …` input and terminate the chain before `utf16le-decode` can run:

| File | Change in `26099be990` | Layer | Restore action |
|---|---|---|---|
| `backend/decoders/ps_alias_normalizer.py` | **NEW** (+298) | Normalization | **Do NOT delete** wholesale — S02, S04, S10 currently rely on it not misfiring; but its "no known aliases found" early-termination on `-encod` inputs must be gated. Two options: (a) `git checkout 8baa7aa -- backend/routers/ops.py` to restore the pre-26099be routing order that ran extract→base64→utf16le BEFORE ps-alias-normalize; (b) surgically patch `ps_alias_normalizer.py` to no-op when the current chain still has un-decoded base64. Prefer (a). |
| `backend/decoders/ps_backtick_normalizer.py` | **NEW** (+225) | Normalization | Same reasoning — gate, don't delete. |
| `backend/routers/ops.py` | +94 lines | **Decoder ordering** | `git checkout 8baa7aa -- backend/routers/ops.py` **then re-apply only the post-26099be improvements that added S05/S09 support (gzip in the chain)**. This is the delicate step. Requires a hand-selected 3-way merge. |
| `backend/magic_decoder.py` | +12 lines | Decoder selection | Same as routers/ops.py — hand-merge. |
| `backend/server.py` | +2 lines | Route registration | Skip if the 2 lines are just `include_router(...)`; else selective revert. |

Expected result after Window A restore set applied: **S001 = ✅ PASS**, S02/S04/S10 still ✅, S01/S03/S05/S07/S08/S09 unchanged from Window-B-restored state → **11/11 PASS**.

---

## Execution order (per owner rule: decoder-correctness first)

1. **Step 5.1 — Apply Window B restore set** (4 files, decoder-only).
2. **Step 5.2 — Run corpus.** Expect S01..S10 = 10/10, S001 = FAIL.
3. **Step 5.3 — Apply Window A restore set** (surgical routers/ops.py + magic_decoder.py restore, keeping post-26099be gzip additions).
4. **Step 5.4 — Run corpus.** Expect 11/11.
5. **Step 5.5 — Emit** `/app/backend/workspace_recovery/phase5_restore_report.md` with per-step corpus results.
6. **Step 5.6 — Freeze.** Add the Decoder Recovery Lock rule (below) to PRD.md.

## Decoder Recovery Lock (permanent rule to be added post 11/11)

> Once the Workspace Decode Pipeline reaches 11/11 on `workspace_recovery/corpus.json` (or its successor `workspace_regression_corpus/`), the Decode Pipeline is FROZEN. No PR that changes any file in the restore set may merge unless it produces 100% PASS on the full corpus in CI. Downstream layers (Intelligence · Timeline · Reports · AI · OSINT) can continue evolving, but must not import from or influence the Decode Pipeline.

---

## What Phase 5 is NOT

- Not a UI restore.
- Not a Timeline restore.
- Not an Investigation restore.
- Not a Reports restore.
- Not an X-Lab restore.
- Not a Lab 2.0 restore.
- Not the isolation split — that is Phase 6, gated on 11/11.
- Not the deployment — that is Phase 7 after the Isolation Certificate.

---

## Ready-to-execute commands (for reference only — nothing has run yet)

```bash
# --- Step 5.1 · Window B restore ---
cd /app
git checkout 194d6ca8e9 -- \
    backend/engine/orchestrator.py \
    backend/engine/models.py \
    backend/rc22_adapter.py \
    backend/v2/semantic/ps_semantic.py

# --- Step 5.2 · verify ---
sudo supervisorctl restart backend
cd /app/backend && python -m workspace_recovery.runner
# expected: S01..S10 all "identical: true"; S001 still FAIL

# --- Step 5.3 · Window A restore (delicate, needs review before running) ---
# We do NOT do a wholesale `git checkout 8baa7aa -- backend/routers/ops.py`
# because that would drop the gzip/S05/S09 support added afterwards.
# Instead we selectively revert the `26099be` hunk that changed the
# ordering to fire ps-alias-normalize before utf16le-decode.

# --- Step 5.4 · verify ---
sudo supervisorctl restart backend
python -m workspace_recovery.runner
# expected: 11/11 identical: true
```

## Rollback plan (in case any step regresses)

Everything is version-controlled. The full rollback is:

```bash
git checkout HEAD~1 -- backend/engine/orchestrator.py backend/engine/models.py \
                        backend/rc22_adapter.py backend/v2/semantic/ps_semantic.py \
                        backend/routers/ops.py backend/magic_decoder.py
sudo supervisorctl restart backend
```

The corpus runner is deterministic; comparing `artifacts/current_raw.json` before and after any restore step gives the definitive PASS/FAIL delta.
