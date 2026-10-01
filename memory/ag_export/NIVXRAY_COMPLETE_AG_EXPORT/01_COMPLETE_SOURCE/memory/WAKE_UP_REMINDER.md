# NivXRay · Wake-Up Reminder · 2026-02-08

**User will ping "Hi" in the morning — resume from here.**

---

## Where we stopped

Production deployment triggered from the preview environment.
All code changes for this session are complete.  Contract for
the next implementation sprint is FINAL.

## Deployment verification checklist (run first thing)

Once the user says "Hi", confirm the deployment has settled by
checking these:

| # | Check | Expected |
|---|-------|----------|
| 1 | Existing Workspace analyse-URL / paste / file | Byte-identical to pre-deploy |
| 2 | Retry the previously "Failed" Securelist case | Completes cleanly · no 30 s timeout |
| 3 | Octlurk trajectory                            | Still ~4 mappings (VEEE flag OFF · correct) |
| 4 | Backend + frontend logs                       | No OCR-related noise · no new 5xx |

If ALL green → open the contract and start P0.15C-1.
If ANY red   → ask user whether they see the issue on
                **preview** (fix directly) or on
                **production** (fix code · they'll redeploy).

## Next implementation task

**File to open first:** `docs/P0.15C-RELEASE-CONTRACT.md`
**Read first:** §−1 Standing Instruction
**Then execute:** P0.15C-1 (Wire VEEE into IDA acquisition)

### Slice cadence (do not deviate)
```
P0.15C-1  →  verify five invariants  →  stop  →
P0.15C-2  →  verify                  →  stop  →
P0.15C-3  →  verify                  →  stop  →
P0.15C-4  →  verify                  →  stop  →
P0.15C-5  →  verify                  →  stop
```

## Frozen rules for next session (from Amendment 4)

* P0.15C is an **implementation** milestone, not an architecture
  milestone.  Architecture is frozen.
* No redesign · no new ADRs · no speculative refactoring · no
  "while we're here" improvements.
* No design questions unless the contract genuinely doesn't
  resolve a blocker.
* Every slice must be independently releasable.

## Explicitly out of scope for P0.15C  (do NOT touch)

* Explainability score
* Rule efficiency improvements
* Mitigation gap sprint (suppressed / dormant / shadowed rules)
* New MITRE mappings unrelated to acquisition
* Behavior engine changes
* Projection layer changes
* Workspace UI redesign

## Standing invariants (block release if violated)

1. Flag OFF = byte-identical to pre-P0.15C production
2. Flag ON  = additive-only · `len(on) ≥ len(off)` AND `set(off) ⊆ set(on)`
3. Complete OCR provenance on every record
4. Zero Workspace regressions
5. Deterministic acquisition (byte-identical across repeated runs)

## Pending items surfaced but explicitly NOT in P0.15C scope

* 4 suppressed recommendation rules (need corpus signals)
* 2 dormant rules (need MITRE tuples · `logic_gap`)
* 1 shadowed rule (`erad.protect_shadow_copies` needs a
  backup-tamper-without-encryption corpus case)
* VEEE line-joining heuristic to reduce "5 of 15 collapse
  to Command execution" gap (this DOES live in P0.15C-4 · fine)

## Files that will change in P0.15C  (bounded whitelist)

* `services/veee/**`          (new stage modules)
* `services/veee/__init__.py` (orchestrator only)
* `backend/.env`              (feature flag continues to default OFF)
* `frontend/src/**/AcquisitionSummary*` (new additive UI · P0.15C-2, -3)
* `tests/test_veee_*.py`      (new regression + determinism suites)
* `docs/P0.15C-RELEASE-CONTRACT.md` (only if a genuine blocker
  requires an ADR revision — otherwise untouched)
* `memory/CHANGELOG.md` + `memory/PRD.md` (per-slice log)

Anything outside this whitelist requires an explicit reason
recorded before the edit.

## Contract state

**FINAL** · 4 amendments recorded · handoff-ready.

---

**Sleep well.**  When you're back and say "Hi" — I run the
deployment verification checklist first, then open the contract
and start P0.15C-1.  No design questions, just execution.
