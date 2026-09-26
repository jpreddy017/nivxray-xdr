# RC4.5.6 · Hard-Ceiling Mitigation Deployment Note

**Date:** Feb 21, 2026
**Change scope:** Single constant in `backend/rc22_adapter.py` (15 s → 45 s)
**Risk classification:** LOW
**Deployment recommendation:** Ship immediately (unblocks user), then contact Emergent Support for permanent CPU-parity fix.

---

## What changed

`backend/rc22_adapter.py:118` — the orchestrator's hard wall-clock ceiling raised from **15 seconds → 45 seconds**.

The safe-fallback behaviour when the ceiling IS exceeded is unchanged — same `output=payload`, same `engine="rc2-orchestrator-hard-ceiling"`, same terminal state. Only the trigger threshold moved.

## Why the ceiling was increased

Evidence-based investigation (see `/app/memory/RC4.5.6_INFRA_REPORT_FOR_EMERGENT.md`) showed:
- In-process decode of a heavy shellcode payload completes in **1.9 seconds**.
- Preview HTTP layer takes **4.8 seconds** end-to-end for the same payload.
- Production HTTP layer takes **~30 seconds** for the same payload.
- Health endpoint and non-CPU work run at PARITY (Prod 115ms vs Preview 141ms).
- CPU-bound work runs consistently ~6× slower on Prod across three independently-sized payloads.

The 15-second ceiling was safe for Preview's CPU allocation but fires as a safe-fallback on Prod, causing users to see `OUTPUT=INPUT` and a `RC2-ORCHESTRATOR-HARD-CEILING` badge even though the underlying decode would eventually succeed.

45 seconds is chosen because:
- It exceeds the observed Prod worst-case (~30s) by 50%
- It stays 55 seconds below Cloudflare's 100-second proxy timeout
- It NEVER fires on Preview (Preview's worst-case is 4.8s → 40s headroom)
- It NEVER fires on Prod if CPU parity is restored (Prod would return to ~5s)

## Why this is low risk

1. **No decode logic changed.** Zero behaviour change in the decoder, orchestration, confidence scoring, verdict, or IOC extraction.
2. **Fallback behaviour unchanged.** Same safe-response shape, same fields, same `engine` label.
3. **RC4.x Quality Gate remains GREEN** (134/134 tests pass post-change).
4. **Preview timing envelope unaffected.** Preview's 4.8s well below the new 45s threshold.
5. **Cloudflare 524 risk unchanged.** Was 15s + margin below CF timeout; now 45s + margin — still comfortable.
6. **Reversible in one line.** Change `_HARD_CEILING_S = 45.0` back to `15.0` and redeploy.

## Why this is a MITIGATION, not the permanent fix

- The **real problem** is that Prod is 6× slower than Preview on identical CPU-bound work.
- Raising the ceiling masks the symptom (users no longer see OUTPUT=INPUT) but does not fix the underlying infrastructure delta.
- **Permanent fix requires Emergent Support** to verify Prod's CPU allocation, worker configuration, and runtime parity with Preview.
- Once Prod parity is restored, this change becomes a no-op (Preview at 1.9s would never approach 45s).

## Rollback procedure

If this change causes any unexpected regression:

1. In `backend/rc22_adapter.py`, change `_HARD_CEILING_S = 45.0` back to `_HARD_CEILING_S = 15.0`.
2. Commit: `git commit -am "Revert RC4.5.6 · restore 15s hard-ceiling"`.
3. Save to GitHub → Deploy.
4. Verify via `curl` that a heavy payload triggers the fallback at 15s.

Rollback wall-time: ~5 minutes.

## Verification performed

- ✅ Backend service restarts cleanly (`sudo supervisorctl restart backend`)
- ✅ `HTTP 200` on `/api/`
- ✅ Heavy payload full-decode on Preview: 5.8s, 6 steps, reached_shellcode=True, confidence 80
- ✅ Trivial payload: no regression (~8s, same as pre-change baseline)
- ✅ Medium payload: no regression (0.3s, same as pre-change)
- ✅ RC4.x Quality Gate: 134/134 GREEN
- ✅ Zero decode-logic changes verified via `grep`

## Deployment steps (user action)

1. **Save to GitHub** — pushes the one-file change to `feature/rc2.1b` branch
2. Wait for GitHub Actions RC4.x Quality Gate to go GREEN (~3 minutes)
3. Merge PR → main
4. Click **Deploy** in Emergent
5. Verify the user's failing payload now completes on Prod
6. (Parallel) Send the Emergent Support report requesting Prod CPU-parity investigation
