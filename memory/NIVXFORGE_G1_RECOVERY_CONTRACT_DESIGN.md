# NIVXFORGE EDR — G1 RECOVERY CONTRACT DESIGN CORRECTION (design only)

Gate: G1. Status: DESIGN READY FOR INDEPENDENT G1 REVIEW.
Release/rollout: HOLD. No code written. No source revision altered.

Subject of inspection (read-only):
- frozen R5 `a14c6693a7013ea7ef86b6fc8d698bae28e87491`
- reviewed successor `1c39885867b2571c9af6b8756f010f2e18f43a65`
- previous repair `8a2c3e91c24224f0361da13eae9264699d26be8b`
- failed candidate `bc8147be15af46e87a95612322e7d17f3859f587`, tree
  `3333fd37737588e3c1be2f632d572d5e2631bb0a` (confirmed)

---

## 0. The single ruling the previous candidate got wrong

The candidate tried to make the installer DECIDE whether a slow service is
healthy or hung. Nothing available to it can decide that: Windows permits a
service never to advance CheckPoint, and the NivXForge sensor in fact never
advances it (`nivxforge_setup.py` `SvcStop`, one `STOP_PENDING` with
`waitHint=20000`, then return).

Therefore: **a deadline is a BOUND ON WAITING, never a diagnosis.** Every
deadline breach yields UNKNOWN and a named recovery exit; no deadline breach
may ever yield "failed" or "stopped". The four corrections below all follow
from that one ruling, which is why they do not contradict each other.

---

## 1. D1 — unified deadline and timeout contract

### 1.1 Defects found in `bc8147be`

**D1-a — the budget is derived from the one quantity that cannot affect stop
latency.** `stop_budget()` = `clamp(interval + 45, 60, 600)`. But in
`SvcDoRun` the inter-cycle wait is
`WaitForSingleObject(self.stop_event, wait_seconds*1000)` — the interval wait
is INTERRUPTIBLE and `SvcStop` signals that event, so the interval
contributes **zero** to stop latency. What actually delays a stop is the
uninterruptible remainder of `sensor.run(..., once=True)`:
`nivxforge_sensor.py` has `HTTP(S)Connection(timeout=30)` with `for attempt in
(1, 2)` per POST, `wevtutil qe` at `timeout=60` per channel, `timeout=30`
boundary probes and `wmic` at `timeout=20`. A single cycle can therefore
block for minutes. `--interval 30` yields a 75 s budget that a healthy stop
can exceed; `--interval 600` yields 600 s for a service that stops in two.
The derivation is not merely imprecise, it is uncorrelated with the bound it
claims to compute.

**D1-b — two different and contradictory bounds on the same PENDING state.**
`wait_for_state` was corrected to let the budget (up to 600 s) govern a
STOP_PENDING. The `observe` action in the same worker still hard-waits a
**fixed 20 s** for PENDING to clear and then reports `state="PENDING"`.
`final_observation` rejects PENDING, so the same 30 s healthy stop that the
mutation path now accepts makes the recovery path emit MANUAL_RECOVERY. The
constant D1 deleted from the mutation path survives verbatim on the
observation path, and D1's fix is void wherever recovery meets a live stop.

**D1-c — the parent/worker margin is a constant where the worker's own work
is not.** `call()` uses `communicate(timeout=(budget or 25) + 10)`. The
worker must still, inside that window: `OpenSCManager`, `OpenService`,
`wait_for_state` up to the FULL budget, then in `entry()` re-open the
operation record, validate its path and write+fsync the acknowledgement. If
the transition consumes the budget, the parent's 10 s margin is spent on the
ack and the parent kills the worker (`process.kill()`, plus
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) mid-acknowledgement — manufacturing an
UNCERTAIN record for an operation that SUCCEEDED.

**D1-d — recovery itself has no bound.** `recovery_safe()` iterates every
record; each unsettled record costs up to two `observe` calls (each up to
~20 s of internal PENDING wait plus full config/ACL enumeration) plus
`OBSERVATION_SETTLE_SECONDS`. `reconcile()` runs inside the `Owner` mutex, so
total runtime grows with record count with no ceiling and no progress output.

**D1-e — a breach is not expressed as a named exit.** `communicate` raising
`subprocess.TimeoutExpired` propagates out of `call()` for stop/start
(`observe()` catches it, nothing else does), so the installer aborts with a
raw stdlib exception instead of a MANUAL_RECOVERY diagnostic.

### 1.2 Designed contract

One transaction clock, five nested budgets, each strictly contained by its
parent. Every value is derived from a declared quantity, never from a literal
at the call site.

| # | Budget | Governs | Derivation | On breach |
|---|---|---|---|---|
| B1 `IDENTITY` | spawn → worker identity durably recorded | fixed 10 s; no I/O but one process query and one fsync | ABORT before dispatch, record NEVER_DISPATCHED (§4) |
| B2 `TRANSITION` | control delivered → SCM reports a final state | `clamp(declared_stop_latency + grace, floor, SERVICE_CEILING)` | UNKNOWN + `STALLED_NO_PROGRESS`/`PENDING_AT_DEADLINE` |
| B3 `WORKER` | parent's wait on the worker subprocess | `B2 + ack_margin`, `ack_margin = worker_setup + ack_fsync` (declared, not 10) | kill worker, record UNCERTAIN, named exit |
| B4 `OPERATION` | one record's whole recovery adjudication | `2*observe_bound + settle_window` | that record stays UNCERTAIN; move to the next |
| B5 `TRANSACTION` | whole `reconcile()`/`run()` under the mutex | `B4 * records + B2 * planned_mutations`, reported up front | stop cleanly at a checkpoint, release the mutex, named exit |

Rules that make contradiction impossible:

1. **Strict containment.** B1 < B3; B2 < B3; B4 < B5. The design requires a
   static assertion that each child plus its declared margin is ≤ its parent,
   so no timeout can fire before the work it is waiting on can possibly
   finish. The B2/B3 inversion in D1-c is a containment violation and is
   caught by that assertion.
2. **One definition of "how long may a stop take".** `declared_stop_latency`
   is a single published constant owned by the sensor module (its own
   worst-case uninterruptible cycle: collection subprocess timeouts +
   delivery attempts × connection timeout + final-record fsync). The
   installer READS it, never re-derives it, and `--interval` is removed from
   the derivation entirely. One number, one owner, therefore nothing to
   contradict.
3. **The observation path uses B2, not a private constant.** D1-b is closed
   by deleting the worker's 20 s PENDING loop. `observe` becomes a pure
   sampler that reports exactly what the SCM says, including PENDING, and the
   CALLER decides how long to keep sampling using its own budget. An
   observation may never silently block.
4. **CheckPoint/WaitHint are diagnostic only** (kept from the candidate) and
   additionally are never used to EXTEND a wait either — a service that keeps
   advancing CheckPoint cannot push past B2 or the absolute ceiling.
5. **Every breach has exactly one encoding:** a domain error carrying
   {budget-name, classification, waited, last-state, record-id, exit
   command}. No stdlib exception escapes `call()`. D1-e closed.
6. **No budget may be inferred from a default argument.** `stop(budget=None)
   → STOP_BUDGET_FLOOR` and `(budget or 25)` in `call()` are forbidden: a
   missing budget is a programming error that must refuse, not silently pick
   60 or 25.

### 1.3 Why these cannot contradict one another

They are a total order on a single clock, all derived from two declared
inputs (`declared_stop_latency`, `ack_margin`), with containment statically
checked. The 20 s/25 s/45 s/60 s/600 s literals that disagreed in `bc8147be`
disappear because there is exactly one place each quantity is stated.

---

## 2. D2 — operation finality and proof contract

### 2.1 Defects found in `bc8147be`

**D2-a — "stable" is an unjustified 0.75 s.** `OBSERVATION_SETTLE_SECONDS =
.75` with two agreeing observations is asserted to prove "nothing is still
arriving". It proves only that nothing arrived in 750 ms. No Windows
guarantee bounds the delay between a delivered control and its effect.

**D2-b — the service's OWN recovery actions falsify a stable STOPPED.** The
installer writes `failure: {"Actions": [[1, 60000]] * 3}` (`SERVICE_CONTROL
RESTART` after 60 s) in `nivxforge_scm_worker.main`'s `defaults`. A stop that
the SCM did not expect leaves a restart armed. Two STOPPED samples 750 ms
apart, settled RESOLVED_BY_OBSERVATION, can be followed 59 s later by a
RUNNING service on the OLD binPath. This is the counterexample the mission
asks for, and it is produced by this installer's own configuration.

**D2-c — settlement conflates "proved applied" with "proved not applied".**
`recovery_safe` writes `RESOLVED_BY_OBSERVATION` whether `outcome["applied"]`
is True or False, and `SETTLED_OPERATIONS` then skips the record forever. An
operation that provably did NOT take effect is marked settled and is never
retried; nothing downstream reads `applied`.

**D2-d — `stop` demands `pid == 0`.** `operation_outcome` requires
`state == "STOPPED" and pid == 0`. The SCM reports STOPPED as soon as the
service reports it, which `SvcRun`'s `finally` does before interpreter
teardown; a non-zero ProcessId in that window yields `applied=False` — a
successful stop recorded as a failure (and then settled, per D2-c).

**D2-e — `set_path` finality is not exclusive.** `applied` is true iff the
observed binPath equals the requested one. A concurrent `sc config` by an
operator produces the same observation; the record cannot distinguish "my
mutation landed" from "someone else's did".

### 2.2 Designed contract

**Settlement vocabulary** (replaces one settled state with four, all
terminal, all auditable):

- `ADJUDICATED_APPLIED` — proof the mutation took effect.
- `ADJUDICATED_NOT_APPLIED` — proof it did not. **Terminal for the RECORD,
  and an input to the transaction, which may legitimately retry the
  mutation.** Closes D2-c.
- `ADJUDICATED_INDETERMINATE` — the worker is provably gone and the SCM is
  final and stable, yet the record cannot be mapped to either (e.g. D2-e).
  Requires operator reconciliation; never auto-settled.
- `UNCERTAIN` — the live, non-terminal state. Always carries its blocking
  reason and its exit command.

**Proof required to leave UNCERTAIN automatically** — all five, conjunctively:

| P | Requirement |
|---|---|
| P1 | The requesting worker is **provably GONE** (§3/§4 identity rules). UNKNOWN never satisfies P1. |
| P2 | The SCM reports a **final** state: `RUNNING`, `STOPPED`, or `ABSENT` proved by `ERROR_SERVICE_DOES_NOT_EXIST (1060)`. PENDING and UNREADABLE never satisfy P2. |
| P3 | The observation is **quiescent**, not merely repeated: the same identity tuple across samples spanning ≥ the declared settle window, AND **no armed deferred effect** — no pending SCM failure/restart action, no `delayed` auto-start pending, no `SERVICE_START_PENDING` scheduled by a trigger. Closes D2-a/D2-b. |
| P4 | The observed state is **attributable** to this record: it matches the record's own requested transition AND no other unsettled record and no externally-observed configuration change can explain it. Closes D2-e. Where attribution is impossible the outcome is `ADJUDICATED_INDETERMINATE`, not a guess. |
| P5 | The record's integrity envelope verifies and its `history` is append-only. |

**Delivered control vs completed transition.** `ControlService`/
`StartService` returning proves DELIVERY only. Delivery is recorded as
`CONTROL_DELIVERED` — evidence, not an outcome. Completion is only ever a
quiescent final SCM observation satisfying P1–P5.

**Delayed effects after worker termination.** A worker's death does not
cancel a delivered control. P3's quiescence window must be ≥ the longest
deferred effect this installer itself can arm — which, with the failure
actions above, is 60 s, not 750 ms. Either the quiescence window covers it,
or the design must **disarm recovery actions for the duration of the
transaction and restore them on completion/rollback** (the preferred option:
cheaper, deterministic, and already inside the installer's existing
configuration authority). The chosen option must be stated by G1 review; both
are sound, only the cost differs.

**Per-state adjudication**

| SCM observation | May settle? | Outcome |
|---|---|---|
| RUNNING, quiescent, attributable | yes | APPLIED for `start`/`create`; NOT_APPLIED for `stop` |
| STOPPED, quiescent, no restart armed | yes | APPLIED for `stop`; NOT_APPLIED for `start` |
| ABSENT with 1060 | yes | APPLIED for `delete`; NOT_APPLIED for `create` |
| ABSENT without 1060 | never | UNCERTAIN (absence unproved) |
| any PENDING | never | UNCERTAIN (`PENDING_AT_DEADLINE`) |
| UNREADABLE | never | UNCERTAIN (`SCM_UNREADABLE`) |
| final but non-quiescent / restart armed | never | UNCERTAIN (`DEFERRED_EFFECT_ARMED`) |
| final, quiescent, not attributable | never auto | INDETERMINATE → operator |

**Operator reconciliation without bypassing safety.** `resolve-operation`
keeps the candidate's correct shape — elevation, the SYSTEM/Administrators
DACL over `operations/`, and the operator's claim CHECKED against the live
SCM — and adds: it may satisfy **P4 only**. It may never substitute for P1,
P2, P3 or P5. An operator may assert *attribution* (a fact they can know);
no operator may assert that a process is dead or that the SCM is final (facts
only the machine can establish). This is the precise line between a usable
remedy and a bypass.

**When finality cannot be proven at all:** the transaction refuses, the
record stays UNCERTAIN with its reason and exit, every payload, record,
journal, cursor and queued evidence is preserved, nothing is deleted, and the
installer exits non-zero naming the exact command to re-run.

---

## 3. D3 — legacy transaction records (PID, no creation-time token)

### 3.1 The blocking defect in `bc8147be` — an unreachable remedy

`worker_state()` returns `UNKNOWN` for any record lacking `worker_token`
**before it ever queries the pid**. `recovery_safe()` then raises, and
`resolve_operation()` begins with `if liveness != "GONE": raise`. For a
legacy record `worker_state` can never return `GONE`, therefore the
documented operator remedy is **mathematically unreachable for exactly the
records that require it**. Every in-flight record written by `8a2c3e91` or
earlier permanently blocks every future install with no supported exit. The
diagnostic even names the condition — "no identity was recorded for pid …" —
and then offers `resolve-operation`, which cannot succeed. This is a
documentation/implementation contradiction and, in the reviewer's view, the
correct basis for the G3 FAIL.

### 3.2 Designed procedure — three provable escapes, no invented identity

A legacy record is adjudicated by **evidence about the pid's existence and
about time**, never by assuming the token.

**L1 — nonexistent pid is conclusive.** `OpenProcess` failing with
`ERROR_INVALID_PARAMETER (87)` means no process holds that id. The recorded
worker cannot be running under an id that does not exist. **This requires no
token and is a complete proof of GONE.** The design therefore *queries first
and short-circuits on GONE*, and reaches the token question only when the pid
EXISTS. Expected to cover the large majority of legacy records.

**L2 — boot-session evidence is conclusive.** If the record's durable
creation time precedes the current boot time (SCM/system boot timestamp, not
wall-clock arithmetic), no process from that session survives, whatever pid
is now in use. GONE. Covers the reboot/power-loss cases that produced most
legacy records.

**L3 — pid exists and the session is the same: genuinely ambiguous.** The
live process may or may not be the original worker. The design **refuses
automatically** and routes to the supported manual procedure. It must not
guess in either direction: assuming alive deadlocks; assuming dead is exactly
the D3 fail-open the candidate fixed.

**Supported manual procedure for L3** (the exit that `bc8147be` lacks),
with its proof requirements, all four mandatory:

1. Elevated, with the operations directory DACL intact (authenticity of the
   record itself).
2. The operator supplies the pid's **current identity evidence** — image path
   and creation time, obtained live — and the installer verifies that this
   process is **not an installer worker** (image is not the installer
   binary/`--transaction-scm-worker`). A pid now held by an unrelated process
   is proof the worker is gone, and the installer checks it rather than
   believing it.
3. The SCM must independently satisfy P2 + P3 (final and quiescent).
4. The operator's expected state must match the observation (as today).

If (2) cannot be satisfied because the pid IS an installer worker, the only
supported action is to let that worker finish or to reboot the host and
re-run recovery, which converts the case to L2. **No path deletes a record,
fabricates a token, or asserts termination without proof, and no legitimately
recoverable case is left without an exit.**

**Forward compatibility.** Records written under the corrected design carry
`schema`, `worker_token`, a durable creation timestamp and a boot identifier,
so L2/L3 are never needed again; L1–L3 exist solely to drain the pre-existing
population and are retained, not removed, so an old record found years later
still has a defined answer.

---

## 4. D4 — worker identity and dispatch ordering contract

### 4.1 Defect found in `bc8147be`

The ordering is right — `Popen`, job assignment, `query_process`,
`operation.amend(...)`, THEN `communicate` releases the request — but the
failure branch is missing:

```
token, status = query_process(process.pid)
operation.amend("REQUESTED", worker_pid=..., worker_token=token,
                worker_identity=status)
stdout, _ = process.communicate(json.dumps(request), ...)
```

If the identity query returns `(None, "UNKNOWN")`, the code records
`worker_token=None` and **dispatches the mutation anyway**, manufacturing a
brand-new record of precisely the legacy shape that §3 shows is
unrecoverable. "Failed identity acquisition cannot silently permit dispatch"
is violated in the candidate's own code. Separately, the deprecated
`process_alive()` shim passes `worker_token: None`, so it now returns False
("dead") for every live process — a reintroduction of the D3 fail-open for
any future caller; it should be deleted, not kept as a shim.

### 4.2 Designed sequence (invariants in order)

| Step | Action | Invariant |
|---|---|---|
| S1 | Create the kill-on-close job object | a worker can never outlive its parent |
| S2 | Spawn the worker with stdin as a **pipe, unwritten** | **the worker cannot act: it is blocked on stdin and no request exists.** This is the invariant the whole contract rests on, and it must be an explicit, tested property of the worker's entry point — no action may precede the first successful stdin read |
| S3 | Assign to the job (before any request) | containment precedes capability |
| S4 | Acquire identity: pid + creation time | within B1 |
| S5 | **If identity is not OK → kill the worker, record `NEVER_DISPATCHED` (a terminal, non-blocking state), refuse the operation.** | no mutation is ever requested without provable identity; no unrecoverable record is created |
| S6 | Durably record pid, token, creation time and boot id, fsync + directory sync, verify the envelope reads back | identity exists on disk before capability is granted |
| S7 | Only now write the request to stdin | dispatch strictly after durable identity |
| S8 | Worker performs the mutation, then writes the acknowledgement | within B2/B3 |

**Interruption safety at every boundary:**

| Crash point | On-disk state | Adjudication |
|---|---|---|
| before S6 | no record, or record without pid | nothing was dispatched → terminal, non-blocking |
| between S6 and S7 | pid + token, `REQUESTED`, **no `dispatched_at`** | no request reached the worker; worker provably gone → terminal, no SCM check needed |
| after S7, before ack | pid + token + `dispatched_at` | full §2 adjudication (P1–P5) |
| after ack | `FINISHED`/`UNCERTAIN` | settled or §2 |

`dispatched_at` is the missing discriminator in `bc8147be`: today a record in
`REQUESTED` cannot be distinguished between "never sent" and "sent and
possibly applied", so the cheapest safe answer is unavailable and every such
record pays for a full SCM adjudication.

**PID reuse.** Identity is always the pair (pid, creation time). Same pid +
different creation time ⇒ GONE (kept from the candidate, correct). Query
failure ⇒ UNKNOWN, never DEAD (kept, correct). `ERROR_INVALID_PARAMETER (87)`
⇒ GONE (kept, correct, and per §3.2 is evaluated BEFORE the token test).

---

## 5. Transaction state machine

```
          ┌──────────── no record ────────────┐
          ▼                                    │
  PREPARING → STAGED → PREPARED → STOPPED → CONFIGURED → ACTIVATED
      │         │         │          │           │           │
      └─────────┴─────────┴──────────┴───────────┴───────────┤
                                                 (any crash) ▼
                                              ROLLING_BACK → ROLLED_BACK ─┐
  ACTIVATED → COMMITTED ──(commit is authoritative; finish forward)──┐    │
                                                  COMPLETE ◄─────────┘    │
  COMPLETE / ROLLED_BACK ──(re-checked before any later update)───────────┘
  any phase + unprovable state → HELD_FOR_MANUAL (terminal until operator)
```

Rules, unchanged from the reviewed design and preserved here: commit is the
point of no return and is finished forward, never half-reverted; rollback
restores configuration, binPath, state, payload and transaction metadata, and
verifies each; a phase the installer does not recognise is HELD_FOR_MANUAL,
never guessed. Added by this design: **the transaction may not enter any
mutating phase while an operation record is UNCERTAIN or INDETERMINATE**, and
`reconcile()` runs `recovery_safe()` first (as today) but under B5.

## 6. Recovery state machine (per operation record)

```
REQUESTED ──no dispatched_at──────────────────► NEVER_DISPATCHED (terminal)
    │ dispatched_at
    ▼
 IN_FLIGHT ──worker ALIVE──────────────────────► refuse, stay IN_FLIGHT
    │ worker GONE (87 / token mismatch / boot)
    │ worker UNKNOWN ──────────────────────────► UNCERTAIN(WORKER_UNKNOWN)
    ▼                                               │ L1/L2 evidence
 AWAITING_PROOF                                     └──► GONE ──┐
    │ P2 fails ──► UNCERTAIN(PENDING|UNREADABLE) ──► re-run ────┤
    │ P3 fails ──► UNCERTAIN(DEFERRED_EFFECT_ARMED) ─► re-run ──┤
    │ P4 fails ──► ADJUDICATED_INDETERMINATE ─► operator ───────┤
    │ P1..P5 all hold                                           │
    ▼                                                           │
 ADJUDICATED_APPLIED | ADJUDICATED_NOT_APPLIED (terminal) ◄──────┘
                                   │ NOT_APPLIED
                                   ▼
                     transaction may retry the mutation
```

Every edge preserves the record. No edge deletes evidence. Every refusing
edge names its exit command.

## 7. Failure-mode matrix

| # | Failure | Detection | Outcome | Exit |
|---|---|---|---|---|
| F01 | healthy slow stop (cycle in progress) | B2 not breached | APPLIED | none |
| F02 | stop exceeds B2 | budget breach | UNCERTAIN `PENDING_AT_DEADLINE` | recover-transaction |
| F03 | service hung, CheckPoint stagnant | B2 breach, 1 checkpoint value | UNCERTAIN `STALLED_NO_PROGRESS` | recover-transaction |
| F04 | service settles on the wrong final state | FINAL_NOT_TARGET | NOT_APPLIED | retry/rollback |
| F05 | parent killed mid-transition | job kills worker; record IN_FLIGHT | §2 adjudication | recover-transaction |
| F06 | worker killed after delivery, control still landing | P3 non-quiescent | UNCERTAIN `DEFERRED_EFFECT_ARMED` | recover-transaction |
| F07 | SCM failure action restarts the service post-stop | P3 armed-effect check | UNCERTAIN, never APPLIED | recover-transaction |
| F08 | process query denied (ACCESS_DENIED) | status UNKNOWN | UNCERTAIN `WORKER_UNKNOWN` | elevated recover-transaction |
| F09 | pid reused by an unrelated process | token mismatch | GONE → adjudicate | none |
| F10 | legacy record, pid absent | L1 (err 87) | GONE → adjudicate | none |
| F11 | legacy record, pre-boot | L2 | GONE → adjudicate | none |
| F12 | legacy record, pid live, same session | L3 | refuse | manual procedure §3.2 |
| F13 | identity query fails before dispatch | S5 | NEVER_DISPATCHED | re-run install |
| F14 | crash between identity and dispatch | no `dispatched_at` | NEVER_DISPATCHED | re-run install |
| F15 | SCM unreadable during recovery | P2 | UNCERTAIN `SCM_UNREADABLE` | recover-transaction |
| F16 | record corrupt / envelope mismatch | P5 | HELD_FOR_MANUAL | manual, evidence kept |
| F17 | concurrent operator `sc config` | P4 attribution | INDETERMINATE | resolve-operation (P4 only) |
| F18 | operator claims a state the SCM denies | claim check | refuse, nothing changed | re-observe |
| F19 | second installer starts during recovery | `Owner` mutex | refuse | wait |
| F20 | recovery exceeds B5 | B5 breach | clean stop, mutex released | recover-transaction |
| F21 | power loss mid-commit | phase COMMITTED | finish forward | automatic |
| F22 | ack write fails after a successful mutation | ACK_FAILED | UNCERTAIN → §2 settles APPLIED | recover-transaction |

## 8. Acceptance tests mapped to every requirement

Positive (must pass):
P-01 F01 healthy stop at the declared latency bound → APPLIED.
P-02 B2 breach → UNCERTAIN with classification, never "failed".
P-03 budget containment assertion holds for every declared pair (B1<B3, B2<B3, B4<B5).
P-04 `observe` returns PENDING immediately instead of blocking (D1-b).
P-05 ack completes inside B3 when the transition consumes all of B2 (D1-c).
P-06 `recovery_safe` over N records completes within B5 (D1-d).
P-07 quiescent STOPPED with no armed restart → APPLIED.
P-08 legacy record, pid absent → GONE → settles automatically (L1).
P-09 legacy record written pre-boot → GONE → settles automatically (L2).
P-10 legacy L3 record → supported manual procedure succeeds with the required evidence.
P-11 identity failure → NEVER_DISPATCHED, no SCM call attempted.
P-12 crash between S6 and S7 → NEVER_DISPATCHED, no SCM adjudication needed.
P-13 NOT_APPLIED permits a transaction retry.
P-14 every refusal preserves record, history, payloads, journal, cursors, queued evidence.

Negative (must refuse):
N-01 PENDING never settles (any of the four pending states).
N-02 UNREADABLE SCM never settles.
N-03 denied process query never reads as dead.
N-04 reused pid never reads as the worker.
N-05 stable STOPPED with an armed 60 s restart action never settles (D2-b).
N-06 two samples 750 ms apart alone never constitute proof (D2-a).
N-07 operator claim may satisfy attribution ONLY; a claim of worker death or SCM finality is rejected.
N-08 `resolve-operation` on a live worker is refused.
N-09 no code path deletes an operation record.
N-10 a missing budget refuses instead of defaulting.
N-11 identity failure never dispatches.
N-12 a record provably not applied is never marked applied.
N-13 an unrecognised phase is never guessed.
N-14 a legacy record never receives a fabricated token.

## 9. Linux-testable vs native-Windows-only

Testable on Linux with the synthetic SCM: all budget arithmetic and
containment assertions; the state machines and every transition; P1–P5
adjudication; the four settlement outcomes; L1/L2/L3 branching; dispatch
ordering S1–S8 including S5 and the `dispatched_at` discriminator; every
refusal message and exit command; append-only history and envelope integrity;
all 14 positive and 14 negative cases above as behavioural tests.

Requires native Windows (cannot be claimed from Linux): real CheckPoint/
WaitHint emission by the live sensor and the true worst-case uninterruptible
cycle; the actual stop latency under load; SCM failure-action restart timing
(F07); `OpenProcess`/`GetProcessTimes`/`GetExitCodeProcess` error codes
including 87 and ACCESS_DENIED under a real token; job-object kill-on-close;
mutex abandonment; `ERROR_SERVICE_DOES_NOT_EXIST` semantics; service SID,
preshutdown and DACL behaviour; reboot and power-loss recovery; mapped-PYD
payload behaviour; and preservation of endpoint identity, journal, cursors
and queued evidence across all of it.

## 10. Minimal implementation scope (NOT implemented here)

1. One declared stop-latency constant owned by the sensor module; delete
   `stop_budget`'s `--interval` derivation and the `(budget or 25)`/
   `budget or STOP_BUDGET_FLOOR` defaults.
2. Delete the worker's 20 s PENDING loop in `observe`; make PENDING a
   reportable value.
3. Introduce the five named budgets with a static containment assertion, and
   one domain error type for every breach.
4. Query-before-token in `worker_state`; add L1/L2 evidence; delete the
   `process_alive` shim.
5. Add `dispatched_at` and `NEVER_DISPATCHED`; refuse dispatch on identity
   failure (S5).
6. Replace `RESOLVED_BY_OBSERVATION` with the four adjudication outcomes;
   add the armed-deferred-effect and attribution checks.
7. Either widen the quiescence window to the armed-restart delay or disarm
   recovery actions for the transaction's duration (G1 review to choose).
8. Narrow `resolve-operation` to attribution-only, and add the §3.2 manual
   procedure for L3.
9. Tests per §8. Declare `mslex` or remove the dependency.

Not in scope: P0-2 predecessor policy, sensor collection/delivery/detection,
backend/XDR, frontend, WiX/MSI, any new product feature.

## 11. Counterexamples that would invalidate this design

C1 If the sensor's worst-case uninterruptible cycle is not boundable (an
unbounded collector), B2 cannot be derived and the only honest contract is
"bounded wait, always UNKNOWN on breach" — the design survives but loses its
derivation; the sensor would need a cooperative progress signal.
C2 If Windows can fire an SCM failure action with no observable armed state,
P3 cannot be evaluated and the only remedy is disarm-during-transaction
(option 7b becomes mandatory, not a choice).
C3 If an L3 legacy record's pid is a live installer worker from a crashed
session that will never exit, only reboot (→ L2) resolves it; if reboot is
refused by the operator there is no automatic exit, by construction.
C4 If `ERROR_INVALID_PARAMETER` is not the only "no such pid" code on some
Windows build, L1 weakens and more records fall to L3.
C5 If a service can report a final state while a control is still queued in
the SCM with no observable trace, no finite quiescence window suffices and
settlement must require an additional independent witness (e.g. the service's
own durable shutdown record).
C6 If two installers can hold the mutex (abandonment handling), attribution
P4 is unsound.
C1–C6 are native-Windows questions. None is answerable from Linux, and G2 may
not assume any of them resolved.

## 12. Safe refusal vs verified recovery vs manual intervention

- **Safe refusal** — no proof, nothing changed, evidence kept, exit named.
  Always available, always correct, never a dead end because it is re-runnable.
- **Verified recovery** — automatic, only on P1–P5. Covers F01–F05, F09–F11,
  F21, F22.
- **Manual intervention** — operator supplies attribution (P4) or live pid
  evidence (L3), each CHECKED, never believed. Covers F12, F16, F17.
No automatic recovery is promised for F12, F16 or F17, and none is claimed
for anything requiring native proof (§11).

## 13. Feasibility: the four corrections challenged together

| Conflict | Verdict |
|---|---|
| timeout vs slow service | Resolved only by abandoning diagnosis. A deadline bounds; it never concludes. Every breach is UNKNOWN + re-runnable, so a slow service is never called failed and a hung one is never waited on forever. |
| worker identity vs legacy records | Resolved by L1/L2: existence and boot-session facts prove GONE without a token, so strict identity does not orphan the legacy population. L3 remains genuinely undecidable and gets a manual procedure — the one place the design declines to promise automation. |
| fail-closed vs usable recovery | Resolved by making refusals re-runnable and exits named, and by the NEVER_DISPATCHED/NOT_APPLIED states that let the transaction make progress without ever assuming an unproven effect. The candidate's dead end came from a refusal with no reachable exit, not from fail-closed itself. |
| SCM observation vs delayed effects | Resolved only by quiescence + armed-effect inspection, or by disarming recovery actions. Repetition at 0.75 s is not proof and is withdrawn. |

No pair of the four corrections requires a change that breaks another. The
design is therefore coherent — **as a design**. It is not evidence about
Windows, and §11 lists the six facts that could still invalidate it.

## 14. Assumptions

A1 The worker performs no action before its first successful stdin read
(must be asserted and tested, not assumed).
A2 Windows answers "no such pid" with ERROR_INVALID_PARAMETER (C4).
A3 A boot timestamp obtainable locally and monotonic across the record's
lifetime is available.
A4 Armed SCM failure actions and delayed auto-start are observable before
they fire (C2).
A5 The sensor's worst-case uninterruptible cycle is finite and declarable
(C1).
A6 The `Owner` mutex genuinely serialises installers, including after
abandonment (C6).

---

STATUS: **DESIGN READY FOR INDEPENDENT G1 REVIEW**
No implementation. No G2 continuation. Release/rollout HOLD preserved.
P0-2 untouched. Security HOLDs and the sensor-to-Device-Trajectory milestone
preserved.
