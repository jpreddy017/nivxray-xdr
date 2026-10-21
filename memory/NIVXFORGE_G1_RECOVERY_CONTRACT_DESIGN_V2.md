# NIVXFORGE EDR — G1 RECOVERY CONTRACT DESIGN, VERSION 2 (CORRECTED)

Design only. No code, no commit, no build, no Windows execution, no deployment.
Supersedes v1 (`889be3cef19fd131b9caba79c72b544ec178859e6c880ebd98799634f8970911`),
which an independent reviewer returned **G1 DESIGN BLOCKED**.

| Input | Identity |
|---|---|
| Independent G1 review | `NIVXFORGE_G1_INDEPENDENT_DESIGN_BLOCKED_REVIEW.md`, 26,110 B, SHA-256 `f15c25d790852ac63933ca558f9aa8af0b0a78c7b295dbf362969749bb463c8b`, 294 lines, read in full |
| Failed implementation | `bc8147be15af46e87a95612322e7d17f3859f587`, tree `3333fd37737588e3c1be2f632d572d5e2631bb0a` (re-verified) |
| Previous repair | `8a2c3e91c24224f0361da13eae9264699d26be8b`, tree `1159965481e658ce1bad1353a197626ad9e132e3` |
| Reviewed successor | `1c39885867b2571c9af6b8756f010f2e18f43a65`, tree `9af61c7b0add7558e7f683855dd89135b3b01950` |
| Frozen R5 | `a14c6693a7013ea7ef86b6fc8d698bae28e87491`, tree `4007dbe3feb9a3e0680dce474cbb379f6c4b6c14` |
| Repository | `jpreddy017/nivxray-xdr` |

Gate on entry: **G1 DESIGN BLOCKED**. G2 NOT AUTHORIZED. Release/rollout HOLD.
P0-2, all security HOLDs and the sensor-to-Device-Trajectory milestone: unchanged.
The approved G0–G6 assessment is **still unavailable**; conformance to it is
NOT certified anywhere in this document.

---

## 0. What changed, and why v1 failed

v1 failed because it tried to prove **history** — what had already happened to
the SCM — and then made every forward action depend on that proof. Windows does
not expose the evidence that requires: a queued restart action cannot be
enumerated or cancelled, `QueryServiceStatusEx` returns the last *reported*
status, and a control call only proves delivery. v1 therefore either had to
weaken its proofs (unsafe) or deadlock (unusable), and the reviewer demonstrated
both outcomes in the same contract.

v2 makes one structural change, from which every correction follows:

> **Three judgments, never conflated, with different evidence and different consumers.**
>
> - **H — historical application.** Did our request take effect? Audit-grade,
>   frequently UNRESOLVED, and **never a precondition for action**.
> - **C — current observed state.** What the SCM reports now. Always stale by
>   construction. Used for convergence checks, never as proof of causation.
> - **R — permission to proceed.** A predicate over *presently verifiable machine
>   facts* only. **R alone gates every mutation.**

Because R never reads H, an uncertain or unresolvable record cannot deadlock an
installation (review §3 "circular dependency", counterexample 9), a legacy record
with no identity at all is no longer a dead end (§4), NOT_APPLIED is no longer
inferred from current state (§3), and attribution stops being load-bearing (§3,
P4 contradiction).

Second structural change: **evidence is bound to process instances and to a
documented start barrier, not to service states and elapsed time.**

---

## 1. Documented OS guarantees vs product-level guarantees

Everything this design relies on is classified. Nothing in column 1 is our
invention; nothing in column 2 is claimed to be a Windows guarantee.

### 1.1 Documented Windows behaviour (citations)

| # | Guarantee | Source |
|---|---|---|
| W1 | "A queued restart action **cannot be canceled**. … The service must be **explicitly disabled** to prevent it from restarting." | [ChangeServiceConfig2W, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w) |
| W2 | `StartService` fails with **ERROR_SERVICE_DISABLED** when the service is disabled; also blocks **30 s** if any service is busy in a control handler, then fails `ERROR_SERVICE_REQUEST_TIMEOUT` | [StartServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew) |
| W3 | `ControlService` blocks up to **30 s** on a busy SCM and fails `ERROR_SERVICE_REQUEST_TIMEOUT`; controls are processed one at a time | [ControlService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice) |
| W4 | On the *N*th failure the SCM performs action *N−1*, repeating the **last** action when *N* > `cActions`; count resets only after `dwResetPeriod` | [SERVICE_FAILURE_ACTIONSW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw) |
| W5 | `QueryServiceStatusEx` returns the **most recent status the service reported**; `dwProcessId` is meaningful only while running | [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex) |
| W6 | `DeleteService` **marks** the service for deletion; the object is removed only when all handles are closed and the service is stopped; interim calls give **1072 ERROR_SERVICE_MARKED_FOR_DELETE** | [DeleteService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice) |
| W7 | `TerminateProcess` is **asynchronous**; "if you need to be sure the process has terminated, call `WaitForSingleObject` with a handle to the process". A process object is not destroyed while any handle to it remains open | [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) |
| W8 | `OpenProcess` on PID 0 fails with **ERROR_INVALID_PARAMETER**; System/CSRSS fail with **ERROR_ACCESS_DENIED** | [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) |
| W9 | A process handle may be waited on; it is signalled when the process terminates | [Wait functions](https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions) |
| W10 | Acquiring an **abandoned mutex** grants ownership and obliges the owner to check protected state for consistency | [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject) |
| W11 | `PROC_THREAD_ATTRIBUTE_JOB_LIST` assigns a process to a job **at creation** (Windows 8+) | [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) |
| W12 | Unbiased interrupt time **excludes** time the system spends in sleep/hibernation; interrupt time includes it | [QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime) |

### 1.2 Product-level guarantees (ours, not Windows')

| # | Guarantee | Enforced by |
|---|---|---|
| X1 | A worker cannot act before the parent releases a request | worker reads one JSON request from stdin before any API call; no action is reachable before that read (native acceptance obligation) |
| X2 | Absence of a durable DISPATCH_INTENT record means no request was released | writer order + fsync, **schema ≥ 2 only** |
| X3 | Record history is append-only and integrity-checked | existing envelope digest + `amend()` semantics |
| X4 | Payload identity is pinned and validated before activation | existing `inventory()`/`validate()` manifest |
| X5 | Only one cooperating installer mutates at a time | existing `Owner` mutex — **does not bind `sc.exe`, other administrators, or the SCM itself** |

Where a claim is neither in 1.1 nor 1.2, this design does not make it.

---

## 2. Existing component inventory and reuse assessment (review §10, mission §5)

| Existing, retained unchanged | Where |
|---|---|
| OS-owned installer mutex, released on death | `nivxforge_transaction.Owner` |
| Atomic durable writes, digest envelope, append-only `history` | `atomic_bytes`, `durable_replace`, `directory_sync`, `Store` |
| Payload manifest inventory/validation | `inventory`, `validate`, `manifest_id` |
| Full SCM configuration capture incl. DACL/`security_safe`, argv, triggers, launch-protected | `nivxforge_scm_worker.main("observe")` |
| Live-image verification, PID/ image binding on RUNNING | `Engine.check` |
| Transaction phases and roll-forward-on-COMMITTED | `Engine.reconcile`, `Engine.run` |
| Predecessor policy (P0-2 — untouched) | `Engine.predecessor`, `WindowsBackend.predecessors` |
| Kill-on-job-close containment of the worker | `WindowsBackend.call` |

| Custom logic **replaced** by a documented OS facility | Replaced by |
|---|---|
| PID polling / `pid == 0` / two-sample "stability" as stop proof | retained **process handle**, waited on (W7/W9) |
| `query_process` re-opening a PID during recovery | the handle retained from creation; PID cannot be re-pointed while held (W7) |
| Custom "quiescence window" for deferred effects | **SERVICE_DISABLED start barrier** (W1/W2) |
| Create-then-assign job gap | `PROC_THREAD_ATTRIBUTE_JOB_LIST` at creation where available (W11) |
| Inferring absence/pending-deletion from presence | **1060** and **1072** returns (W6) |
| Fixed 20 s PENDING loop inside `observe` | caller-driven sampling against an absolute deadline |

| Stays custom, and why |
|---|
| Transaction journal, phases, roll-forward — Windows has no installer transaction primitive |
| Payload manifest/identity — no OS equivalent for our payload semantics |
| H/C/R adjudication vocabulary — a product policy, deliberately not an OS claim |
| Operator reconciliation — an authorisation decision, which no API can make |

No new library, framework or packaging migration is proposed. The reviewer
concurred that none is justified.

---

## 3. D1 — unified deadline, clock and resource contract

### 3.1 Clock contract (review §2, §9/A6, mission §3)

| Clock | Use | Rule |
|---|---|---|
| `T_progress` — unbiased interrupt time (W12) | **all deadlines** | excludes sleep/hibernate, so a suspended machine cannot consume a service's budget |
| `T_elapsed` — interrupt time (W12) | suspend detection | if `ΔT_elapsed − ΔT_progress > SUSPEND_EPSILON`, the machine slept |
| `T_wall` — UTC | **records only** | never compared for a decision; clock steps cannot change a verdict |

Rules:
1. Every operation carries an **absolute** `deadline` on `T_progress`, propagated
   to every callee as `remaining = deadline − now()`. No callee invents a timeout.
2. A callee whose `remaining < its minimum viable slice` **refuses before
   starting**. A partially attempted mutation is worse than a refused one.
3. **Suspend during an operation ⇒ `UNCERTAIN_SUSPENDED`**, never a timeout
   verdict: the SCM and the service were frozen and cannot be judged.
4. **Reboot:** a record whose last durable update precedes the current boot is
   never time-adjudicated. Legacy records carry no boot identifier, so for them
   this rule yields "no time-based conclusion available" (see §5).
5. A deadline breach **never** produces "hung", "failed" or "not applied". It
   produces UNCERTAIN with a classification for the operator.

### 3.2 Segment accounting (replaces B1–B5)

Each segment is separately bounded, separately accounted and separately
classified on breach. Durations are design parameters for G2, not asserted facts.

| Segment | Covers | Breach verdict |
|---|---|---|
| `S_PRE` | elevation check, mutex acquisition (incl. abandoned-mutex consistency check, W10), DACL protect, record enumeration | refuse, no mutation attempted |
| `S_RESTORE` | **barrier restoration** (always first, §4.4) | `HELD_FOR_MANUAL(restoration_pending)` |
| `S_SPAWN` | process creation + job association (W11 or suspended-create) | kill + wait (W7); refuse |
| `S_IDENT` | identity from the retained handle | `NEVER_DISPATCHED` (affirmative: no intent written) |
| `S_PERSIST` | one durable write + fsync + directory sync | `UNCERTAIN_PERSIST`; storage may be unresponsive — no clean-checkpoint promise |
| `S_DELIVER` | the control/config call itself — **up to 30 s documented block** (W2/W3) | `UNCERTAIN_DELIVERY` (ambiguous: the control may or may not have been delivered) |
| `S_TRANSITION` | SCM transition to a final state | `UNCERTAIN_TRANSITION(PENDING_AT_DEADLINE \| STALLED_NO_PROGRESS)` |
| `S_ACK` | worker acknowledgement write + parent read | `UNCERTAIN_ACK` (mutation possibly applied) |
| `S_TEARDOWN` | terminate + **wait on handle** (W7) | worker `UNKNOWN`, never "terminated" |
| `S_OBSERVE` | exactly one non-blocking observation | observation `UNREADABLE` |
| `S_ADJUDICATE` | one record: read, identity, ≤`MAX_OBSERVATIONS`, one persist | that record stays UNCERTAIN; continue |
| `S_POST` | final verification + barrier restoration + verification | `HELD_FOR_MANUAL` |

Composition, with explicit positive reserves:

```
OP(action)   = S_SPAWN + S_IDENT + 2·S_PERSIST + S_DELIVER
             + S_TRANSITION(action) + S_ACK + S_TEARDOWN + RESERVE_OP
WORKER_WAIT  = OP(action) − S_SPAWN − RESERVE_PARENT      (parent > worker, always)
RECOVERY     = Σ_records S_ADJUDICATE + RESERVE_REC
TRANSACTION  = S_PRE + S_RESTORE + RECOVERY
             + Σ_planned OP(action) + S_POST + RESERVE_TX
```

**Containment theorem.** For every parent P and child C,
`C ≤ P − reserve(P)` with `reserve(P) > 0`, hence `C < P` **strictly**, including:

- zero records, zero mutations: `TRANSACTION = S_PRE + S_RESTORE + S_POST + RESERVE_TX > 0` — the zero case has a positive bound covering preflight and postflight (review §2, boundary case).
- one record, zero mutations: `RECOVERY = S_ADJUDICATE + RESERVE_REC < TRANSACTION` because `S_PRE, S_POST, RESERVE_TX > 0` (counterexample 3 resolved).
- `S_DELIVER` is accounted **separately from** `S_TRANSITION`, so the documented 30 s block can no longer be charged to the transition (review §2, "B2 starts too late").
- `S_IDENT` and `S_PERSIST` are bounded segments with failure paths, not a constant asserted to have "no I/O" (review §2, "B1").

### 3.3 Resource ceilings (review §2, "no resource ceiling")

`MAX_RECORDS_PER_RUN`, `MAX_RECORD_BYTES`, `MAX_HISTORY_ENTRIES`,
`MAX_OBSERVATIONS_PER_RECORD`, `MAX_ADJUDICATION_ATTEMPTS`,
`MAX_OPERATIONS_DIR_BYTES`. Exceeding any ceiling ⇒ `HELD_FOR_MANUAL` with a
printed inventory. **Never** silent truncation, **never** deletion, **never**
unbounded enumeration. Enumeration is itself inside `S_PRE`.

### 3.4 The stop-latency bound (review §2, final paragraph)

v1 claimed `--interval` contributes zero. **That was wrong**, and the reviewer is
right: `nivxforge_sensor.py` scales its own internal budgets from the interval —
`acquire_budget_seconds ≈ 0.5 × interval` (line 175), `deliver_budget_seconds ≈
1 × interval` (180), `legacy_drain_budget_seconds ≈ 0.25 × interval` (185) — each
with environment overrides, on top of fixed subprocess timeouts (`wevtutil` 60 s,
`wmic` 20 s, HTTP 30 s × 2 attempts). The interrupted idle sleep contributes
nothing; the remaining cycle contributes a great deal.

v1's replacement — a sensor-owned constant — is also rejected, for a reason v1
missed: **the installer stops the sensor that is already installed, which is a
predecessor build.** No constant shipped in the candidate can bind an older
running sensor. Therefore:

> `S_TRANSITION(stop)` is an **installer policy ceiling**, owner-selected,
> identical for every predecessor, and explicitly **not** a proof of completion.
> Exceeding it yields `UNCERTAIN_TRANSITION`. It is a *wait policy*, never a
> *worst-case completion guarantee* — exactly the distinction the reviewer drew.

Consequence, stated plainly: this design never diagnoses a hung service and
never claims a healthy one. It bounds waiting and classifies the remainder.

---

## 4. D2 — finality, deferred effects and the start barrier

### 4.1 The three judgments

| | Question | Evidence | Who consumes it |
|---|---|---|---|
| **H** | did our request take effect at least once? | §4.2, per action | the audit record, and *only* the audit record |
| **C** | what does the SCM report now? | one observation, stale by W5 | convergence checks (`Engine.check`) |
| **R** | may we mutate now? | §4.3, present machine facts | **every mutation gate** |

H values: `APPLIED`, `PARTIAL`, `NOT_APPLIED`, `UNRESOLVED`,
`UNRESOLVED_ACCEPTED` (operator-closed). **UNRESOLVED is a normal, permanent,
non-blocking outcome.** `NOT_APPLIED` is never inferred from C (review §3;
counterexample 5).

### 4.2 Action-specific H evidence and postconditions (mission §4)

| Action | H = APPLIED requires | H = NOT_APPLIED requires | Partial / special |
|---|---|---|---|
| **stop** | a handle to the targeted service **process instance**, opened while RUNNING **before** delivery, observed **signalled** (W7/W9) | the worker witnessed and journalled an SCM error for the control call itself | handle not retained (legacy) ⇒ UNRESOLVED. `pid == 0` is **not** required and **not** sufficient (W5) |
| **start** | SCM reported RUNNING **and** the reported PID opened to a handle whose creation time is later than our delivery and whose image equals the target | witnessed `ERROR_SERVICE_DISABLED`, `1072`, `ERROR_PATH_NOT_FOUND`, logon failure, etc. | RUNNING with an unverifiable image ⇒ UNRESOLVED |
| **create** | **composite**: `CreateService` ack **and** every `ChangeServiceConfig2` level ack **and** the DACL ack, each journalled | `CreateService` itself failed and no object exists (1060) | any sub-step missing ⇒ **`PARTIAL`**, with an idempotent completion path re-applying only the missing configuration sub-steps (counterexample 7) |
| **delete** | `DeleteService` ack **and** a subsequent `OpenService` → **1060** | witnessed failure with the object intact and unchanged | ack **and** `1072`/handle held ⇒ **`APPLIED_PENDING_REMOVAL`** (W6): deletion is real but incomplete; blocks same-name create; exit = close handles or reboot, then re-verify (counterexample 8) |
| **set_path / config change** | write ack **and** read-back equal to the exact requested value | witnessed failure and read-back equal to the pre-image | a later external change moves **C**, never retracts **H** (counterexample 5) |
| **inhibit (disable)** | write ack **and** read-back `start type == SERVICE_DISABLED` | witnessed failure and read-back unchanged | barrier is only *active* once read-back verifies |
| **restore** | write ack **and** read-back equal to the captured before-image, field by field | witnessed failure | failure ⇒ `HELD_FOR_MANUAL(restoration_pending)` + protection-gap alarm |

Delivery is recorded as `CONTROL_DELIVERED`, never as an outcome; on
`S_DELIVER` breach it is recorded as `DELIVERY_AMBIGUOUS` (W2/W3).

### 4.3 The R predicate — the only mutation gate

| | Requirement | How it is verified now |
|---|---|---|
| R1 | elevated, installer mutex held, abandoned-mutex consistency check done (W10) | present-tense checks |
| R2 | **no live installer worker anywhere** — a *global* check over processes whose image is this installer and whose command line carries the worker flag, plus any handle we still hold | machine-verified, **independent of any record**; denial ⇒ UNKNOWN ⇒ R fails |
| R3 | SCM readable, and the service object's configuration equals the captured pre-image **or** a known target configuration | one observation + `same_config` |
| R4 | **start barrier verified active** (§4.4) for any transaction touching the service | read-back of start type |
| R5 | payload manifest validated | existing `validate()` |
| R6 | no ceiling exceeded, no `HELD_FOR_MANUAL` record outstanding | enumeration in `S_PRE` |

**R never reads H.** R2 being *global* rather than per-record is what dissolves
the legacy and corruption deadlocks: a record with no identity, or an unreadable
one, cannot tell us whether a worker is alive, but the process table can.

### 4.4 Deferred effects: the start barrier (the reviewer's central objection)

Both v1 options are abandoned. We do not wait 60 s, and we do not claim that
removing failure actions empties anything. W1 is explicit on both counts.

**We do not prove the queue is empty. We prove that nothing in it can start the
service while the barrier is up.** W1 names the mechanism — the service must be
*explicitly disabled* — and W2 gives the failure that makes it observable.

Protocol:

| Step | Action | Crash-safety |
|---|---|---|
| **B0** | Preconditions R1, R2, R3, R5 (**not** R4 — this is the narrowly allowed recovery mutation) | refuse if unmet |
| **B1** | Capture the **complete** original configuration (existing `observe` already captures start type, failure actions, failure flag, delayed auto-start, triggers, preshutdown, SID type, privileges, DACL) and write a durable `barrier_record` containing the before-image, the intended barrier, schema version, boot id and UTC — **fsync'd before any change** | WAL: before-image exists before the mutation |
| **B2** | `ChangeServiceConfig(start type = SERVICE_DISABLED)`. Failure actions are **left alone** — changing them proves nothing (W1) and only enlarges the restoration surface | ack journalled |
| **B3** | Verify by read-back; barrier is "active" only after verification | unverified ⇒ refuse, restore, exit |
| **B4** | **Permitted while inhibited:** observe, stop, set_path/config, payload staging, create, delete, adjudication, restoration. **Forbidden:** start (W2 would fail anyway) | — |
| **B5** | Perform the transaction's mutations | each under §4.2 |
| **B6** | **Restore** the before-image field by field, then verify by read-back | failure ⇒ `HELD_FOR_MANUAL(restoration_pending)` + alarm |
| **B7** | Only now may the service be started and `Engine.check` run | start binds to a process instance (§4.2) |

**What the barrier does and does not establish**

- Establishes: while verified-disabled, an SCM-initiated start — failure-action
  restart, delayed auto-start, trigger start — **cannot succeed** (W1/W2).
- Does **not** establish: that no action is queued. After restoration a queued
  restart may still fire.
- Why that residual is acceptable: by B6/B7 the service's configuration and
  payload are already the verified target, so a later queued restart can only
  start the **new, verified** image. The window in which a restart could have
  started a half-mutated configuration is exactly the window the barrier covers.
  This is the argument that makes the design safe; it is stated so a reviewer can
  attack it directly (counterexample 6).
- Does **not** bind an administrator who re-enables and starts the service by
  hand, nor `sc.exe` (X5). Such interference is detected by R3/`check` as a
  configuration or state mismatch and refuses; it is never silently absorbed.

**Protection gap — an explicit, owner-visible cost.** While the barrier is up,
and for as long as any `restoration_pending` persists, the endpoint's EDR sensor
cannot be started by the SCM. A crash inside the window leaves an endpoint
unprotected until recovery runs. Mitigations, all mandatory:

1. `S_RESTORE` is the **first** act of every installer invocation, before any
   adjudication, idempotent from the before-image.
2. The barrier record carries a **lease** (bounded by `TRANSACTION`); an expired
   lease found by any later run forces immediate restoration.
3. Any `restoration_pending` prints `SENSOR DISABLED — PROTECTION GAP` with the
   exact remedy, writes the event log, and makes the exit status non-zero.
4. **Owner decision D-1 (§13):** accept this exposure window, or reject the
   barrier and accept that no deferred-effect exclusion exists at all.

### 4.5 Why two observations are gone

W5 makes repeated sampling worthless as a cancellation barrier, at any spacing.
Stop finality is now a **process-instance** fact (W7/W9); start finality binds to
a creation time and an image. Service-state sampling survives only as **C**.

### 4.6 Operator reconciliation (review §3, P4)

`reconcile-operation` (renamed from `resolve-operation`) requires elevation, the
protected DACL, a readable SCM and an expected-state match. On success it writes
`OPERATOR_ADJUDICATED` with the operator identity, the observation, and this
text: *an authorised reconciliation decision, not machine-proved causation.*

It may set H only to **`UNRESOLVED_ACCEPTED`**. It may **never** set APPLIED or
NOT_APPLIED, and it can satisfy **no** R component — those are machine facts. The
P4-vs-NOT_APPLIED contradiction disappears because attribution left the proof
system entirely: it is now an audit annotation, and the forward decision was
never its consumer.

---

## 5. D3 — legacy records, as actually produced

### 5.1 Baseline defect, independently confirmed in source

`WindowsBackend.call()` records identity via
`operation.amend("REQUESTED", worker_pid=…, worker_token=…, worker_identity=…)`,
and `Store.amend()` builds `entry = {"from": …, "to": …, **evidence}` and appends
it to `history` **without promoting any field to top level**. `worker_state()`
reads `record.get("worker_pid")` only. The reviewer's trace
(`top_level_pid: None`, `history_pid: 1234`, `worker_state: GONE`) is reproduced
by inspection.

Severity is worse than "missing token": with no top-level pid the function takes
its *first* branch and returns **GONE** — it **fails open** for every authentic
record, and the P0-1 tests passed only because they construct top-level identity
by hand (`test_installer_transaction.py` lines 366, 683, 722, 747…). The
history-only shape is therefore the **normal** shape, not an edge case.

### 5.2 Classification of real records

PID validation precedes any API call: reject non-integer, 0 (W8 — error 87 is
also how Windows answers PID 0), and out-of-range values. Only then is a result
interpreted.

| Class | Record as produced | Evidence available | H | Blocks install? |
|---|---|---|---|---|
| **A1** | v1, identity in history, PID valid and absent (error 87 after validation) | that worker is not running | adjudicate per §4.2 from C where possible, else UNRESOLVED | no |
| **A2** | v1, history identity, PID live but the image/command line is not our worker | PID reuse (W7/W8) ⇒ worker gone | as A1 | no |
| **A3** | v1, history identity, PID live **and** it is our worker | worker ALIVE | UNRESOLVED | **yes, with an attainable prerequisite**: let it finish, or let its kill-on-job-close parent exit |
| **A4** | v1, history identity, query **denied** | UNKNOWN (never dead) | UNRESOLVED | yes → prerequisite: elevated re-run; if still denied, `UNRESOLVED_MANUAL` naming PPL/third-party protection |
| **A5** | v1, **no identity anywhere** (crash between `write` and `amend`) | none; no boot id, no timestamp, no dispatch state | **UNRESOLVED, permanently** | **no** — R2 is global (§4.3) |
| **A6** | envelope digest mismatch / unparseable | none | `QUARANTINED`, UNRESOLVED | no, provided R2 holds; the record is never deleted, never rewritten |

**L2 (earlier-boot evidence) is withdrawn as a general route.** No existing record
carries a creation timestamp or boot identifier; filesystem mtime and wall-clock
comparison are not authentic historical evidence and will not be substituted. L2
applies **only** to schema ≥ 2 records that carry `boot_id`, where it is an
optimisation, never a requirement.

**"Reboot converts L3 to L2" is withdrawn.** A reboot terminates the process but
creates no evidence about a legacy record. After a reboot an A3 record becomes A1
**only if the PID is then observed absent** — observed, not assumed
(counterexample 4).

**A5/A6 are the honest residue.** Their history is permanently unresolvable. They
are retained as audit evidence, reported in every run, and **do not block**
installation, because the forward gate is R and R2 is answered by the process
table. **Owner decision D-2 (§13):** accept permanently-unresolved historical
records as a supported outcome.

### 5.3 Supported manual procedure (A4 / A6 / `restoration_pending`)

Prerequisites that can actually be satisfied, replacing v1's "re-run":

1. Elevated prompt with the protected DACL intact.
2. For A4: the live PID's image and command line obtained by the installer and
   **checked** (not asserted) against the worker signature. If it is our worker,
   the exit is to wait or reboot — and after reboot the PID must be **observed**
   absent.
3. For A6: the record is quarantined in place; the operator cannot replace P5.
   The supported outcome is `UNRESOLVED_MANUAL` plus an explicit statement that
   the historical outcome of that operation is unknowable (counterexample 10).
4. For `restoration_pending`: `sc config NivXForgeSensor start= <captured>`
   printed verbatim from the before-image, then re-run recovery to verify.

Each procedure names its prerequisite, its verification and its terminal state.
A procedure whose prerequisite cannot be met returns `UNRESOLVED_MANUAL` — an
explicit terminal outcome, not an invitation to retry. The v1 claim that refusal
is "never a dead end because it is re-runnable" is **withdrawn**; the reviewer is
correct that repetition manufactures no evidence.

---

## 6. D4 — identity, containment and write-ahead dispatch

### 6.1 Ordered protocol

| Step | Action | Failure handling |
|---|---|---|
| **S1** | Create the job **and** associate at creation via `PROC_THREAD_ATTRIBUTE_JOB_LIST` (W11). Where unavailable: create **suspended**, assign, then resume | creation/assignment failure ⇒ `TerminateProcess` **and wait on the handle** (W7); if the wait does not signal ⇒ worker `UNKNOWN`, never "terminated". An empty job is not containment (review §5/S1) |
| **S2** | stdin is a private, non-inherited pipe, unwritten (X1) | EOF, malformed JSON and oversized input are contracted worker-side: the worker exits without acting; inheritance is explicitly disabled |
| **S3** | Identity from the **retained handle**: creation time, image, handle kept open for the operation's lifetime so the PID cannot be re-pointed (W7) | query failure ⇒ identity failure ⇒ S5 |
| **S4** | Persist identity **top-level** (schema 2), fsync + directory sync, read back | persist failure ⇒ `UNCERTAIN_PERSIST`; terminate and wait |
| **S5** | **Identity failure ⇒ no dispatch.** Terminate, wait on handle, write `NEVER_DISPATCHED` (affirmative: no intent record exists) | a failed termination is `UNKNOWN`, never "proved dead" (review §5/S5) |
| **S6** | Persist **`DISPATCH_INTENT`** — fsync'd — *before* anything is written to the pipe | the WAL boundary |
| **S7** | Write the request to the pipe | partial write ⇒ `UNCERTAIN_DISPATCH` |
| **S8** | Worker acts, writes its acknowledgement incl. the witnessed API return | ack is **H evidence**, not finality and not transaction completion (review §5/S8) |

### 6.2 The S7 counterexample, resolved

The reviewer's sequence — identity persisted, request sent, mutation executed,
parent crashes before `dispatched_at` — is resolved by **ordering, not by a
field**: the intent is durable *before* the pipe write, so the window the
reviewer identified no longer exists. The inverse window (intent durable, nothing
sent) is resolved **conservatively**:

| Durable state | Interpretation |
|---|---|
| no intent, schema ≥ 2 | `NEVER_DISPATCHED` — affirmative, from X2 (writer order + fsync) |
| no intent, schema 1 | **`UNCERTAIN_DISPATCH`** — the old writer gives no such guarantee (review §5, final rule) |
| intent, no ack | `UNCERTAIN_DISPATCH` — possibly applied; adjudicate per §4.2 |
| intent + ack | H evidence available |

Filesystem persistence and pipe delivery are **not** made atomic, and this design
does not pretend otherwise: the interval between them is explicitly a
possibly-dispatched state with a conservative verdict.

### 6.3 Authoritative record schema v2 (one writer, one reader)

```
schema            2
id                operation id (= filename stem)
action            stop|start|create|delete|set_path|inhibit|restore
request           exact requested parameters (e.g. binpath, config digest)
created_utc       audit only
created_progress  unbiased interrupt time at creation
boot_id           current boot identity
worker            { pid, created_filetime, image, handle_retained: bool }   ← TOP LEVEL
dispatch          { intent_at, sent: bool|unknown, ack_at, api_return }
h_state           APPLIED|PARTIAL|NOT_APPLIED|UNRESOLVED|UNRESOLVED_ACCEPTED|
                  APPLIED_PENDING_REMOVAL|QUARANTINED
c_last            last observation summary (stale by W5)
barrier           { before_image, applied_at, verified, lease_until, restored_at }
history           append-only; every entry carries its basis
envelope          sha256 over the canonical record
```

Reader rules:

- **schema 2:** top-level only. Writer and reader are the same contract, and a
  conformance test asserts that every field the writer emits is a field the
  reader consults (the defect in §5.1 becomes a test, not a hope).
- **schema 1:** read top-level, then **fall back to scanning `history`** for
  identity. This is the history-only class and it is now first-class.
- **Interpretation never rewrites.** A v1 record is never upgraded in place.
  Derived interpretations are **appended** with their basis, preserving the
  original evidence exactly (mission D3).
- Unknown future schema ⇒ `HELD_FOR_MANUAL`, never a guess.

---

## 7. Transaction state machine (revised)

```
                     ┌──────────────── every invocation ────────────────┐
                     │  S_PRE → RESTORE_BARRIER(if any) → RECOVERY      │
                     └──────────────────────┬───────────────────────────┘
                                            │ R satisfied
      PREPARING → STAGED → PREPARED → BARRIER_ACTIVE → STOPPED
                                            │
                           CONFIGURED → ACTIVATED → COMMITTED
                                            │                  (roll forward)
                 BARRIER_RESTORING → BARRIER_RESTORED → VERIFIED → COMPLETE
            any crash before COMMITTED
                 → ROLLING_BACK → BARRIER_RESTORING → ROLLED_BACK
            ¬R, ceiling, restoration failure, unknown phase, schema
                 → HELD_FOR_MANUAL  (terminal until an operator prerequisite is met)
```

Rulings added for the reviewer's §6 table:

- **Barrier states are first-class phases.** v1 proposed a configuration mutation
  with no restoration states; `BARRIER_ACTIVE`, `BARRIER_RESTORING`,
  `BARRIER_RESTORED` make restoration part of the machine, and restoration
  precedes activation on the forward path and precedes completion on the
  rollback path.
- **COMMITTED is split** by the durability of the commit record itself:
  `COMMIT_PENDING` (commit intent durable, phase replacement not yet durable) is
  resolved by roll-forward; only `COMMITTED` is a replaced phase. Interruption
  before and after durable commit persistence are now distinct (review §6).
- **COMPLETE / ROLLED_BACK revalidation** includes the barrier before-image: a
  completed transaction must show the service's full original start type and
  failure configuration, not merely the right binPath.
- **`HELD_FOR_MANUAL` is legitimate only with a named prerequisite** or an
  explicit `UNRESOLVED_MANUAL`.
- **`INDETERMINATE` is removed.** It was called terminal and then transitioned.
  Its cases are now `UNRESOLVED` (open, non-blocking) or `UNRESOLVED_ACCEPTED`
  (operator-closed).
- **`FINISHED`** from the existing worker ack is mapped into the vocabulary as
  "ack present" — an H input, not a settled state.

## 8. Recovery state machine (per record)

```
QUARANTINED ◄── envelope invalid ── READ
                                     │ valid
RESERVED ──no intent, schema≥2────► NEVER_DISPATCHED            (terminal)
   │  no intent, schema 1
   └──────────────────────────────► UNCERTAIN_DISPATCH ─┐
INTENT_DURABLE ─────────────────────────────────────────┤
   │ ack present                                        │
ACKED ──────────────────────────────────────────────────┤
                                                        ▼
                                          ┌──── worker liveness ────┐
                                   ALIVE ─┤ refuse (prerequisite)   │
                                 UNKNOWN ─┤ refuse (elevated/manual)│
                                    GONE ─┤ adjudicate H per §4.2   │
                                          └────────────┬────────────┘
                 APPLIED | PARTIAL | NOT_APPLIED | APPLIED_PENDING_REMOVAL
                 | UNRESOLVED (open, NON-BLOCKING) | UNRESOLVED_ACCEPTED
```

`PARTIAL` has an idempotent completion path; `APPLIED_PENDING_REMOVAL` has a
handle-closure/reboot path; `UNRESOLVED` simply persists. **No state in this
machine blocks a mutation; only ¬R does.**

## 9. Failure and interruption matrix

| # | Failure | Detection | H | Forward effect |
|---|---|---|---|---|
| F01 | slow but healthy stop within policy | handle signalled | APPLIED | proceed |
| F02 | stop exceeds the policy ceiling | `S_TRANSITION` breach | UNRESOLVED | R still decidable ⇒ may proceed or refuse on R3 |
| F03 | service genuinely hung | same as F02 — **indistinguishable by design** | UNRESOLVED | operator diagnosis |
| F04 | service settles on the wrong final state | C ≠ target | **not** NOT_APPLIED | rollback/retry under R |
| F05 | control call blocks 30 s then fails (W2/W3) | `ERROR_SERVICE_REQUEST_TIMEOUT` | `DELIVERY_AMBIGUOUS` | re-adjudicate |
| F06 | parent killed mid-operation | job kill-on-close; handle wait | per §4.2 | recovery |
| F07 | queued restart fires after restoration | C changes to RUNNING on the **target** image | H unaffected | tolerated by §4.4; `check` verifies the image |
| F08 | queued restart would fire mid-transaction | prevented while barrier verified (W1/W2) | — | — |
| F09 | process query denied | UNKNOWN | UNRESOLVED | R2 fails ⇒ elevated/manual |
| F10 | PID reuse | handle retained / image mismatch | per §4.2 | proceed |
| F11 | identity acquisition fails | `S_IDENT` | `NEVER_DISPATCHED` | retry install |
| F12 | crash between identity and intent | no intent, schema 2 | `NEVER_DISPATCHED` | retry install |
| F13 | crash between intent and pipe write | intent, no ack | `UNCERTAIN_DISPATCH` | adjudicate |
| F14 | crash after mutation, before ack | intent, no ack | adjudicate per §4.2 | proceed if R |
| F15 | legacy history-only identity | schema-1 fallback | per A1–A4 | proceed unless A3/A4 |
| F16 | legacy record with no identity (A5) | — | UNRESOLVED permanent | **proceeds** (R2 global) |
| F17 | corrupt envelope (A6) | digest | QUARANTINED | proceeds if R2 holds |
| F18 | create partially applied | missing sub-step acks | PARTIAL | idempotent completion |
| F19 | delete pending with open handles | 1072 / not 1060 (W6) | APPLIED_PENDING_REMOVAL | blocks same-name create |
| F20 | barrier applied, crash before restore | barrier record + lease | — | **restoration first**, protection-gap alarm |
| F21 | restoration fails | read-back mismatch | — | `HELD_FOR_MANUAL(restoration_pending)` |
| F22 | external `sc.exe` change mid-transaction | R3 / `check` mismatch | — | refuse; never absorbed |
| F23 | machine sleeps mid-operation | `T_elapsed − T_progress` (W12) | `UNCERTAIN_SUSPENDED` | re-adjudicate, no timeout verdict |
| F24 | reboot mid-operation | `boot_id` mismatch (v2) / none (v1) | no time verdict | adjudicate by evidence only |
| F25 | storage unresponsive at persist/cleanup | `S_PERSIST`/`S_POST` breach | `UNCERTAIN_PERSIST` | **no clean-checkpoint promise** |
| F26 | ceilings exceeded | `S_PRE` enumeration | — | `HELD_FOR_MANUAL` + inventory |
| F27 | abandoned mutex found | W10 | — | consistency check before any mutation |
| F28 | two installers | X5 mutex | — | refuse |

## 10. Acceptance tests (positive · negative · adversarial)

Positive — P-01 segment accounting totals equal the measured elapsed decomposition; P-02 containment holds for 0 records/0 mutations and 1 record/0 mutations; P-03 absolute deadline propagation refuses a callee with insufficient remaining budget; P-04 `observe` returns PENDING immediately, never blocking; P-05 ack completes inside the parent wait when the transition consumes the whole ceiling; P-06 suspend injection yields `UNCERTAIN_SUSPENDED`, not a timeout; P-07 stop finality from a signalled handle, with `pid != 0` still present; P-08 start finality binds creation time + image; P-09 create `PARTIAL` completes idempotently; P-10 delete `APPLIED_PENDING_REMOVAL` with a held handle, then completes on closure; P-11 barrier apply → verify → restore → verify, field by field; P-12 restoration runs first on the next invocation after an injected crash; P-13 **authentic** history-only records (produced by the real writer, not hand-built) are read correctly; P-14 A5 record present ⇒ installation still proceeds; P-15 request-received counters and SCM mutation counters agree across an interruption at every one of the eight dispatch boundaries; P-16 "applied, then externally reversed" ⇒ H stays APPLIED, C differs, no false NOT_APPLIED; P-17 interrupted persistence and interrupted restoration both recover; P-18 ceilings trip into `HELD_FOR_MANUAL` with nothing deleted.

Negative — N-01 PENDING never settles H; N-02 UNREADABLE never settles H; N-03 denied query never reads as dead; N-04 PID 0 / malformed / out-of-range never interpreted as absence (W8); N-05 failed termination never reported as terminated (W7); N-06 current state alone never yields NOT_APPLIED; N-07 operator cannot set APPLIED/NOT_APPLIED and cannot satisfy any R component; N-08 operator claim contradicting the SCM is refused; N-09 no path deletes, renames or rewrites a record; N-10 a missing budget refuses instead of defaulting; N-11 identity failure never dispatches; N-12 schema-1 record with no intent is never `NEVER_DISPATCHED`; N-13 unknown schema is never guessed; N-14 start is refused while the barrier is active; N-15 barrier is never reported active without a verifying read-back; N-16 a transaction never completes with `restoration_pending`.

Adversarial, from the reviewer's ten — A-01 dispatch/persistence split (F13); A-02 history-only identity against the real writer (F15); A-03 single-record budget containment (P-02); A-04 legacy reboot gap: PID reused after reboot with no prior-session evidence ⇒ must not conclude (F24); A-05 applied-then-reversed (P-16); A-06 restart queued before the barrier, fires after restoration onto the target image (F07); A-07 partial creation (F18); A-08 pending deletion with an open handle (F19); A-09 repair deadlock: an UNCERTAIN record must not prevent applying the barrier (B0 excludes R4) and must not prevent the transaction (R excludes H); A-10 irrecoverable checksum failure ⇒ `UNRESOLVED_MANUAL`, with no retry and no attribution workaround.

**Controls must be real.** A negative control that mocks `armed=False`,
`attribution=True` or a settled record assumes the disputed guarantee and is not
evidence. Native tests must establish their preconditions and must demonstrate a
deliberately defective control **failing** (review §11).

## 11. Linux/simulation vs native Windows proof matrix

| Provable on Linux with the synthetic SCM | Requires native Windows |
|---|---|
| Segment arithmetic, containment, boundary cases, deadline propagation | Real `ControlService`/`StartService` 30 s blocking and `ERROR_SERVICE_REQUEST_TIMEOUT` (W2/W3) |
| Both state machines and every transition | Real CheckPoint/WaitHint emission and real stop latency of each **predecessor** sensor |
| H/C/R separation; all H outcomes incl. PARTIAL and PENDING_REMOVAL logic | `SERVICE_DISABLED` actually preventing a **queued** restart (W1/W2) |
| Record schema v2 writer/reader conformance; schema-1 history fallback | Real `OpenProcess` error codes incl. 87 and ACCESS_DENIED under PPL/third-party protection (W8) |
| Dispatch ordering S1–S8 and all eight interruption points | Job association at creation (W11), kill-on-job-close, handle lifetime (W7) |
| PID validation rules; refusal and message contracts | Signalled-handle stop proof on a real service process |
| Ceilings, quarantine, append-only history | `1060`/`1072` deletion semantics with handles held (W6) |
| Simulated suspend/clock-step behaviour | Real sleep/resume and unbiased-time behaviour across supported Windows generations (W12) |
| | Abandoned-mutex acquisition and consistency check (W10) |
| | Reboot and power-loss durability of every record and the barrier |
| | Preservation of endpoint identity, tenant state, credentials, journal, cursors and queued evidence across install/upgrade/rollback |

**Windows-native evidence: NOT RUN. End-to-end acceptance: NOT RUN.**

## 12. Minimal bounded G2 proposal (NOT implemented, NOT authorised)

Ordered so that each step is independently testable and the two critical
fail-open defects are closed first.

| # | Scope | Test |
|---|---|---|
| G2-1 | Record schema v2 + one writer/reader contract + schema-1 history fallback. **Closes the §5.1 fail-open.** | P-13, N-12, N-13, writer/reader conformance |
| G2-2 | Write-ahead dispatch intent, `NEVER_DISPATCHED` only on affirmative evidence, handle-based identity, terminate-and-wait | P-15, F11–F14, N-05, N-11 |
| G2-3 | H/C/R separation; R as the sole mutation gate; R2 global worker check | P-14, A-09, N-06 |
| G2-4 | Action-specific H contracts incl. PARTIAL and APPLIED_PENDING_REMOVAL | P-07–P-10, F18, F19 |
| G2-5 | Barrier apply/verify/restore/verify + barrier phases + restoration-first + lease + protection-gap alarm | P-11, P-12, N-14–N-16, F20, F21 |
| G2-6 | Segment budgets, absolute deadlines, dual clock, suspend rule, ceilings | P-01–P-06, F23, F25, F26 |
| G2-7 | Legacy classes A1–A6 and their manual procedures | P-13, A-02, A-04, A-10 |
| G2-8 | `reconcile-operation` narrowed to `UNRESOLVED_ACCEPTED` | N-07, N-08 |
| G2-9 | Native acceptance scenarios authored (not run) + declare the `mslex` test dependency | static review only |

Out of scope: P0-2, sensor collection/delivery/detection, backend/XDR, frontend,
packaging migration, any new product feature.

## 13. Owner decisions required

| ID | Decision | If refused |
|---|---|---|
| **D-1** | Accept the start-barrier protection gap (service disabled for the transaction window, and until any `restoration_pending` is cleared) in exchange for the only documented deferred-effect exclusion (W1) | no deferred-effect exclusion exists; every stop adjudication stays UNRESOLVED and the installer can only converge on configuration, never on history |
| **D-2** | Accept permanently-unresolved historical records (classes A5/A6) as a supported audit outcome | installation remains blocked by legacy records, as in `bc8147be` |
| **D-3** | Select the supported Windows envelope (W11 job-at-creation availability; W12 clock behaviour across generations) | the spawn/assignment gap keeps a suspended-create fallback on every platform |
| **D-4** | Choose the stop wait **policy** ceiling, acknowledging it is not a completion guarantee for any predecessor sensor | no bound can be stated |
| **D-5** | Supply the approved **G0–G6** assessment | conformance remains uncertifiable, as the reviewer noted |

## 14. Residual uncertainty — stated, not resolved

1. A queued SCM action can never be enumerated (W1). The barrier excludes its
   *effect* while active; it does not inventory the queue.
2. Service-state observation is inherently stale (W5). Nothing in this design
   treats C as proof of anything.
3. Classes A5/A6 are permanently unresolvable for H.
4. "Hung" and "slow" remain indistinguishable (F02 vs F03), by design.
5. Persistent query denial (A4) and unresponsive storage (F25) terminate in
   manual outcomes, not automatic recovery.
6. X1 (the worker cannot act before its first stdin read) is a code-structure
   guarantee whose frozen-build, inherited-handle and EOF behaviour is a native
   acceptance obligation.
7. No claim in §1.1 has been exercised on Windows by this project.

---

## 15. Finding → correction traceability

| Review finding | Correction | Section |
|---|---|---|
| §2 B5 excludes operation time | Segment model; `TRANSACTION` includes `S_PRE`, `S_RESTORE`, per-op `OP()`, `S_POST`, `RESERVE_TX` | 3.2 |
| §2 containment fails at boundaries | Positive reserves ⇒ strict containment; 0/0 and 1/0 cases proven | 3.2 |
| §2 B1 not a hard bound | `S_SPAWN`/`S_IDENT`/`S_PERSIST` separated, each with a failure path | 3.2 |
| §2 B2 starts too late; `ControlService` 30 s | `S_DELIVER` is its own segment; `DELIVERY_AMBIGUOUS` (W2/W3) | 3.2, 4.2 |
| §2 B4 incomplete | `S_ADJUDICATE` covers identity, reads, observations, persistence, with `MAX_OBSERVATIONS` | 3.2, 3.3 |
| §2 no resource ceiling | Six explicit ceilings ⇒ `HELD_FOR_MANUAL` | 3.3 |
| §2 interval premise wrong | Corrected with source lines; replaced by an installer **policy** ceiling | 3.4 |
| §2 predecessor behaviour | Policy ceiling applies to every predecessor; no sensor constant is trusted | 3.4 |
| §2 clocks, sleep, resume, reboot | Dual-clock contract; `UNCERTAIN_SUSPENDED`; boot rule | 3.1 |
| §2 cleanup may be impossible | `S_PERSIST`/`S_POST` breach ⇒ `UNCERTAIN_PERSIST`, no clean-checkpoint promise | 3.2 |
| §2 termination asynchronous | Terminate **and wait on handle**; failure ⇒ UNKNOWN (W7) | 6.1 |
| §3 P1 insufficient | H requires per-action instance evidence, not worker death | 4.2 |
| §3 P2 not historical proof | C is separated from H entirely | 4.1 |
| §3 P3 unspecified | Replaced by the verified start barrier; the queue is never claimed empty | 4.4 |
| §3 P4 contradicts NOT_APPLIED | Attribution removed from the proof system; operator may set only `UNRESOLVED_ACCEPTED` | 4.6 |
| §3 P5 insufficient | `QUARANTINED` + `UNRESOLVED_MANUAL`; no operator substitute | 5.2, 5.3 |
| §3 60 s rejected | Withdrawn | 4.4 |
| §3 removing failure actions rejected | Withdrawn; failure actions are left untouched (W1) | 4.4 |
| §3 inhibition needs a full contract | B0–B7: capture, WAL, verify, permitted ops, crash recovery, restoration ordering, failure handling | 4.4 |
| §3 circular dependency | R excludes H; the barrier itself is gated by R1–R3+R5, not R4 | 4.3, 4.4 |
| §3 stop then external restart | H/C separation; H is not retracted | 4.1, F07 |
| §3 mutex does not serialise `sc.exe` | Stated as X5; external change ⇒ R3/`check` refusal | 1.2, F22 |
| §3 two observations prove nothing | Removed; replaced by instance evidence (W5/W7/W9) | 4.5 |
| §3 STOPPED-PID replacement | Retained handle, signalled (W7/W9); `pid == 0` neither required nor sufficient | 4.2 |
| §4 L1 error 87 / PID 0 | Validate identifiers first (W8); denial stays UNKNOWN | 5.2 |
| §4 L2 unusable | Withdrawn; schema ≥ 2 only | 5.2 |
| §4 reboot claim unsupported | Withdrawn; post-reboot absence must be observed | 5.2 |
| §4 L3 identity rules | Handle-based identity; image + worker-flag checked by the installer | 5.2, 5.3 |
| §4 unrecoverable cases | A5/A6 declared permanently unresolved, non-blocking, with procedures | 5.2, 5.3 |
| §5 S1 empty job | Associate at creation (W11) or suspended-create | 6.1 |
| §5 S2 EOF/inheritance | Contracted worker-side; non-inherited pipe | 6.1 |
| §5 S3 assignment failure | Terminate + wait; defined cleanup | 6.1 |
| §5 S4 stable handle | Identity from the retained handle | 6.1 |
| §5 S5 failed termination | Never "proved dead" | 6.1 |
| §5 S6 versioned schema | Schema v2 + conformance test | 6.3 |
| §5 **S7 missing boundary** | Write-ahead `DISPATCH_INTENT` **before** the pipe write | 6.2 |
| §5 S8 ack ≠ finality | Ack is H evidence only | 6.1 |
| §5 legacy must not imply never-dispatched | Schema-1 ⇒ `UNCERTAIN_DISPATCH` | 6.2 |
| §5 `amend()`/`worker_state()` mismatch | Confirmed **fail-open** (returns GONE); one writer/reader contract + history fallback | 5.1, 6.3 |
| §6 INDETERMINATE terminality | Removed | 7 |
| §6 NEVER_DISPATCHED unsafe | Affirmative evidence only, schema-aware | 6.2 |
| §6 NOT_APPLIED from opposite state | Forbidden; R is the retry predicate | 4.1, 4.3 |
| §6 FINISHED unintegrated | Mapped to "ack present" | 7 |
| §6 no barrier restoration states | Barrier phases added | 7 |
| §6 COMMITTED durability split | `COMMIT_PENDING` vs `COMMITTED` | 7 |
| §6 "re-runnable" claim false | Withdrawn; prerequisites or `UNRESOLVED_MANUAL` | 5.3 |
| §6 F16 contradiction | `QUARANTINED` + explicit unknowable outcome | 5.2, 5.3 |
| §7 matrix gaps F01–F22 | 28-row matrix | 9 |
| §7 test gaps | 18 positive, 16 negative, 10 adversarial, with real controls | 10 |
| §8 counterexamples 1–10 | A-01 … A-10 | 10 |
| §9 C1–C6 / A1–A6 | Interval premise corrected; armed-action observability abandoned; reboot claim withdrawn; error 87 narrowed; no finality fence claimed; abandoned-mutex consistency added; X1 made a native obligation | 1.2, 3.4, 4.4, 5.2, 14 |
| §10 nine corrections | §12 G2-1 … G2-9 | 12 |
| §11 evidence classes | §11 proof matrix | 11 |
| §13 owner decisions | D-1 … D-5 | 13 |

---

**STATUS: G1 CORRECTED DESIGN v2 — READY FOR INDEPENDENT REVIEW.**

Not a PASS, not self-approved. The authors of `bc8147be` and of v1 (this agent)
are ineligible to review it. G2 remains NOT AUTHORIZED pending an independent G1
review and owner decisions D-1 … D-5. Release/rollout HOLD. Windows-native and
end-to-end evidence: **NOT RUN**. No source was modified in producing this design.
