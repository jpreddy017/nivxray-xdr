# NIVXFORGE EDR · IMPLEMENTATION PLAN (POST-AUDIT)

Derived **only** from `NIVXFORGE_EDR_CISCO_GAP_MATRIX.md` (read-only
audit, 2026-09-26). Nothing here has been started. **No implementation,
code, sensor, CSS or test change was made while writing this plan.**

Every item states: the measured gap it closes, what will be built, and
the **acceptance evidence** required before it may be called done. The
evidence standard is the owner's: a code path plus a passing
deterministic test **or** a reproducible live proof, cited.

Sequencing rules applied:

1. **Correctness and authority before capability.** A destructive verb
   without authority, or a verdict that is discarded, gets worse with
   scale.
2. **Field completeness before new event classes.** New classes on top of
   unmeasured `null` rates multiply unusable evidence.
3. **Never widen a claim before the release declaration can carry it.**
   `catalog.py` remains the single source the policy authority reads.
4. **No Windows capability is signed off without a real Windows host**
   (Gate 1 stays BLOCKED, not waived).

---

## P0 — Correctness, authority and evidence integrity

### P0.A · Response authority (RBAC + separation of duties)
*Closes:* critical gap 1 / family E / family L (**C3**).
*Build:* action-level authority for `KILL_PROCESS`, `ISOLATE_ENDPOINT`,
`RELEASE_ISOLATION`; an approver who cannot be the requester for
containment; explicit `AUTHORIZATION_DENIED` records; every decision on
the audit surface.
*Acceptance:* deterministic tests proving (a) an under-privileged
principal is refused, (b) self-approval of containment is refused the way
`SELF_APPROVAL_REFUSED` already works for exclusions, (c) a denied
command never reaches `claim_pending`, (d) cross-tenant request still
403s; plus a live proof against the preview host. No new response verb
ships in this item.

### P0.B · Exclusion scope (`COLLECTION | DETECTION | PREVENTION`)
*Closes:* critical gap 2 / family F.
*Build:* a scope axis on the exclusion contract, defaulting to
`DETECTION` — suppress the verdict, keep the evidence. `COLLECTION` stays
available and must be chosen explicitly, with the evidence-loss
consequence stated at the point of choice. Endpoint evaluator continues
to refuse what it cannot honour.
*Acceptance:* tests proving a `DETECTION`-scoped exclusion delivers the
event and suppresses the finding, a `COLLECTION`-scoped exclusion still
drops before the outbox, existing exclusions migrate to an explicit scope
with no silent reinterpretation, and the byte-identical-evaluator test
still passes; live enforcement-proof delta re-run.

### P0.C · Findings persistence, read path and surface
*Closes:* critical gap 3 / family C / family G.
*Build:* give `fabric/store.persist` a caller on the authenticated ingest
path; tenant-partitioned read API; the Detections surface reads findings
rather than derivations.
*Acceptance:* `edr_findings` non-zero from real ingest; idempotency test
(same evidence + same analyzer version + same features ⇒ no duplicate);
cross-tenant read refusal test; a live proof that a detected event
produces exactly one persisted finding with resolvable `evidence_refs`.

### P0.D · Policy provenance on evidence
*Closes:* critical gap 4 / family B.
*Build:* stamp `policy_id`, `policy_version`, `config_digest` on the
evidence row at authenticated ingest, sourced from the endpoint's
acknowledged state — never from the request body.
*Acceptance:* test proving the stamp comes from the ACKed state and
cannot be asserted by a sensor; a query that reconstructs "which policy
governed this event"; `OUT_OF_SYNC` endpoints stamp the *acknowledged*
version, not the assigned one.

### P0.E · Telemetry field completeness (before new classes)
*Closes:* family A field-level gap / critical gap 8.
*Build:* measured null-rate reporting per field per endpoint;
close the resolvable cases (`image_path`, `command_line`, `user`,
`sha256`) and declare the unresolvable ones as `NOT_OBSERVABLE` with the
reason, never as absence of activity.
*Acceptance:* a completeness metric exposed and asserted by test;
before/after null rates recorded on the real Linux sensor; every
remaining null carries a declared reason.

### P0.F · Drop accounting and sensor resource metering
*Closes:* critical gap 5 / family J.
*Build:* `DROPPED_EVENT_COUNT`, `DROP_REASON`, `QUEUE_PRESSURE`, first
and last dropped timestamps, plus sensor CPU/memory/disk/event-rate
self-measurement, all on the heartbeat.
*Acceptance:* a forced-pressure test proves counters increment and are
reported; `ZERO` and `UNKNOWN` become distinguishable on the console.

### P0.G · Windows object telemetry (process → file → network → registry)
*Closes:* family A Windows rows / Gate 1 / Gate 2.
*Build:* real object telemetry on Windows, in that order, with the same
canonical fields and the same honest `not_observed` discipline as Linux;
`catalog.py` declarations advance **only** per capability actually
shipped.
*Acceptance:* per class — a deterministic test on a captured real record
set, **and** live proof on an owner-provided Windows host (install,
policy ACK, telemetry, exclusion enforcement, no source rebuild). Gate 1
remains BLOCKED until that host exists. Nothing here is simulated.

### P0.H · Response verb declaration correction
*Closes:* family K PARTIAL (**C1**).
*Build:* a response-action axis in the release declaration so a proven
`KILL_PROCESS` and the Linux containment engine are declared, and an
undeclared verb is refused by the authority.
*Acceptance:* test proving the authority refuses a verb the running
connector version does not declare, per OS, and accepts a declared one.

---

## P1 — Detection depth, prevention v1, release integrity

* **P1.1 · Endpoint-local deterministic detection + offline decision
  plane.** EDR-owned endpoint rule content, evaluated on the sensor,
  cached for offline operation. *Acceptance:* a benign negative test
  alongside every malicious positive; detection identical online and with
  the network severed; content version reported and ACKed like policy.
* **P1.2 · Prevention v1: terminate-on-detection and quarantine with
  restore.** *Acceptance:* the quarantined artifact is recoverable
  byte-for-byte; a refused prevention is reported as refused; the release
  declaration flips only after the live proof.
* **P1.3 · Retrospection.** Re-evaluate stored evidence with new content
  without rewriting provenance (Gate 6, unblocked by P0.C).
  *Acceptance:* a new finding generation appears with the original
  evidence untouched.
* **P1.4 · File Trajectory + estate-wide SHA-256 pivots.**
  *Acceptance:* every node resolves to an `evidence_ref`; measured
  performance on the real corpus.
* **P1.5 · Outbreak Control lists** (simple custom detections, blocked /
  allowed application lists, IP block lists) with two-operator approval,
  reusing the exclusion authority pattern.
* **P1.6 · Connector and policy signing, build ID, SBOM.**
  *Acceptance:* an unsigned or tampered artifact/policy is refused by the
  endpoint, proven by test.
* **P1.7 · Connector self-protection**: authenticated uninstall, tamper
  detection, command anti-replay, remote upgrade with rollback.
* **P1.8 · Gate 12 responsive closure.** Restructure away from
  fixed-width layouts. *Acceptance:* the full mobile assertion set passes
  in **both** themes on the real SPA (currently 30/30 failing;
  recurrence count 2).
* **P1.9 · Audit export + immutability**, and the deferred **weekly
  exclusion digest** (owner-deferred; still not started).
* **P1.10 · Evidence-ref resolvability assertion** across trajectory,
  process tree and campaign story (converts three
  `IMPLEMENTED + UNPROVEN` rows).
* **P1.11 · `AUDIT` policy mode and safe rollback** with ACK-verified
  revert.

---

## P2 — Advanced capability and reach

* **P2.1 · Live Query** (on-demand endpoint interrogation) with a bounded
  query language and per-query audit.
* **P2.2 · Forensic snapshot + file retrieval** with chain-of-custody.
* **P2.3 · Behavioural / sequence / injection / persistence /
  ransomware engines** on the telemetry P0.E–P0.G makes trustworthy.
* **P2.4 · ML scoring — only with a validated model.** No interface is to
  be shipped before a measured model exists; false-positive and
  false-negative rates must be published with it.
* **P2.5 · Exploit and memory protection** (requires a kernel/ETW-grade
  component — a scope decision, not an increment).
* **P2.6 · macOS connector.**
* **P2.7 · Public documented EDR API**, scoped tokens, SIEM connectors,
  alert egress, scheduled reporting and the compromise roll-up.
* **P2.8 · Filter taxonomy baseline** — blocked on the owner's verbatim
  43 items (`capability/taxonomy.py` refuses a partial list by design).

---

## Standing constraints

* Gate 1 (Windows real-host proof) is **BLOCKED on an owner-provided
  host** and must never be simulated.
* `catalog.py` remains the only place a capability is declared; no
  surface may claim enforcement the released artifact does not perform.
* No capability moves to `IMPLEMENTED + PROVEN` without a cited test or
  live proof.
* `tests/edr` baseline to hold at **425 passed / 0 failed** or better
  through every item.
