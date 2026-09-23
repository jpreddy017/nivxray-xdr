# G1 · DEAD-LETTER ACCOUNTABILITY — ROOT-CAUSE / CONTRACT INVENTORY

**Status: analysis only. Nothing implemented, nothing fixed, no G1 artefact touched.**
Owner decision required before any implementation.

Scope of the discrepancy under investigation (owner-supplied endpoint capture vs
measured Preview server state):

| measurement | value | source |
|---|---|---|
| endpoint durable rows | 125,452 | endpoint outbox |
| endpoint dead-lettered | 14,868 | endpoint outbox |
| endpoint delivered at capture | 2,884 | endpoint outbox |
| endpoint retrying | 125 | endpoint outbox |
| endpoint queued | 107,525 | endpoint outbox |
| server canonical events | 2,876 | `xdr_canonical_events` (tenant `ten_f1a5…`) |
| server canonical evidence | 2,876 | `xdr_canonical_evidence` |
| server dedupe claims | 2,876 | `xdr_ingest_dedupe` |
| server durable refusals | **26** | `xdr_ingest_routing_blocks` |

---

## 1 · Measured current architecture

### 1.1 Endpoint side (`apps/nivxray-xdr-collector`)

`framework/delivery.py` — one POST per envelope (`delivery_worker.py:91-104`,
"Phase B.5 delivers per-row so per-row status is authoritative"). Outcome mapping
(`delivery.py:127-146`):

```
2xx                          -> OK        -> mark_delivered
408, 429, 5xx                -> RETRYABLE -> mark_retry (backoff)
transport / timeout error    -> RETRYABLE -> mark_retry
ingest_not_configured        -> RETRYABLE -> mark_retry
ANY OTHER 4xx                -> FATAL     -> mark_dead   <-- terminal, first attempt
```

`mark_dead()` (`framework/outbox.py:338`) is terminal and immediate — **no attempt
threshold applies to a 4xx**. `mark_retry()` (`:312-336`) is the only path that
consults `_max_attempts` (`DEFAULT_MAX_ATTEMPTS = len(DEFAULT_BACKOFF_SECONDS)`).

The only thing recorded for a terminal failure is `last_error`, and its value is
built at `delivery.py:143` as:

```python
self.last_error = f"HTTP {code}"
```

**The HTTP response body is never read on the failure path.** The server's
`detail` object — which carries `code`, `reason`, `retryable`, `honesty_note`,
`stage` — is discarded before the dead-letter decision is written. The endpoint
therefore stores the *number* 4xx and nothing else: no stage, no reason, no
server request id, no server-side correlation handle.

### 1.2 Server side (`backend/routers/xdr_ingest.py`, POST `/api/xdr/ingest/telemetry`)

Ordered stages, with the exact line at which each can terminate the request:

| # | stage | terminal outcome | durable record written? |
|---|---|---|---|
| 0 | edge / ingress + `RequestHardeningMiddleware` body cap | `413` (`request_hardening.py:80-92`) | **NO** — route never runs |
| 0b | middleware hard timeout (30 s) | `504` (`:102`) | NO (but retryable) |
| 0c | middleware unhandled error | `500` (`:119`) | NO (but retryable) |
| 1 | FastAPI/Pydantic body validation of `TelemetryBatch` | `422` | **NO** — handler never runs |
| 2 | `require_permission("collectors.enroll")` auth/tenant claim | `401` / `403` | NO |
| 3 | empty batch | `400` (`xdr_ingest.py:784`) | **NO** |
| 4 | storage unavailable | `503` (`:786`) | NO (retryable, correct) |
| 5 | mixed tenants in one batch | `403 TENANT_ISOLATION_VIOLATION` (`:795`) | **NO** |
| 6 | header tenant != envelope tenant | `403` (`:802`) | **NO** |
| 7 | mixed collectors in one batch | `400 MIXED_COLLECTORS` (`:809`) | **NO** |
| 8 | collector not found | `404` (`:820`) | **NO** |
| 9 | envelope tenant != collector's owner tenant | `403` (`:824`) | **NO** |
| 10 | header tenant != collector's owner tenant | `403` (`:831`) | **NO** |
| 11 | **declared-source routing (D15)** | per-envelope `BLOCKED`, request continues | **YES** -> `xdr_ingest_routing_blocks` (`:841-842`) |
| 12 | idempotency store unavailable | `503 INGEST_IDEMPOTENCY_UNAVAILABLE` (`:871`) | NO (retryable, correct) |
| 13 | duplicate / in-flight / resume | `200`, reported in receipt | YES -> `xdr_ingest_dedupe` |
| 14 | raw persistence | `200` | YES -> `xdr_canonical_events` |
| 14b | `mark_raw_persisted` failure | `503` (`:1006`) | partial — raw row exists, claim stuck `RAW_PERSISTED` |
| 15 | parse / normalize outcome | `200` — counted, never rejected | YES (counters + `processing_outcome`) |
| 16 | canonicalization / reasoning | `200` — `NO_DSM` / `FAILED` are reported answers | YES -> `xdr_canonical_evidence` |

### 1.3 The structural asymmetry (the heart of the defect)

```
stages 0-10  : terminal 4xx, ZERO durable server record   -> endpoint DEAD_LETTER
stage  11    : durable refusal record written  ->  HTTP 200  -> endpoint DELIVERED
stages 12-16 : durable evidence written        ->  HTTP 200  -> endpoint DELIVERED
```

**Every stage that produces a durable refusal record answers 200. Every stage that
answers 4xx produces no record at all.** The two ledgers are therefore
*disjoint by construction*: `xdr_ingest_routing_blocks` can never explain a single
endpoint dead-letter, because a routing block is never communicated as a failure.

This is confirmed by the measured data: all 26 routing blocks carry
`honesty_note: "no raw row, no idempotency claim and no canonical evidence exist
for this delivery"` and were returned inside `TelemetryReceipt.routing_blocked`
with HTTP 200 — i.e. those 26 events sit in the endpoint's **delivered** 2,884,
not in its 14,868 dead letters.

---

## 2 · Failure-path matrix

`server durable record?` = does a refusal survive in the database after the request?

| stage | trigger | HTTP/result | endpoint classification | retryable? | dead-letter condition | server durable record? | collection / type | reason persisted? | evidence identity available? |
|---|---|---|---|---|---|---|---|---|---|
| DNS failure | name resolution fails | `httpx.TransportError` | RETRYABLE | yes | only after `max_attempts` | **NO** (never reached server) | — | endpoint `last_error` only | endpoint-side only |
| network unreachable / TLS reset | transport error | `httpx.TransportError` | RETRYABLE | yes | only after `max_attempts` | **NO** | — | endpoint `last_error` only | endpoint-side only |
| timeout (client) | > `NIVX_INGEST_TIMEOUT` (10 s) | `httpx.TimeoutException` | RETRYABLE | yes | after `max_attempts` | **NO** (may have been processed server-side — dedupe protects) | — | endpoint only | endpoint-side only |
| timeout (server) | > 30 s in middleware | `504` | RETRYABLE | yes | after `max_attempts` | **NO** | — | app log only | request id only |
| **payload too large** | `content-length > 512 KB` | **`413`** | **FATAL** | **no** | **immediate** | **NO** | — | **app log line only** | **none** |
| authentication failure | bad/revoked/expired key | `401`/`403` | **FATAL** | no | immediate | **NO** | — | no | none |
| tenant mismatch (batch mixes tenants) | `len(body_tenants)!=1` | `403` | **FATAL** | no | immediate | **NO** | — | in response body only (discarded) | none |
| tenant mismatch (header vs envelope) | `body_ten != ten_hdr` | `403` | **FATAL** | no | immediate | **NO** | — | response body only | none |
| tenant mismatch (envelope vs collector) | `e.tenant_id != owner_ten` | `403` | **FATAL** | no | immediate | **NO** | — | response body only | none |
| collector unknown | `find_one({"id": cid})` empty | `404` | **FATAL** | no | immediate | **NO** | — | no | none |
| mixed collectors | `len(collector_ids)!=1` | `400` | **FATAL** | no | immediate | **NO** | — | response body only | none |
| empty batch | `not envelopes` | `400` | FATAL | no | immediate | **NO** | — | no | n/a |
| **schema / envelope rejection** | Pydantic validation of `TelemetryBatch` | **`422`** | **FATAL** | no | immediate | **NO** — handler never entered | — | FastAPI error body only (discarded) | **none** |
| unauthorized source | `declared_source` outside collector allowlist | `200` + `SOURCE_NOT_AUTHORIZED` | DELIVERED | n/a | never | **YES** | `xdr_ingest_routing_blocks` | yes | yes (`source_event_id`, keys, excerpt) |
| declaration missing | no `declared_source` | `200` + `DECLARATION_REQUIRED` | DELIVERED | n/a | never | **YES** | routing_blocks | yes | yes |
| **source-format mismatch** | payload not structurally consistent with declaration | `200` + `SOURCE_FORMAT_MISMATCH` | DELIVERED | n/a | never | **YES** (24 of the 26 measured) | routing_blocks | yes | yes |
| DSM unavailable | `SOURCE_DSM_UNAVAILABLE` | `200` | DELIVERED | n/a | never | YES | routing_blocks | yes | yes |
| idempotency store down | `IdempotencyUnavailable` | `503` | RETRYABLE | yes | after max_attempts | NO | — | response body | none |
| raw persistence unavailable | `_c_events() is None` | `200` | DELIVERED | n/a | never | **NO raw row** — `raw_ref.state=MISSING` | evidence only | yes (in evidence) | yes |
| `mark_raw_persisted` failure | idempotency write fails after raw insert | `503` | RETRYABLE | yes | after max_attempts | **PARTIAL** — raw row orphaned, claim `RAW_PERSISTED` | canonical_events + dedupe | partial | yes |
| parser failure | `parser_ok=false` | `200` | DELIVERED | n/a | never | YES (counted `events_error`) | canonical_events | yes | yes |
| parser undeclared | `parser_ok=None` | `200` | DELIVERED | n/a | never | YES (`parse_unmeasured`, `NOT_DECLARED`) | canonical_events | yes | yes |
| normalization failure | no normalized view | `200` | DELIVERED | n/a | never | YES (`events_error`) | canonical_events | yes | yes |
| canonicalization `NO_DSM` | no authoritative parser | `200` | DELIVERED | n/a | never | **raw retained, no canonical evidence** (this is the B4 gap) | canonical_events | yes | yes |
| unexpected server error | unhandled exception | `500` | RETRYABLE | yes | after max_attempts | NO | — | app log | request id |

---

## 3 · Root cause(s)

**Answer to the A/B/C/D/E classification: E — multiple causes, dominated by B, with
a C amplifier. D is ruled out; A cannot yet be excluded for part of the volume.**

* **B (primary) — the server rejects terminally before any durable rejection
  persistence exists.** Stages 0-10 have *no* accountability write path in the
  code. This is not a bug in one branch; there is no mechanism at all. Eleven
  distinct terminal 4xx exits share the same property.
* **C (amplifier) — the endpoint makes an irreversible terminal decision from a
  single integer.** Any non-408/429 4xx becomes `DEAD_LETTER` on the **first**
  attempt, and the response body explaining *why* is thrown away
  (`delivery.py:143`). A transient edge 4xx (mis-set header, proxy 413, a
  momentarily wrong tenant header) is therefore indistinguishable from a genuine
  permanent rejection, and is unrecoverable.
* **D is ruled out by measurement.** The previous census covered
  `xdr_ingest_routing_blocks` (26), `edr_rejected_telemetry` (0 for this tenant),
  `xdr_cortex_ingest_audit` (0), `xdr_audit_log` (11, lifecycle only). There is no
  other collection holding rejections; they were never written.
* **A cannot be excluded for an unknown share.** A 413 raised by
  `RequestHardeningMiddleware` (cap **512 KB** — `/api/xdr/ingest/telemetry` is
  **not** in `_LARGE_BODY_PATHS`) or by the ingress/CDN in front of it never
  reaches the route, leaves only a log line, and is classified FATAL by the
  endpoint. Security `4624` and PowerShell `4104` envelopes are exactly the large
  ones, which makes this a credible contributor to both the dead-letter mass and
  the total absence of PowerShell artefacts.

**The one measurement that discriminates A from B is not yet taken** and is
endpoint-local, read-only, and requires no replay:

```sql
SELECT last_error, COUNT(*) FROM envelopes
 WHERE status = 'dead_letter' GROUP BY last_error ORDER BY 2 DESC;
```

Because `last_error` is exactly `"HTTP {code}"`, that single query yields the
code histogram: `413` -> edge/size (A/B boundary), `422` -> schema, `403`/`404` ->
identity, `400` -> batch shape. Until it is read, attributing the 14,868 to one
cause would be a guess.

### Why this is worse than a missing collection
The system is *honest where it succeeds* — `honesty_note`, `raw_ref.state`,
`parser_ok_basis`, `NOT_EVALUATED`, three-clock provenance — and *silent where it
refuses hardest*. The stages with the greatest security significance (tenant
isolation violations, unknown collector, auth failure) are precisely the ones that
leave no trace. A tenant-isolation violation is a security event and it is
currently unlogged as evidence.

---

## 4 · Defect ownership

| # | defect | owner layer | severity |
|---|---|---|---|
| D-1 | 11 terminal 4xx exits write no durable rejection record | **server** `routers/xdr_ingest.py:784-834` | P0 |
| D-2 | `422` schema rejection happens before the handler; nothing can record it | **server** app-level (needs a `RequestValidationError` handler) | P0 |
| D-3 | `413` body cap applies to ingest at 512 KB with no accountability record | **server** `request_hardening.py` + path allowlist | P0 |
| D-4 | endpoint discards the response body and stores only `"HTTP {code}"` | **endpoint** `framework/delivery.py:143` | P0 |
| D-5 | any 4xx is terminal on the first attempt, with no operator review queue | **endpoint** `delivery.py:141-146` + `outbox.mark_dead` | P1 |
| D-6 | durable refusals answer 200, so endpoint and server ledgers cannot reconcile by status | **contract** (both sides) | P1 |
| D-7 | no reconciliation surface: nothing compares endpoint terminal counts to server accountability counts | **product** | P1 |
| D-8 | auth/tenant refusals are not emitted as audit events either | **server** (`emit_audit` is used only for state change) | P1 |

---

## 5 · Minimum production-grade remediation design (NOT implemented)

Design invariant to satisfy:

> Every terminally rejected telemetry item must remain accountable: what event ->
> which tenant/collector/source -> when -> which stage -> exact reason ->
> retryability -> disposition.

Preserving the existing three-way distinction, which must NOT be collapsed:

```
rejection evidence   != accepted raw evidence   != canonical evidence
(control record,         (trusted-boundary raw,      (interpreted,
 bounded, untrusted)      full payload retained)      DSM-backed)
```

1. **`xdr_ingest_rejections` (new control collection, not evidence).**
   One document per terminally refused *delivery*, modelled on the existing
   `xdr_ingest_routing_blocks` shape (which already proves the pattern works):
   `tenant_id` (claimed + resolved, both, marked), `collector_id` (claimed +
   resolved), `declared_source`, `source_event_id`, `stage`, `code`, `reason`,
   `retryable: bool`, `disposition`, `nivx_received_at`, `request_id`,
   `payload_keys`, `payload_excerpt` (bounded, e.g. 300 chars — already the
   routing-block convention), `payload_bytes`, `payload_digest`, and an explicit
   `honesty_note` that no raw/canonical evidence exists.
   **Bounded by construction: never the full untrusted payload.**
2. **Write it at *every* terminal exit.** Replace the 11 bare `raise
   HTTPException(...)` sites with one helper that persists the rejection *and
   then* raises, so the record cannot be forgotten by a future branch. Where
   tenant identity is itself unproven, store the *claimed* value clearly labelled
   `claimed_unverified` — never in a field that looks resolved.
3. **App-level `RequestValidationError` handler** so `422` produces the same
   record (D-2). Same for a `413` path: either add the ingest route to a
   size-aware branch with its own accountability write, or record the refusal in
   the middleware before returning (D-3).
4. **Return a stable machine-readable envelope on every 4xx**:
   `{code, stage, reason, retryable, rejection_id, request_id}`.
5. **Endpoint: persist the server's answer** (D-4). Store `rejection_id`,
   `code`, `stage`, `reason` on the outbox row instead of `"HTTP {code}"`. This
   is the single change that makes endpoint and server reconcilable by identity.
6. **Endpoint: make terminality evidence-based** (D-5). Honour the server's
   `retryable` flag; require either an explicit non-retryable server answer or
   `max_attempts` exhaustion before `DEAD_LETTER`; keep a
   `DEAD_LETTER_UNEXPLAINED` sub-state for a 4xx that carried no
   `rejection_id` (e.g. an edge 413), so "the server never told us" is itself a
   visible, countable condition rather than a silent drop.
7. **Reconciliation surface** (D-7): read-only projection
   `endpoint_terminal_count` vs `server_rejection_count` per tenant/collector/stage,
   with the unexplained delta shown explicitly. Non-zero unexplained delta is a
   health signal, not a hidden number.
8. **Emit an audit event for identity-class refusals** (D-8): tenant isolation
   violation, unknown collector and auth failure are security events.
9. **Raise the ingest body cap deliberately** to a measured value based on real
   Windows Security/PowerShell envelope sizes — and record any refusal above it.
   *Not* an unbounded cap.

Explicitly **out of scope** of this design: replaying the existing 14,868
(historic rows lack the reason data — they can only ever be reconciled as
`UNEXPLAINED_LEGACY`), and B4 raw retention for `NO_DSM`, which is a separate
accepted gate.

---

## 6 · Tests required to prove zero silent terminal drops

1. **Exhaustive stage-coverage test**: for each of the 13 failure classes, assert
   a rejection record exists with a non-empty `stage` + `reason` and correct
   `retryable`. Parameterised so a newly added terminal exit fails the suite.
2. **Guard test**: static/AST assertion that no `raise HTTPException(4xx)` in
   `xdr_ingest.py` bypasses the rejection helper. This is what stops regression.
3. **`422` handler test**: malformed envelope -> record written, `code=422`.
4. **`413` test**: body over cap -> record written (or explicit
   `UNEXPLAINED_EDGE` disposition), never nothing.
5. **Conservation test (the real invariant)**:
   `accepted + duplicates + routing_blocked + rejections == deliveries_attempted`
   for a synthetic mixed batch. No path may vanish.
6. **Endpoint mapping tests**: `retryable=true` 4xx -> RETRYING not DEAD_LETTER;
   4xx with `rejection_id` -> stored on the row; 4xx without one ->
   `DEAD_LETTER_UNEXPLAINED`.
7. **Reconciliation test**: endpoint terminal count == server rejection count for
   a simulated run; unexplained delta 0.
8. **Tenant-isolation-refusal audit test**: cross-tenant attempt produces both a
   rejection record and an audit event, and still leaks nothing about the other
   tenant.
9. **Bounded-record test**: rejection records never contain the full payload;
   excerpt length capped; digest present.
10. **Golden-event non-regression**: Sysmon `3286059` still produces
    raw + canonical + provenance with all three clocks, and **no** rejection
    record.

---

## 7 · Impact on the three G1 channels

* **Sysmon** (`Microsoft-Windows-Sysmon/Operational`) — the working path. 2,872
  canonical events; golden record `3286059` fully proven. No change expected;
  test 10 protects it.
* **Security** (`Security`) — **mixed, and the only channel with partial
  evidence both ways.** 4 accepted (records 239165-239168) and 24 durably
  blocked with `SOURCE_FORMAT_MISMATCH`. The specific dead-lettered `4624` /
  record `238776` has **no** server trace, so it did not take the routing-block
  path; it terminated at one of stages 0-10. The format mismatch is a *second,
  separate* defect (the Security payload shape does not satisfy its own declared
  source) and must not be conflated with the accountability gap.
* **PowerShell** (`Microsoft-Windows-PowerShell/Operational`) — **zero server
  artefacts of any kind**, despite `windows-powershell-evd` being in the
  collector's `authorized_sources`. Since a blocked declaration would have left a
  routing-block row, PowerShell deliveries never reached stage 11. That is
  consistent with a stage 0-2 refusal (413 / 422 / identity), i.e. **PowerShell is
  most likely a symptom of this same accountability gap** — which is exactly why
  the owner's ordering (dead-letter first, PowerShell second) is correct. Fixing
  the ledger will produce the reason record that tells us what PowerShell hit,
  instead of us guessing at the PowerShell parser.

---

## 8 · Decision

**`DEAD_LETTER_ROOT_CAUSE = PASS` for the architectural defect (D-1 … D-8):**
the silent-drop mechanism is proven from code and measured data, the owning layer
is identified for each defect, and a bounded remediation design exists that does
not weaken the rejection / raw / canonical separation.

**`MOVE_TO_IMPLEMENTATION = HOLD`** on one specific point: the *attribution of the
14,868* is not yet measured, only bounded. One read-only endpoint query
(§3, `GROUP BY last_error` on dead-lettered rows) converts a plausible cause into a
measured one, and it also tells us whether the 512 KB cap must be part of the first
change. Designing the ledger from a guess about the code distribution is precisely
the mistake the owner warned against.

Recommended next step (read-only, no replay, no state change): run that one query
on the endpoint and report the `last_error` histogram. Implementation should begin
only after that histogram is in hand and the owner has reviewed this document.

---

## 9 · Measured G1 Dead-Letter Histogram

**Status: NOT YET MEASURED — measurement cannot be performed from the Preview
environment. Read-only measurement instrument delivered to the operator.**

### 9.1 Why the measurement could not be executed here

The authoritative 125,452-row outbox exists **only on the Windows endpoint** at
`C:\ProgramData\NivXForge\state\outbox.db`. Nothing in the Preview container
holds a copy of it. Proven by exhaustive search rather than assumed:

```
find / -name "outbox.db*"  ->  only two unrelated development databases:
  apps/nivxray-xdr-collector/.state/outbox.db   38 rows   (delivered 35, dead_letter 3)
  backend/xdr_state/outbox.db                    0 rows
```
Neither contains a `windows_channel_state` table, so neither ever ran the Windows
connector — they are not the G1 authority and must not be reported as such. The
G1 proof artifacts held here (`run-context.json`, `acquisition-state.json`, …) were
never pasted back to this environment, and `acquisition-state.json` groups the
outbox by **status only**, not by `last_error`, so it could not answer this
question even if present.

### 9.2 Delivered instrument

`memory/G1_DEAD_LETTER_HISTOGRAM_READONLY.ps1` — elevated, read-only, ASCII-only.

Non-mutation design:
* refuses to run if a collector process is still alive (a copy taken under an
  active writer could be torn);
* copies `outbox.db` + `-wal` + `-shm` to a temp folder and queries the **copy**;
  the live files are only ever read; temp copy deleted at the end;
* `SELECT`-only — no `UPDATE`/`INSERT`/`DELETE`/`DROP` anywhere in the script;
* no acquisition, no replay, no status change, no recovery, no cleanup, no
  collector start, no server call, no credential use;
* emits counts, codes, sizes and identity only — **no event payload bodies**.

What it produces (`C:\nivx\g1-proof\dead-letter-histogram.json`):
1. `totals_by_status` + reconciliation against the captured accounting
   (125,452 / 2,884 / 14,868 / 125 / 107,525) with the exact delta;
2. `histogram_exact` — **unnormalised** `last_error` values with counts and
   `percentage_of_dead_letters`;
3. `classification` into the 14 required buckets, derived strictly from the
   stored string, with `classification_unmatched_exact_values` so nothing is
   silently forced into a bucket;
4. `dead_letter_attempts_distribution` — terminality evidence;
5. `dead_letter_payload_bytes` (min/max/avg, rows over 256 KB / 512 KB) plus
   `delivered_payload_bytes_for_contrast` — the direct test of the 512 KB
   hypothesis;
6. `dead_letter_by_source_and_error` and `all_status_by_source` — channel
   correlation;
7. `named_records` — the two named rows located by
   `source_event_id LIKE '%|510'` / `'%|238776'`, returning outbox id, source,
   declared_source, event_type, status, attempts, last_error, created/updated,
   `length(raw_json)`, `length(canonical_json)`, and EventID/EventRecordID read
   from the canonical view;
8. `dead_letter_window` — first/last created and updated timestamps.

### 9.3 Evidence-discipline caveat carried into the artifact

The script embeds this note verbatim: a stored `HTTP 413` proves only that the
endpoint *received* 413; it does not prove why the server produced it. Likewise
`403` is not proof of a tenant violation and `400` is not proof of a malformed
batch. Attribution requires the corresponding server path or configuration to
independently establish it.

### 9.4 Indirect corroboration available today (NOT G1 evidence)

The unrelated 38-row development outbox in this container was read read-only and
shows a pattern worth carrying into the analysis as a *hypothesis*, not a finding:

```
last_error='HTTP 422'  count=3   attempts=0   raw_json 174-451 bytes
source='Generic Syslog Receiver'  declared_source=NULL
```
Three observations follow, and only the first two are firm:
* the query shape and schema assumptions are correct (`envelopes.last_error`,
  `status='dead_letter'`);
* **`attempts=0` confirms defect D-5 empirically**: a 4xx dead-letters on the
  first attempt, with no retry;
* these rows are **174-451 bytes** — three orders of magnitude below the 512 KB
  cap — so at least in this unrelated sample, dead-lettering happened with tiny
  payloads and `declared_source = NULL`, which is the `DECLARATION_REQUIRED` /
  `422` family rather than a size problem. **This weakens the 512 KB hypothesis
  as a sole or dominant cause and raises `422` to an equally serious candidate.**
  It is not G1 data and does not settle the question.

### 9.5 512 KB hypothesis

**UNRESOLVED.** It is neither confirmed nor rejected. Direct discriminators are
already built into the instrument: `dead_letter_payload_bytes.rows_over_512KB`
and the delivered-row contrast. If that number is near 14,868 the hypothesis is
confirmed; if it is near zero the hypothesis is rejected and the cause is an
identity or schema class. The 512 KB limit has **not** been changed.

### 9.6 Hypothesis cross-check status

| hypothesis | status |
|---|---|
| durable refusals answer 200, so routing blocks can never be dead letters | **CONFIRMED** (code + measured data, §1.3) |
| 11 terminal 4xx exits write no durable record | **CONFIRMED** (code, `xdr_ingest.py:784-834`) |
| endpoint stores only `"HTTP {code}"` and discards the reason | **CONFIRMED** (`delivery.py:143`) |
| a 4xx is terminal on the first attempt | **CONFIRMED** in code; **SUPPORTED** by observed `attempts=0` in a non-G1 sample |
| `422` schema rejection is a real dead-letter producer | **SUPPORTED** (non-G1 sample only) |
| 512 KB cap is a major contributor | **UNRESOLVED** — measurement pending |
| rejection records exist in some uncensused collection | **NOT OBSERVED** — ruled out |
| PowerShell terminated before stage 11 | **CONFIRMED** (zero routing blocks for that channel) |
| which stage PowerShell/Security actually hit | **UNRESOLVED** — measurement pending |

### 9.7 Decision

`MOVE_TO_IMPLEMENTATION` **remains HOLD**. The histogram is the input that decides
whether the first change is size/batching semantics or identity/schema semantics,
and it can only be produced on the endpoint. Run
`memory/G1_DEAD_LETTER_HISTOGRAM_READONLY.ps1` and return
`dead-letter-histogram.json`; this section will then be replaced with the measured
result.
