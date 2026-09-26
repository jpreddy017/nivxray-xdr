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

---

## 10 · G1 HTTP 404 ROOT CAUSE

**`G1_HTTP_404_ROOT_CAUSE = PASS`**

Owner-supplied endpoint measurement accepted as authoritative: 125,452 rows
(107,525 queued · 14,868 dead_letter · 2,884 delivered · 125 retrying ·
50 delivering); **14,868 / 14,868 dead letters = `HTTP 404` (100 %)**; zero
payloads over 512 KB; size range 754–28,135 bytes, mean ≈1,240 bytes. The
512 KB / `413` hypothesis is therefore **REJECTED** for this population, and so
are the `422`, `403`, `400`, DNS, TLS and timeout families — none is present.

### 10.1 Every 404 producer in the deployed ingest path

| # | file:line / function | condition | response detail | reaches ingest handler? | anything persisted? | compatible with measured G1 behaviour? |
|---|---|---|---|---|---|---|
| P1 | `routers/xdr_ingest.py:818-820` `ingest_telemetry` | `_c_collectors().find_one({"id": cid})` returns nothing | `404 detail="collector not found"` (JSON body) | yes — 404 raised *inside* the handler, after auth | **no** | **NO — excluded, see 10.2** |
| P2 | `routers/xdr_api_keys.py:265/277/311/340/361` | key-management routes only (`GET`/`revoke`/`rotate`) | `404 "api key not found"` | n/a — different routes | no | NO — not in the ingest path |
| P3 | Starlette router (no matching route/method) | path or method not registered | bare `404 {"detail":"Not Found"}` | no | no | possible in principle; **excluded, see 10.2** |
| P4 | **infrastructure in front of the app** (Kubernetes ingress / preview router) | no live backend behind the preview hostname | edge `404`, no application body | **no** | **no** | **YES — this is the proven producer** |

Note the collector lookup at P1 is `find_one({"id": cid})` with **no** tenant,
`enabled`, `state` or `deleted_at` filter, so mere existence of the document is
sufficient for it to pass. `state = PARSE_ERROR` is irrelevant to it.

### 10.2 Three independent proofs that the application never produced these 404s

**Proof 1 — the API key's own counter.** `verify_api_key()`
(`routers/xdr_api_keys.py:396-401`) increments `use_count` and stamps
`last_used_at` on **every successful verification**, and that dependency runs
*before* the route body. So an in-app 404 at P1 would still have incremented the
counter. Measured:

```
key_17105f51ce76424ca1bd : use_count = 2901 , last_used_at = 2026-09-22T23:38:34.104017Z
server-side work         : 2876 canonical + 26 routing blocks = 2902
```
`use_count` matches the requests that were *processed*, with no surplus. Had even a
fraction of the 14,868 reached the app, `use_count` would be ≈17,700. **14,868
POSTs performed zero key verifications, therefore they never entered the ASGI
application.** (Also decisive: `last_used_at` never advanced past 23:38:34, while
dead-lettering continued afterwards.)

**Proof 2 — the backend request log contains no 404 at all.**
`/var/log/supervisor/backend.err.log` covers `2026-09-22T17:45:21` →
`2026-09-23T14:28:18` — squarely across the dead-letter window. Measured:

```
grep -c 'status=404 | "status": 404'                      -> 0
'"route": "/api/xdr/ingest/telemetry"'  by status         -> status=200 : 312   (only value present)
first 2026-09-22T17:45:22.494Z   last 2026-09-22T23:38:34.211Z
```
Both the structured `nivxray.request` logger and the `nivxray.middleware` logger
recorded **not one** 404 for any route in the entire window.

**Proof 3 — the application was not running during the loss window.** Counting
*all* app-reaching requests per hour (the local EDR agent heartbeats continuously
while the backend is up, so absence is meaningful):

```
2026-09-22T17  174        <- app up
2026-09-22T18  (absent)   <- app DOWN
2026-09-22T19  (absent)
2026-09-22T20  (absent)
2026-09-22T21  (absent)
2026-09-22T22  (absent)
2026-09-22T23  504        <- app back: "Started server process [162]" @ 23:33:54.437
2026-09-23T00  555 ... (further down-windows 04-07, 10-12)
```
Zero requests of any kind for ~5 h 46 m (17:47 → 23:33). The preview backend was
**not serving**; the hostname in front of it answered `404`.

### 10.3 Why record 3286059 succeeded while thousands of later events got 404

Pure temporal coincidence with backend availability — not source type, not size,
not parser:

```
16:43:27  temporary key minted; collector starts; delivery begins
16:43:32  Sysmon 3286059 delivered -> raw + canonical evidence (app UP)
16:43-17:47  2,707 events processed (382 in hour 16, 2,325 in hour 17)   app UP
17:26-17:41  26 Security routing blocks recorded (app UP, durable refusals)
17:47 -> 23:33  app DOWN  ->  every POST answered 404 by the edge  ->  endpoint
                dead-letters each one immediately (attempts = 0)
23:33:54  backend restarted
23:33-23:38  169 more events delivered successfully (app UP again)
23:38:34  last app-reaching ingest request; collector later stopped
           (50 rows left in `delivering` = worker killed mid-flight)
```
The same collector, same key, same tenant, same three channels succeeded before
17:47 and again at 23:33. **Nothing about the events changed; only backend
availability did.**

### 10.4 Answers to the specific questions

| question | answer | classification |
|---|---|---|
| Which exact server code path produced the 404s? | **None.** P4 — the infrastructure in front of the ASGI app, while the backend was not running. `xdr_ingest.py:820` did not execute. | **PROVEN** (3 independent proofs, §10.2) |
| Why could 3286059 succeed while others 404'd? | It was delivered at 16:43:32 while the backend was up; the 404s fall in the 17:47→23:33 outage. 169 later deliveries also succeeded after the 23:33:54 restart. | **PROVEN** |
| Collector temporarily unregistered? | **No.** Single document `_id 6ab288a9589e534d6c49bb6a`, `created_at 13:54:49.832948Z`, `deleted_at null`, `enabled true`; only one collector has ever existed in the tenant. | **PROVEN** |
| Tenant lookup failing? | **No.** Tenant `ten_f1a5…` `ACTIVE`, created 13:54:49.453547Z, never modified. A tenant/collector mismatch yields `403`, not `404`, and zero 403s were recorded either side. | **PROVEN** |
| Wrong deployment / wrong backend hit? | Not a *different* backend — the same hostname with **no live backend behind it**. | **PROVEN** for "app not reached"; the precise edge component that emitted the 404 is infrastructure-side and **UNRESOLVED** (no ingress logs are available to this environment) |
| Routing / proxy issue? | Yes, in the sense of §10.2 Proof 3: the route existed in code but no process was listening. | **PROVEN** |
| Any lifecycle op created/deleted/recreated/changed `col_d6b0b9e8…`? | Audit log for the tenant holds 15 rows: `TENANT_CREATED`, `COLLECTOR_CREATED` (13:54:49.840705Z), 6× `API_KEY_CREATED`, 6× `API_KEY_REVOKED`, and exactly one `COLLECTOR_STATE_CHANGED` at 16:43:32.137133Z (by `apikey:key_17105f51ce76424ca1bd`). **No delete, no recreate.** `updated_at 23:38:34.106091Z` = the last successful ingest, not a lifecycle edit. | **PROVEN** |
| Are the 14,868 genuinely terminal? | **No.** They are transient-outage casualties. Proven by construction: 169 events of the same kinds succeeded minutes after the backend returned, and the rows still hold their `raw_json` + `canonical_json`. | **PROVEN** |
| Does the endpoint misclassify this 404 as permanently dead on first failure? | **Yes.** `framework/delivery.py:141-146` maps any non-408/429 4xx to `FATAL`; `outbox.mark_dead()` is terminal with no attempt threshold. Measured `attempts = 0` on every dead letter confirms a single attempt. | **PROVEN** |
| Is PowerShell a parser problem? | **No.** Record 510's single attempt received an edge 404, so PowerShell telemetry has **never been evaluated server-side**. Its parser/DSM status is simply untested. | **PROVEN** that it was never evaluated; **UNRESOLVED** whether it would parse |
| Is the Security format mismatch real? | Yes, but **separate**. The 24 `SOURCE_FORMAT_MISMATCH` routing blocks occurred at 17:26-17:41 while the app was up. Record 238776's own single attempt was an edge 404. | **PROVEN** (both facts, independently) |

### 10.5 Revised defect model

The earlier analysis (§3) identified the *accountability* architecture correctly,
but it mis-ranked the cause of **this** incident. Corrected ranking:

1. **D-5 is the primary defect here, not a secondary amplifier.** A transient
   infrastructure outage was converted into 14,868 permanent evidence losses by a
   first-attempt terminal decision on a status code the endpoint cannot attribute.
   The retry/backoff machinery already exists (`mark_retry`, `_max_attempts`,
   `DEFAULT_BACKOFF_SECONDS`) — it was simply not reachable for a 404.
2. **D-4 (`last_error = "HTTP {code}"`) is what made diagnosis this expensive.**
   An edge 404 (no JSON body, no `X-Request-ID`, different `content-type`/`server`
   headers) is trivially distinguishable from the app's
   `404 {"detail":"collector not found"}` — but the endpoint discarded exactly the
   bytes that distinguish them.
3. **D-1/D-2/D-3 (the server-side rejection ledger) remain valid and unwaived**,
   but they are **second-order for this incident**: a server-side ledger cannot
   record a request the server never received. Any ledger design that claimed to
   explain these 14,868 would be false by construction.
4. **New defect D-9: no delivery health gate.** The worker drained the outbox at
   full rate into a dead endpoint for nearly six hours without a single
   reachability pre-flight or circuit breaker.
5. **New defect D-10: unattributable-terminal has no representation.** There is no
   `DEAD_LETTER_UNEXPLAINED` state, so "the server never told us why" is
   indistinguishable from "the server refused this event".

### 10.6 Recommended bounded remediation scope (NOT implemented)

Ordered by ratio of loss prevented to risk introduced:

1. **Endpoint — terminality must require an application-attributable refusal.**
   Treat a 4xx as terminal only when the response is provably from the
   application (parseable NivXRay error envelope, ideally a `rejection_id`);
   otherwise classify `RETRYABLE` / `DEAD_LETTER_UNEXPLAINED` and honour
   `_max_attempts`. Specifically: **404 must not be first-attempt terminal.**
2. **Endpoint — persist the discriminating bytes**: status, `content-type`,
   `X-Request-ID`, a bounded body excerpt, plus the resolved URL. This alone would
   have answered this question in minutes.
3. **Endpoint — delivery health gate (D-9)**: cheap pre-flight probe plus a
   circuit breaker so an unreachable server pauses the drain instead of shredding
   the queue.
4. **Bounded recovery of the existing 14,868** — the rows still contain
   `raw_json` and `canonical_json`, so a one-off operator-gated requeue of
   `status='dead_letter' AND last_error='HTTP 404'` is feasible and would restore
   the lost evidence. **Separate owner-authorised gate; not part of any fix
   above; must not run automatically.**
5. **Server — rejection ledger (D-1/D-2/D-3)** as designed in §5, correctly
   scoped to refusals the server actually issues.
6. **Only after (1)-(3)** does re-testing PowerShell make sense; today its
   server-side behaviour is simply unmeasured.

Not in scope and untouched: the 512 KB cap (hypothesis rejected — no change
justified), Security `SOURCE_FORMAT_MISMATCH`, the clock collapse, `parser_ok`
declaration, the `RAW_PERSISTED` orphan, B4, G2.

---

## 11 · G1-R1 RETRY CLASSIFICATION IMPLEMENTATION

**`G1_R1_RETRY_CLASSIFICATION = PASS`** · owner-authorised scope only. No
failure-detail capture, no health gate, no requeue, no ledger, no PowerShell
work, no B4/G2, no deployment, no replay, no endpoint mutation.

### 11.1 Old behaviour

`framework/delivery.py` (pre-change, final lines):

```python
if code in (408, 429) or 500 <= code < 600:   # retryable
    ...
# Any other 4xx is a fatal, don't-retry response.
self.failed_fatal += len(batch)
self.last_error = f"HTTP {code}"
return {"outcome": IngestOutcome.FATAL, ...}
```
`delivery_worker.py` mapped `FATAL -> outbox.mark_dead()`, which is terminal
with **no attempt threshold** (`framework/outbox.py:338`). Consequence: a status
code alone decided permanence. During the G1 outage this converted 14,868
transient infrastructure 404s into permanent evidence loss at `attempts = 0`.

### 11.2 New behaviour

Terminality now requires an **application-attributable** refusal. Attribution
is the presence of the `X-Request-ID` response header, which the application
stamps on **every** response — success and error alike
(`backend/request_hardening.py:125` `response.headers["X-Request-ID"] = rid`,
and explicitly on its own 413/504/500 JSON responses). An infrastructure
response produced when no backend is listening does not carry it.

The test is deliberately one-directional: it can only ever **withhold**
terminality, never manufacture it. It is a header-only check — no response body
is read or stored, because richer capture is G1-R2.

### 11.3 Classification contract

| condition | classification | worker action | terminal? |
|---|---|---|---|
| `2xx` | `ACCEPTED` | `mark_delivered` | n/a (accepted) |
| not configured / timeout / transport error | `RETRYABLE` | `mark_retry` | only on exhaustion |
| `408`, `429`, `5xx` | `RETRYABLE` | `mark_retry` | only on exhaustion |
| **`404` (attributed or not)** | `UNATTRIBUTED_FAILURE` | `mark_retry` | **only on exhaustion** |
| other `4xx` **without** `X-Request-ID` | `UNATTRIBUTED_FAILURE` | `mark_retry` | only on exhaustion |
| other `4xx` **with** `X-Request-ID` | `AUTHORITATIVE_TERMINAL` | `mark_dead` | **yes, immediately (fail-closed)** |

`404` is never terminal even when attributed: the application's only ingest 404
is `"collector not found"`, which a later enrolment legitimately resolves.

Bounded, never infinite: `RETRYABLE`/`UNATTRIBUTED_FAILURE` go through the
existing `mark_retry` machinery (`_max_attempts`, `DEFAULT_BACKOFF_SECONDS`).
On exhaustion the worker now writes a distinct disposition —
`"<reason> | retries exhausted"` — so *"we tried and gave up"* is never
confusable with *"the authority refused this event"*.

Reason strings written to `envelopes.last_error`:
```
HTTP 404 | UNATTRIBUTED_FAILURE (no X-Request-ID) | bounded retry
HTTP 404 | UNATTRIBUTED_FAILURE (app-attributed) | bounded retry
HTTP 403 | AUTHORITATIVE_TERMINAL (app-attributed refusal)
HTTP 404 | UNATTRIBUTED_FAILURE (no X-Request-ID) | bounded retry | retries exhausted
```

### 11.4 Changed files

| file | change |
|---|---|
| `framework/delivery.py` | `DeliveryClassification` taxonomy + `APP_ATTRIBUTION_HEADER`; attribution-aware classification; `failed_unattributed` / `last_classification` counters; `classification` + `app_attributed` in every returned dict and in `status()`. `IngestOutcome` wire values (`ok`/`retryable`/`fatal`) intentionally unchanged, so `routes/preflight.py` and the worker keep working. |
| `framework/delivery_worker.py` | imports `OutboxStatus`; on retry exhaustion writes the explicit `"… | retries exhausted"` disposition and counts it as dead; `FATAL` branch now documented as application-attributed refusals only. |
| `tests/test_outbox.py` | `test_4xx_marks_dead_letter` now sends `X-Request-ID` with its 400, preserving the test's intent (an authoritative refusal stays terminal) under the corrected contract. |
| `tests/test_g1_r1_retry_classification.py` | **new**, 30 tests. |

### 11.5 Tests and results

```
tests/test_g1_r1_retry_classification.py  ->  30 passed
full collector suite                      ->  210 passed in 3.09s   (0 failures)
import check                              ->  framework.delivery, delivery_worker,
                                              routes.preflight, main all import
```
Coverage, mapped to the required list:

| requirement | test |
|---|---|
| infrastructure/bare 404 not immediate dead-letter | `test_bare_404_is_not_immediate_dead_letter` |
| **exact G1 shape cannot go `queued -> dead_letter` on attempt one** | `test_queued_cannot_transition_directly_to_dead_letter_on_first_404` (asserts the transition and `attempts == 1`) |
| unattributed 404 -> retry path | `test_unattributed_404_classification_is_explicit`, `test_attributed_404_is_still_retryable` |
| retry accounting advances | `test_retry_attempts_advance_and_exhaust_explicitly` (1 -> 2 -> 3) |
| exhaustion has an explicit truthful disposition | same test: `"retries exhausted"` present, `AUTHORITATIVE_TERMINAL` absent |
| 408 retryable · 429 retryable · 5xx retryable | `test_known_retryable_statuses_stay_retryable[408/429/500/502/503/504]` |
| authoritative refusal stays terminal | `test_app_attributed_refusal_is_terminal[400/401/403/409/413/422]` |
| unattributed 4xx is retried, not destroyed | `test_unattributed_4xx_is_retried_not_destroyed[400/401/403/409/422]` |
| 2xx remains delivered | `test_2xx_still_delivers` |
| tenant/auth rejection never becomes success | `test_auth_and_tenant_rejection_never_becomes_delivered[403/401/404 × attributed/not]` |
| acquisition/bookmark invariants unchanged | `test_404_does_not_acknowledge_or_drop_the_row` (no acknowledgement, no row loss) |
| outbox durability/idempotency unchanged | `test_idempotency_and_durability_unaffected_by_404` (one row, payload intact, zero delivered) |
| transport contract unchanged | `test_transport_error_stays_retryable` |

### 11.6 Historical data

Untouched. No requeue, no rewrite, no status change. The 14,868 rows and
`C:\ProgramData\NivXForge\state\outbox.db` are preserved as evidence; recovery
is the separate owner-gated **R4**.

### 11.7 Remaining gaps / risks

1. **Attribution is a header, not a signature (accepted risk).** An
   intermediary that echoes `X-Request-ID` could make an edge response look
   attributed. Blast radius is bounded: it would make an unattributed failure
   *terminal* for non-404 statuses only — the exact G1 shape (404) is terminal
   under **no** circumstances. A signed refusal contract belongs to the server
   ledger work (D-1/D-2/D-3).
2. **Reason strings carry a classification label, not the server's own words**
   (D-4 remains open). Full detail capture — body excerpt, `content-type`,
   resolved URL — is **R2**.
3. **No health gate (D-9 open).** The worker will now *retry* into an
   unreachable endpoint rather than shred the queue, but it still drains at
   full rate. Bounded exhaustion means a long outage can still end in
   `retries exhausted` dead letters — materially better than `attempts = 0`
   destruction, and not yet the full answer. **R3.**
4. **`DEAD_LETTER_UNEXPLAINED` is expressed in `last_error` text, not as a
   distinct status (D-10 partially open).** A first-class state is deferred so
   this change stays additive to the existing status machine.
5. **Server-side rejection ledger untouched** (D-1/D-2/D-3) — still unwaived.
6. **`max_attempts` is `len(DEFAULT_BACKOFF_SECONDS)`**; whether that budget is
   right for a multi-hour outage is a tuning question deliberately left to R3
   alongside the circuit breaker.
7. **Not deployed and not exercised against a live endpoint** — unit-proven
   only, by instruction.

---

## 12 · G1-R2 FAILURE DETAIL CAPTURE IMPLEMENTATION

**`G1_R2_FAILURE_DETAIL_CAPTURE = PASS`** · owner-authorised scope only. No
health gate (R3), no requeue/recovery (R4), no rejection ledger, no PowerShell
work, no B4/G2, no deployment, no replay, no endpoint mutation.

### 12.1 Old behaviour (the reason G1 diagnosis was expensive)

Every failure preserved exactly one string:

```python
self.last_error = f"HTTP {code}"        # everything else discarded
```
The response object was read for its status and then dropped. The
`X-Request-ID` stamp, content type, body and resolved URL — the only things
that separate an infrastructure refusal from an authoritative one — were gone
before the terminal decision was written. Establishing "these 14,868 never
reached the application" needed API-key `use_count` arithmetic, backend log
archaeology and per-hour traffic reconstruction.

### 12.2 New behaviour

Every failed attempt now writes a bounded, redacted record **onto the row**:

```json
{
  "classification":     "UNATTRIBUTED_FAILURE",
  "reason":             "HTTP 404 | UNATTRIBUTED_FAILURE (no X-Request-ID) | bounded retry",
  "attempted_at":       "2026-…Z",
  "url":                "https://…/api/xdr/ingest/telemetry",
  "status_code":        404,
  "app_attributed":     false,
  "attribution_header": "X-Request-ID",
  "request_id":         null,
  "content_type":       "text/html",
  "server":             "edge-proxy",
  "body_excerpt":       "<html><body>404 Not Found</body></html>",
  "body_bytes":         39,
  "body_truncated":     false,
  "capture_note":       "bounded and redacted; body excerpt capped at 300 chars …"
}
```
Transport failures record the same shape with `status_code: null` and
`transport_error: "ConnectError"`. Retry exhaustion adds
`disposition: "RETRIES_EXHAUSTED"`.

Two hard limits, both tested:
* **bounded** — body excerpt capped at `FAILURE_BODY_EXCERPT_CHARS = 300`, with
  `body_bytes` + `body_truncated` so truncation is never silent. This is a
  diagnosis record, not a payload store.
* **redacted** — `nvx_…` keys, `Bearer …` tokens and `api_key: …` values are
  stripped before storage, so a failure record can never become the place a
  credential leaks. Only the last failure per row is kept (replaced, not
  appended), so the record cannot grow without bound.

### 12.3 Live validation of the attribution signal

Probed the deployed Preview app with an unknown `/api` route (no ingest, no
mutation):

```
via edge :  HTTP/2 404 · content-type: application/json · server: cloudflare
                       · x-request-id: nvx-256a2413ff77
localhost:  HTTP/1.1 404 Not Found · content-type: application/json
                       · x-request-id: nvx-944d866ce925
```
The application stamps `X-Request-ID` on a 404 and **the header survives the
edge**, so attribution is observable end-to-end in the real deployment.

### 12.4 Changed files

| file | change |
|---|---|
| `framework/delivery.py` | `FAILURE_BODY_EXCERPT_CHARS`, `_redact()`, `_failure_detail()`; every non-accepted return now carries `failure_detail`; `last_failure_detail` on the client, cleared on success, exposed in `status()`. |
| `framework/outbox.py` | `OutboxRow.failure_detail`; additive migration `ALTER TABLE envelopes ADD COLUMN failure_detail_json TEXT`; `mark_retry(..., detail=)` and `mark_dead(..., detail=)` persist it via `COALESCE` so a caller that passes nothing never erases an existing record; `_row()` deserialises defensively when the column is absent. |
| `framework/delivery_worker.py` | forwards `result["failure_detail"]` on both the retry and terminal paths; stamps `disposition: RETRIES_EXHAUSTED` on exhaustion. |
| `routes/outbox.py` | `failure_detail` exposed on `GET /outbox` and `GET /outbox/{id}` so an operator can read it without touching SQLite. |
| `tests/test_g1_r2_failure_detail_capture.py` | **new**, 16 tests. |

### 12.5 Tests and results

```
tests/test_g1_r2_failure_detail_capture.py  ->  16 passed
full collector suite                        -> 226 passed in 3.23s, 0 failed
imports                                     -> delivery, delivery_worker,
                                               routes.outbox, routes.preflight, main
schema                                      -> failure_detail_json present
```

| requirement | test |
|---|---|
| the exact G1 edge-404 shape becomes self-explaining | `test_infrastructure_404_records_absence_of_attribution` |
| app 404 vs infrastructure 404 are distinguishable | `test_application_404_is_distinguishable_from_infrastructure_404` |
| capture is bounded and truncation is visible | `test_body_excerpt_is_bounded_and_flagged_truncated` |
| a failure record can never leak the credential | `test_credential_is_redacted_from_failure_detail` |
| every failure class persists a record | `test_all_failure_classes_persist_detail[404/403 unattributed · 403 attributed · 429 · 503]` |
| transport failure with no response still records | `test_transport_failure_records_detail_without_a_response` |
| not-configured still records | `test_not_configured_records_detail` |
| exhaustion disposition recorded | `test_exhaustion_disposition_is_recorded` |
| record reflects the latest attempt, not an accumulation | `test_detail_reflects_the_latest_attempt` |
| survives process restart | `test_failure_detail_persists_across_reopen` |
| opens a pre-R2 database additively | `test_additive_migration_on_a_pre_r2_database` |
| success carries no stale failure narrative | `test_success_clears_client_side_failure_detail` |
| R1 contract still intact | full suite, incl. all 30 R1 tests |

### 12.6 Historical data

Untouched. The preserved 14,868 rows keep `last_error = "HTTP 404"` and
`failure_detail = NULL`; the migration is additive and back-fills nothing,
because inventing detail for past attempts would be fabrication. Recovery
remains owner-gated **R4**.

### 12.7 Remaining gaps / risks

1. **Attribution is still an unsigned header** (unchanged from R1). R2 makes the
   surrounding evidence — content type, `server`, body shape — available so a
   spoof is *detectable after the fact*, but it is not prevented. A signed
   refusal contract belongs to the server-side ledger (D-1/D-2/D-3).
2. **The no-backend case was not reproduced live** — proving it would require
   taking the Preview backend down, which is out of scope. The edge-404 path is
   unit-proven with a synthetic response; the app-404 path is confirmed against
   the real deployment (§12.3).
3. **Cloudflare sits in front** and was observed to pass the application header
   through without inventing one, but only in the app-up case.
4. **D-9 (no health gate) still open** — R3.
5. **D-10 partially open** — `disposition` now records `RETRIES_EXHAUSTED` in
   the detail record, but `DEAD_LETTER_UNEXPLAINED` is still not a first-class
   status.
6. **`replay_dead()` deliberately preserves `failure_detail`** so a requeue
   cannot erase why the row previously failed. R4 must decide whether a
   successful replay should archive it.
7. **Not deployed, not exercised against a live ingest delivery** — unit-proven
   only, by instruction.

---

## 13 · G1-R3 DELIVERY HEALTH GATE IMPLEMENTATION

**`G1_R3_DELIVERY_HEALTH_GATE = PASS`** · owner-authorised scope only. No R4,
no requeue/replay, no Windows endpoint contact, no deployment, no merge, no
force-push, no B4/G2, no credential work.

### 13.1 Why R1+R2 were not enough

R1 and R2 are *per-event* corrections. Neither stops the worker from grinding
the whole queue against a destination that is not there. With R1 alone, the G1
outage would no longer destroy events on attempt one — it would walk each of
125,452 rows to `retries exhausted` instead. The retry budget exists to absorb
*per-event* problems; spending it on a *destination* problem is the same
category error in slower motion.

So health is now tracked per destination, and the evidence that moves it is
destination-level evidence only.

### 13.2 State machine

```
  CLOSED ──failure──▶ SUSPECT ──threshold reached──▶ OPEN
     ▲                   │                            │
     │                   └──success/refusal──┐        │ cooldown elapsed
     │                                       ▼        ▼
     └──────── probe succeeds ──────── HALF_OPEN ◀────┘
                                            │
                                    probe fails → OPEN
                                    (cooldown ×2, clamped)
```

| state | delivery | rows claimed | retry budget |
|---|---|---|---|
| `CLOSED` | normal | up to `batch_size` | spent normally |
| `SUSPECT` | **normal** — visible, not paused | up to `batch_size` | spent normally |
| `OPEN` | **paused** | **none** | **none spent** |
| `HALF_OPEN` | probing | **exactly one** | one row only |

Defaults (env-overridable, invalid values fall back rather than disabling the
gate): `NIVX_DELIVERY_GATE_THRESHOLD=5`,
`NIVX_DELIVERY_GATE_COOLDOWN_SECONDS=30`,
`NIVX_DELIVERY_GATE_MAX_COOLDOWN_SECONDS=300`. Cooldown doubles per failed
probe and clamps at the maximum, so the gate **always keeps re-probing** — it
never gives up permanently and never busy-loops (an `OPEN` tick performs zero
network I/O).

### 13.3 Contract — what moves the gate, and what must not

| evidence | gate effect | rationale |
|---|---|---|
| `ACCEPTED` (2xx) | resets run, closes gate | the destination is provably alive |
| `RETRYABLE` (5xx/408/429/timeout/connect/DNS) | destination failure | service-level condition |
| `UNATTRIBUTED_FAILURE` (incl. the G1 edge 404) | destination failure | nothing proves the app answered |
| `AUTHORITATIVE_TERMINAL` (attributed 4xx) | **no effect** — resets the run | the application answering correctly about one event *is* health; a stream of bad events must never stall good ones |

This is the invariant that stops the gate from becoming a new way to lose
evidence: **an authoritative application refusal is never disguised as an
infrastructure outage, and an infrastructure outage is never disguised as a
refusal.**

### 13.4 Safety properties, and how each is enforced

| property | mechanism |
|---|---|
| no event loss | while `OPEN` no row is claimed; when the gate opens mid-batch the un-attempted rows are handed back with `release_delivering()` (status-guarded `WHERE status='delivering'`, `attempts` and `next_attempt_at` untouched) |
| no retry-budget burn | `allow_delivery()` returns `False` before `next_batch()`, so no attempt is recorded |
| no false `DELIVERED` | only a real 2xx reaches `mark_delivered()`; unchanged |
| no duplicate acknowledgement | the gate never acknowledges; a probe is an ordinary single-row delivery |
| no bookmark advancement | bookmarks follow acknowledgement, and the gate produces none |
| backpressure accounting preserved | `counts()`/`metrics()` untouched; queue depth stays truthful while paused |
| restart is deterministic | gate is in-memory and starts `CLOSED`; `Outbox.__init__` already resets `DELIVERING -> QUEUED`, so no row is stranded and retry budgets survive |
| tenant/auth stays fail-closed | untouched — those are `AUTHORITATIVE_TERMINAL` when attributed, and bounded-retry when not (R1) |
| R1 preserved | classification logic untouched; the gate reads it, never overrides it |
| R2 preserved | failure detail still written on every attempted row |
| operationally visible | `worker.status()["health_gate"]` and `GET /outbox/health` -> `delivery_health` + `state: "delivery_paused"` |

### 13.5 Changed files

| file | change |
|---|---|
| `framework/health_gate.py` | **new** · `DeliveryHealthGate`, `GateState`, env config with safe fallback, bounded exponential cooldown, `status()` telemetry |
| `framework/delivery_worker.py` | gate injected (default-constructed); pre-drain `allow_delivery()` short-circuit; `HALF_OPEN` single-row probe; destination-failure recording *before* the row update so a mid-batch open stops further attempts; `release_delivering()` for un-attempted rows; `AUTHORITATIVE_TERMINAL` reported as event-refusal, not destination failure; gate state in `status()` and in every tick result |
| `framework/outbox.py` | **new** `release_delivering()` — status-guarded return of claimed-but-unattempted rows to `QUEUED` without touching `attempts`/`next_attempt_at` |
| `routes/outbox.py` | `GET /outbox/health` reports `delivery_health` and a distinct `delivery_paused` state instead of mislabelling a paused destination as `degraded` |
| `tests/test_g1_r3_delivery_health_gate.py` | **new**, 19 tests |

### 13.6 Tests and results

```
tests/test_g1_r3_delivery_health_gate.py  ->  19 passed
full collector regression                 -> 245 passed in 3.12s, 0 failed
                                             (R1 30 · R2 16 · R3 19 · pre-existing 180)
imports                                   -> main, routes.outbox, routes.preflight,
                                             framework.delivery_worker, health_gate
```

| required scenario | test |
|---|---|
| outage -> pause | `test_gate_opens_after_threshold_and_stops_consuming_attempts` (3 calls spent, not 10; 5 later ticks attempt nothing; attempts map unchanged) |
| no stranded/lost rows | `test_unattempted_rows_are_released_not_stranded` (`delivering == 0`, 2 retrying + 6 queued, total 8) |
| bounded recovery -> resume | `test_half_open_probes_a_single_row_then_closes_on_success` (probe risks exactly 1 row, then 5 drain normally) |
| failed probe backoff, bounded | `test_failed_probe_reopens_with_bounded_backoff` (10 -> 20 -> 40 -> 40 clamp, still probing) |
| attributed refusal must not pause | `test_authoritative_refusal_does_not_open_the_gate` (all 6 refused, gate `CLOSED`) |
| success resets the run | `test_success_resets_the_failure_run` |
| connect/DNS/timeout | `test_transport_failure_is_destination_evidence` |
| repeated 404 | tests 1, 2, 3, 9, 11 |
| repeated 5xx | `test_suspect_state_is_visible_before_pausing`, `test_success_resets_the_failure_run` |
| R1+R2 not bypassed | `test_gate_preserves_r1_classification_and_r2_evidence` |
| no false DELIVERED / no dup ack | `test_no_duplicate_acknowledgement_and_no_delivery_while_open`, `test_concurrent_ticks_do_not_double_acknowledge` |
| durability + idempotency | `test_idempotency_and_payloads_survive_a_gated_outage` |
| restart while unhealthy | `test_restart_while_unhealthy_is_safe_and_deterministic` (fresh gate `CLOSED`, `delivering == 0`, `delivered == 0`, 6 rows, attempts identical) |
| concurrency | `test_concurrent_ticks_do_not_double_acknowledge` (4 concurrent drains; no row invented or lost) |
| no retry storm | `test_open_gate_performs_no_network_io` (25 ticks, zero network calls, queue of 50 intact) |
| observability | `test_gate_state_is_reported_in_worker_status`, `test_suspect_state_is_visible_before_pausing` |
| configuration | `test_gate_defaults_come_from_environment`, `test_gate_rejects_nonsense_configuration`, `test_worker_has_a_gate_by_default` |
| happy path unaffected | `test_healthy_destination_is_unaffected` (12/12 delivered, gate never opened) |

### 13.7 Unresolved risks

1. **The gate is in-memory.** A restart during an outage begins `CLOSED` and
   re-probes immediately, so a crash-loop could re-spend the threshold each
   time. Deterministic and bounded (threshold attempts per start), but not
   persisted. Persisting gate state was not in scope.
2. **Row claiming is still select-then-update.** Two concurrent drains of the
   same outbox could claim the same row; the invariants hold (idempotent
   ingest, single terminal status, no row loss — proven by test 10) but this
   pre-existing race was not fixed under R3.
3. **Threshold semantics are consecutive-failure based**, not a rolling error
   rate; a destination failing 50 % of requests will oscillate
   `SUSPECT -> CLOSED` rather than opening. Acceptable for the outage class
   that caused G1; a rate-based policy is a later refinement.
4. **A long outage still ends in `retries exhausted`** for rows already close
   to their budget when the gate opened — materially better than instant
   destruction, but the gate does not retroactively restore budget.
5. **Attribution remains an unsigned header** (unchanged from R1/R2).
6. **Not deployed and not exercised against a live destination** — unit-proven
   only, by instruction.
