# B5 | EID 5 END-TO-END ACCEPTANCE | READ-ONLY EVIDENCE REPORT

Endpoint: DESKTOP-A9HGFJJ. Read-only throughout: no deploy, no endpoint
change, no Sysmon change, no service restart, no UI work, no backfill, no
synthetic EID 5, no heuristic matching, nothing patched to obtain a PASS.

`OLD_ROLLBACK_BLOCKER = CLOSED` (superseded by the v2 baseline
`F5FFD2CA…16C9B9` and candidate `9398464D…0362E3`).

---

## GATE 1 | EID 5 CODE CONTRACT — PASS (8/8)

| invariant | verdict | code |
|---|---|---|
| Sysmon EID 5 admitted | PASS | `edr_plane/windows_eventlog.py:83` `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` |
| maps to `process_exit` / `ACTIVITY_PROCESS_TERMINATION` | PASS | `windows_eventlog.py:64,83`; `detection_content/telemetry/sysmon_dsm.py:241` `5: "process_exit"`; `process_identity.py:68` `TERMINATION_KINDS = {"process_exit","process_terminate"}` |
| `UtcTime` is EXIT time, never `start_time` | PASS | `windows_eventlog.py:668-694`: writes `process.exit_time` only, provenance `sysmon:UtcTime (EventID 5)`, and lists `process.start_time` in `not_observed` |
| ProcessGuid authoritative when present | PASS | `process_identity.py:205-221` `AUTHORITY_SOURCE_GUID`, key `guid\|tenant\|process_guid` |
| no identity ⇒ no `process_key` minted | PASS | `process_identity.py:232-252`: PID-only and no-process both return `process_key=None` (`AUTHORITY_PID_ONLY`, `AUTHORITY_NOT_OBSERVED`) |
| PID-only cannot terminate another process | PASS | same: a null key cannot join any lifecycle |
| PID reuse cannot cross-bind | PASS | GUID key survives reuse; the PID fallback additionally requires `start_time` (`AUTHORITY_ENDPOINT_PID_START`) |
| identity scoped by tenant | PASS | tenant is the first component of every key |

One nuance stated rather than glossed: the GUID key is
`guid\|tenant_id\|process_guid` — **tenant**-scoped, not endpoint-scoped.
Cross-endpoint separation relies on the machine component Sysmon already
mints inside the GUID (documented at `process_identity.py:207-211`), not on
an explicit endpoint term. Correct for Sysmon GUIDs; it would not hold for a
source that minted a non-machine-unique identifier.

## GATE 2 | THE GENUINE EID 5 RECORDS — NOT PRESENT IN THIS BACKEND

Read-only queries across the live preview database:

| query | result |
|---|---|
| `edr_endpoints` where hostname ~ `A9HGFJJ` | **0** — the laptop is not enrolled as an EDR agent endpoint here |
| `edr_raw_events` total | 263,445 (all from the Linux sensor `ep_2d57cbe6…`) |
| `edr_raw_events` payload contains `WINDOWS_EVENT_LOG` | **0** |
| `edr_raw_events` payload contains `Sysmon/Operational` | **0** |
| `edr_raw_events` payload contains `<EventID>5</EventID>` | **0** |
| `v2_shadow_observations` `event.kind = process_exit` | **0** |
| `xdr_canonical_evidence` `event_type = process_exit` | **0** (not even in the distinct list) |
| the 10 owner-supplied ProcessGuids, in raw / canonical / observations | **0 of 10** |

What *does* exist for this host, and how it got here:

* 3,300 canonical rows for `host.hostname = DESKTOP-A9HGFJJ`, tenant
  `ten_f1a5479243e901cf159e230fa0`;
* source event ids **1, 3, 11, 12, 13, 22, 4624, 4672** — **no 5**;
* newest `event_time` **2026-09-22 16:20**, newest `ingest_time`
  **2026-09-25T15:35:33Z**;
* provenance shows the **XDR collector** path (`collector_id: col-timecheck-…`,
  `dsm_id: microsoft-sysmon`), not the EDR agent path;
* `xdr_collectors` seen in the last 7 days: **0**.

So this backend has received **nothing at all** from that host since
2026-09-25T15:35Z — four days before the EID 5 enablement at ~14:48 UTC on
2026-09-29. The absence is upstream of every parser and every identity rule.

### Boundary table

| # | boundary | status | count | evidence |
|---|---|---|---|---|
| B0 | endpoint generation | **PROVEN** (owner) | 10 GUID pairs | owner transcript, Sysmon log, 14:48–14:50 UTC |
| B1 | sensor read | NOT_MEASURABLE | — | sensor counters OFF by design (`NIVX_SENSOR_DELIVERY_COUNTERS` not enabled); no server-side view of endpoint reads |
| B2 | sensor queue / outbox | NOT_MEASURABLE | — | endpoint-local state; not read (read-only, no endpoint contact) |
| B3 | sensor sent | NOT_MEASURABLE | — | same; `boundary_measurability = NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED` |
| B4 | backend received | NOT_YET_OBSERVED | 0 | 0 Windows envelopes in `edr_raw_events`; tenant counters `received = 0`; last delivery from this host 2026-09-25T15:35Z |
| B5 | accepted / refused / deduped | NOT_YET_OBSERVED | 0 | nothing received ⇒ nothing to accept. **No refusal of any genuine EID 5 occurred** |
| B6 | DSM / parser | NOT_YET_OBSERVED | 0 | contract verified in Gate 1; no record has reached it |
| B7 | canonicalized | NOT_YET_OBSERVED | 0 | `process_exit` absent from both canonical stores |
| B8 | process identity bound | NOT_YET_OBSERVED | 0 | none of the 10 GUIDs resolve to any observation |
| B9 | lifecycle termination projected | NOT_YET_OBSERVED | 0 | every process on this host correctly remains `PROCESS_LIFETIME_UNKNOWN` |

**This is not telemetry loss and it is not called loss.** But it is also not
purely spool latency: the counters show nothing arriving from this host on
any path, and the delivery destination of the laptop's sensor in *this*
forked environment is unverified — the preview URL changed with the fork.
That is a destination question for the owner, not a defect in the chain.

## GATE 3 | CANONICAL EID 5 PROOF — NOT_YET_OBSERVED

No genuine EID 5 exists downstream, so nothing is asserted. The contract that
*will* apply is proven by code and by test, not by claim:
`exit_time` is written from `UtcTime` with provenance
`sysmon:UtcTime (EventID 5)`, and `process.start_time` is explicitly declared
`not_observed` on the EID 5 record — a start time can never be synthesised
from an exit record.

## GATE 4 | EID 1 / EID 5 IDENTITY — NOT_YET_OBSERVED (0 pairs downstream)

The owner proved 10 GUID-identical EID1/EID5 pairs **on the endpoint**. None
have reached this backend, so no downstream pair can be shown. Nothing was
matched by PID, time or name to manufacture one.

## GATE 5 | NEGATIVE SAFETY INVARIANTS — PASS (38 focused tests)

`pytest tests/edr/test_b5_process_termination.py tests/edr/test_b2_process_identity.py`
→ **38 passed**. No broad regression suite was run.

| invariant | verdict |
|---|---|
| GUID A termination cannot terminate GUID B | PASS |
| same PID reused by another GUID cannot cross-bind | PASS |
| cross-tenant GUID lookup cannot bind | PASS (tenant is in the key) |
| cross-endpoint GUID lookup cannot bind | PASS *via the GUID's own machine component* (see the Gate 1 nuance) |
| EID 5 without authoritative identity mints no `process_key` | PASS |
| duplicate / replayed EID 5 is idempotent | PASS |
| observations without EID 5 stay `PROCESS_LIFETIME_UNKNOWN` | PASS |
| enabling EID 5 reconstructs no history | PASS — and confirmed in data: 0 `process_exit` rows, no backfill attempted |

## GATE 6 | DELIVERY ACCOUNTING

Tenant `ten_f1a5479243e901cf159e230fa0` (the DESKTOP-A9HGFJJ tenant):

```
endpoint_generated        NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED
                          (endpoint-side proof exists in the owner transcript)
sensor_read               NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED
sensor_queued             NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED
sensor_sent               NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED
backend_received          0
backend_accepted          0
backend_refused           0
backend_deduplicated      0
canonicalized             0
```

For reference, tenant `default` (the Linux sensor) over the same counter
epoch: received 1047 · accepted 1046 · deduplicated_payload 1 · parsed 1044 ·
canonicalized 1044 · parse_failed 2 · refused 0 · `unaccounted_received = 0` ·
`unaccounted_accepted = 0`. The counters work; they simply have nothing to
count for the Windows host. No boundary was derived by subtraction. **No
genuine EID 5 was refused anywhere.**

## GATE 7 | IDENTIFIER AUTHORITY — NOT_YET_OBSERVED, NO DIVERGENCE

No new EID 5 canonical evidence exists, so no new identifier has been minted
and no divergence can be reported. The path it will take was proven in the
closure wave (`tests/edr/test_c5_identifier_end_to_end.py`): the bridge mints
the id, the DSM carries it, and `xdr_canonical_evidence` no longer mints a
`_pl` duplicate. Every resolution query carries the tenant. No historical
evidence was migrated.

## GATE 8 | PROCESS LIFETIME RESULT — CORRECT

Zero authoritative terminations exist in this backend, and every process is
`PROCESS_LIFETIME_UNKNOWN`. Nothing was converted to a guess: no process is
claimed terminated, and no process is claimed still running.

---

## FINAL

```
EID5_ENDPOINT_GENERATION        = PROVEN (owner endpoint evidence)
EID5_SENSOR_READ                = NOT_MEASURABLE
EID5_SENSOR_DELIVERY            = NOT_MEASURABLE
EID5_BACKEND_RECEIVE            = NOT_YET_OBSERVED
EID5_BACKEND_ACCEPTANCE         = NOT_YET_OBSERVED
EID5_CANONICAL_PROCESS_EXIT     = NOT_YET_OBSERVED
EID5_PROCESSGUID_BINDING        = NOT_YET_OBSERVED
EID5_LIFECYCLE_TERMINATION      = NOT_YET_OBSERVED
EID5_TENANT_ENDPOINT_ISOLATION  = PROVEN (code + 38 focused tests)
EID5_IDENTIFIER_AUTHORITY       = NOT_YET_OBSERVED (no divergence; path proven)
EID5_DELIVERY_ACCOUNTING        = PARTIAL - server boundaries measured (all 0
                                  for this tenant); sensor boundaries
                                  NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED
OLD_ROLLBACK_BLOCKER            = CLOSED

B5_EID5_END_TO_END = WAITING_FOR_DELIVERY
```

Not PASS: no genuine EID 5 has reached canonical evidence. Not BLOCKED: no
admission, parser, canonicalisation, identity or security defect was
demonstrated — the contract passes on code and on tests, and nothing has been
refused.

### What the owner may want to resolve (no action taken)

The last delivery from DESKTOP-A9HGFJJ into this backend was
**2026-09-25T15:35Z**, four days before enablement, and it arrived on the
**XDR collector** path (no collector seen in 7 days) rather than the EDR
agent path — the host is not in `edr_endpoints` at all. So before treating
spool latency as the only explanation, it is worth confirming which backend
URL the laptop's sensor is configured to deliver to, since the preview URL
changed when this environment was forked. Read-only ways to answer that exist
on the endpoint, but none were run.
