# Windows Security `SOURCE_FORMAT_MISMATCH` — server-side root cause

**Lane:** read-only. No endpoint contact, no new Windows event generated, no
code changed, no DSM widened. All evidence below is stored G1 evidence read
out of MongoDB and the routing authority source.

**Verdict:** `MECHANISM = DETERMINED`. `EXACT_REFUSED_EVENT_IDS =
EVIDENCE_INCOMPLETE` (the one missing link is named in §5).

---

## 1 · The refusal population

`xdr_ingest_routing_blocks` (96 rows total) refusal histogram:

| reason | rows |
|---|---|
| `SOURCE_FORMAT_MISMATCH` | 56 |
| `SOURCE_NOT_AUTHORIZED` | 27 |
| `DECLARATION_REQUIRED` | 11 |
| `UNSUPPORTED_SOURCE` | 2 |

Of the mismatches, the Windows Security population from the G1 endpoint is:

| declared_source | reason | rows |
|---|---|---|
| `windows_security` | `SOURCE_FORMAT_MISMATCH` | **24** |
| `microsoft-sysmon` | `SOURCE_FORMAT_MISMATCH` | 13 |

The 24 Security refusals are contiguous `EventRecordID` 239169 … 239192 on
`DESKTOP-A9HGFJJ`, collector `col_d6b0b9e8172246f29be9`, tenant
`ten_f1a5479243e901cf159e230fa0`.

A representative record (verbatim fields):

```
source_event_id : ten_…|DESKTOP-A9HGFJJ|Security|239192
collection_method: windows-eventlog
payload_shape   : DOCUMENT
payload_keys    : ["channel", "xml"]
payload_excerpt : ""                      <-- see §5
routing:
  declared_source          : windows_security
  declared_source_resolved : windows-security-evd
  collector_authorized_sources: [microsoft-sysmon, windows-security-evd,
                                 windows-powershell-evd]
  selected_dsm_id          : windows-security-evd
  content_compatible       : false
  content_recognized_as    : []
  mismatch_reason          : SOURCE_FORMAT_MISMATCH
honesty_note: no raw row, no idempotency claim and no canonical evidence
              exist for this delivery
```

## 2 · The evidence chain, link by link

| Link | Status | Evidence |
|---|---|---|
| Windows event → rendered XML | OK | `payload_keys: [channel, xml]` |
| collector envelope | OK | same envelope shape as the ACCEPTED events |
| source declaration | OK | `declared_source: windows_security` |
| alias → catalog key | OK | resolved to `windows-security-evd` (`source_routing.SOURCE_ALIASES`) |
| collector allowlist | OK | `windows-security-evd` IS in `collector_authorized_sources` |
| DSM availability | OK | `selected_dsm_id` set; no `SOURCE_DSM_UNAVAILABLE` |
| content compatibility | **REFUSED** | `content_compatible: false`, `content_recognized_as: []` |
| canonical evidence | not produced | by design for a BLOCKED delivery |

Every link before content validation is proven correct by the block record
itself, so this is neither a declaration defect, an authorization defect, nor a
DSM-loading defect.

## 3 · The decisive control: the SAME channel was ACCEPTED minutes earlier

`xdr_canonical_events` holds 4 Security-channel rows from the same collector,
and `xdr_canonical_evidence` shows all 4 routed to `windows-security-evd`:

| EventRecordID | EventID | canonical event_type | normalized_ok |
|---|---|---|---|
| 239165 | 4624 | `logon_success` | true |
| 239166 | 4672 | `special_privileges_assigned` | true |
| 239167 | 4624 | `logon_success` | true |
| 239168 | 4672 | `special_privileges_assigned` | true |

The refused records (239169-239192) are the IMMEDIATELY FOLLOWING contiguous
records from the same channel, same collector, same envelope shape, same
declaration, same allowlist, same DSM.

This eliminates every systemic candidate: the EVTX XML decoder
(`evtx_xml.decode_document`), the envelope key contract (`xml` is in
`ENVELOPE_XML_KEYS`), the alias table, the allowlist and the DSM registry all
demonstrably work for this exact channel and this exact collector.

## 4 · Mechanism

`WindowsSecurityDSM.supports()`
(`backend/detection_content/telemetry/windows_security_dsm.py:670-686`) is the
only remaining discriminator. After decoding, its entire decision is:

```python
return int(eid) in SUPPORTED_EVENT_IDS
```

`SUPPORTED_EVENT_IDS` is 15 event IDs (4688, 4768, 4769, 4624, 4625, 4657,
4648, 4672, 4720, 4726, 4732, 4776, 4698, 1102). The Windows Security channel
carries hundreds — 4634, 4647, 4798, 4799, 4907, 5379, 5058, 5061 and so on
appear continuously on an idle desktop.

So the mechanism is:

> **A Security record whose EventID is outside the DSM's 15-ID coverage set is
> refused by content validation, and that refusal is reported as
> `SOURCE_FORMAT_MISMATCH`.**

`content_recognized_as: []` corroborates it: no other DSM claimed the payload
either, which is what a correctly-decoded Windows record of an uncovered
EventID looks like.

### Secondary finding (semantic, not required for R3)

`SOURCE_FORMAT_MISMATCH` currently conflates two different facts:

1. "this payload is not the declared format" — a real declaration violation;
2. "the declaration is CORRECT and the authorized DSM simply does not
   interpret this record type" — a COVERAGE gap.

The Security population is category 2 being reported as category 1. That
mislabels a coverage gap as a security-relevant format violation, and it is why
the channel looked broken rather than partially covered. A distinct refusal
code (e.g. `SOURCE_RECORD_NOT_SUPPORTED`) would separate them. **Not changed
here** — it is not required for R3/R3.1 correctness, and source validation must
not be weakened to make Security events pass.

## 5 · `EVIDENCE_INCOMPLETE` — the exact missing link

The precise EventID of each of the 24 refused records **cannot** be determined
from server-side evidence, because a refused delivery retains no payload:

* `xdr_ingest.py:748-751` writes only `payload_keys` plus an excerpt taken from
  `raw.get("line") or raw.get("message")`. The Windows adapter's raw uses
  `channel` + `xml`, so **`payload_excerpt` is empty for every Windows
  refusal**;
* no raw row is persisted for a BLOCKED delivery (stated in the record's own
  `honesty_note`) — this is the **B4 forensic raw-retention defect**;
* the endpoint-side outbox rows are not to be read in this lane.

Therefore:

* `MECHANISM` — determined (§3, §4), by elimination against a same-channel
  ACCEPTED control, not by inference about the payload.
* `EXACT_EVENT_IDS` — **EVIDENCE_INCOMPLETE**. Missing evidence, named
  precisely: *the rendered `System/EventID` (or the raw XML) of Security
  EventRecordIDs 239169-239192*. Recoverable two ways, neither executed here:
  (a) B4 raw retention, which would make future refusals self-describing;
  (b) a read-only extraction of those 24 records from the endpoint — owner
  decision, explicitly out of scope for this lane.

## 6 · What must NOT be concluded

* This is **not** evidence that the XML decoder failed — a per-record decode
  failure cannot be excluded for any individual row, but it is excluded as the
  population cause by the ACCEPTED control set.
* This is **not** a reason to widen `SUPPORTED_EVENT_IDS` or to relax
  `registry.compatible()`. Coverage is a DSM decision with canonical-model
  consequences, and loosening validation to make refusals disappear would
  destroy the declaration contract D15 exists to enforce.

## 7 · Read-only instruments used

* `/app/memory/rca_security_format_mismatch.py` — refusal histogram + records
* `/app/memory/rca_security_accepted_probe.py` — accepted-vs-refused probe
* `/app/memory/rca_canonical_shape_probe.py` — stored evidence shape
* `/app/memory/rca_security_eid_evidence.py` — Security EventID evidence

All four are read-only (`find` / `count_documents` only).
