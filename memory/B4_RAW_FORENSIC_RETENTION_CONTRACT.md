# B4 · Raw forensic retention + refusal semantics — contract

Wave 0 evidence-integrity gate. Backend, persistence, authorization,
retrieval API and tests only. **No frontend scope.**

## 1 · The defect this closes

The G1 Windows Security RCA could name the MECHANISM of 24 refusals and not
the EventID of a single one. Two faults sat behind that:

1. a record whose EventID the DSM does not interpret was refused as
   `SOURCE_FORMAT_MISMATCH` — a COVERAGE gap presented as a malformed source,
   which made a healthy Security channel look broken;
2. nothing of the record survived the refusal. The delivery was
   authenticated, tenant-authorized and declared, and was then discarded;
   the block record kept only `payload_keys` and an excerpt sampled from
   `raw["line"]`/`raw["message"]`, fields a Windows record does not have.

## 2 · The refusal model

```
 ACCEPTED
     ↓
 RAW RETAINED
     ↓
 SOURCE RECOGNITION
   ├── SOURCE_FORMAT_MISMATCH        (≡ FORMAT_INVALID)
   ├── SOURCE_NOT_AUTHORIZED
   ├── SOURCE_RECORD_NOT_SUPPORTED   ← NEW
   └── SUPPORTED
           ↓  PARSED → NORMALIZED → EVALUATED
```

| code | meaning | raw retained |
|---|---|---|
| `DECLARATION_REQUIRED` | the delivery declared nothing | **no** |
| `UNSUPPORTED_SOURCE` | declaration names no catalog source | **no** |
| `SOURCE_NOT_AUTHORIZED` | allowlist does not permit the declaration | **no** |
| `SOURCE_FORMAT_MISMATCH` | the payload is not the declared format | yes |
| `SOURCE_RECORD_NOT_SUPPORTED` | the payload **is** the declared format; NivXRay has no coverage for this record type yet | yes |
| `SOURCE_DSM_UNAVAILABLE` | the authorized DSM is not loaded (code fault) | yes |

Authority failures retain nothing, on purpose: an undeclared or unauthorized
caller must never be able to buy durable storage inside a tenant by being
refused. `SOURCE_FORMAT_MISMATCH` keeps its exact historical spelling, so the
56 stored G1 block rows and the D15 suite remain valid;
`FORMAT_INVALID ≡ SOURCE_FORMAT_MISMATCH` is documentation only.

## 3 · DSM format-recognition contract

New OPTIONAL DSM hook:

```python
def recognizes_format(self, ev) -> bool: ...
```

Routing semantics (`services/source_routing.route`):

| `supports()` | `recognizes_format()` | outcome |
|---|---|---|
| True | not asked | ACCEPTED → normal DSM processing |
| False | True | `SOURCE_RECORD_NOT_SUPPORTED` |
| False | False / absent / raises | `SOURCE_FORMAT_MISMATCH` |

`DSM_REGISTRY.format_recognized()` is asked ONLY after compatibility already
failed, and fails closed twice over: a DSM without the hook, and a hook that
raises, both answer "not recognised" (the raise is recorded as
`RECOGNIZES_FORMAT_ERROR` in `resolve_failures()`). Recognition can therefore
never rescue a declaration.

Implemented on the Windows EVTX family, and deliberately per SOURCE FAMILY
rather than "is this EVTX" — a Security record declared as PowerShell is still
a `SOURCE_FORMAT_MISMATCH`:

| DSM | recognises when |
|---|---|
| `windows-security-evd` | readable record with an EventID **and** `Channel == Security` or provider contains `security-auditing` |
| `windows-powershell-evd` | readable record and `_is_powershell()` (provider/channel) |
| `windows-defender-evd` | readable record and `_is_defender()` (provider/channel) |
| `microsoft-sysmon` | readable record, provider contains `Sysmon`, EventID present |

`SUPPORTED_EVENT_IDS` was **not** widened anywhere. Parser support is claimed
only where parsing and normalization actually exist.

## 4 · Persistence contract · `xdr_ingest_raw_retained`

One document per retained forensic identity.

```
id                       rr_<hex24>   authoritative evidence identity
tenant_id, collector_id, connector_id, authority_basis
retained_identity_key    ingest_idempotency.event_identity().key
payload_digest, raw_sha256
source, source_event_id, collection_method
declared_source, declared_source_resolved, selected_dsm_id
raw                      VERBATIM, as delivered
raw_format               WINDOWS_RENDERED_EVTX_XML | VERBATIM_LINE |
                         DOCUMENT | OPAQUE
raw_keys
record_hints             {event_id, event_record_id, channel, provider,
                          time_created, extraction}   ADDITIVE hints only
clocks                   {activity_time_declared_by_source, source_timestamp,
                          collection_timestamp, collector_received_at,
                          nivx_received_at, retained_at}
provenance               {trace_id, routing (full decision),
                          parser_version_declared_by_collector,
                          event_type_declared_by_collector}
disposition              see below
honesty_note
first_seen_at, last_seen_at, delivery_count
```

Indexes:
* `ux_retained_identity` — UNIQUE `(tenant_id, retained_identity_key)`
* `ux_retained_id` — UNIQUE `(tenant_id, id)`
* `(tenant_id, first_seen_at DESC)`
* `(tenant_id, disposition.mismatch_reason)`

### Disposition — what a retained row does NOT claim

```
state                              RAW_RETAINED_NOT_EVALUATED
parsed                             false
normalized                         false
detection_evaluated                false
canonical_evidence_created         false
verdict                            null
benign_assertion                   false
counts_toward_connected_gate       false
ingest_idempotency_claim_consumed  false
reprocessable_when_coverage_exists true
```

Invariant: **RAW RETAINED ≠ PARSED ≠ NORMALIZED ≠ EVALUATED ≠ DETECTED.**
Absence of a verdict is absence of evaluation, never a clean bill of health.

Clocks are kept under their own names; a clock NivXRay did not observe is
absent, never manufactured from a neighbour. `record_hints` exist so an
investigator can FIND records ("which EventIDs did we refuse?") — `raw` stays
the authority and is never rewritten.

## 5 · Idempotency

* Retention takes **NO** `xdr_ingest_idempotency` claim. A record refused for
  missing coverage must be able to enter the normal pipeline once that
  coverage exists; consuming the claim would make the same delivery look like
  a DUPLICATE forever. Proven by test E, which enables coverage for EventID
  4798 in a controlled scope and watches the SAME delivery route to ACCEPTED.
* Inside the retention namespace, uniqueness is enforced on
  `(tenant_id, retained_identity_key)` via an atomic
  `find_one_and_update(..., upsert=True)`: the first delivery returns
  `RETAINED`, every repeat returns `ALREADY_RETAINED` and only increments
  `delivery_count`. One thousand re-deliveries of an unsupported record leave
  ONE forensic row.
* Accepted-path dedupe semantics are untouched.

## 6 · Refusal → evidence bridge

`xdr_ingest_routing_blocks` rows now carry:

```
retained_raw_id   the authoritative retained identity, or null
raw_retention     {state: RETAINED | ALREADY_RETAINED | NOT_ELIGIBLE |
                          UNAVAILABLE | FAILED, reason?, delivery_count?}
```

A retention store failure is reported as `FAILED` with its reason rather than
being presented as retained — the delivery was already refused, and claiming
retention that did not happen would be the same silent evidence loss this gate
ends.

The routing decision itself additionally carries
`declared_format_recognized` and `raw_retention_eligible`, so the disposition
and the retention promise can never disagree.

## 7 · Retrieval API (UI-ready, no frontend in this gate)

```
GET /api/xdr/ingest/routing/retained-raw
GET /api/xdr/ingest/routing/retained-raw/{retained_raw_id}
```

* Existing authenticated principal, existing session-derived tenant scope
  (`resolve_tenant_scope`), existing RBAC. No new authentication or tenant
  authority was created. `X-Tenant-Id` remains ignored on this surface.
* List is metadata-only (`raw_included: false`), bounded (`limit ≤ 200`) and
  paginated (`offset`), filterable by `reason_code`, `collector_id`,
  `declared_source`, `event_id`, `channel`, `since`, `until`. It is never a
  global enumeration: the tenant filter is always applied from the session.
* Fetch-by-id returns the verbatim raw. A record outside the caller's scope is
  answered with the same 404 as a record that does not exist, so the surface
  never confirms the existence of another tenant's evidence.

## 8 · Changed files

| file | change |
|---|---|
| `backend/services/source_routing.py` | `SOURCE_RECORD_NOT_SUPPORTED`, `RAW_RETENTION_ELIGIBLE_CODES`, `raw_retention_eligible()`, split refusal in `route()`, decision keys, catalog vocabulary |
| `backend/detection_content/telemetry/registry.py` | `format_recognized()` (fail-closed, observable) |
| `backend/detection_content/telemetry/evtx_xml.py` | `decoded_view()` — never-raising readability probe |
| `.../windows_security_dsm.py`, `windows_powershell_dsm.py`, `windows_defender_dsm.py`, `sysmon_dsm.py` | `recognizes_format()` |
| `backend/services/raw_forensic_retention.py` | **new** — retention authority + projections |
| `backend/routers/xdr_ingest.py` | retention at the refusal boundary + `retained_raw_id` bridge |
| `backend/routers/xdr_ingest_routing.py` | retained-raw list/fetch, retention fields on projections |
| `backend/tests/test_b4_raw_forensic_retention.py` | **new** — 25 tests, cases A-I |

## 9 · Not done, on purpose

* No Telemetry-health UI.
* No historical migration of the 56 stored `SOURCE_FORMAT_MISMATCH` rows;
  they are reported as `raw_retention.state = NOT_RECORDED` with the reason
  "this refusal predates B4".
* The 24 G1 Security EventIDs remain unrecoverable server-side — B4 makes
  FUTURE refusals self-describing; recovering the historical ones needs an
  owner-authorised read-only endpoint extraction.
* No `SUPPORTED_EVENT_IDS` widening, no validation weakened, no R4.
