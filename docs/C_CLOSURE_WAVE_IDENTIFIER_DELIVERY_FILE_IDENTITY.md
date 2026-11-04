# CLOSURE WAVE · IDENTIFIER AUTHORITY → PARSE/DELIVERY OBSERVABILITY →
# DELIVERY COUNTERS → FILE CONTENT IDENTITY

Owner-approved order executed in one pass. **STOPPED before EID 5 PRE.**
Nothing deployed, no endpoint touched, no historical evidence migrated or
rewritten, no heuristic matching introduced, no UEBA/ML/trajectory work
started.

---

## PRIMARY_ID_RESOLUTION_NEW_DATA — **PROVEN (hermetic end-to-end)**

`canonical_bridge.canonical_event_id(raw_id, generation)` is now the ONLY
minting function on the affected canonical path
(`CANONICAL_EVENT_ID_AUTHORITY = "edr_plane.canonical_bridge.canonical_event_id"`).

* the bridge publishes the minted id on the authenticated ingest
  envelope (`_authenticated_ingest.canonical_event_id` +
  `canonical_event_id_authority` + `replay_generation`);
* `detection_content/telemetry/nivxforge_sensor_dsm.py` **carries** it
  (canonical evidence → authenticated envelope → authority function for
  the first generation) and publishes `provenance.canonical_event_id_basis`
  so the basis of every id is visible. The `_pl` string is **no longer
  composed anywhere** (pinned by a source assertion);
* `canonical_bridge.py` now contains exactly ONE `cev_` format string —
  the authority itself (pinned by a source assertion).

End-to-end proof on a real `bridge()` run
(`tests/edr/test_c5_identifier_end_to_end.py`, 6 cases): for one
authenticated event the bridge result, `v2_shadow_observations`,
`edr_raw_events.derivations[].event_id`, **`xdr_canonical_evidence`** and
the campaign detection row (`_campaign_detection`) all name the SAME
identifier, and resolution reports `resolved_via = canonical_event_id`
with `is_fallback = false`. Before this wave the detection plane wrote
the `_pl` form into `xdr_canonical_evidence` for the same event — that
duplicate authority is gone for new data.

*Not yet observed on LIVE data*: the live corpus has produced no new
rule-matching detection since the repair, so the live proof of primary
resolution is **PENDING REAL DETECTION**, not claimed.

## LEGACY_FALLBACK_RESOLUTION — **PRESERVED AND MEASURABLE**

New `edr_plane/evidence_resolution.py` resolves in the fixed order
authority id → legacy `_pl` → `raw_event_id`
(`event.provenance.ingest_job_id`). Only authoritative references; no
timestamp/PID/name/proximity matching anywhere.

Every activity in Campaign Story now publishes:
`process_identity_resolved_via`, `resolution_is_fallback`,
`canonical_event_id_form`, `resolution_attempts[]`,
`resolution_unresolved_reason`. The existing
`canonical_id_scheme_divergence` gap is now raised on FALLBACK usage
(not only on the raw-id path), so a fallback that keeps working can no
longer hide a primary-id regression.

LIVE (`inc_c253027ba781494684db`, tenant `default`, read-only):
15/15 activities resolve, all `resolution_is_fallback = true`,
`canonical_event_id_form = LEGACY_PIPELINE_MINTED`, request 0.367 s
(the B5.2 indexes are still doing their job).

Measured debt baseline (preview DB, read-only):

| measurement | value |
|---|---|
| campaign detection rows carrying the LEGACY `_pl` reference | **1,680** |
| campaign detection rows carrying the AUTHORITY reference | **4** |
| rows with no reference at all | **0** |
| `v2_shadow_observations` holding a `_pl` id | 2 |
| `xdr_canonical_evidence` rows holding a `_pl` id (history) | **254,943** |

None of it was migrated, back-filled or deleted. Fallback usage is now a
published, countable number, so it can be watched down over time.

## CROSS_TENANT_ID_TEST — **REFUSED, NON-DISCLOSING**

Tenant is part of every resolution query. With an identical
`canonical_event_id` and `raw_event_id` planted in two tenants, a
third tenant resolves NOTHING and the returned object contains no field
from either tenant's evidence (asserted on the serialised result).
Resolution inside the other tenant returns that tenant's own row only.

## PARSE_FAILURE_ACCOUNTING — **COUNTED, AUDITABLE, REASON-CODED**

`/api/edr/agent/telemetry` now records a terminal delivery outcome for
every received event, in TWO layers (an event has two outcomes — was it
stored, and was it canonicalised):

```
storage:          received = accepted + deduplicated_payload
canonicalisation: accepted = canonicalized + deduplicated_activity
                             + parse_failed + refused
```

A parser failure increments `parse_failed` **plus** a reason code
(`parse_failure_reasons.PARSER_FAILED`); a canonicalisation refusal
increments `refused` plus `refusal_reasons.<CODE>`. Deduplication is
classified (`deduplicated_payload` = byte-identical re-delivery,
`deduplicated_activity` = re-observation of activity already held as
evidence) and is explicitly **not** loss; latency is not loss either.

LIVE (tenant `default`, read-only, real Linux sensor):
received 365 · accepted 364 · deduplicated_payload 1 · parsed 363 ·
canonicalized 363 · parse_failed 1 (`PARSER_FAILED`) · refused 0 ·
`unaccounted_received = 0` · `unaccounted_accepted = 0`. The failing
record is visible as its own channel `UNPARSEABLE_ENVELOPE`. No
historical refusal reason was invented — counters start from the epoch
they were introduced.

## DELIVERY_BOUNDARY_MEASURABILITY — **SERVER MEASURED · SENSOR CAPABLE (NOT DEPLOYED)**

`edr_plane/delivery_counters.py` (new), published read-only on the
existing `GET /api/edr/wave0/raw-events/stats` as `delivery_boundaries`:

* boundaries: `endpoint_observed → endpoint_read → sensor_attempted →
  sensor_sent → received → parsed | parse_failed | refused → accepted |
  deduplicated → canonicalized`;
* server counters are `$inc` only, keyed `(tenant_id, endpoint_id,
  channel)`, never reset, never `$set`/`$unset`/deleted (pinned by a
  source assertion), `evidence_authority: false`;
* sensor counters are stored under the reserved channel `__sensor__` as
  a **CLAIM** (`authority: SENSOR_CLAIMED`) and never contribute to a
  server measurement. Restart semantics are explicit: a new
  `counter_epoch` closes the previous one into `sensor_epoch_history`
  with its final snapshot — counters never appear to decrease and epochs
  are never merged;
* the payload allow-list refuses anything that is not a declared
  boundary, a negative value, a non-int, a bool or an out-of-range value;
* channel classification is coarse metadata (`Security`,
  `SENSOR_PROCESS`, `UNPARSEABLE_ENVELOPE`) — no event content, no path,
  no command line, no credential enters a counter document (asserted).

SENSOR SIDE, implemented and **default OFF**
(`agents/nivxforge-{linux,windows}/nivxforge_delivery_counters.py`,
byte-identical copies, the same convention `nivxforge_exclusions.py`
uses): monotonic per-epoch counters, a high-water gauge for queue depth,
`heartbeat_fields()` returns `{}` unless
`NIVX_SENSOR_DELIVERY_COUNTERS=1`. Wired into both sensors at collect,
policy suppression, drain attempt/sent/failed and queue depth. The
heartbeat route accepts the additive `counter_epoch` +
`delivery_counters` fields and refuses malformed ones with 422
`SENSOR_COUNTER_REFUSED`.

LIVE state: `sensor_claimed: []` and `endpoint_observed /
sensor_sent = NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED` — correct,
because the capability is not deployed to any endpoint in this wave.

## FILE_CONTENT_HASH_CONTRACT — **ENFORCED AT THE SERVER BOUNDARY**

`edr_plane/file_content_acquisition.py` (new). The three digests are
separate constants and are never substituted:
`PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256 != RAW_PAYLOAD_CONTENT_DIGEST`.

A digest is admitted ONLY when the record states `ACQUIRED` **and** a
declared `content_version_state` **and** `acquired_at` **and** a
lowercase 64-hex SHA-256. Otherwise it is refused with a named cause.
Declared acquisition states: `ACQUIRED`, `NOT_ELIGIBLE_BY_POLICY`,
`FILE_ABSENT_AT_ACQUISITION`, `ACCESS_DENIED`,
`LOCKED_OR_SHARING_VIOLATION`, `SIZE_LIMIT_EXCEEDED`, `TIMEOUT`,
`IO_ERROR`, `RATE_LIMITED`, `HASH_NOT_ATTEMPTED`, `DROPPED_QUEUE_FULL`,
`CAPABILITY_DISABLED`. `CHANGED_DURING_ACQUISITION` (torn read) is
**discarded**; `CHANGED_SINCE_EVENT` is retained, labelled and filterable
("NOT provably the content the event described"), per the owner's
decision. Field provenance is `sensor:content_acquisition(SHA-256)` —
never `sysmon:*`. Backward compatibility: a bare source-stated digest is
still admitted but marked `SOURCE_STATED_NO_ACQUISITION_RECORD` with
`content_version_state: UNKNOWN`. Absence stays
`HASH_NOT_OBSERVED` / `HASH_NOT_ATTEMPTED` — **UNKNOWN never becomes
BENIGN** (asserted: the string `BENIGN` cannot appear in the result).

Carried on both canonical paths: the sensor FILE branch and the Windows
envelope branch of `canonical_bridge`, as
`file.content_acquisition` + `file.hash_state` + `file.hash_class` +
`file.hash_reason` + `file.field_provenance`.

## FILE_CONTENT_HASH_POSITIVE_CONTROL — **REAL BYTES HASHED**

`agents/nivxforge-*/nivxforge_content_acquisition.py` (new, default OFF
behind `NIVX_SENSOR_FILE_HASHING`) implements the owner-approved B3
defaults: allow-list by extension, privacy trees excluded by default,
64 MiB ceiling, 120 files/min + 512 MiB/min budget, 2 s settle window,
1 MiB streamed reads, 5 s per-file deadline, pre/post `(file_id, size,
mtime)` TOCTOU comparison, `(dev, inode, size, mtime)` cache with a
24 h TTL where a CACHE_HIT keeps the ORIGINAL `acquired_at`.

Positive control: a real file is read and its digest equals
`hashlib.sha256(bytes)`, the record passes the server contract and B3's
`from_canonical()` then reports `CONTENT_IDENTITY_SHA256`.
Negative controls: capability disabled, absent file, non-allow-listed
extension, DELETE operation, size ceiling, rate budget, torn read,
missing version, missing read time, malformed digest, undeclared state —
each yields NO digest and a stated cause. The record is also asserted to
contain no file content.

Windows sensor: Sysmon 11/15 `TargetFilename` acquisition is wired
behind the same flag (Sysmon states no content digest of its own).
**Not deployed.**

## PROCESS_IMAGE_VS_FILE_CONTENT_SEPARATION — **HELD**

A FILE event with a process-image SHA-256 on the same canonical event
yields `file.hashes == {}`, `identity_basis = PATH_IDENTITY_ONLY`, while
`process_image_identity()` returns the image digest under
`hash_class = PROCESS_IMAGE_HASH`. A record that DECLARES
`hash_class = PROCESS_IMAGE_SHA256` for a file is refused outright.

## EID5_PRE_STATUS — **NOT CAPTURED (owner action)**

`docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1` has not been run with
`$Label = 'PRE'`. No endpoint configuration was touched by this wave.

## EID5_POST_STATUS — **NOT STARTED** (blocked on PRE, by instruction)

## PROCESS_TERMINATION_BINDING — **SERVER-READY, UNCHANGED THIS WAVE**

B5-1 stands: Sysmon EID 5 canonicalises as `process_exit`, binds through
`ProcessGuid` to the same `process_key`, and lifetime moves to
`PROCESS_TERMINATION_OBSERVED` only on collected evidence. No historical
termination was reconstructed.

## TESTS

* new: `tests/edr/test_c1_canonical_event_identity.py` (13),
  `test_c2_evidence_resolution.py` (12),
  `test_c3_delivery_counters.py` (14),
  `test_c4_file_content_identity.py` (25),
  `test_c5_identifier_end_to_end.py` (6) → **70 new cases, all green**;
* regression: `pytest tests/edr` → **1,759 passed, 2 skipped** (live-API
  files excluded as usual);
* pre-existing and NOT caused by this wave (verified by stashing the
  whole wave and re-running):
  `tests/test_b4b5_tenant_registry_authority.py` — 3 failures
  (`TENANT_NOT_RESOLVED` vs `TENANT_REQUIRED` and two cross-tenant
  principal expectations). Reported, not patched.

## CODE_CHANGED — YES

New: `backend/edr_plane/{evidence_resolution,delivery_counters,file_content_acquisition}.py`,
`agents/nivxforge-{linux,windows}/{nivxforge_delivery_counters,nivxforge_content_acquisition}.py`,
5 test files.
Modified: `backend/edr_plane/{canonical_bridge,campaign_story}.py`,
`backend/detection_content/telemetry/nivxforge_sensor_dsm.py`,
`backend/routers/{edr_enrollment,edr_wave0}.py`, `backend/server.py`
(one index block), both sensors, the Windows installer script and the
Windows build script (two new module names).

## DATA_CHANGED — NO EVIDENCE CHANGED

No evidence, detection, incident or observation was written, rewritten,
migrated or deleted. The only NEW documents are operational counters in
the new `edr_delivery_counters` collection (3 documents live), which are
explicitly `evidence_authority: false`. One new index
`uniq_tenant_endpoint_channel` on that new collection.

## ENDPOINT_CHANGED — NO

No endpoint was modified. Both new sensor capabilities are OFF by
default and are not installed anywhere. The EID 5 change was NOT applied.

## DEPLOYED — NO

Preview only. No production publish.

## BLOCKERS / NEXT OWNER ACTION

1. Run `docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1` elevated with
   `$Label = 'PRE'` and return the transcript. PRE is not complete
   without it.
2. Then, and only then, apply the approved Sysmon ProcessTerminate
   change and we measure POST at T+24 h (the measured 59-minute p50 /
   2.9-day worst-case spool).
3. Open, deliberately: LIVE proof of primary-id resolution needs one new
   rule-matching detection on real telemetry.
4. Open, deliberately: the third identifier scheme was **REVIEWED AND
   CLASSIFIED, NOT CHANGED** (owner instruction). Measured:
   * `detection_content/telemetry/sysmon_dsm.py:229` mints
     `f"sysmon-{eid}-{uuid4().hex}"`;
   * `detection_content/telemetry/windows_security_dsm.py:639` mints
     `str(uuid4())`.

   Classification: both are **NON-DETERMINISTIC per-normalisation
   surrogates**. They identify a NORMALISATION PASS, not an immutable raw
   event — re-processing the same record yields a different identifier,
   so they cannot carry provenance the way the bridge's identifier does.
   That is a genuinely different identity semantic, which is exactly why
   they were not converted: making them authority-minted requires a
   stable raw-event identity + replay generation on the XDR collector
   ingest path (both normalizers receive a `trace_id`, so it is
   feasible), and that is its own decision with its own regression
   surface. Flagged, not guessed.
5. Sensor delivery counters and B3 hashing are code-complete and OFF.
   Turning either on at an endpoint is a separate owner decision.
