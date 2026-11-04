# B5 — CLOSURE RECORD (OWNER DECISION: OPTION 1)

Owner ruling 2026-09-30. B5 closed on the 17 genuine production Sysmon EID5
ProcessTerminate events. `B5-GAP-1` opened and preserved. Provider-qualified EID5
measurement contract implemented and regression-tested.

## STATUS

```
B5_FINAL_STATUS      = PASS
B5_GAP_1_STATUS      = OPEN / ROOT CAUSE NOT YET PROVEN
EID5_PROVIDER_FILTER = IMPLEMENTED
REGRESSION_TEST      = 18 new tests PASS · full EDR gate suite 1,738 passed, 0 failed
B5_READY_TO_LEAVE    = YES
```

## 1 · WHAT B5 PASS RESTS ON

17 genuine `Microsoft-Windows-Sysmon` EventID 5 (ProcessTerminate) records from
`DESKTOP-A9HGFJJ`, UtcTime 2026-09-29 15:17:21 → 17:40:10Z, measured in production
store `greeting-app-5782-test_database` on run `3bd64025`, each proven through the
complete ordinary delivery chain:

```
Sysmon EID5 → sensor → raw received → accepted (0 refusals)
→ canonical process_exit (17, exactly 1:1)
→ exit_time ← "sysmon:UtcTime (EventID 5)", start_time null
→ ProcessGuid identity, nivx:ProcessIdentity.mint(endpoint_id, ProcessGuid)
→ ≥4 EID1/EID5 pairs sharing one ProcessGuid and process_key
→ lifecycle termination observed
→ Device Trajectory projection under dev_2adbb41a04a4
→ tenant ten_e759b7288598bd882e3dcac49d preserved · no _pl authority · no backfill
```

The capability B5 existed to prove — evidence-backed process termination instead of
`PROCESS_LIFETIME_UNKNOWN`, bound by authoritative `ProcessGuid` rather than PID
heuristics — is demonstrated on genuine production telemetry.

### The original 10 ProcessGuids
Not required to close the capability gate. They remain historical evidence of a
separate collection-coverage gap and **must not be replayed, reconstructed, backfilled,
synthesized or otherwise manufactured**. Nothing of the sort was done or proposed.

## 2 · B5-GAP-1 — OPEN

```
B5-GAP-1 · Sysmon EID5 collection start-point coverage gap (~14:48–15:16Z,
           DESKTOP-A9HGFJJ)
STATUS   · OPEN / ROOT CAUSE NOT YET PROVEN
```

Measured facts only:
- No Sysmon EID5 exists for the ~14:48–15:16Z UtcTime window (28 minutes).
- Every Sysmon EID5 from 15:17:21Z onward is present and fully processed.
- 0/10 target ProcessGuids in `edr_raw_events`, `xdr_ingest_raw_retained`,
  `xdr_canonical_events`, `v2_shadow_observations`.
- 0 refusals for this endpoint in `edr_rejected_telemetry`.
- The frontier passed the window by ~6h of event-time, so this is not lag.

**The "sensor subscription predated the Sysmon configuration change" explanation is a
HYPOTHESIS ONLY and is NOT recorded as root cause.** Establishing root cause requires
endpoint/sensor evidence — whether the 10 guids still exist in the host's local Sysmon
log, and where the sensor's EID5 channel coverage actually starts. That investigation is
deferred by owner instruction; nothing on the endpoint, sensor, Sysmon config or outbox
was inspected or touched.

## 3 · EID5 MEASUREMENT CONTRACT — CORRECTED

The defect: a bare `EventID = 5` count returned **249** records for this endpoint and
looked like abundant termination evidence. Only **17** were genuine Sysmon
ProcessTerminate; the remainder were `Microsoft-Windows-IsolatedUserMode` EventID 5
(Secure Trustlet start), which is not a termination. A 14× overstatement of termination
evidence is a measurement that lies.

Implemented in `backend/edr_plane/windows_eventlog.py`:

| Addition | Purpose |
|---|---|
| `SYSMON_PROVIDER_GUID = "5770385F-C22A-43E0-BF4C-06F5698FFBD9"` | the provider identity, documented with the 249-vs-17 defect that motivated it |
| `FAMILY_PAYLOAD_REGEX["sysmon"]` extended | now also recognises the provider **GUID** (`"provider_guid"` JSON key and XML `Guid='…'`), the XML `<Channel>` form and XML `Provider Name='…'`. Every alternative stays keyed to a field name or attribute, never a bare substring, so a command line that merely mentions Sysmon cannot qualify a record |
| `event_id_regex(event_id)` | matches the event id in **both** payload shapes — JSON envelope and event XML |
| `sysmon_event_clause(event_id, payload_field="payload")` | THE sanctioned `find()` clause: requires provider **AND** event id. Usable against other fields (e.g. `raw.xml`) |
| `is_sysmon_event(payload, event_id)` | in-process counterpart for counting over a corpus |
| `payload_event_id_regex` docstring | now states **PROVIDER-BLIND** and "never use alone to COUNT a Sysmon event id" |

Product queries were *already* provider-qualified (`activity_query_clauses` and
`activity_projection_expr` both AND the family regex with the event id), so no live
query was ever wrong — the defect lived in ad-hoc measurement. The additions make the
safe path the obvious one and widen genuine-Sysmon recognition to GUID-only and
XML-shaped payloads.

## 4 · REGRESSION TEST

`backend/tests/edr/test_b5_sysmon_provider_qualified_counting.py` — **18 passed**:

- genuine Sysmon EID5 counts in JSON envelope, event XML, GUID-only XML, GUID-only JSON
- `Microsoft-Windows-IsolatedUserMode` EID5 does **not** count, in both shapes
- an event id with no provider at all does not count
- a command line mentioning "Sysmon" is not provenance (checked for both 5 and 4688)
- right provider + wrong event id does not count
- `5` is not matched inside `5379`
- **the 249-vs-17 defect in miniature**: a mixed corpus of 3 Sysmon + 16 Trustlet +
  noise yields exactly 3, and the test asserts that a provider-blind count overstates
- the sanctioned clause has exactly two terms, one of which carries the provider GUID
- the canonicaliser maps Sysmon EID5 → `ACTIVITY_PROCESS_TERMINATION`, and **refuses**
  IsolatedUserMode EID5 with "not a supported Windows evidence source … not evidence of
  absence"
- **the B5 invariant re-proved**: `exit_time` from `UtcTime (EventID 5)`,
  `start_time` null, and no `start_time` provenance entry

## 5 · INVARIANTS PRESERVED (re-verified, not assumed)

`EID5 UtcTime → exit_time` · never `start_time` · `ProcessGuid` authoritative ·
no PID/time/name heuristic termination binding · EID5 never leaves a process at
`PROCESS_LIFETIME_UNKNOWN` · no historical termination backfill · tenant isolation
preserved · no new `_pl` authority.

Full EDR gate suite, CI command and CI-only env, backend unreachable:
**1,738 passed, 0 failed, 0 errors.**

### Disclosed: a defect I introduced and fixed in this step
The platform-designation tests I added in the previous step used
`asyncio.get_event_loop().run_until_complete(...)`, which fails once another async test
has replaced or closed the loop — 17 failures when the suite ran in full, though they
passed in isolation. Replaced with a fresh `asyncio.new_event_loop()` per call, closed
in a `finally`. The CI gate would have caught this; it is fixed and the full suite is
green. The product change in this step (the provider-qualified matcher) caused none of
those failures.

## 6 · NOT DONE

E3 NOT started. No endpoint / sensor / Sysmon / outbox contact. No replay, backfill,
reconstruction or synthesis. No deploy (this is source + tests only; the corrected
matcher reaches production on the next ordinary publish). No UI change.

STOP FOR OWNER REVIEW.
