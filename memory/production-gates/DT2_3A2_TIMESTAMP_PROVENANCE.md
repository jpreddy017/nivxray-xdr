# DT2-3a.2 · SOURCE TIMESTAMP PROVENANCE INVESTIGATION

Owner decision: investigate provenance first. DATA_CHANGED: NO. CODE_CHANGED: NO.

## CORPUS_ORIGIN

`/app/scripts/p0_w1_sysmon_onboarding_proof.py` — Gate W1 synthetic Sysmon
acceptance harness. Line 132 hardcodes the timestamp for EVERY record:

```python
"UtcTime": "2026-06-01T10:00:00Z",
```

The script's own docstring: "REPLAY/SYNTHETIC PROVEN — NOT REAL-SOURCE PROVEN …
no Windows host is reachable from this environment, so W1's real-source
acceptance is REAL_SOURCE_BLOCKED and W1 is NOT closed."

Delivered over `POST /api/xdr/ingest/telemetry`, `source: "w1-proof"`,
`collection_method: "wef"`, collector `col_806bb4469dbd48d1ae12`,
host `WS-W1-1789575060`, ingested 2026-09-16T16:11:01Z.

## TIMESTAMP_PROVENANCE_TABLE

| SEQ | EVENT (source_event_id) | SOURCE_TS (raw.UtcTime) | NORMALIZED_TS | STORED event.ts | STATUS |
|---|---|---|---|---|---|
| 0 | proc_creation_win_susp_encoded_pshell | 2026-06-01T10:00:00Z | 2026-06-01T10:00:00Z | 2026-06-01T10:00:00Z | PRESERVED |
| 1 | proc_creation_win_regsvr32_squiblydoo | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 2 | proc_creation_win_mshta_remote_hta | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 3 | proc_creation_win_rundll32_user_writable | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 4 | proc_creation_win_certutil_urlcache | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 5 | proc_creation_win_bitsadmin_download | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 6 | proc_creation_win_wmic_process_call | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 7 | proc_creation_win_schtasks_persistence | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 8 | proc_creation_win_msiexec_remote | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 9 | proc_creation_win_office_spawns_shell | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 10 | behavior_lolbin_from_office | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 11 | win_persistence_registry_run_key (EID 13) | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 12 | benign | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 13 | rename | 2026-06-01T10:00:00Z | same | same | PRESERVED |
| 14 | file (EID 11) | 2026-06-01T10:00:00Z | same | same | PRESERVED |

Stages verified: `xdr_canonical_events.raw.UtcTime` → `sysmon-normalizer` →
`v2_shadow_observations.event.ts` / `captured_at`. Identical at every stage.

## ROOT_CAUSE_IDENTICAL_TIMESTAMP

**F — synthetic fixture events that never had individual authoritative
timestamps.** One hardcoded literal in the W1 proof harness, faithfully
carried through the pipeline.

Classification: `SINGLE_INSTANT_SYNTHETIC_ACCEPTANCE_FIXTURE`.
Not representative real Windows trajectory data.

- SOURCE_TIMESTAMP_PRESERVED: **YES**
- DATA_PIPELINE_TIMESTAMP_BUG: **NO**

## STEP 3 — REAL TIME-DIVERSE CORPUS INVENTORY (nothing replayed/modified)

### A. dev_2adbb41a04a4 — DESKTOP-A9HGFJJ (BEST WINDOWS CANDIDATE)

```
SOURCE                 NivXForge Windows collector, connector windows-eventlog-g1proof01,
                       collector col_d6b0b9e8172246f29be9, tenant ten_f1a5479243e901cf159e230fa0
REAL_OR_SYNTHETIC      REAL — full Sysmon EVTX XML retained, sequential EventRecordID
                       3286059+, real ProcessGuids {9949e5f2-…}, real host/user
                       DESKTOP-A9HGFJJ\jpred, native 100 ns TimeCreated
WINDOWS_SOURCE         YES — Microsoft-Windows-Sysmon/Operational + Windows Security Log
EVENT_COUNT            3298 observations (3299 canonical)
MIN_TIMESTAMP          2026-09-22T15:43:31.770Z
MAX_TIMESTAMP          2026-09-22T16:46:06.3636853Z
SPAN                   ~62 min 35 s
TIMESTAMP_PRECISION    100 ns (EVTX SystemTime) / ms (EventData UtcTime); 360 distinct instants
PROCESS_EVENTS         16 process_create (all 16 carry parent_iid)
FILE_EVENTS            107 file_write
NETWORK_EVENTS         72 network_connect
DNS_EVENTS             1 dns_query
REGISTRY_EVENTS        present at source (EID 12 CreateKey dominates) but the
                       normalizer currently files them under kind=detection (3102).
                       Flagged as a separate normalizer-mapping question, NOT a
                       timestamp defect.
RELATIONSHIP_SUPPORT   PARTIAL — genuine parent/child on the 16 process_create
                       records; the registry bulk carries process_iid but is not
                       classified as registry activity
SAFE_FOR_ACCEPTANCE    YES for time-domain/horizontal-distribution acceptance.
                       CAVEAT: only 16 real process rows, so it is thinner than
                       Cisco's demo for relationship-density parity.
```

### B. dev_42e8c6dc74b9 — live Linux sensor (largest real corpus)

```
SOURCE                 nivxforge-linux-sensor/1.0.0, origin collector-live, tenant default
REAL_OR_SYNTHETIC      REAL (this container's own sensor, still running)
WINDOWS_SOURCE         NO — Linux
EVENT_COUNT            247884 (244055 distinct timestamps)
MIN / MAX              2026-06-01T00:00:00Z → live (2026-09-29T02:27Z at read time)
SPAN                   ~4 months, continuously growing
TIMESTAMP_PRECISION    microsecond
PROCESS_EVENTS         13361 (13320 with parent_iid)
FILE_EVENTS            27
NETWORK_EVENTS         234511
DNS / REGISTRY         0 / 0 (not applicable on Linux)
RELATIONSHIP_SUPPORT   STRONG (real parent/child chains)
SAFE_FOR_ACCEPTANCE    YES as real time-diverse evidence, NO for Windows AMP parity
```

### C. dev_f16bc9f016fd — second Sysmon fixture

```
REAL_OR_SYNTHETIC      SYNTHETIC (4 distinct timestamps, 10:00:00 → 10:11:00)
EVENT_COUNT            15 · SAFE_FOR_ACCEPTANCE: NO (fixture, deterministic tests only)
```

### D. `golden@1.0` devices (dev_a0267ae20737, dev_b40e2b15648a, …)

```
REAL_OR_SYNTHETIC      SYNTHETIC golden corpus, 2026-02-25T14:00:00Z + seconds
SAFE_FOR_ACCEPTANCE    NO for live acceptance; YES for deterministic regression
```

## BEST_ACCEPTANCE_SOURCE

Priority 2 of the owner's ladder is already satisfied in this environment:
**dev_2adbb41a04a4 / DESKTOP-A9HGFJJ**, real NivXForge Windows collector
telemetry with preserved authoritative EVTX timestamps over a 62-minute span.
Priority 1 (fresh capture from a live Windows test host) remains preferable for
relationship density; this environment still has no reachable Windows host, so
W1 stays REAL_SOURCE_BLOCKED for new capture.

## VERDICT

```
DATA_CHANGED:                     NO
CODE_CHANGED:                     NO
DT2_3A_2:                         CLOSED
DATA_PIPELINE_TIMESTAMP_BUG:      NO
EXISTING_REAL_TIME_DIVERSE_CORPUS: YES
BLOCKS_DT2_3B:                    NO — no canonical timestamp or evidence-contract
                                  defect exists; the renderer and the pipeline are
                                  both correct, only the W1 fixture is single-instant
```
