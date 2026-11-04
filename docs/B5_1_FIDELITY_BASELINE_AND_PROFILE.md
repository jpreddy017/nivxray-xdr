# B5.1 · PRE FIDELITY BASELINE · EID 5 OWNER COMMAND · B3 DECISIONS · CAMPAIGN STORY PROFILE

`process_exit` accepted as the single canonical event type; `ProcessTerminate`
kept as SOURCE/provenance terminology only. No rename performed.

Endpoint UNCHANGED · Sysmon XML UNCHANGED · not restarted · auditing
UNCHANGED · 4688/4689 NOT enabled · NOT deployed · endpoint hashing NOT
implemented · Device Trajectory presentation FROZEN · no historical
reconstruction · no fabricated termination.

---

## 1 · PRE FIDELITY BASELINE

The measurement has two halves. **Backend half: BUILT AND RUN**
(`backend/scripts/b5_delivery_fidelity.py`). **Endpoint half: PREPARED
FOR OWNER EXECUTION, NOT RUN**
(`docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1`, read-only).

### Boundary availability — stated, never inferred

| boundary | status | why |
|---|---|---|
| **B0** endpoint generated | `NOT_MEASURABLE_FROM_BACKEND` | only the endpoint channel knows; the owner script counts it |
| **B1** sensor observed / read | **`NOT_MEASURABLE` — the sensor exposes no per-channel read counter** | this is itself a finding: until the sensor reports records read per channel, B0→B1 loss cannot be attributed |
| **B2** sensor sent | `PARTIAL` | records that ARRIVED carry `collector_received_at`; what was sent and never arrived is invisible from here |
| **B3** backend accepted | **MEASURED** | equals the canonicalized rows |
| **B3** backend refused | **MEASURED, WITH A COVERAGE GAP** | `xdr_ingest_routing_blocks` recorded **0** refusals for this collector in the window, yet the collector's own state says `PARSE_ERROR · "parser failed on every event" · received 1 / parsed 0 / normalized 0` at 2026-09-22T16:43:32Z. **A parse failure is therefore NOT recorded as a routing block** — refusal counting is incomplete, and this is exactly why Wave A's `windows-security-evd` loss was so hard to localise |
| **B3** dedupe suppressed | **MEASURED — and it is not loss** | 3,299 suppressed for this collector |
| **B4** canonicalized | **MEASURED** | `xdr_canonical_evidence` |

No boundary was derived by subtracting another.

### Backend baseline · DESKTOP-A9HGFJJ · 2026-09-22 15:43–16:46 UTC

Run as an **instrument validation** on the only window we have. The
endpoint half of THIS window is `INVALID_ROLLOVER` (oldest retained
record is 2026-09-29T09:27:09Z), so it yields no B0 — as accepted.

| Sysmon EID | canonicalized (B4) | event_type |
|---|---|---|
| 1 | **16** | process_create |
| 3 | 70 | network_connect |
| 11 | 107 | file_create |
| 12 | 766 | registry_event |
| 13 | 2,335 | registry_event |
| 22 | 1 | dns_query |
| (Security) | 2 | logon_success · special_privileges_assigned |
| **total** | **3,297** in window (+3 for this host outside it) | |

`nivx_received_to_parsed` p50 **0.003 s** — once a record arrives,
canonicalisation is not the bottleneck.

### The finding that changes the test design

Delivery is **heavily spooled**, measured across all 3,297 records:

| hop | p50 | min | max |
|---|---|---|---|
| `sensor_observed_at → collector_received_at` | **3,532 s (59 min)** | 44 s | 3,599 s |
| `collector_received_at → nivx_received_at` | **2,594 s (43 min)** | 4 s | **253,006 s (2.9 DAYS)** |

My original plan said "wait 5 minutes before measuring". **That was
wrong, and the data says so.** A window measured 5 minutes after it
closes would have reported almost the entire hour as LOSS when it was
LATENCY. The plan is corrected: compare no earlier than **24 h** after
the window closes, and re-count at **72 h** before calling any record
lost. The endpoint script now carries that warning inline.

### How to run the PRE baseline (owner)

1. Agree a 60-minute UTC window, at least 90 minutes in the past.
2. Run `docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1` elevated with
   `$Label = 'PRE'`. It is read-only and prints its own retention and
   config-stability verdicts — if it says `INVALID_ROLLOVER`, or if
   Sysmon EID 16 / Security 1102 appear inside the window, the run is
   void and repeats.
3. Return the transcript. **Expected in PRE: EID 5 = 0.**
4. At T+24 h I run `python3 backend/scripts/b5_delivery_fidelity.py
   --host DESKTOP-A9HGFJJ --start <s> --end <e>` and place the two halves
   side by side, per Event ID, per boundary.

---

## 2 · EID 5 · EXACT OWNER COMMAND AND ROLLBACK

Server support is already in place (B5-1), so EID 5 canonicalises as
`process_exit` the moment it arrives. **Do not run this until the PRE
baseline is captured.** One line changes; nothing else in the file, no
other Sysmon setting, no service restart, no audit policy.

The line today, in `C:\NivX\sysmon\nivx-w1-sysmon.xml`:

```xml
    <ProcessTerminate onmatch="include"/>         <!-- 5  -->
```

`onmatch="include"` with no rules inside matches NOTHING, which is why
EID 5 has never been generated.

### Owner steps (elevated PowerShell)

```powershell
# 1 · BACKUP FIRST (this file is the rollback)
Copy-Item 'C:\NivX\sysmon\nivx-w1-sysmon.xml' `
          'C:\NivX\sysmon\nivx-w1-sysmon.pre-eid5.bak.xml' -Force

# 2 · THE ONE-LINE CHANGE: include -> exclude, that line only.
#     "exclude with no rules" excludes nothing, i.e. log all of EID 5.
(Get-Content 'C:\NivX\sysmon\nivx-w1-sysmon.xml') `
  -replace '<ProcessTerminate onmatch="include"/>', `
           '<ProcessTerminate onmatch="exclude"/>' |
  Set-Content 'C:\NivX\sysmon\nivx-w1-sysmon.xml' -Encoding UTF8

# 3 · CONFIRM exactly one line changed and nothing else
Compare-Object (Get-Content 'C:\NivX\sysmon\nivx-w1-sysmon.pre-eid5.bak.xml') `
               (Get-Content 'C:\NivX\sysmon\nivx-w1-sysmon.xml')

# 4 · APPLY. No service restart. Sysmon reloads its own config.
& "$env:SystemRoot\Sysmon64.exe" -c 'C:\NivX\sysmon\nivx-w1-sysmon.xml'

# 5 · VERIFY the config in force (dump: -c with NO file argument)
& "$env:SystemRoot\Sysmon64.exe" -c | Select-String 'ProcessTerminate'

# 6 · VERIFY generation (wait ~60 s, close a few programs first)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; ID=5;
    StartTime=(Get-Date).AddMinutes(-5) } |
  Measure-Object | Select-Object Count
```

### Rollback (one command plus re-apply)

```powershell
Copy-Item 'C:\NivX\sysmon\nivx-w1-sysmon.pre-eid5.bak.xml' `
          'C:\NivX\sysmon\nivx-w1-sysmon.xml' -Force
& "$env:SystemRoot\Sysmon64.exe" -c 'C:\NivX\sysmon\nivx-w1-sysmon.xml'
& "$env:SystemRoot\Sysmon64.exe" -c | Select-String 'ProcessTerminate'
```

No uninstall, no restart, no registry edit, no log clear. Measured
volume impact ≈ **+0.5 %** (one exit per creation: ~16 records against
3,299 in the reference window).

**After you apply it**, run the endpoint script again with
`$Label = 'POST'`, wait 24 h, and I will prove the full chain:
`EID 5 → process_exit → ProcessGuid → the SAME process_key as the
creation → PROCESS_TERMINATION_OBSERVED`, with **no PID-only
termination binding** (regressed: an exit without authoritative identity
mints no key and terminates nothing).

---

## 3 · B3 · THE SIX OUTSTANDING DECISIONS

Invariant throughout: `PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256` —
different subjects, different canonical blocks, and an acceptance test
that the writer's image hash never appears in `file.hashes`.
Process-image SHA-256 already works (16/16) and is NOT part of this work.

| # | DECISION | OPTIONS | SECURITY IMPACT | PERFORMANCE IMPACT | RECOMMENDED DEFAULT | WHY |
|---|---|---|---|---|---|---|
| 1 | Authorise sensor-side hashing in principle | (a) not at all · (b) acceptance endpoint only · (c) fleet-wide | (a) created-file content identity stays impossible forever: no file reputation, no retrospective hunt on dropped payloads · (c) widest value, widest blast radius | (a) none · (b) one machine, fully observable · (c) unmeasured across unknown hardware | **(b) acceptance endpoint only** | it is the one gap blocking E4 file intelligence, and one endpoint makes the real cost measurable before anyone else feels it |
| 2 | File selection posture | (a) allow-list by type (exe/dll/script/archive/LNK/macro-doc) · (b) all files with exclusions | (b) catches an unusual extension; (a) misses that, but nothing an attacker EXECUTES escapes (a) | (a) small and predictable · (b) hashes every document, log and cache write — the dominant write class on a desktop, ~an order of magnitude more I/O | **(a) allow-list by type** | executable content is where content identity earns its keep; (b) buys marginal coverage for most of the cost and most of the privacy exposure |
| 3 | Privacy-sensitive trees | (a) excluded by default · (b) included · (c) operator-declared per tenant | a SHA-256 IS a content identifier: a hash of a private document can confirm possession of a known file. (b) creates that exposure silently | negligible either way once #2 is an allow-list | **(a) excluded, with (c) available** | privacy exposure must be an explicit decision, never a default; data-protection defensibility matters as much as detection |
| 4 | Size ceiling / rate budget | 16 / 64 / 256 MiB · 60 / 120 / 300 files per minute | a ceiling is an attacker-visible evasion (pad past the limit), so `SIZE_LIMIT_EXCEEDED` must be a LOUD huntable state, never a silent skip | 64 MiB @ 120 files/min ≈ a few hundred MiB/min worst case, background-priority sequential reads on one bounded worker | **64 MiB · 120 files/min · 512 MiB/min** | covers essentially all real malware (overwhelmingly < 16 MiB) while capping worst-case I/O; revisit only with measured data from decision 1(b) |
| 5 | Settle window for repeated writes | 0 s · **2 s** · 30 s | 0 s yields the most hashes but mostly of half-written files (`CHANGED_DURING_ACQUISITION`) — noise, not intelligence; 30 s lets droppers delete the file first | 0 s multiplies hashing on ordinary streaming writes; 2 s collapses a burst into one acquisition | **2 s** | coalescing is what makes the feature affordable, and the write EVENTS are still preserved individually via `coalesced_event_refs[]` |
| 6 | Retain `CHANGED_SINCE_EVENT`? | (a) retain, labelled and filterable · (b) discard | (b) loses the real content identity of a real file — often the dropper's FINAL payload; (a) risks a consumer misreading it as the observed version, which is why the label and the filter are mandatory | (a) no extra cost · (b) work discarded | **(a) retain, labelled** | the hash is true about a real file; only its binding to that event is uncertain. Evidence integrity is served by labelling uncertainty, not by deleting evidence |

Full state machine and field contract:
`docs/B5_FILE_HASHING_SENSOR_CONTRACT.md`. **No sensor-side hashing code
will be written until these six are approved as answers, not as
recommendations.**

---

## 4 · CAMPAIGN STORY · MEASURED READ-ONLY PROFILE

No code changed. No story semantics, evidence, causality, tenant
authority or trajectory touched.

Request: `GET /api/edr/campaign-story?incident_id=inc_c253027ba781494684db`
→ **10.99 s**, returning **15 activities** and 5 responses.

Dominant stage, measured: `edr_plane/campaign_story.py::_activity()` runs
**per activity**, and performs up to two `find_one` lookups against
`v2_shadow_observations` (256,944 documents):

```python
find_one({"tenant_id": …, "canonical_event_id": …})                   # line 75
find_one({"tenant_id": …, "event.provenance.ingest_job_id": raw_id})  # line 88
```

**Neither field is indexed.** Every call is a COLLSCAN:

| query shape | docs examined | time per call |
|---|---|---|
| `tenant_id + canonical_event_id` | **256,944** | **0.51 s** |
| `tenant_id + event.provenance.ingest_job_id` | **256,944** | **0.55 s** |

15 activities × up to 2 unindexed lookups ≈ **8–16 s** — which is the
whole of the observed 11 s. `nivx_received_to_parsed` p50 of 0.003 s
confirms nothing else in the path is slow.

**Measured minimum fix: two indexes. No code change at all.**

```
{ tenant_id: 1, canonical_event_id: 1 }
{ tenant_id: 1, "event.provenance.ingest_job_id": 1 }
```

Proven by a reversible probe — the indexes were created, measured, and
**dropped again** (index list verified back to its original 12 entries,
and the lookup returned to 0.506 s afterwards):

| | PRE | POST (probe) |
|---|---|---|
| `canonical_event_id` lookup | 0.51 s · 256,944 docs examined | **0.000 s · 0 docs examined** |
| `ingest_job_id` lookup | 0.55 s · 256,944 docs examined | **0.000 s · 0 docs examined** |

Expected result: ~11 s → well under 1 s, with **identical output**,
because an index changes only how rows are found, never which rows.

### A second, non-performance finding in the same profile

`resolved_via` is **`None` for all 15 activities**. Neither
`canonical_event_id` nor `event.provenance.ingest_job_id` matched any
observation, so **not one detection in this story is bound to its
canonical observation.** The story is honest about it (the link is
reported as absent rather than invented) but the evidence chain
`detection → canonical observation` is currently unresolved for this
incident. That is an **E1 linkage gap, not a performance issue**, and
indexing will make it fail fast rather than slowly. It needs its own
measured investigation — I have not touched it.

---

## BLOCKERS

1. Owner: run the PRE endpoint count (read-only) and return the
   transcript.
2. Owner: apply the EID 5 one-liner **after** the PRE baseline; rollback
   is one `Copy-Item` plus one `-c` re-apply.
3. Owner: approve the six B3 decisions as answers.
4. Owner: authorise the two campaign-story indexes (a datastore change,
   no code, no semantics).
5. **Sensor exposes no per-channel read/sent counters**, so boundaries
   B1 and B2 cannot be measured. Closing that is a sensor work item.
6. **Parse failures are not recorded as routing blocks**, so refusal
   counting is incomplete. Same class of defect as the Wave A
   `windows-security-evd` blindness.
7. `detection → canonical observation` linkage is unresolved for all 15
   activities of the reference incident.
