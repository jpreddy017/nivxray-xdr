# WINDOWS PRE-CHECK ASSESSMENT · WAVE B REVIEW INPUT

Endpoint untouched. Nothing deployed. Device Trajectory frozen. No file
hashing implemented. Sysmon config, Windows auditing and services on
DESKTOP-A9HGFJJ were NOT modified.

Owner-reported PRE-check values used as input (I did not re-derive them
and I do not restate them as my own measurements):

| fact | value |
|---|---|
| Sysmon version | 15.22, running |
| active config | `C:\NivX\sysmon\nivx-w1-sysmon.xml` |
| Sysmon hash algorithms | MD5, SHA256 |
| current EID 1 fields | ProcessGuid, ParentProcessGuid, Image, OriginalFileName, CommandLine, ParentCommandLine, Hashes |
| current EID 1 volume | non-zero |
| Sysmon channel | circular; oldest retained record **2026-09-29T09:27:09Z** |
| Security · Process Creation audit | **No Auditing** |
| Security · Process Termination audit | **No Auditing** |
| Sysmon config · ProcessTerminate | `onmatch="include"` |
| current 4688 / 4689 counts | 0 |
| NivXForgeSensor | running as LocalSystem |

---

## HISTORICAL_EID1_DECISION

### `NO_LONGER_PROVABLE_FROM_ENDPOINT_RETENTION`

The Sysmon Operational channel is circular and its oldest retained record
is 2026-09-29T09:27:09Z. The window under question — 2026-09-22
15:43–16:46 UTC — is roughly seven days older than that, so it has
rolled out. A zero result from any query against that window is a
**retention artefact and carries no information about what was
originally generated.** The same rollover destroyed the Sysmon
EventID 16 (ServiceConfigurationChange) records that would have shown
which configuration was in force at the time.

**KNOWN (still provable, server side):**
* the backend holds exactly **3,299 canonical observations** for that
  window, of which **16 are `process_create`**;
* all 16 carry ProcessGuid, CommandLine, MD5 and SHA-256 with
  `sysmon:EventData.Hashes` provenance — and B1 now proves they reach the
  read model without loss;
* the window's per-Event-ID distribution: 13 × 2,335 · 12 × 766 ·
  11 × 107 · 3 × 70 · **1 × 16** · 22 × 1;
* Windows Security 4688 was **never** a source for that window — process
  creation auditing is off today and there is no evidence it was ever on,
  so the 16 could never have been supplemented from the Security channel;
* the configuration in force TODAY does not filter EID 1
  (`<ProcessCreate onmatch="exclude"/>` with no rules excludes nothing),
  and today's EID 1 records carry the full field set.

**UNKNOWN (and no longer establishable from this endpoint):**
* how many EID 1 records Sysmon actually wrote during that window;
* whether the configuration then was identical to the configuration now;
* whether any EID 1 record was generated and then lost between Sysmon and
  canonical evidence.

**Therefore I withdraw any implication that 16 was the total generated.**
16 is the number that reached canonical evidence. That is all it is. A
ratio of 2,335 registry events to 16 process creations in 63 minutes is
*consistent* with an idle desktop and *also* consistent with partial
loss; the PRE-check cannot separate the two, and I will not claim it can.

**The only way to establish delivery fidelity now is forward-looking:** a
fresh measured window, counting EID 1 on the endpoint and canonical
`process_create` in the backend over the same UTC minutes. That needs no
endpoint change — it is two read-only counts. I recommend it before any
configuration work, because it also validates the sensor path that a
termination change would depend on.

## CURRENT_EID1_HEALTH

**HEALTHY, per the owner-reported evidence.** Sysmon 15.22 running,
ProcessCreate unfiltered, MD5+SHA256 configured and present, and the
full identity field set (ProcessGuid, ParentProcessGuid,
OriginalFileName, CommandLine, ParentCommandLine) present on current
records. Those are exactly the fields B1 proved survive projection and
B2 uses as its preferred identity authority — so the endpoint is
producing what the engines now require. No endpoint change is needed for
process CREATION.

## EID5_ROOT_CAUSE

Three independent blocks. Every one is confirmed **in this repository**,
not inferred. Even if one were removed the others would still stop the
evidence — which is why an endpoint-only change would have failed.

**BLOCK 1 · IT IS NOT GENERATED (endpoint, our own configuration).**
`memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` — the source of
`C:\NivX\sysmon\nivx-w1-sysmon.xml`, matching the owner-reported active
config — contains:

```xml
<!-- onmatch="include" rule matches nothing. These would be refused at
     ingest ... -->
<ProcessTerminate onmatch="include"/>         <!-- 5 -->
```

A Sysmon `onmatch="include"` group **with no rules inside matches
nothing**, so ProcessTerminate is switched OFF at the source. Our own
comment states the intent: these event classes were deliberately
suppressed because the server would have refused them. So this is a
*designed* gap that was never reopened — not a misconfiguration and not
a Sysmon defect.

**BLOCK 2 · IT WOULD BE REFUSED BY THE SENSOR PLANE.**
`backend/edr_plane/windows_eventlog.py` · `SUPPORTED` maps
`("sysmon", 1|3|11|12|13|22)` only. There is no `("sysmon", 5)`, so an
EID 5 record raises `WINDOWS_EVENT_ID_NOT_SUPPORTED` — an honest refusal
that retains the raw record and is replayable, but produces no canonical
observation.

**BLOCK 3 · IT WOULD NOT BE CANONICALISED BY THE XDR DSM PLANE.**
`backend/detection_content/telemetry/sysmon_dsm.py` maps
`1, 3, 11, 12, 13, 14, 22` only. No 5 ⇒ no `process_exit`.

**The 4689 alternative is also blocked, but only once:** the B2 wave
already added `4689 → process_exit` to `WINSEC_KIND`, so the server is
ready — but Windows Process Termination auditing is **No Auditing**, so
nothing is generated.

Classification requested: **Event ID 5 is NOT GENERATED (rule
configuration)** — and, additionally, would be **collected-but-refused**
if it were. Both, not one.

## TERMINATION_TELEMETRY_PROPOSAL

Smallest safe change, in this order. **Server first** — because with
Blocks 2 and 3 in place, enabling the endpoint first would only produce
refusals and would tell us nothing.

**STEP 1 · SERVER (no endpoint impact, no deployment, reversible).**
Add `("sysmon", 5) → ACTIVITY_PROCESS` to `SUPPORTED` in
`edr_plane/windows_eventlog.py`, and `5: "process_exit"` to the
`sysmon_dsm.py` kind map. Sysmon EID 5 carries `UtcTime`, `ProcessGuid`,
`ProcessId`, `Image`, `User` — no new field mapping is required, and
`ProcessGuid` means B2 resolves the termination to the *same*
`process_key` as the creation, with `SOURCE_PROCESS_GUID` authority. Add
the event-ID review-gate entry and a positive/negative regression pair
(a fixture EID 5 must produce `process_exit` and must move that process
from `PROCESS_LIFETIME_UNKNOWN` to `PROCESS_TERMINATION_OBSERVED`; an
absent EID 5 must NOT). Estimated change: two dictionary entries, one
gate entry, one test file.

**STEP 2 · ENDPOINT (requires your explicit authorisation).** One line in
`nivx-w1-sysmon.xml`:

```diff
- <ProcessTerminate onmatch="include"/>
+ <ProcessTerminate onmatch="exclude"/>
```

Applied with `sysmon64.exe -c C:\NivX\sysmon\nivx-w1-sysmon.xml`. This
**does not require a service restart** and does not touch Windows
auditing, the registry or any other event class. Keep a copy of the
current XML first so the change is revertible in one command.

**Measured volume impact:** EID 5 occurs approximately once per process
creation. In the reference window that is ~16 records against 3,299 —
about **0.5 % more telemetry**, against 2,335 registry events we already
accept. This is the cheapest high-value event class available to us.

**What NOT to do, and why.** Do not enable Security 4688/4689 as the
termination source. 4689 carries **no ProcessGuid**, so B2 would resolve
it as `PID_ONLY_NOT_AUTHORITATIVE` and could not bind the exit to the
process that started — it would be a PID-keyed guess, which is precisely
the fabrication B2 exists to prevent. Sysmon EID 5 is GUID-bearing and is
therefore the only trustworthy option. (Keeping process-creation auditing
off also avoids duplicating EID 1 at lower fidelity.)

**STEP 3 · PROVE IT.** One read-only measured window: endpoint EID 5
count vs backend canonical `process_exit` count vs processes moving out
of `PROCESS_LIFETIME_UNKNOWN`, reported by
`scripts/wave_b_foundation_measure.py`.

**Honest limit:** even with EID 5, a process whose exit was never
collected (sensor down, rollover, machine off) stays
`PROCESS_LIFETIME_UNKNOWN`. Termination remains an observation, never an
inference — `last_seen` will never become an exit.

## PROCESS_IMAGE_HASH_STATUS

**PRESENT, PROVEN, PRESERVED — NOT TO BE REBUILT.** 16/16
`process_create` observations carry MD5 + SHA-256 with
`sysmon:EventData.Hashes` provenance; B1 proves they survive projection;
B3 exposes them as `hash_class = PROCESS_IMAGE_HASH`. The endpoint
confirms `HashAlgorithms = MD5,SHA256`, so the configuration and the
evidence agree. Nothing to do.

## FILE_CREATE_HASH_STATUS

**0 of 107 · `HASH_NOT_OBSERVED` · `PATH_IDENTITY_ONLY`.** Sysmon EID 11
states path, writer and time — never a content hash and never a size,
and the PRE-check confirms no additional file-hashing event class is
enabled (`FileCreateStreamHash` EID 15 is `onmatch="include"` with no
rules, i.e. also off; it would in any case only cover alternate data
streams, not ordinary writes). `PROCESS_IMAGE_SHA256 !=
FILE_CREATE_CONTENT_SHA256` holds, and no file has ever inherited a hash
from its writer.

## B3_OWNER_DECISIONS

| # | DECISION | OPTIONS | SECURITY IMPACT | PERFORMANCE IMPACT | RECOMMENDED DEFAULT | WHY |
|---|---|---|---|---|---|---|
| 1 | Authorise sensor-side hashing in principle? | (a) not at all · (b) acceptance endpoint only · (c) fleet-wide | (a) created-file content identity stays permanently impossible: no file reputation, no retrospective hunt on dropped payloads, no "this dropper wrote a known-bad DLL" · (c) widest value, widest blast radius | (a) none · (b) one machine, observable · (c) unmeasured across unknown hardware | **(b) acceptance endpoint only** | It is the only capability gap that blocks E4 file intelligence, and one endpoint makes the cost measurable before anyone else feels it. |
| 2 | Default file selection posture | (a) allow-list by type (exe/dll/script/archive/LNK/macro-doc) · (b) all files with exclusions | (b) catches an attacker using an unusual extension; (a) misses exactly that, but nothing an attacker *executes* escapes (a) | (a) small, predictable · (b) hashes every document, log and cache write — the dominant write class on a desktop, an order of magnitude more I/O | **(a) allow-list by type** | Executable content is where content identity actually earns its keep; (b) buys marginal coverage for most of the cost and most of the privacy exposure. Reviewable per tenant later. |
| 3 | Privacy trees (user documents, mail stores, DB files) | (a) excluded by default · (b) included by default · (c) operator-declared per tenant | A SHA-256 *is* a content identifier: a hash of a private document can confirm possession of a known file. (b) creates that exposure silently | negligible either way once #2 is an allow-list | **(a) excluded by default, (c) available** | Privacy exposure must be an explicit decision, never a default. Data-protection defensibility matters as much as detection here. |
| 4 | Size ceiling / rate budget | ceiling 16 / 64 / 256 MiB · budget 60 / 120 / 300 files per minute | A ceiling is an attacker-visible evasion (pad the payload past the limit) — so `SIZE_LIMIT_EXCEEDED` must be a LOUD, huntable state, not a silent skip | 64 MiB at 120 files/min ≈ worst case a few hundred MiB/min of background-priority sequential reads, on one bounded worker | **64 MiB · 120 files/min · 512 MiB/min** | Covers essentially all real malware (overwhelmingly < 16 MiB) while capping worst-case I/O. Revisit only with measured evidence from decision 1(b). |
| 5 | Settle window for repeated writes | 0 s (hash every write) · **2 s** · 30 s | 0 s produces the most hashes but mostly of half-written files (`CHANGED_DURING_ACQUISITION`) — noise, not intelligence. 30 s lets a file be deleted before we ever read it | 0 s multiplies hashing on ordinary streaming writes; 2 s collapses a write burst into one acquisition | **2 s** | Coalescing is what makes the feature affordable; the write events themselves are still preserved individually with `coalesced_event_refs[]`, so no evidence is lost. |
| 6 | Retain `CHANGED_SINCE_EVENT` acquisitions? | (a) retain, labelled · (b) discard | (b) loses real content identity of a real file — often the dropper's *final* payload after it finished writing. (a) risks a consumer misreading it as the bytes the event described, which is why the label and a filterable field are mandatory | (a) no extra cost · (b) wasted work discarded | **(a) retain, clearly labelled and filterable** | The hash is true about a real file; only the *binding to that event* is uncertain. Evidence integrity is served by labelling uncertainty, not by deleting evidence. |

Implementation remains **not started**, as instructed.

## READ_PATH_PERFORMANCE_ROOT_CAUSE

Measured read-only on the preview substrate (no code changed):

`v2_shadow_observations` — **264,241 documents · 606 MB · 2,417 B
average** — and **two unfiltered full-collection reads** in the EDR read
path:

| location | statement | cost |
|---|---|---|
| `services/edr/device_identity.py:195` (`list_devices`) | `_obs.find({}, {"_id": 0})` | 4.3–4.4 s per call, 606 MB over the wire, 264k documents deserialised in Python |
| `services/edr/device_identity.py:446` (`observations`) | `_obs.find({}, {"_id": 0})`, then filters **in Python** with `_addresses(doc, ev, ref_set)` | 4.3–4.4 s per call, irrespective of the device or the time window |

A `device-trajectory` request that falls back to `resolve()` executes
both, which is the measured 14.3 s. `campaign-story` (11.2 s) pays the
directory scan. The docstring at line 187 still says "The whole (small)
collection is read" — it was small once; it is 606 MB now. This is not a
Wave B regression: I reproduced both failing live tests at HEAD with all
Wave B source files stashed.

**The indexes to serve this already exist and are simply not used:**
`obs_deviceiid_ts`, `obs_device_ts`, `obs_computer_ts`,
`obs_hostname_ts`, `obs_evcomputer_ts`, `obs_device_identity_facts`.

Measured alternatives, same inputs, same semantics:

| approach | result | time |
|---|---|---|
| current unfiltered scan | 264,241 docs | **4.45 s** |
| indexed `$or` over the five device-reference fields | **6,597 docs** (identical set), `docsExamined == nReturned == 6,597` | **0.143 s** — 31× |
| unresolved device (indexed) | 0 docs | **0.001 s** — vs 4.45 s today |
| directory as a server-side `$group` | 63 rows | **0.47 s** — 9× |
| directory as a projected read | 264,241 docs, only the needed fields | 1.21 s — 3.6× |

**Minimum fix — two changes, no behavioural change, evidence semantics
untouched:**

1. `observations()`: push the device predicate into the query as an
   indexed `$or` over the five reference fields, and push `since_iso`
   into the same query as a `$gte` on the timestamp. Keep
   `_addresses()` as a post-filter so the admissibility rule stays
   exactly where it is and nothing widens.
2. `list_devices()`: replace the full-document scan with a server-side
   `$group` producing one row per device reference. **The cross-tenant
   semantics must be preserved literally** — the reason the code reads
   everything is to detect a device appearing in two tenants and fail
   closed. `$group` with `$addToSet` over `tenant_id` and `connector_id`
   evaluates that over *every* observation, so the invariant is kept
   while 264k documents stop crossing the wire. (`resolve_fast()`
   already proved this pattern for single-device resolution.)

Not proposed here, deliberately: no change to Device Trajectory
behaviour, response shape or lane semantics; no schema change; no
migration; no new index (they exist). Regression must include the
cross-tenant fail-closed cases and a device with observations in two
tenants.

## PROPOSED_NEXT_WAVE

1. **B5a — termination readiness (server only, no endpoint change).**
   Sysmon EID 5 mapped in both planes + regression. Leaves the endpoint
   untouched and makes Step 2 a one-line, provable change.
2. **B5b — read-path performance fix.** The two changes above, with the
   cross-tenant regression. Clears the 2 remaining live-test failures
   honestly.
3. **B5c — read-only measured window** to establish endpoint→backend
   delivery fidelity for EID 1 (and EID 5 once enabled). This is what
   replaces the now-unprovable historical question.
4. Then the Cisco Secure Endpoint / Defender / CrowdStrike / SentinelOne
   / Sophos / Carbon Black capability study, before finalising E4/E5.

Sequencing note: B5a and B5b are independent of each other and of any
endpoint change, so both can be done and proven while the B3 decisions
are still open.

## ENDPOINT_CHANGE_REQUIRED

**Not yet — and not for anything in the proposed next wave.** One line of
`nivx-w1-sysmon.xml` (`ProcessTerminate` include → exclude) is required
*eventually* for termination telemetry, and it needs your explicit
authorisation. It should be applied only AFTER B5a, otherwise it produces
refusals. No audit-policy change is required or recommended. No service
restart is required.

## DEPLOYMENT_REQUIRED

**No.**

## BLOCKERS

1. **Owner decision** — authorise B5a (server-side EID 5 mapping) and
   B5b (read-path performance fix)? Both are server-only.
2. **Owner authorisation** — the single-line Sysmon `ProcessTerminate`
   change, to be applied only after B5a.
3. **The six B3 decisions** above; file-content identity stays
   unavailable until they are answered.
4. **Historical EID 1 volume is permanently unprovable** from this
   endpoint. Accept the forward-looking measured window as the
   replacement, or the question stays open indefinitely.
