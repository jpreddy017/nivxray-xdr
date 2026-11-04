# WINDOWS MULTI-CHANNEL EVIDENCE COLLECTOR — DISCOVERY AUDIT (read-only)

Owner-authorised discovery for the milestone **after** W1. 2026-09-18, 17:47 IST
(12:17 UTC — clock verified in-session).

**Nothing was implemented.** No code, configuration or deployment change; no
production write; no endpoint execution; no telemetry; no replay; UDOF not
started. W1 remains CLOSED and FROZEN at 6/6
(`memory/W1_EVIDENCE_PACKAGE.md` §8).

Method: static reading of the deployed source tree plus one local registry
introspection (`DSM_REGISTRY._dsms`, no I/O). Every claim below cites the file
it came from. Where a fact can only be established on the Windows host (channel
ACLs, per-channel record rates) it is marked **OWNER-VERIFY** rather than
asserted.

---

## A · CURRENT FORWARDER STATE — `scripts/windows/NivXRay-SysmonForwarder.ps1`

| question | finding | evidence |
|---|---|---|
| how it reads the Event Log | `Get-WinEvent -LogName <channel> -FilterXPath <xpath> -MaxEvents N -Oldest`, forward from a record-id bookmark, with a newest-first fallback on failure | `:196-250` |
| is the channel hard-coded? | **YES.** `$script:Channel = 'Microsoft-Windows-Sysmon/Operational'` — a script constant, not a config field. `Get-ForwarderConfig` validates only `ApiBaseUrl`, `TenantId`, `CollectorId`, `SourceLabel` (+ optional `BatchSize`); there is no `Channel` key | `:66`, `:96-114` |
| declared source hard-coded? | **YES.** `$script:Declared = 'microsoft-sysmon'`, `$script:Method = 'windows_eventlog_pull'` | `:67-68` |
| event filter | hard-coded to the Sysmon DSM's ids `1,3,11,12,13,14,22`, injected into the XPath as `(EventID=1 or …)`. Not configurable | `:65`, `:204-206` |
| multi-channel subscription | **NOT SUPPORTED.** One channel, one XPath, one pass per cycle | `:196-250`, `:318-399` |
| bookmark / checkpoint | ONE file, `"$StateDir\sysmon-bookmark.json"`, holding a single `LastRecordId` + `UpdatedUtc`. The filename and the shape are channel-agnostic in name only — a second channel would overwrite the first | `:132-148` |
| bookmark safety | advances **only after** the server has accounted for the chunk (`Set-Bookmark` after `Send-Batch`), so at-least-once is preserved and the ordering is correct | `:391-397` |
| gap honesty | if the pending set exceeds `-MaxEvents`, a genuine hole is written to `state\gap.jsonl` as `BACKLOG_WINDOW_EXCEEDED`, and a first run with no bookmark is explicitly NOT reported as a gap | `:222-249` |
| retry / backpressure | **NONE.** `Send-Batch` throws on any HTTP failure; there is no outbox, no spool, no exponential backoff. Recovery is "the bookmark did not move, so the next run re-reads the chunk" — which is exactly the case W1 proved is now unrecoverable if the channel rolls first | `:264-294` |
| batching | `BatchSize` from config (W1 used 5), `-MaxEvents` caps the pending set, one POST per chunk | `:381-398` |
| loop mode | `-Loop` + `-PollSeconds` exist; W1 ran single-shot | `:55-57` |
| credential handling | key read from an ACL-checked file, refused if `Everyone`/`BUILTIN\Users`/`Authenticated Users` hold any ACE; never logged | `:124-131` |
| raw shape | flat `EventData` name→value map plus `event_id`, `provider`, `channel`, `Computer`, `record_id`, `TimeCreated`; reserved `_nivx*` names are dropped, never renamed | `:150-179` |
| identity | `source_event_id = '<Computer>|<EventRecordID>'` | `:187` |

**Verdict: the forwarder is a single-channel Sysmon tool, not a Windows
collector.** Channel, declared source and event-id filter are three separate
hard-coded constants, and the checkpoint is a single scalar. Multi-channel is
`EXTEND`, not `CONFIGURE`.

## B · WHAT THE INGEST CONTRACT REQUIRES OF A NEW CHANNEL (unchanged by W1)

Adding a channel is **not** just a forwarder change. D15 is fail-closed on both
sides:

1. the channel's payloads must map to a `declared_source` that exists in
   `services/source_routing.catalog()`;
2. the collector document's `authorized_sources` must contain it
   (`POST/PUT /api/xdr/collectors`);
3. every envelope must carry `declared_source`;
4. a DSM with that exact id must be loaded, and its `supports()` must accept
   the payload — content compatibility is checked, not assumed
   (`routers/xdr_ingest.py:640-688`, `detection_content/xdr_pipeline.py:298-305`).

Otherwise the delivery is refused `DECLARATION_REQUIRED` /
`UNSUPPORTED_SOURCE` / `SOURCE_NOT_AUTHORIZED` / `SOURCE_FORMAT_MISMATCH` with
no raw row, no evidence, no counter movement. **So every new channel needs a
declared source AND a DSM before a single event can land.** That is the
gating fact for this milestone.

## C · DSM / PARSER COVERAGE PER CHANNEL

Registry state, read live from the deployed code
(`DSM_REGISTRY._dsms`, `load_failures() == []`): **9 DSMs loaded** —
`snort-eve`, `windows-security-evd`, `linux-auditd`, `aws-cloudtrail`,
`microsoft-sysmon`, `cef-leef`, `m365-unified-audit`, `zeek-json`,
`nivxforge-linux-sensor`.

| Windows channel | declared source | DSM | coverage today | verdict |
|---|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | `microsoft-sysmon` | `SysmonDSM` | EventIDs 1, 3, 11, 12, 13, 14, 22 (`sysmon_dsm.py:491`) | **ADOPT** — proven in W1 |
| `Security` | `windows-security-evd` | `WindowsSecurityDSM` | **only 4688, 4768, 4769, 4624, 4625, 4657** (`windows_security_dsm.py:43`); `supports()` reads `EventID` flat or under a `System` block, so the forwarder's flat shape fits (`:483-492`) | **EXTEND** — DSM exists, event coverage is 6 ids; anything else is refused `SOURCE_FORMAT_MISMATCH` |
| `System` | — | — | none | **BUILD** (declared source + DSM) |
| `Application` | — | — | none | **BUILD** |
| `Microsoft-Windows-PowerShell/Operational` (4103/4104/4105) | — | — | none | **BUILD** — highest detection value of the four |
| `Microsoft-Windows-Windows Defender/Operational` | — | — | none | **BUILD** |
| `Microsoft-Windows-AppLocker/*` | — | — | none | **BUILD** |
| `Microsoft-Windows-WMI-Activity/Operational` | — | — | none | **BUILD** |
| `Microsoft-Windows-TaskScheduler/Operational` | — | — | none | **BUILD** |
| `ForwardedEvents` (WEF/WEC) | — | — | none | **BUILD** — see §H |

Searched the whole tree for `ForwardedEvents`, `PowerShell/Operational`,
`Windows Defender/Operational`, `AppLocker`, `WMI-Activity`, `TaskScheduler`:
the only hits are detection-content corpora, rule libraries, MITRE mapping and
LOLBAS text — **no acquisition path, no parser, no DSM**. The rule library
*talks about* PowerShell (19 mentions) and WMI (20) while no telemetry source
can currently feed those rules. That asymmetry is itself a finding: detection
content is ahead of collection.

Corroborating W1 data point: all five Sysmon `process_create` events came back
`RULE_NO_MATCH` / `INCONCLUSIVE`. More channels will not produce detections on
their own — rule-to-channel binding has to be part of the acceptance gates, or
the milestone will deliver telemetry that still detects nothing.

## D · DEDUPE IDENTITY ACROSS CHANNELS

Identity is
`sha256(tenant_id | collector_id | source | source_event_id | sha256(raw))`
(`services/ingest_idempotency.py:139-158`), where `source` is the envelope's
`source` label and `source_event_id` is `<Computer>|<EventRecordID>`.

* **`EventRecordID` is per-channel, not per-host.** Two channels can legitimately
  hold the same record number, so `DESKTOP-A9HGFJJ|4711` is ambiguous the
  moment a second channel is added.
* **No false suppression risk:** different channels produce different `raw`,
  so the payload digest differs and the delivery is `FRESH`. The mechanism
  stays correct.
* **But the identity string stops being human-meaningful**, and any future
  channel that produced a byte-identical payload under the same label would be
  indistinguishable from a retry.
* Recommendation for the design gate: make the identity channel-qualified —
  `<Computer>|<Channel>|<EventRecordID>` — and treat it as a **contract
  change** that needs its own acceptance evidence, because it changes what a
  "retry" means. It must not be slipped in silently alongside W1's proven
  identity.

## E · TIMESTAMP SEMANTICS PER CHANNEL — the real cross-source hazard

| channel | activity time | basis produced | consequence |
|---|---|---|---|
| Sysmon | `EventData.UtcTime` | `ACTIVITY_TIME`, `event_time_substituted=false`, `activity_occurred_at` AVAILABLE | causal ordering is sound (proven, `W1_TIMELINE_CHECK.md`) |
| Security (EVTX) | **none exists in the format** | `OBSERVATION_TIME` from `System.TimeCreated`, `activity_occurred_at` **NOT_OBSERVED** with an explicit reason (`windows_security_dsm.py:427-449`) | Security events can never carry a measured activity time. A timeline that mixes Sysmon and Security is mixing activity with observation, and the platform already says so honestly — the **UI** must not flatten the two |
| System / Application / PowerShell / Defender / AppLocker / WMI / TaskScheduler | mostly `TimeCreated` only; PowerShell 4104 carries no separate activity field | would be `OBSERVATION_TIME` | same caveat, multiplied |

`services/event_time_basis.py` already enforces the invariant that
`activity_occurred_at` is AVAILABLE **only** under `ACTIVITY_TIME`
(`Resolution.verify()`, `:96-118`), so the platform cannot lie about this. The
gap is downstream presentation plus the offset problem in §K.1.

## F · BATCHING / BACKPRESSURE / RETRY — two very different implementations exist

| | PowerShell forwarder | collector service (`apps/nivxray-xdr-collector`) |
|---|---|---|
| durable spool | none | SQLite **outbox** with `record/next_batch/mark_delivering/statuses_for` (`framework/outbox.py:110-300`) |
| acquisition checkpoint | one scalar per install | **`AcquisitionState`** per `(tenant, connector, stream)` with `claim_batch` / `release_batch` / `forget_batch` / `reconcile` / quarantine (`framework/acquisition_state.py:76-460`) |
| retry | none — throws | `delivery_worker.py` + `scheduler.py` |
| dedup | server-side only | `framework/dedup.py DedupCache` in front of delivery |
| multi-stream | no | **yes — `stream` is already a first-class key** |
| reference connector | — | `framework/m365_activity.py` (`M365ManagementActivityConnector`, `DECLARED_SOURCE = "m365-unified-audit"`, registered in `framework/runtime.py:20`) |

**This is the most consequential finding of the audit.** The multi-stream,
durable, quarantining acquisition engine the Windows milestone needs **already
exists** in the collector service; it simply has no Windows Event Log reader
(its acquisition modules are `syslog`, `webhook`, `rest_poller`, `m365_activity`).
The PowerShell script has the Windows reader and none of the engine.

So the strategic question for the owner is not "how do we add channels to the
script" but **which of these two becomes the Windows collector**:

* **Path 1 — extend the PowerShell forwarder** (channel list in config,
  per-channel bookmarks, per-channel declared source). Fast, stays agentless,
  but re-implements outbox/retry/quarantine in PowerShell, and W1 showed the
  weakness: a circular channel that rolls before a retry loses the evidence.
* **Path 2 — add a Windows Event Log acquisition connector to the collector
  service**, reusing `AcquisitionState` (`stream` = channel), `Outbox`,
  `DedupCache`, scheduler and the `M365ManagementActivityConnector` pattern.
  More engineering up front; it inherits durability, per-stream checkpoints,
  reconciliation and quarantine, and it is the same contract W1 already proved.
* **Path 3 — WEF/WEC** (§H), which turns N endpoints into one collection point.

My reading: Path 2 is the architecture, Path 1 is a tactical bridge. **This is
an owner decision, not mine to make.**

## G · PRIVILEGES — OWNER-VERIFY on the host, not assertable from here

| channel | expected requirement |
|---|---|
| `Security` | Administrators, or membership of **Event Log Readers**; the channel is not world-readable |
| `Microsoft-Windows-Sysmon/Operational` | Administrators (as used in W1) |
| `Windows Defender/Operational`, `AppLocker`, `WMI-Activity`, `TaskScheduler` | Administrators typically |
| `System`, `Application`, `PowerShell/Operational` | usually readable by `Authenticated Users` |
| `ForwardedEvents` | Administrators on the collector host |

Read-only confirmation when the milestone opens:
`(Get-WinEvent -ListLog <channel>).SecurityDescriptor` and
`wevtutil gl <channel>` — plus `LogMode`, `MaximumSizeInBytes` and
`RecordCount` per channel, which W1 proved matter more than anyone expected.

## H · WEF / WEC — NOT SUPPORTED, BUT THE INGEST CONTRACT DOES NOT BLOCK IT

No reference to WEF, WEC or `ForwardedEvents` exists anywhere in the tree. A
`ForwardedEvents` reader could reuse the ingest contract unchanged, but three
things break if it is treated as "just another channel":

1. `Computer` in a forwarded record is the **origin** host while the collector
   runs elsewhere — so `source_event_id` must be built from the forwarded
   `System.Computer`, never from `$env:COMPUTERNAME`;
2. `EventRecordID` on the WEC host is the **collector's** record number, not the
   origin's — identity must be origin-qualified or it will collide across hosts;
3. one collector document would then represent many endpoints, so the
   `CONNECTED` state and the counters stop being per-endpoint truth.

All three are contract questions, not code questions, and they belong in the
design gate.

## I · WHAT CAN BE ADOPTED / CONFIGURED / BUILT

| item | verdict |
|---|---|
| ingest contract, auth, tenant isolation, routing, dedupe, canonical evidence, collector state machine | **ADOPT unchanged** — proven end-to-end in W1 |
| `microsoft-sysmon` channel | **ADOPT** |
| `windows-security-evd` DSM | **ADOPT the DSM, EXTEND its event coverage** beyond the 6 ids |
| collector-service acquisition engine (outbox, per-stream state, dedup, scheduler, quarantine) | **ADOPT** — already multi-stream |
| forwarder channel / declared-source / event-filter | **EXTEND** — three hard-coded constants + a single bookmark |
| declared sources + DSMs for System, Application, PowerShell, Defender, AppLocker, WMI, TaskScheduler | **BUILD** |
| Windows Event Log acquisition connector inside the collector service | **BUILD** (if Path 2) |
| channel-qualified dedupe identity | **BUILD** — contract change, needs its own evidence |
| WEF/WEC support | **BUILD** |
| rule-to-channel binding so new telemetry actually detects | **BUILD** |

## J · PROPOSED ACCEPTANCE GATES (for owner approval — not started)

Same discipline as W1: real telemetry, per-criterion PASS/FAIL, no seeded data.

* **W2-0 · design ratification.** Path 1 / 2 / 3 chosen; identity scheme
  (channel-qualified) ratified; per-channel declared sources named. No code
  before this closes.
* **W2-A · per-channel declaration and refusal.** For every new channel: it is
  in the catalog, in the collector allowlist, and an **undeclared or
  unauthorised** delivery is refused with no raw row and no counter movement.
  Refusal proof is as important as acceptance proof.
* **W2-B · per-channel DSM correctness.** Each channel's real records select
  exactly one DSM, `content_compatible=true`, and an unsupported event id is
  refused `SOURCE_FORMAT_MISMATCH` rather than silently normalised.
* **W2-C · per-channel checkpoint isolation.** Independent checkpoints; no
  channel can advance, reset or overwrite another's; a gap in one channel is
  recorded for that channel only.
* **W2-D · identity uniqueness across channels.** Deliberately collide
  `EventRecordID` across two channels and prove both are stored as distinct
  deliveries with distinct keys — and that a true retry of either still
  dedupes.
* **W2-E · temporal honesty per channel.** `ACTIVITY_TIME` only where the
  format proves it (Sysmon); `OBSERVATION_TIME` with
  `activity_occurred_at = NOT_OBSERVED` everywhere else; a mixed-channel
  timeline sorts correctly and never labels an observation as an activity.
* **W2-F · durability under failure.** Kill delivery mid-batch: nothing lost,
  nothing duplicated, checkpoint intact. **This is the W1 lesson** — a
  circular channel can roll before a retry, so durability must be proven, not
  assumed.
* **W2-G · least privilege.** Exact privilege per channel documented and
  verified; a channel the account cannot read fails loudly, never silently.
* **W2-H · detection value.** At least one real rule fires on at least one new
  channel. Otherwise the milestone has added collection, not security.

## K · THE FOUR RESIDUALS + DEDUPE FIXTURE REPAIR — assessed separately

1. **Timezone safety — highest priority, and it is a correctness issue, not
   cosmetic.** Sysmon `UtcTime` arrives as `"2026-09-18 08:38:17.569"`: space
   separated, no offset. It is stored verbatim with the honest reason "offset
   is UNKNOWN", yet `event_time_format_state` still reads `ISO_8601`
   (`event_time_basis.py:_split` / `validate`). The field is semantically UTC
   and should be canonicalised to `2026-09-18T08:38:17.569Z` **while
   preserving the original value and its provenance** — the owner's stated
   invariant (original → semantics → UTC instant → normalised ISO →
   cross-source sort). Until then a cross-source timeline sorts offset-naive
   strings against offset-aware ones. Scope: `event_time_basis` + each DSM's
   declaration; needs its own regression evidence because it touches every
   source. **Blocker for the Attack Progress timeline, not for W2 collection.**
2. **Computed latency.** Both boundaries exist (`activity_occurred_at`,
   `nivx_received_at`); nothing derives the delay. W1's 1 h 23 m 25 s was
   hand-calculated. Small, additive, high observability value.
3. **Raw-projection `source_timestamp` null.** Consistency/observability only —
   no consumer reads that projection for time. Low priority, but it is what
   made this look like a defect, and it will mislead the next reader.
4. **`parser_ok` / `normalized_ok` default `True`.** They default in
   `CanonicalEnvelope` (`routers/xdr_ingest.py:118-119`) and the forwarder
   never sends them, so they assert an unmeasured outcome while feeding
   `events_parsed` / `events_normalized` and the `CONNECTED` gate. Either
   measure them or rename them to state they are collector-asserted. Medium —
   it is a truthfulness issue in a state gate, and multi-channel makes it
   worse, because a channel whose DSM refuses everything would still report
   `parser_ok=true` on the raw lane.
5. **Dedupe fixture repair.** `tests/test_p0_ingest_idempotency.py` and
   `tests/test_p0_dedupe_hardening.py` = 7 passed / 25 errors; every error is
   the module fixture creating a collector for an unregistered tenant, which
   the enforced registry refuses with `403 TENANT_NOT_FOUND`. Test-infrastructure
   repair (register the tenant in the fixture), not a production defect — but
   until it is fixed the replay regression gate is **disarmed**, and W2-D/W2-F
   will lean on exactly that gate. Recommend doing it **before** W2
   implementation begins.

## L · OPEN QUESTIONS FOR THE OWNER (blocking W2-0)

1. **Path 1, 2 or 3** — extend the PowerShell forwarder, build the Windows
   acquisition connector inside the collector service, or go WEF/WEC first?
2. **Channel priority.** Which channels in the first wave? On detection value
   per unit of work my reading is PowerShell/Operational → Security (extend the
   existing DSM) → Defender → TaskScheduler/WMI → AppLocker → System/Application.
3. **Identity scheme.** Adopt channel-qualified `source_event_id` now, as a
   declared contract change with its own evidence?
4. **Retention reality.** W1 proved a 64 MB circular Sysmon channel rolls
   130k records in ~95 minutes on this host. Do we raise channel sizes,
   shorten the poll interval, or accept that a lost batch is unrecoverable?
   This decision precedes any durability gate.
5. **Fixture repair first?** Recommended, so W2-D/W2-F land on an armed gate.
