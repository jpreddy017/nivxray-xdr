# W2 RESEARCH PASS 2 — PRODUCTION DESIGN CLOSURE (research only)

2026-09-18. No code, config, deployment, production write, endpoint execution,
W1 replay or UDOF. W1 CLOSED/FROZEN 6/6. Labels: [FACT] documented ·
[PATTERN] industry practice · [NIVX] our design choice.
**Recommendation: this is the last research pass.** Every foundational contract
below is now evidence-supported; further reading would be research-for-its-own-sake.

## 1 · FINDINGS THAT CLOSE THE OPEN QUESTIONS

### P1 [FACT] Stale/clear semantics — now exact, including the trap
* `EvtSubscribeStrict` (0x10000): `EvtSubscribe` **fails with `ERROR_NOT_FOUND`**
  if the bookmarked event no longer exists; strict is **required** to receive
  `ERROR_EVT_QUERY_RESULT_STALE` (**Win32 15011**) in the callback via
  `EvtSubscribeActionError`.
* **Without** strict, the API silently starts at "the event closest to the
  bookmark" — *a silent gap*. This is exactly the W1 trap, now named.
* A log clear (`wevtutil cl`) invalidates bookmarks; STALE (and
  `ERROR_INVALID_OPERATION`) invalidate the **handle**, forcing full
  re-subscription.
* **Documented real-world defect to avoid:** re-subscribing with the *same*
  stale bookmark under strict fails `ERROR_NOT_FOUND`; if the code then falls
  back to `EvtSubscribeToFutureEvents`, **every event in the gap window is
  dropped silently**. Also a live mis-mapping bug (4317 vs 15011).
  (learn.microsoft.com .../ne-winevt-evt_subscribe_flags; .../wes/bookmarking-events;
  windows-commands/wevtutil; github.com/vectordotdev/vector#26118)
→ [NIVX] strict mode is mandatory, and recovery must be an explicit state
machine that **emits a collection-gap record before** it resumes.

### P2 [FACT] Winlogbeat operational parameters (the closest documented analogue)
State is a registry file of **bookmarks**; `registry_flush` default **5 s**
(`0s` = flush after every published batch); `batch_read_size` default **512**
(Windows caps ~1024); `ignore_older` is **incompatible** with `xml_query`;
`xml_query` needs a unique `id` and is mutually exclusive with
`name`/`event_id`/`provider`/`level`; `ignore_missing_channel` defaults **true**
so a missing channel does not fail the service; `no_more_events: wait|stop`;
`record_number` is a **legacy fallback** behind bookmarks; channel-not-found
now triggers subscription retry (8.17+).
(elastic.co/docs/reference/beats/winlogbeat/configuration-winlogbeat-options;
elastic/beats#29330, #34605, #46190)
→ [NIVX] confirms our W1 `LastRecordId` is the *legacy* model. Note the
durability consequence: a 5 s flush window means replay after crash — our
server-side dedupe (W1-proven) is what makes that safe.

### P3 [FACT] Cortex XDR collector lifecycle (the management pattern)
Profile-based config (`winlogbeat.yml` / `filebeat.yml` editors in console),
collector build pinned to specific Winlogbeat versions, install **packages**,
`Settings → XDR Collectors → Administration` for select-and-upgrade, upgrade
status and cancellation in **Action Center**, optional auto-upgrade policy
(latest / maintenance-only / pinned), MSI + `DATA_PATH`/`PROXY_LIST`, and a
documented footgun: **custom settings in the config file may be erased on
upgrade**. (cortex-docs.paloaltonetworks.com — xdr-collectors, profiles,
upgrade-xdr-collectors, installation-resource)
→ [NIVX] adopt profiles + versioned packages + an action-centre-style audit of
every collector operation; **reject** raw YAML editing in the console (it is
the cause of their upgrade data-loss note). Our profiles must be declarative
and server-owned.

### P4 [FACT] CrowdStrike LogScale Collector — quantified durability & backpressure
Per-sink **memory or disk queue**, `fullAction: pause` (halts *sources* at
`maxLimitInMB`), metrics `queues.*.dropped_bytes` (**non-zero = data loss**),
`used_bytes`, `sinks.*.ingest_latency`, `workers` (default 4, ~16 MB each).
`format: xmlOnly` ≈ **65.7 MB/s** vs `renderFieldsWithXml` ≈ **24.5 MB/s**.
High-volume channels (e.g. `ForwardedEvents`) should be **isolated into
separate source definitions**. Disk queue is "not strictly required" for
Windows Event Log because bookmarking resumes exactly.
(library.humio.com/falcon-logscale-collector — prerequisites, multisource
config examples, querying-metrics)
→ [NIVX] two conclusions: our no-rendering choice is **~2.7× faster**, not just
cleaner; and the industry contract for backpressure is *pause the source and
publish a drop counter*, never silent loss.

## 2 · CONFLICTS / TRADE-OFFS BETWEEN INDUSTRY APPROACHES

| # | tension | vendors | [NIVX] resolution |
|---|---|---|---|
| C1 | strict resume (honest, needs recovery logic) vs lenient (never stalls, silently lies) | MS offers both; Vector bug shows the cost | **strict + gap record**. Completeness beats convenience |
| C2 | checkpoint flush cadence: replay volume vs disk cost | Winlogbeat 5 s default / 0 s option | commit the bookmark **after server accounting** (W1 behaviour) and let server dedupe absorb replay |
| C3 | backpressure: pause source vs drop with counter vs unbounded spool | CrowdStrike pause + `dropped_bytes` | **pause**, and any unavoidable loss becomes a gap record — no silent drop, ever |
| C4 | filter placement: big XPath vs post-acquisition drop | 22-clause limit; Elastic drop_event | three tiers; per-channel query capped ≤ 20 clauses |
| C5 | config surface: raw beat YAML vs declarative profile | Cortex raw YAML (erased on upgrade) | declarative, versioned, server-owned profile |
| C6 | rendering: raw XML vs pre-rendered text | Splunk `renderXml`; CrowdStrike `xmlOnly` 2.7× | raw XML only; all resolution server-side where it is auditable |
| C7 | one collector per host vs centralised WEC | Elastic/Cortex/CrowdStrike agent · MS WEF | agent-side first; WEF **DEFER** (capacity envelope from Pass 1) |

## 3 · REVISED ADOPT / ADAPT / EXTEND / BUILD / DEFER

**ADOPT** — ingest contract, auth, tenant isolation, routing, dedupe, canonical
evidence, collector state machine (all W1-proven); collector-service
acquisition engine (per-`stream` state, outbox, dedup, scheduler, quarantine);
raw-XML-only acquisition; bookmark-after-server-accounting.
**ADAPT** — checkpoint → native bookmark XML + strict; identity →
`origin_computer | channel | event_record_id`; filtering → three tiers;
backpressure → pause + published counters.
**EXTEND** — `windows-security-evd` beyond its 6 event ids; provenance to carry
`provider_guid`, `activity_id`, `related_activity_id`, `subscription_id`,
`collector_hostname`.
**BUILD** — Windows Event Log acquisition connector in the collector service;
collection-gap evidence type; generic/customer-defined channel support;
declarative collection profiles (Minimal/Security/Forensic/Custom); DSMs for
PowerShell, Defender, TaskScheduler, WMI, AppLocker, System, Application;
collector package/upgrade/health plane.
**DEFER** — WEF/WEC; ETW; macOS; third-party endpoint telemetry; AD/SID
resolution at the edge (server-side only, later).

## 4 · FINAL RECOMMENDED W2 ARCHITECTURE (for ratification)

```
Windows Event Log service
  └─ native API: EvtSubscribe · EvtCreateBookmark · EvtUpdateBookmark
                 EvtRender(EvtRenderBookmark) · StartAfterBookmark · STRICT
        │  Tier-1 source filter (≤20 clauses/channel, structured XML)
        ▼
Windows Acquisition Adapter          one independent reader PER CHANNEL
  Security · Sysmon · PowerShell · …   (stream = channel)
        │  Tier-2 collector filter (declarative profile / tenant policy)
        ▼
nivxray-xdr-collector
  AcquisitionState(tenant, connector, stream=channel)  ← bookmark XML per stream
  Outbox (durable, pause-on-full, published counters)
  DedupCache → scheduler → delivery worker
        ▼
/api/xdr/ingest/telemetry   (unchanged, W1-proven, fail-closed)
        │  Tier-3 server filter: routing → DSM → normalization → suppression
        ▼
Canonical evidence  +  COLLECTION GAP evidence
```
The W1 PowerShell forwarder is retired to what it is: a **proof vehicle**. It
does not dictate the production design.

## 5 · PROPOSED CONTRACTS

**Identity** — `source_event_id = origin_computer | channel | event_record_id`.
Preserved separately as evidence, never in the key: `event_id`, `provider`,
`provider_guid`, `activity_id`, `related_activity_id`, `collector_hostname`,
`collector_id`, `subscription_id`. Declared contract change; needs its own
evidence (W2-D).

**Checkpoint** — per-`(tenant, collector, channel)` Windows **bookmark XML**,
committed only after the server has accounted for the batch. `record_id` kept
for human readability only, explicitly **not** the resume authority.

**Collection gap** — a first-class evidence record, never a log line:
```
source=windows_eventlog · origin=<host> · channel=<channel>
reason=BOOKMARK_STALE | LOG_CLEARED | SUBSCRIPTION_NOT_FOUND |
       BACKLOG_WINDOW_EXCEEDED | QUEUE_PAUSED | CHANNEL_UNREADABLE
gap_status=CONFIRMED · win32_status=15011 · detected_at · last_good_bookmark
resume_point · events_lost=UNKNOWN · cause=SOURCE_LOG_ROLLOVER · evidence_ref
```
Consequence: evidence **completeness** becomes a displayable, queryable
property of a channel, a collector, a timeline and an incident. A collector
with a confirmed gap may never render as plain `Healthy`.

**Time** — `ACTIVITY_TIME` only where the format proves it (Sysmon `UtcTime`);
`OBSERVATION_TIME` with `activity_occurred_at = NOT_OBSERVED` elsewhere
(Security EVTX); offset-naive values canonicalised to explicit UTC **with the
original preserved** and the basis declared; source→NivX latency computed.

**Durability** — outbox survives restart; `pause` on full; `dropped` counter
published and any drop raises a gap; crash replay is safe because server-side
dedupe is W1-proven.

**Security** — least privilege per channel (Security needs Administrators or
**Event Log Readers**); no description rendering; no edge SID/AD resolution;
key file ACL-checked as in W1; TLS floor enforced; tenant resolved from the
authenticated collector, never a header.

## 6 · REVISED EXECUTABLE GATES

W2-0 ratification · **A** per-channel declaration + refusal proof ·
**B** DSM correctness incl. `SOURCE_FORMAT_MISMATCH` · **C** per-channel
checkpoint isolation + bookmark-XML resume across restart ·
**C2** rollover/clear honesty: induce a cleared channel, prove
`15011`/`ERROR_NOT_FOUND` produces a **CONFIRMED gap record** and never a
silent jump — and explicitly prove we do **not** fall back to
`SubscribeToFutureEvents` without recording the gap (the documented Vector
defect) · **D** cross-channel identity uniqueness incl. deliberate
`EventRecordID` collision · **E** temporal honesty · **E2** timezone safety ·
**F** durability under mid-batch kill · **F2** filter-limit conformance
(≤20 clauses; overflow proven to fall to post-acquisition filtering) ·
**F3 (NEW)** backpressure honesty: fill the outbox, prove sources pause,
nothing is lost, counters are published, and any loss is a gap ·
**G** least privilege per channel · **H** ≥1 real rule fires on a new channel ·
**I (NEW)** profile/upgrade integrity: a collector upgrade must not erase
collection configuration (the documented Cortex footgun) and every collector
operation is auditable.

## 7 · IMPLEMENTATION PLAN (for owner approval — not started)

* **Wave 0 · prerequisite.** Repair the two drifted dedupe fixtures so the
  replay gate is armed (W2-D/F depend on it). Test-only change.
* **Wave 1 · engine.** Windows acquisition connector in the collector service:
  native subscription + bookmark XML + strict, one reader per channel, gap
  records, three-tier filter skeleton, outbox pause. Channels: **Sysmon
  (regression against W1) + PowerShell/Operational (highest detection value)**.
  Gates A, B, C, C2, D, F, F2, F3.
* **Wave 2 · breadth.** Security (extend the existing DSM), Defender,
  TaskScheduler, WMI, AppLocker, System, Application + generic/custom channel
  support + collection profiles. Gates B, E, E2, G, H.
* **Wave 3 · fleet.** Packages, upgrade/rollback, health telemetry,
  offboarding, audit. Gate I.
* **Wave 4 · DEFERRED.** WEF/WEC as its own milestone with its own capacity
  and origin-identity gates.

## 8 · UI/UX REFERENCE BOARD — PASS 2 (owner-supplied, patterns only)

| ref | documented behaviour observed | [NIVX] extraction |
|---|---|---|
| **Cortex XDR → Configurations → XDR Collectors → Administration** | table: Name · Status (Connected) · Operating System · Collector Version · IP; status filter chip ("Status = Connected, Disconnected"), per-column filters, bulk row actions, `Revert`; nav separates *Configuration* from *Administration*, and *Data Broker/Broker VMs* from *XDR Collectors* | adopt: collector **inventory table with version column** + saved status filter + bulk ops + audited actions. Reject: version-as-identity (we show version *and* the streams it serves) |
| **Splunk → Add Data → Select Source → Local Event Logs** | left rail of input types (Local/Remote Event Logs, Files & Directories, HEC, TCP/UDP, Registry monitoring…); two-pane channel picker (Available / Selected, `add all` / `remove all`) listing Application, Security, Setup, System, ForwardedEvents, plus a long tail of provider channels; inline FAQ | adopt: **two-pane channel picker incl. the long tail** (our "customer-defined channels" requirement made visual) + inline "what does this channel give me" |
| **Elastic Fleet → Add agent** | numbered: ① host type → **agent policy** (shows "will collect data for 1 integration: Elastic Defend") ② **Enroll in Fleet (recommended)** vs Run standalone ③ install command per platform; agent table Host · Status(Healthy) · Tags · Agent policy | adopt: **policy-first onboarding**, managed-vs-standalone as an explicit choice, and copyable per-platform install command |
| **Defender → Settings → Endpoints → Onboarding** | Step 1 OS selector · Step 2 deployment option cards (Intune, Defender for Cloud, deployment tool, MDM, Configuration Manager) · Step 3 **Monitor progress** ("can take a few hours… view in Device Inventory") · right-hand **Deployment guide** panel with prerequisites · sibling nav: Deployment packages, **Offboarding** | adopt: OS → method → **deploy → monitor** staging, persistent guidance panel, and **Offboarding as a first-class screen** |

Cumulative weakness across all nine references, and our differentiation:
**none of them proves the telemetry became evidence.** They end at
`Connected` / `Healthy`. Several actively invite the opposite (raw YAML in a
console; a version column as a proxy for health).

### 8.1 NivX information architecture (proposed)
```
NivXRay XDR → Data Sources
  Overview · Sources · Add Data Source · Collectors · Integrations · Coverage · Health
NivXForge EDR → Endpoints
  Devices · Add Endpoints · Deployment · Agent Policies · Agent Health · Offboarding
```
Meeting point: NivXForge EDR appears **as a source** inside XDR Data Sources.

### 8.2 The screen that does not exist in the industry — VERIFY INGESTION
Nine steps, each backed by a real field, each able to be `PENDING`, `PASS`,
`REFUSED` or `GAP`:
```
source → collected → authenticated → received → parsed → normalized →
canonicalized → evidence → detection-ready
```
| row | authoritative backend source | status |
|---|---|---|
| authenticated / tenant / collector identity | collector doc + `routing_authority=AUTHENTICATED_COLLECTOR_DECLARATION` | exists |
| received per channel | collector `events_received` + `last_event_at` **per stream** | stream-level = BUILD |
| declared → resolved → DSM → content_compatible | `/api/xdr/ingest/routing/deliveries` | exists |
| parsed / normalized | `parser_ok` / `normalized_ok` | **must become measured** (residual #4) |
| canonicalized + evidence_ref | `xdr_canonical_evidence` + `evidence_ref` | exists |
| activity time / timezone explicit / latency | `event_time_basis`, `activity_occurred_at`, `nivx_received_at` | basis exists; latency = BUILD |
| dedupe | `xdr_ingest_dedupe` claim state | exists, **no read API** → BUILD |
| completeness | **collection-gap records** | BUILD |
| detection-ready | rules bound to that channel + last match | BUILD |

**Binding rule, per the standing directive:** every one of those cells renders
from an authoritative source or renders as `UNKNOWN`. No decorative data. No
`Healthy` without a computable contract. A channel with a CONFIRMED gap shows
**`HEALTHY · EVIDENCE INCOMPLETE`**, never plain `Healthy` — that single
behaviour is the clearest expression of "Verdict, cited" in an admin console.

## 9 · ASSUMPTIONS STILL NEEDING REAL-ENVIRONMENT VERIFICATION
1. Per-channel ACLs, `LogMode`, size, record rate on real hosts.
2. Whether PowerShell 4103/4104 logging is enabled by GPO in target estates.
3. Per-endpoint / per-tenant EPS for outbox sizing.
4. Sysmon config standardisation (schema varies by config).
5. Whether the collector service will run as a Windows service under a
   least-privilege account that can read `Security`.
