# W2 RESEARCH PASS 1 — INDUSTRY/STANDARDS COMPARISON (documented facts only)

Read-only research. No implementation. W1 CLOSED/FROZEN 6/6. 2026-09-18.
Standing rule adopted: **research → industry patterns → repo comparison →
ADOPT/ADAPT/EXTEND/BUILD/DEFER → contracts → gates → build → evidence**, and
**industry parity first, NivX differentiation second**. Labels used below:
[FACT] vendor/standards documentation · [PATTERN] industry practice ·
[NIVX] our inference/design choice.

## 1 · FIVE FINDINGS THAT CHANGE OUR PLAN

**F1 [FACT] Our int-bookmark is the wrong primitive, and Windows already
solves the exact failure W1 hit.** `EvtSubscribe` + `EvtCreateBookmark` /
`EvtUpdateBookmark` / `EvtRender(EvtRenderBookmark)` give a *push* subscription
resumed with `EvtSubscribeStartAfterBookmark`, with the bookmark persisted as
an **XML string**. With `EvtSubscribeStrict`, the service reports
**`ERROR_EVT_QUERY_RESULT_STALE`** when records are missing; without a
bookmark it starts from the oldest record.
(learn.microsoft.com/windows/win32/wes/bookmarking-events; .../nf-winevt-evtsubscribe;
.../ne-winevt-evt_subscribe_flags)
→ [NIVX] this is a *detector for the circular-log rollover that made W1-E1
unprovable*. Our `LastRecordId` integer cannot distinguish "nothing new" from
"your records were overwritten". **ADAPT the checkpoint to the Windows bookmark
XML + strict mode, and treat STALE as a first-class, recorded gap event.**

**F2 [FACT] Hard 22-clause XPath limit.** Windows Event Log XPath allows ~22
clauses (effectively 21 in some combinations); Microsoft says switch to a
structured XML query above ~20 expressions or for multiple sources. Elastic
cannot raise it and recommends collecting broader and dropping post-acquisition
(`drop_event`); Elastic Agent ≥8.18 auto-splits event ids across multiple
queries. (elastic.co/docs/reference/integrations/winlog; github.com/elastic/integrations#6228;
learn.microsoft.com/windows/win32/wes/consuming-events)
→ [NIVX] our forwarder already spends **7 clauses on one channel**. A
hard-coded per-channel id list does not scale. **Adopt three-tier filtering:
source (small XPath) → collector (profile/policy) → server (rules/suppression).**

**F3 [FACT] Origin vs collector identity is a known, documented bug class.**
Elastic preserves `winlog.computer_name` (originating host, distinct from
`agent.hostname`), `winlog.channel`, `winlog.provider_guid`, `winlog.record_id`;
for WEF the channel is the *original* channel, `forwarded: true` disables local
re-rendering, and `host.name` can be overwritten by the collector's hostname
unless explicitly mapped. (elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog;
.../configuration-winlogbeat-options; github.com/elastic/beats#13706)
→ [NIVX] validates the identity concern. **Windows Event Identity =
`origin_computer | channel | event_record_id`**, with `event_id`,
`provider`, `provider_guid`, `activity_id`, `related_activity_id` preserved
**separately as evidence**, never folded into identity.

**F4 [FACT] WEF/WEC has documented ceilings.** Source-initiated subscriptions
are the scalable pattern; ~2,000–4,000 concurrent clients and ~3,000 EPS per
collector; the default 20 MB `ForwardedEvents` log "fills in seconds" and needs
a dedicated disk; each source writes a registry bookmark key and **>100,000
lifetime sources corrupts the registry**; `NT AUTHORITY\NETWORK SERVICE` must
join **Event Log Readers** on sources to forward Security; XPath tuning cuts
40–90 % of volume; prefer `Suppress` nodes over negation.
(learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription;
MicrosoftDocs/SupportArticles configure-eventlog-forwarding-performance; nxlog.co WEC scaling limits)
→ [NIVX] WEF is **DEFER for wave 1** — it is a *customer-architecture* choice
with its own capacity envelope, not a shortcut.

**F5 [FACT] Rendering and AD resolution are explicit trade-offs.** Splunk uses
`renderXml=true` (locale-independent, structured), requires the `$XmlRegex`
key for whitelist/blacklist when XML is on, `blacklist` wins over `whitelist`,
`checkpointInterval` governs state, `evt_resolve_ad_obj` costs resources and
can conflict with `renderXml`; high-volume channels are split across inputs.
(help.splunk.com .../monitor-windows-event-log-data-with-splunk-enterprise)
→ [NIVX] our forwarder already reads raw XML and never renders descriptions —
that choice is **validated** (and is exactly why W1's `%1` description error
was our bug, not Windows'). Keep raw-XML-only; **never** resolve SIDs at the
edge — resolve server-side where it is auditable.

## 2 · ADOPT / ADAPT / EXTEND / BUILD / DEFER (revised by the research)

| capability | verdict | why |
|---|---|---|
| ingest contract, auth, tenant isolation, routing, dedupe, canonical evidence, collector state | **ADOPT** | proven end-to-end in W1 |
| collector-service acquisition engine (per-`stream` state, outbox, dedup, scheduler, quarantine) | **ADOPT** | already multi-stream; matches industry durability expectations |
| raw-XML-only acquisition, no description rendering | **ADOPT** | matches Splunk `renderXml` rationale; W1-proven |
| checkpoint model | **ADAPT** | int `LastRecordId` → Windows **bookmark XML** + `EvtSubscribeStrict` STALE detection (F1) |
| delivery identity | **ADAPT** | → `origin_computer \| channel \| event_record_id` (F3); contract change, own evidence |
| filtering | **ADAPT** | three-tier, ≤~20 clauses per channel query (F2) |
| `windows-security-evd` DSM | **EXTEND** | only 4688/4768/4769/4624/4625/4657 today |
| channel/provider/activity-id preservation | **EXTEND** | keep provider_guid + activity_id + related_activity_id as evidence |
| Windows Event Log acquisition connector in the collector service (Path 2) | **BUILD** | candidate confirmed, now on documented primitives |
| generic/customer-defined channel support | **BUILD** | Elastic pattern: specialised pipelines **and** arbitrary channels |
| DSMs: System, Application, PowerShell, Defender, AppLocker, WMI, TaskScheduler | **BUILD** | none exist |
| WEF/WEC | **DEFER** | capacity envelope + origin-identity contract must land first (F4) |
| ETW / macOS / third-party endpoint telemetry | **DEFER** | later milestones |

**Path 2 remains the candidate and is now research-supported**, with the
qualification that its checkpoint and identity contracts must be rebuilt on
F1/F3 rather than copied from the W1 forwarder.

## 3 · REVISED ACCEPTANCE GATES

W2-0 design ratification (path, identity, checkpoint, filter tiers) ·
**W2-A** per-channel declaration + refusal proof · **W2-B** DSM correctness
incl. `SOURCE_FORMAT_MISMATCH` · **W2-C** per-channel checkpoint isolation
**plus bookmark-XML resume** · **W2-C2 (NEW) rollover honesty** — force a
stale bookmark and prove `ERROR_EVT_QUERY_RESULT_STALE` is recorded as a gap,
never silent (this is the W1 lesson turned into a gate) · **W2-D** identity
uniqueness across channels, incl. deliberate `EventRecordID` collision ·
**W2-E** temporal honesty (`ACTIVITY_TIME` only where the format proves it) ·
**W2-E2 (NEW) timezone safety** — offset-naive source times canonicalised to
explicit UTC with the original preserved · **W2-F** durability under mid-batch
failure · **W2-F2 (NEW) filter-limit conformance** — no generated query
exceeds the documented clause limit; the overflow path is post-acquisition
filtering, proven · **W2-G** least privilege per channel (incl. Event Log
Readers for Security) · **W2-H** at least one real rule fires on a new channel.

## 4 · UI/UX RESEARCH — REFERENCE BOARD, PASS 1 (owner-supplied images)

Five owner-supplied references, patterns only — no vendor visual design will be
reproduced:
1. **Elastic Integrations catalog** — category rail with counts, search, tiles,
   `Browse` vs `Installed` split. → [NIVX] separate **Integration Catalog**
   from **Connected Sources**.
2. **Splunk Add Data wizard** — `Select Forwarders → Select Source → Input
   Settings → Review → Done`, with a two-pane channel picker listing
   `Application/ForwardedEvents/Security/Setup/System`. → [NIVX] validates a
   staged wizard and an explicit channel picker; we add *why this channel
   matters* (rules + ATT&CK coverage), which none of the references show.
3. **Cisco XDR Integrations** — `My integrations` with error/warning counts,
   Cisco vs Third-party tabs, per-tile `Enable` / `Get started`. → [NIVX] adopt
   the health-count header on our Data Sources overview.
4. **Elastic Fleet "Add Endpoint Security integration"** — numbered
   `Select an agent policy → Configure integration`, defaults declared. →
   [NIVX] policy-first assignment for NivXForge EDR.
5. **Cortex XDR "Add Feed"** — `Set Properties → Input Parameters → Finalize`
   with Source Type / Log Type selectors. → [NIVX] our declared-source +
   DSM selection maps exactly onto this, and is **fail-closed**, which theirs
   is not.

Weakness common to all five, and our differentiation: **none proves the
telemetry actually became evidence.** They stop at "connected". [NIVX] the
**Verify Ingestion** screen must walk
`source → collected → authenticated → received → parsed → normalized →
canonicalized → evidence → detection-ready`, every row backed by a real
backend field (collector counters, routing deliveries, canonical evidence,
dedupe claims, `event_time_basis`). Same discipline as W1's evidence package:
no status may be displayed without a computable contract, and no decorative
mock data may ever become a product claim.

**Held for the owner's next image batch:** full information architecture,
wireframes for Data Sources (Overview/Sources/Add/Collectors/Integrations/
Coverage/Health) and NivXForge Endpoints (Devices/Add/Deployment/Policies/
Health), per-element backend field mapping, empty/loading/error/degraded
states, RBAC + destructive-action behaviour, accessibility, and UI acceptance
tests. Not started — by design, pending the remaining references.

## 5 · ASSUMPTIONS NEEDING OWNER / REAL-ENVIRONMENT VERIFICATION
1. Per-channel ACLs, `LogMode`, size and record rates on real hosts
   (`wevtutil gl`, `Get-WinEvent -ListLog`).
2. Whether PowerShell 4103/4104 module+script-block logging is enabled by GPO
   in target estates (without it the highest-value channel is empty).
3. Whether customers will run WEF/WEC at all, and at what fan-out.
4. Expected EPS per endpoint and per tenant, to size outbox and backpressure.
5. Whether Sysmon config is standardised, since schema varies by config.
