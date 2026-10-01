# NIVXFORGE EDR + SANDBOX — CURRENT STATE & INDUSTRY PARITY

**Document ID**: `NIVXFORGE-EDR-SANDBOX-CURRENT-STATE-PARITY-2026-09-05`
**Method**: read-only reconciliation of the AG complete export, the EDR/Sandbox handoff
package, the live `/app` source tree, the live FastAPI route table, the live MongoDB
instance, and live authenticated HTTP calls against the preview backend.
**Honest-State rule**: every status below is separated into **code existence**,
**runtime capability** and **verified operational capability**. A React page, a
router file, a class or a design document is NOT evidence of capability.

---

## 0. The three headline findings

### F1 — There is no hidden AG EDR/Sandbox codebase to merge.
`/app/memory/ag_export/NIVXRAY_COMPLETE_AG_EXPORT/01_COMPLETE_SOURCE/` was diffed
recursively against the live `/app/backend` and `/app/apps` trees. The only
differences are (a) this session's own edits (`QueueContextMenu.jsx`,
`QueueSearchBar.jsx`, `nx-theme.css`, `nx-epistemic.css`, `sysmon_dsm.py`,
incident-numbering work) and (b) build/cache/env artifacts. The AG export is a
**snapshot of this same repository**, not a parallel implementation.

`07_EDR/EDR_MANIFEST.json` (199 files) and `08_SANDBOX/SANDBOX_MANIFEST.json`
(17 files) classify every **code** file as `PRE_EXISTING`. Every file classified
`AG_CREATED` is documentation, a specification, or the single-file HTML prototype.

> **Conclusion**: AG contributed *design and audit assets*, not engines. Reuse the
> docs and the prototype. There is nothing to "reconcile in" at the code level.

### F2 — EDR is code-present but runtime-empty. Zero devices exist.
| Probe | Result |
|---|---|
| `GET /api/edr/endpoints` (admin, live) | `{"endpoints":[],"count":0,"source":"workspace_cases.ssot.investigation_object","note":"no_matching_evidence"}` |
| `GET /api/edr/device-trajectory?device=…` (live) | `{"events":[],"lane_counts":{…all 0},"incidents":[],"reason":"no_matching_evidence"}` |
| `workspace_cases` total | 484 |
| `workspace_cases` with `ssot.investigation_object` | 209 |
| …with `ssot.investigation_object.host` non-empty | **0** |
| …with `ssot.investigation_object.device.hostname` non-empty | **0** |
| Any device-shaped host field anywhere in the case store | none — the only `host` keys found are `ida.url_intent.host` and `osint.urls[].host`, which are **URL/network domains, not devices** |

`_extract_host()` in `/app/backend/routers/edr.py:29` reads exactly
`ssot.investigation_object.host` → `ssot.investigation_object.device.hostname`.
Both are empty in 100% of cases, so the function returns `None` for every
document, so the endpoint inventory is unconditionally empty, so the Device
Trajectory canvas has **never had a device to render**.

The prior AG audit `/app/docs/security-state/NIVXFORGE_EDR_TRUTH_AUDIT.md` marks
Device Trajectory and Process Tree `IMPLEMENTED`. That claim is **code-existence
only** and is contradicted by runtime. This document supersedes it on that point.

### F3 — A real device-identity substrate does exist, but it is not the one EDR reads.
`v2_shadow_observations` (IRG shadow plane) holds 639 observations across 36 cases:

| Field | Population |
|---|---|
| `process_iid` | 639 / 639 |
| `event.device_iid` | **223 / 639** |
| `event.actor_iid` | 114 / 639 |
| `kind` values | `process_create`, `file_create`, `file_write`, `file_delete`, `registry_value_set`, `network_connect`, `network_listen`, `service_install`, `memory_alloc`, `kernel_event`, `cloud_iam_action` |

These are exactly the lanes an EDR investigation plane needs, and they already
carry an authoritative `device_iid`. **The endpoint plane is reading the wrong
substrate.** This is the single highest-leverage correction available and it
requires no new telemetry, no agent, and no fabrication.

---

## 1. Pre-AG NivXRay vs AG additions vs current aligned project

```
PRE-AG NivXRay  ──►  AG additions  ──►  Current aligned project
     │                    │                      │
     │                    │                      └── = PRE-AG code + AG docs
     │                    │                          + this session's UI/queue work
     │                    └── docs/uiux/*, docs/security-state/NIVXFORGE_*,
     │                        docs/handoff/*, docs/emergent-handoff-package/*,
     │                        NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html
     └── backend/nivxforge/** (CIM, investigation pipeline, attribution),
         backend/routers/edr.py, backend/services/artifact_intelligence/**,
         backend/decoders/** (59), apps/nivxray-xdr/src/nivxforge/**,
         apps/nivxray-xdr/src/xdr/pages/XdrDeviceTrajectoryPage.jsx
```

The NivXRay reasoning spine remains authoritative and untouched:
`Canonical Evidence → IUE → ICE → VEEE → IKG → Verdict → Security State →
Investigation → Response → Verification`. Neither EDR nor Sandbox introduces a
competing verdict, correlation, evidence-store or intelligence engine, and this
audit found no such duplication in code.

---

## 2. EDR capability audit — 24 capabilities, three-column truth

`CODE` = files exist. `RUNTIME` = the code path can execute end-to-end.
`VERIFIED` = observed working against the live backend in this audit.

| # | Capability | CODE | RUNTIME | VERIFIED | Status | Evidence |
|---|---|---|---|---|---|---|
| 1 | EDR agent / sensor | ✗ | ✗ | ✗ | `MISSING` | no agent source anywhere in repo |
| 2 | Endpoint enrollment | ✗ | ✗ | ✗ | `MISSING` | no enrollment route, no heartbeat collection |
| 3 | Endpoint inventory | ✓ | ✓ | ✓ (returns 0) | `PARTIAL` | `edr.py:203`; live call returns `count:0` |
| 4 | Endpoint health | ✗ | ✗ | ✗ | `MISSING` | no health field, no daemon |
| 5 | Endpoint identity (`device_iid`) | ✓ | ✓ | partial | `PARTIAL` | schema present; 223/639 IRG observations populated; **never surfaced in UI** |
| 6 | Telemetry ingestion | ✓ | ✓ | ✓ | `PARTIAL` | `xdr_canonical_events` 280 docs; `collection_method: syslog`; no endpoint event schema |
| 7 | Endpoint detections | ✓ | ✓ | ✓ (schema) | `PARTIAL` | `edr.py:176`, projection over `verdict_stage2.evidence[]`; requires `incident_id` |
| 8 | Process tree | ✓ | ✓ | not exercised | `PARTIAL` | `edr.py:191` + `ActivityInventory`; needs a case with a timeline |
| 9 | Process ancestry / causality | ✓ | ✓ | not exercised | `PARTIAL` | `v2/ancestry.py`, `irg_enrich()` |
| 10 | Device trajectory | ✓ | ✓ | ✓ (empty) | `PARTIAL` | `edr.py:300` + `XdrDeviceTrajectoryPage.jsx`; 0 devices resolvable |
| 11 | File / FIM lane | ✗ | ✗ | ✗ | `SCAFFOLD` | `EdrReservedPages.jsx` honest stub |
| 12 | Network / socket lane | ✗ | ✗ | ✗ | `SCAFFOLD` | `EdrReservedPages.jsx` honest stub |
| 13 | Registry lane | ✗ | ✗ | ✗ | `MISSING` | no surface; lane exists only inside trajectory lane map |
| 14 | Services / modules lane | ✗ | ✗ | ✗ | `MISSING` | `service_install` kind exists in IRG only |
| 15 | Threat hunting / event search | ✗ | ✗ | ✗ | `SCAFFOLD` | `EdrReservedPages.jsx` honest stub |
| 16 | Forensics acquisition | ✗ | ✗ | ✗ | `SCAFFOLD` | honest stub; no MFT/prefetch/shimcache code |
| 17 | Live query | ✗ | ✗ | ✗ | `SCAFFOLD` | honest stub; no osquery/eBPF coordinator |
| 18 | Memory / volatile evidence | ✗ | ✗ | ✗ | `MISSING` | no acquisition path |
| 19 | Response orchestration | ✓ | ✓ | not exercised | `PARTIAL` | `xdr_response_executions` 183, `xdr_response_timeline` 535, `AnalystResponseDrawer.jsx` |
| 20 | Isolate / kill / quarantine drivers | ✓ (stubs) | ✗ | ✗ | `SCAFFOLD` | `response/adapters.py` stub returns; no endpoint driver |
| 21 | Artifact retention (≤64 KB) | ✓ | ✓ | ✓ | `IMPLEMENTED` | `v2_decoded_payloads` 169 docs |
| 22 | Static malware analysis | ✓ | ✓ | ✓ | `IMPLEMENTED` | `services/artifact_intelligence/analyzers/{pe,elf,office,pdf,archive,shellcode}.py` |
| 23 | Decoder chain (59) | ✓ | ✓ | ✓ | `IMPLEMENTED` | `decoders/registry.py`; frozen 615 corpus untouched |
| 24 | IKG / Security State / VEEE | ✓ | ✓ | ✓ | `IMPLEMENTED` | `xdr_iue_understanding` 227, `verdict_shadow_observations` 280, `xdr_canonical_evidence` 239 |

### Live EDR API surface — complete and exhaustive
```
GET /api/edr/detections?incident_id=…      (required param)
GET /api/edr/process-tree?incident_id=…    (required param)
GET /api/edr/endpoints
GET /api/edr/device-trajectory?device=…&hours=…
GET /api/v2/cases/{case_id}/trajectory/device   ← admin-only, flag-gated (TRAJECTORY_ENGINE=shadow)
```
Four analyst-facing read-only projections. Nothing else. No POST, no mutation,
no live action, no streaming.

### Frontend EDR surface — real vs reserved
| Real | Reserved (honest stub) |
|---|---|
| `EdrOverviewPage`, `EdrDetectionsPage`, `EdrProcessTreePage`, `XdrDeviceTrajectoryPage`, `XdrEndpointsPage` | `EdrFilesPage`, `EdrNetworkPage`, `EdrHuntingPage`, `EdrForensicsPage`, `EdrLiveQueryPage`, `EdrResponsePage` |

The reserved pages are **correct behaviour** — they render "Reserved · later
slice" with no fabricated rows. They should be upgraded to the
`⊘ CAPABILITY UNAVAILABLE` grammar but they are not a defect.

---

## 3. Sandbox capability audit

**Verdict: `DESIGN ONLY` + `PROTOTYPE ONLY`. Zero runtime detonation capability.**

Grep of the entire `/app/backend` tree for `sandbox` returns only: comments in
`routers/iue_lane_c.py` ("Static analysis only. No execution, no sandbox, no
network."), narrative strings in `v2/semantic/ps_storyline.py` and
`v2/investigation/verdict/__init__.py` recommending sandbox reproduction, and
`tests/test_bits_and_sandbox_evasion.py` (which tests *evasion detection*, not a
sandbox). **There is no sandbox router, no VM orchestrator, no detonation
service, no snapshot manager, no PCAP capture, no screenshot capture.**

| Sandbox capability | Status | Evidence |
|---|---|---|
| Submission intake | `MISSING` (design only) | no route |
| Artifact routing | `IMPLEMENTED` (static) | `detection_content/artifact_router.py` |
| Static analysis | `IMPLEMENTED` | 6 real analyzers, 1,446 LOC |
| Decoder / embedded-artifact extraction | `IMPLEMENTED` | 59 decoders, `v2_decoded_payloads` |
| Static verdict | `IMPLEMENTED` | VEEE `verdict_stage2` |
| VM lifecycle / snapshots / interactive VM | `MISSING` | no code |
| Dynamic process / file / registry / network observation | `MISSING` | no code |
| DNS / HTTP / TLS / PCAP capture | `MISSING` | no code |
| Memory capture, API behaviour trace | `MISSING` | no code |
| Config / C2 extraction | `PARTIAL` | static decoder + IOC extraction only (`iocs` 98,152 docs) |
| ATT&CK mapping | `IMPLEMENTED` | `xdr_framework_mappings` 1,114 docs |
| Screenshots / replay / multi-stage / anti-evasion / multi-OS | `MISSING` | no code |
| Evidence export | `PARTIAL` | case/report export exists; no dynamic-run export |
| Canonical evidence integration | `DESIGN ONLY` | contract documented (`POST /api/v2/evidence/ingest`), no producer |

**Reusable immediately**: the static half of the sandbox story is genuinely
strong and shippable as a "Static Detonation Report" today. The dynamic half is
a specification and an HTML prototype.

---

## 4. Industry parity

Benchmarked against live vendor documentation (retrieved 2026-09-05) plus the
existing AG 12-platform benchmark
(`/app/docs/security-state/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md`).

### 4.1 EDR parity
| Capability | NivXForge today | Defender XDR | Cisco XDR | CrowdStrike Falcon | Cortex XDR | SentinelOne | Trellix | Splunk ES | Parity verdict |
|---|---|---|---|---|---|---|---|---|---|
| Incident-centric queue | **strong** | ✔ reference | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ reference | **at parity** |
| Attack story / narrative | **strong** (`analyst_narrative.py` 795 LOC) | ✔ | ✔ | partial | ✔ | partial | ✔ | partial | **exceeds** — narrative is generated from evidence, not templated |
| Causality / process chain | code present, unexercised | ✔ | ✔ | ✔ reference | ✔ reference (CGO/CI chain) | ✔ | ✔ | — | **behind** |
| Device timeline / trajectory | canvas exists, **0 devices** | ✔ | ✔ | ✔ reference | ✔ | ✔ | ✔ | — | **behind (blocking)** |
| Immutable entity identity | `device_iid` exists, unused | ✔ | ✔ | ✔ reference (AID GUID) | ✔ | ✔ | ✔ | ✔ | **behind (blocking)** |
| Event search / hunting | none | ✔ KQL | ✔ | ✔ CQL | ✔ XQL | ✔ reference | ✔ | ✔ reference SPL | **behind** |
| Live query | none | ✔ | ✔ | ✔ RTR | ✔ | ✔ | ✔ | ✔ | **behind** |
| Forensics acquisition | none | ✔ | partial | ✔ Falcon Forensics | ✔ | ✔ | ✔ | — | **behind** |
| Response with approval → verify | orchestration real, drivers stubbed | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ reference | ✔ SOAR | **partial** |
| Evidence provenance on every fact | **strong** | partial | partial | partial | partial | partial | partial | partial | **exceeds — differentiator** |
| Explicit epistemic state (◆◇?○⊘) | **unique** | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | **exceeds — no vendor does this** |
| Decoder/deobfuscation depth (59 codecs) | **unique** | partial | ✘ | partial | partial | partial | partial | ✘ | **exceeds — differentiator** |

### 4.2 Sandbox parity
| Capability | NivXForge today | ANY.RUN | WildFire | Joe Sandbox | Parity verdict |
|---|---|---|---|---|---|
| Static analysis / hashes / PE-ELF-Office-PDF | **operational** | ✔ | ✔ | ✔ | **at parity** |
| Config / C2 extraction | static-only | ✔ 50+ families | ✔ | ✔ 270+ extractors | **behind** |
| Interactive detonation | none | ✔ reference | ✘ (automated) | ✔ live interaction | **absent** |
| Dynamic process tree / process graph | none | ✔ reference | ✔ | ✔ execution graph | **absent** |
| Network sim / PCAP / DNS / TLS | none | ✔ FakeNet/TOR/proxy | ✔ | ✔ | **absent** |
| Memory analysis | none | ✔ | ✔ run-time memory | ✔ + IDA integration | **absent** |
| Behaviour signatures | rules exist in XDR content plane | ✔ Suricata | ✔ | ✔ 2,580+ | **partial** |
| Multi-OS | none | ✔ Win/macOS/Linux/Android | ✔ | ✔ | **absent** |
| ATT&CK mapping of dynamic behaviour | mapping engine exists, no dynamic input | ✔ | ✔ | ✔ Sigma | **partial** |
| Evidence → single reasoning spine | **unique** | ✘ | ✘ | ✘ | **exceeds — differentiator** |

### 4.3 Where NivXRay already exceeds the industry
1. **Explicit epistemic state as a first-class UI primitive.** No commercial XDR
   distinguishes ◆ evidence present / ◇ no evidence / ? unknown / ○ not run /
   ⊘ capability unavailable. Every vendor renders an empty pane, which analysts
   misread as a negative finding.
2. **Deterministic, evidence-derived narrative.** `analyst_narrative.py` +
   `narrative_lexicon_gate.py` gate the language against the evidence set.
3. **59-codec recursive deobfuscation with intermediate-payload retention.**
4. **Single reasoning spine.** One verdict engine, one evidence store — the
   opposite of the multi-engine sprawl every acquired-stack vendor carries.

---

## 5. Device Trajectory routing defect — placed in context

Two independent defects, both confirmed:

**D1 · dead route.** `/edr/trajectory` is not registered in
`/app/apps/nivxray-xdr/src/App.jsx` (verified against the full `Route path` list).
React Router therefore matches `<Route path="*" element={<Navigate to="/xdr" />}>`,
and `/xdr` redirects to `/xdr/incidents`. Seven call sites link to it:
`Pivot.jsx:22`, `Pivot.jsx:77-78`, `EdrProcessTreePage.jsx:142`,
`EdrDetectionsPage.jsx:64`, `EdrOverviewPage.jsx:16`, `NivXForgeConsole.jsx:30`,
`InvestigationTab.jsx:70`. All seven dead-end at the Incident Queue.

**D2 · no resolvable device identity.** Even the *live* path
`/xdr/endpoints/:device/trajectory` cannot resolve a device, because
`XdrIncidentDomainPage.jsx:103` derives the host from
`ssot.investigation_object.host` — the field that is empty in 100% of the 484
cases (F2). The correct authority is `device_iid`.

**Answer to "extension or only routing/data-binding correction?"**
→ **Both, in this order**: (1) routing correction — make `/edr/trajectory` a
resolver, not a third surface; (2) data-binding correction — bind the endpoint
plane to `v2_shadow_observations.event.device_iid` instead of the empty SSOT
host field; (3) only then extension (entity-per-row rewrite, lane sync,
scrubber). The canvas itself (`XdrDeviceTrajectoryPage.jsx` +
`TrajectoryTimelineCanvas.jsx`) is sound and must be extended, not replaced.

---

## 6. Final acceptance answers

| Question | Answer |
|---|---|
| What EDR functionality already exists in the AG ZIP/project? | 4 read-only projection APIs, 3 real EDR pages + the trajectory canvas + endpoints list, the `nivxforge` CIM/investigation pipeline, response orchestration, static analyzers, 59 decoders, IKG/VEEE/Security-State. |
| What is genuinely operational vs prototype/scaffold? | Operational: static analysis, decoders, IKG/VEEE, artifact retention, incident/investigation plane, ATT&CK mapping. Scaffold: files/network/hunting/forensics/live-query/response pages, response drivers. Runtime-empty: endpoint inventory + device trajectory. |
| What Sandbox functionality already exists? | Static analysis + artifact routing + decoders + IOC/ATT&CK mapping. Nothing dynamic. |
| What is missing? | Endpoint identity binding, agent/sensor, endpoint lanes (file/net/registry/services/modules), event search, live query, forensics, memory, real response drivers, the entire dynamic sandbox. |
| What can be reused immediately? | The trajectory canvas, the IRG `device_iid` substrate (223 populated), the 37-surface IA, the attack-chain UX matrix, the HTML operational prototype, the whole dark-first token system, the static-analysis + decoder chain. |
| How does it compare with the leading XDR/EDR vendors? | At parity on incident-centric queue; ahead on narrative, provenance, epistemic honesty and deobfuscation; behind on endpoint telemetry, causality-at-runtime, hunting, live query, forensics, response execution. |
| How does the Sandbox compare with ANY.RUN / WildFire / Joe Sandbox? | At parity on static analysis only; absent on every dynamic capability. |
| What must be added for enterprise parity? | Device Identity Resolution → endpoint lanes → event search → live query/forensics → response drivers; then dynamic sandbox. |
| What stays NivXRay-native differentiation? | Epistemic state grammar, evidence-first provenance, single reasoning spine, deterministic narrative, decoder depth. |
| Does Device Trajectory need extension or correction? | Correction first (routing + identity binding), extension second. |

---

## 7. Audit provenance

| Probe | Instrument |
|---|---|
| AG export vs live tree | recursive `diff -rq` on `backend/` and `apps/` |
| AG classification | `07_EDR/EDR_MANIFEST.json`, `08_SANDBOX/SANDBOX_MANIFEST.json` |
| Route table | grep of `@router.(get\|post\|…)` across `backend/routers`, `backend/v2/routers` |
| Frontend routes | full `Route path` enumeration in `App.jsx` |
| Persistence | live MongoDB collection census (77 collections) + field-population queries |
| Runtime | authenticated live calls to `/api/auth/login`, `/api/edr/endpoints`, `/api/edr/detections`, `/api/edr/process-tree`, `/api/edr/device-trajectory` |
| Industry | vendor documentation retrieved 2026-09-05 (CrowdStrike developer/API + Falcon 202 syllabus, Cortex XDR 5.x causality docs, ANY.RUN feature docs, Joe Sandbox v44 feature sheet, Advanced WildFire docs) |

**Not claimed, not verified**: `GET /api/threat-intel`, `GET /api/sigma`,
`GET /api/mitre`, `GET /api/attack-story` and `GET /api/incidents` appear in the
design-agent tier matrix as `LIVE NOW`; this audit did **not** verify those
paths. `/api/xdr/incidents` returned `404 Not Found`. Treat those rows as
unverified until probed.
