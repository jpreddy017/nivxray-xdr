# NIVXFORGE EDR + SANDBOX — CAPABILITY PARITY / GAP MATRIX

**Document ID**: `NIVXFORGE-EDR-SANDBOX-GAP-MATRIX-2026-09-05`
**Companion to**: `NIVXFORGE_EDR_SANDBOX_CURRENT_STATE_AND_INDUSTRY_PARITY.md`
**Priority scale**: `P0` foundational / blocking · `P1` enterprise parity ·
`P2` advanced capability · `P3` differentiation

**Status vocabulary** (exactly one per row):
`IMPLEMENTED` · `PARTIAL` · `SCAFFOLD` · `DESIGN ONLY` · `PROTOTYPE ONLY` ·
`DOCUMENTED ONLY` · `MISSING`

---

## 1. EDR capability matrix

| Capability | Current NivXRay | AG | EDR industry leaders | Status | Reuse | Gap | Priority |
|---|---|---|---|---|---|---|---|
| Device identity resolution (`device_iid`) | schema present, 223/639 IRG observations populated, **never surfaced** | doc only | CrowdStrike AID GUID, Cortex CGO, Defender device ID | `PARTIAL` | `v2_shadow_observations.event.device_iid`, `irg_enrich()` | no resolver service, no projection to the endpoint plane, UI binds to an empty SSOT field | **P0** |
| Endpoint inventory | `GET /api/edr/endpoints` returns `count:0` | doc only | all vendors | `PARTIAL` | route + page shell | reads `ssot.investigation_object.host` (empty in 484/484 cases) | **P0** |
| Device trajectory canvas | 3-pane 5-lane canvas, 0 devices resolvable | doc + prototype | Falcon device timeline, Cortex timeline | `PARTIAL` | `XdrDeviceTrajectoryPage.jsx`, `TrajectoryTimelineCanvas.jsx` | identity binding; entity-per-row rows; timeline scrubber; tri-pane sync | **P0** |
| Trajectory navigation spine | `/edr/trajectory` dead route, 7 dead links | — | single-spine entity nav everywhere | `MISSING` | existing canvas route | resolver route not registered | **P0** |
| Tenant scoping of EDR reads | `/api/edr/*` scopes by `user_email` only | — | strict tenant isolation | `PARTIAL` | `services/dashboard_lenses.resolve_tenant_scope()` | EDR routes bypass the shared scope helper the incident queue uses | **P0** |
| Endpoint detections | projection over `verdict_stage2.evidence[]` | doc only | all vendors | `PARTIAL` | `edr.py:176` | no streaming evaluation, no endpoint-native detections | **P1** |
| Process tree | `ActivityInventory` root-first tree | doc only | Falcon process tree | `PARTIAL` | `edr.py:191`, `v2/ancestry.py` | requires a case timeline; not exercised at runtime | **P1** |
| Process ancestry / causality chain | `irg_enrich()` supplies parent/root IIDs | doc only | Cortex causality (CGO/CI) reference | `PARTIAL` | IRG fields | no causality canvas; no CGO concept surfaced | **P1** |
| File / FIM lane | honest reserved stub | doc + prototype | all vendors | `SCAFFOLD` | `file_create/write/delete` IRG kinds exist | no API, no surface | **P1** |
| Network / socket lane | honest reserved stub | doc + prototype | all vendors | `SCAFFOLD` | `network_connect/listen` IRG kinds exist | no API, no surface | **P1** |
| Registry lane | none (lane label only inside trajectory) | doc | Defender, Falcon, Cortex | `MISSING` | `registry_value_set` IRG kind exists | no API, no surface | **P1** |
| Services / modules lane | none | doc | Falcon, SentinelOne | `MISSING` | `service_install` IRG kind exists | no API, no surface | **P2** |
| Unified device timeline | trajectory only | doc | Defender, Falcon | `PARTIAL` | trajectory aggregation | no cross-lane unified timeline view | **P1** |
| Event search / hunting | honest reserved stub | doc + prototype | SPL, KQL, CQL, XQL reference | `SCAFFOLD` | `v2_shadow_observations`, `xdr_canonical_events` | no query language, no index, no saved hunts | **P1** |
| Live query | honest reserved stub, adapter stubs | doc | Falcon RTR, osquery | `SCAFFOLD` | approval workflow (`xdr_approvals` plane) | no query coordinator, no agent | **P2** |
| Forensics acquisition (MFT/prefetch/shimcache/event logs/persistence) | honest reserved stub | doc + prototype | Falcon Forensics reference | `SCAFFOLD` | evidence custody ledger | no acquisition service | **P2** |
| Memory / volatile evidence | none | doc | Falcon, Cortex, Joe Sandbox | `MISSING` | — | entire acquisition plane | **P2** |
| Response orchestration (approve → execute → verify → audit) | real ledger: 183 executions, 535 timeline rows | doc | Trellix, Defender, SOAR | `PARTIAL` | `xdr_response_executions`, `AnalystResponseDrawer.jsx` | endpoint drivers are stubs; verification loop unproven | **P1** |
| Isolate / kill / quarantine drivers | `response/adapters.py` stub returns | doc | all vendors | `SCAFFOLD` | orchestration layer | no real driver or vendor live call | **P1** |
| Agent / sensor | none | doc | all vendors | `MISSING` | — | agent daemon, kernel hooks, TLS enrollment, update rings | **P2** |
| Endpoint health / telemetry health | none | doc | all vendors | `MISSING` | — | heartbeat, sensor metrics | **P2** |
| Entity 360 | none | doc + prototype | Defender entity page reference | `MISSING` | pivot component (`Pivot.jsx`) | no entity aggregate view | **P1** |
| Hash / reputation intelligence | `iocs` 98,152 docs; OSINT enrichers live | pre-existing | all vendors | `PARTIAL` | `ioc_intelligence.py`, `osint_enricher.py` | no endpoint-scoped reputation surface | **P1** |
| ATT&CK mapping | `xdr_framework_mappings` 1,114 docs, heatmap page | pre-existing | all vendors | `IMPLEMENTED` | mitre heatmap | — | — |
| Evidence provenance on every fact | enforced platform-wide | pre-existing | none at this depth | `IMPLEMENTED` | canonical evidence plane | — | **P3 (differentiator — protect)** |
| Epistemic state grammar (◆◇?○⊘) | shipped tokens + chips | pre-existing + this session | **no vendor has this** | `IMPLEMENTED` | `nx-epistemic.css`, `NxChip.jsx` | extend to EDR/Sandbox surfaces | **P3 (differentiator — extend)** |
| Deterministic analyst narrative | `analyst_narrative.py` 795 LOC + lexicon gate | pre-existing | templated at best | `IMPLEMENTED` | narrative engine | — | **P3 (differentiator — protect)** |
| 59-codec deobfuscation + payload retention | operational, `v2_decoded_payloads` 169 | pre-existing | partial at best | `IMPLEMENTED` | decoder registry | — | **P3 (differentiator — protect)** |

---

## 2. Sandbox capability matrix

| Capability | Current NivXRay | AG | Sandbox leaders | Status | Reuse | Gap | Priority |
|---|---|---|---|---|---|---|---|
| Submission intake | none | spec + prototype | ANY.RUN, Joe, WildFire | `DESIGN ONLY` | upload plane (`routers/artifacts.py`) | no sandbox job model | **P1** |
| Artifact router | operational | pre-existing | ✔ | `IMPLEMENTED` | `detection_content/artifact_router.py` | no runtime-required decision branch | **P1** |
| Static analysis (PE/ELF/Office/PDF/Archive/Shellcode) | operational, 1,446 LOC | pre-existing | ✔ | `IMPLEMENTED` | `services/artifact_intelligence/analyzers/` | not surfaced as a sandbox report | **P1** |
| Decoder / embedded-artifact extraction | operational, 59 codecs | pre-existing | partial | `IMPLEMENTED` | decoder registry | — | — |
| Static verdict | operational (VEEE) | pre-existing | ✔ | `IMPLEMENTED` | `verdict_stage2` | — | — |
| VM lifecycle / snapshots | none | spec | ✔ | `DESIGN ONLY` | — | hypervisor, microVM orchestrator | **P2** |
| Detonation execution | none | spec | ✔ | `DESIGN ONLY` | — | entire execution plane | **P2** |
| Interactive VM | none | spec + prototype | ANY.RUN reference, Joe live interaction | `PROTOTYPE ONLY` | prototype HTML console frame | streaming framebuffer, input channel | **P2** |
| Dynamic process tree / execution graph | none | spec | ✔ ANY.RUN process graph, Joe execution graph | `DESIGN ONLY` | IRG process model would receive it | no dynamic producer | **P2** |
| API / behaviour trace | none | spec (NtCreateProcess, NtWriteVirtualMemory, AMSI, ETW) | ✔ | `DESIGN ONLY` | — | kernel instrumentation | **P2** |
| Dynamic file / registry / services observation | none | spec | ✔ | `DESIGN ONLY` | IRG kinds already model these | no dynamic producer | **P2** |
| Network sim / DNS / HTTP / TLS / PCAP | none | spec (fake DNS, HTTP sinkhole, TLS inspect) | ✔ FakeNet/TOR/proxy | `DESIGN ONLY` | Suricata evidence path exists | no capture plane | **P2** |
| Memory capture | none | spec | ✔ WildFire run-time memory, Joe + IDA | `MISSING` | — | acquisition + parser | **P2** |
| Config / C2 extraction | static-only via decoders | spec | ✔ 50+ (ANY.RUN) / 270+ (Joe) extractors | `PARTIAL` | decoders, `iocs` corpus | no memory-derived MalConf | **P1** |
| IOC extraction | operational | pre-existing | ✔ | `IMPLEMENTED` | `iocs` 98,152 docs | — | — |
| Behaviour signatures | XDR content plane (Sigma/YARA) | pre-existing | ✔ 2,580+ (Joe) | `PARTIAL` | `yara_engine.py`, 615 frozen corpus | no dynamic-behaviour signature set | **P2** |
| ATT&CK mapping of dynamic behaviour | mapper exists, no dynamic input | pre-existing | ✔ | `PARTIAL` | mapping engine | needs dynamic observations | **P2** |
| Screenshots / replay | none | spec + prototype | ✔ | `DESIGN ONLY` | — | capture + player | **P3** |
| Multi-stage execution / anti-evasion / multi-OS | none | spec | ✔ | `DESIGN ONLY` | evasion *detection* tests exist | execution plane | **P3** |
| Evidence export | case/report export only | spec | ✔ STIX/MISP/MAEC | `PARTIAL` | report builders, TAXII push log | no dynamic-run export bundle | **P2** |
| Canonical evidence integration | contract documented | spec (`POST /api/v2/evidence/ingest`) | none — vendors keep sandbox verdicts separate | `DESIGN ONLY` | canonical evidence plane | no producer | **P3 (differentiator when built)** |

---

## 3. Classification summary

| Bucket | Count (EDR) | Count (Sandbox) |
|---|---|---|
| `IMPLEMENTED` | 5 | 5 |
| `PARTIAL` | 10 | 4 |
| `SCAFFOLD` | 6 | 0 |
| `DESIGN ONLY` / `PROTOTYPE ONLY` | 0 | 12 |
| `MISSING` | 7 | 1 |

## 4. Strategic position

- **NivXRay already exceeds industry**: epistemic-state grammar, evidence
  provenance depth, deterministic narrative, 59-codec deobfuscation, single
  reasoning spine.
- **Industry parity**: incident-centric queue, investigation record, ATT&CK
  mapping, static malware analysis, IOC intelligence.
- **Industry-leading capability missing**: endpoint telemetry lanes, causality at
  runtime, event search, live query, forensics, response execution, and the
  entire dynamic sandbox.
- **Differentiation opportunity**: be the only platform where a sandbox
  detonation and an endpoint trajectory feed **one** verdict engine and where
  every pane declares its own epistemic state instead of rendering an ambiguous
  empty table.
