# NivXRay XDR — Technology Adoption Matrix

**Status:** Living document · initiated 2026-02-10 · owner-locked directive
"NivXRay XDR must not become a second, weaker implementation of technology that already exists in NivXRay."

## Guiding rule
**Adopt before invent.**  For every XDR capability need:

1. Inspect the existing NivXRay implementation under `/app/backend/`.
2. Identify the existing engine / mechanism / route.
3. Decide the adoption method: `CONSUME` (call the API), `PROXY` (thin XDR route wrapping the base), `SHARED_LIBRARY` (import a Python module), `ADAPTER` (wrap for a new telemetry source), `EXTEND` (add capability to the base), `NEW` (only if the base genuinely lacks it), `EXTERNAL` (open-standard adoption).
4. Never build a "simplified" duplicate.  If not yet exposed to XDR, show honestly: **AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED**.

## Adoption states
| State | Meaning |
| --- | --- |
| ADOPT       | Already exists in NivXRay; XDR must consume via API/library |
| EXTEND      | Exists but insufficient for XDR; add capability to the base |
| ADAPT       | Exists but needs an adapter for a new telemetry/vendor source |
| NEW         | Genuinely does not exist; must be built |
| EXTERNAL    | Best solved by adopting an established open standard/library |
| CONNECTED   | Adoption is wired and green tests exist |

## Complete capability matrix
_The following was assembled from a survey of `/app/backend/*.py`, `/app/backend/routers/*.py`, and `/app/backend/engine/*`.  Not every one-off helper is listed — the aim is production-relevant security engineering._

### 1 · Evidence & Analysis
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **Evidence ingestion**       | `evidence_extractor.py`, `engine/evidence_graph_builder.py` | CONSUME via `/api/analyze` + Stage-2 pipeline | ADOPT |
| **Canonical evidence schema**| `engine/evidence_graph.py`, `schemas.py`                    | SHARED_LIBRARY (import types)              | ADOPT |
| **Evidence normalization**   | `engine/normalizers_ps/`, `ps_normalize.py`                 | CONSUME (analyze pipeline)                  | ADOPT |
| **Provenance**               | `engine/evidence_graph.py` + xdr_response_evidence router   | CONNECTED (Response Engine already forwards) | CONNECTED |
| **Evidence dedup**           | `engine/evidence_graph_builder.py` (fingerprint_util)       | CONSUME                                     | ADOPT |
| **Artifact router**          | `routers/artifacts.py` (`/api/artifacts`)                   | CONSUME                                     | ADOPT |
| **File analysis / PE / ELF** | `file_extractors.py`, `routers/die.py` (DIE)                | CONSUME                                     | ADOPT |
| **Script / macro analysis**  | `powershell_ast.py`, `engine/parsers/`                      | CONSUME                                     | ADOPT |
| **Decoder chain**            | `magic_decoder.py`, `engine/decoder_base.py`, `llm_decoder.py` | CONSUME via `/api/analyze` decode fields | ADOPT |
| **Command-line intel**       | `command_analyzer.py`, `commandline_miner.py`, `routers/behavioral.py` | CONSUME                            | ADOPT |
| **Obfuscation detection**    | `engine/parsers/` + `corrupt_payload_detector.py`           | CONSUME                                     | ADOPT |
| **IOC extraction**           | `routers/ioc_intelligence.py` (`/api/ioc`)                  | CONSUME                                     | ADOPT (wired) |
| **Malware family intel**     | `routers/ioc_intelligence.py`, `lolbas.py`, `lolbas_chain.py` | CONSUME                                   | ADOPT |
| **Reputation / TI**          | `osint.py` + admin OSINT services                           | CONSUME                                     | ADOPT |
| **Archive / compression**    | `file_extractors.py` + `security/archive_guard.py`          | CONSUME                                     | ADOPT |
| **Shellcode analyzer**       | `shellcode_analyzer.py`                                     | CONSUME                                     | ADOPT |
| **Crypto hints**             | `crypto_hints.py`                                           | CONSUME                                     | ADOPT |

### 2 · Detection & Intelligence
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **Detection rules**          | `engine/detectors/lolbin_v2.py`, `behavior_extractor.py`    | CONSUME                                     | ADOPT |
| **MITRE mappings (rule→technique)** | `engine/detectors/mitre_mapper.py`, MITRE Navigator export | CONSUME                              | CONNECTED (frontend uses `mitreTactics.js`) |
| **ATT&CK STIX export**       | `engine/detectors/mitre_stix_export.py`                     | CONSUME                                     | ADOPT |
| **Behavioral registry**      | `routers/behavior_registry.py`, `routers/behavioral.py`     | CONSUME                                     | ADOPT |
| **Correlation engine**       | `engine/correlation_engine.py`                              | CONSUME                                     | ADOPT |
| **Confidence / severity**    | `analysis_core.py`, `engine/detectors/verdict_v2.py`        | CONSUME                                     | ADOPT |
| **False-positive controls**  | `engine/detectors/explainability.py` + Sigma `falsepositives` | CONSUME + Sigma standard adoption         | ADOPT + EXTERNAL |
| **Sigma interchange**        | not present in base                                         | EXTERNAL (js-yaml + local evaluator)        | NEW · CONNECTED (XDR only) |

### 3 · Investigation
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **SSOT**                     | `engine/orchestrator.py` + `routers/analyze.py`             | CONSUME                                     | ADOPT (authoritative) |
| **IKG / evidence graph**     | `engine/evidence_graph_builder.py`, `evidence_graph.py`     | CONSUME                                     | ADOPT (Canvas already reads projection) |
| **Process tree**             | `routers/edr.py` + `chain_analyzer.py`                      | CONSUME                                     | ADOPT (pivot menu deep-link) |
| **Device trajectory**        | `routers/edr.py` + trajectory routes                        | CONSUME                                     | ADOPT (deep-link `/xdr/endpoints/:host/trajectory`) |
| **Attack story**             | `investigation_report.py` + `routers/incident_summary.py`   | CONSUME                                     | CONNECTED (Canvas Attack Story) |
| **Timeline**                 | `routers/iue_timeline.py` + xdr_response_timeline           | CONSUME                                     | CONNECTED (SyncTimeline) |
| **Investigation report**     | `investigation_report.py` + `routers/report_writer.py`      | CONSUME                                     | ADOPT |
| **Analyst corrections**      | `routers/analyst_corrections.py`                            | CONSUME                                     | ADOPT |

### 4 · Verdict
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **Deterministic verdict**    | `engine/detectors/verdict_v2.py`, `routers/verdict_stage2.py` (`/api/verdict/stage2`) | CONSUME (authoritative) | ADOPT |
| **Negative explainability**  | `engine/detectors/explainability.py`, `explain_export.py`   | CONSUME                                     | ADOPT |
| **Scoring model**            | `analysis_core.py`                                          | CONSUME                                     | ADOPT |

### 5 · Response
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **Response Engine**          | `/app/apps/nivxray-xdr-response`                             | native (XDR owns it)                        | CONNECTED |
| **Vendor adapter contract**  | `framework/vendor_adapters.py` (CrowdStrike / Defender / SentinelOne / Cisco SEP) | native + Phase-C flip     | CONNECTED (stubs) |
| **Evidence-forward sink**    | `/app/backend/routers/xdr_response_evidence.py`             | CONNECTED (XDR-only base endpoint)          | CONNECTED |
| **Approval workflow**        | Response Engine state machine + `xdr/pages/XdrApprovalsPage`| native                                      | CONNECTED |

### 6 · Testing / Quality
| Capability | Existing implementation | Adoption method | Status |
| --- | --- | --- | --- |
| **Golden corpus**            | `engine/golden_corpus*.py`, `corpus_refresh.py`             | CONSUME (regression proof)                  | ADOPT |
| **Deterministic benchmarks** | `routers/benchmark.py`, `multilayer_battery.py`             | CONSUME                                     | ADOPT |
| **Corpus validation**        | `routers/corpus_validate.py`                                | CONSUME                                     | ADOPT |

### 7 · Genuinely-new XDR capabilities
| Capability | Reason it is NEW / EXTERNAL | Status |
| --- | --- | --- |
| **Sigma detection authoring**| Not in base; adopt open Sigma standard + js-yaml     | CONNECTED (XDR only)  |
| **Multi-vendor response adapter contract** | XDR concern by design                    | CONNECTED (contract shipped) |
| **Response Engine state machine + SQLite spine** | XDR-owned execution plane             | CONNECTED |
| **Investigation Canvas (semantic edges, timeline sync)** | Visualisation, not detection tech        | CONNECTED |
| **Analyst Response Drawer**   | UX-only surface over the Response Engine            | CONNECTED |

## Gap report (rollup)
- **ADOPT — not yet wired:** File analysis, decoder chain, IOC intel, OSINT reputation, behavioral registry, correlation engine, verdict Stage-2, investigation report writer, analyst corrections, golden corpus.  These MUST become XDR-consumed via existing base APIs, not reimplemented.
- **CONNECTED:** MITRE mapping (via `mitreTactics.js`), Timeline (via `xdr_response_timeline` + Canvas), Evidence provenance (via `/api/xdr/response-evidence`), Attack story (via incident payload), Response evidence sink.
- **EXTEND:** none identified in this pass — base engines are already rich enough for the current XDR MVP.
- **NEW (XDR-only):** Response Engine, vendor adapter contract, Sigma authoring, Investigation Canvas visualisation.
- **EXTERNAL adopted:** Sigma (SigmaHQ), MITRE ATT&CK taxonomy, js-yaml.

## Adoption priority order (execute without asking)
1. **Verdict Stage-2 consumer** — XDR incident detail must surface `/api/verdict/stage2` output directly instead of only what the incident payload embeds.
2. **IOC Intelligence proxy** — Investigation Canvas Threat-Intel pivot must call `/api/ioc/*` rather than a placeholder.
3. **Decode chain consumer** — Sigma test/replay should optionally decode a base64 command line by calling `/api/analyze` (real decoder), not re-implementing.
4. **Investigation report** — surface `/api/incidents/:id/summary` in an XDR "Investigation Report" panel.
5. **Golden-corpus regression proof** — the XDR CI must run a subset of base golden-corpus checks to prove no regression when engines change.

## Boundary invariant (unchanged)
The original NivXRay Tool `/app/backend/` remains **authoritative**.  XDR:
- deploys its own frontend (`/app/apps/nivxray-xdr`) and services
  (`/app/apps/nivxray-xdr-collector`, `/app/apps/nivxray-xdr-response`);
- consumes NivXRay via existing `/api/*` routes;
- writes only via the one owner-authorised sink
  (`POST /api/xdr/response-evidence`).

No merging of XDR routes into the original SPA.  No silent modifications of unrelated base functionality.
