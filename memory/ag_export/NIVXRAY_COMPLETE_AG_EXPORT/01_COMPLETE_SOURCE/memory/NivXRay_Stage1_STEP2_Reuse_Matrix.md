# NivXRay Stage 1 · STEP 2 — Module-by-Module Reuse Matrix

**Date:** 2026-02-14  
**Prerequisite:** STEP 1 (v3) audit at `/app/memory/NivXRay_Stage1_STEP1_Architecture_Audit.md`  
**Scope:** Read-only blueprint. **Zero code.** Halts at end per v3 §28.

## 🔴 Reuse principle (locked)

**Reuse first → adapt second → create only when genuinely missing.**  
Every capability below MUST NOT spawn a parallel engine. Forbidden duplicates:
another parser framework · another normalization engine · another IUE · another recursion engine · another evidence model · another correlation engine · another SSOT · another verdict engine.

## Master Matrix

| # | Stage-1 capability | Existing NivXRay component | Reuse | Gap | New code? | Effort |
|---|---|---|---|---|---|---|
| 1 | **Intake Router** (lightweight kind detection) | `services/ida/input_classifier.py` (`IDA_INPUT_CLASSES` tuple + `classify()`) + `services/die/input_understanding.py::classify()` | ✅ FULL | Superset vocabulary — add `RAW_JSON`, `NDJSON`, `CSV`, `XML`, `EDR_REPORT`, `XDR_REPORT`, `SIEM_EXPORT`, `EMAIL`, `CLOUD_LOG`, `NETWORK_LOG`, `UNKNOWN` as lane hints | **Thin facade only** | ~60 LOC in `services/iue/intake.py` — wraps both classifiers; emits `IntakeDecision(kind, lane, confidence, reasons)`. **No new classifier logic.** |
| 2 | **Collection · URL** | `services/ida/acquisition.py::acquire_url()` (Fix 1 preserved) | ✅ FULL | None | ❌ NO — reused as-is via a lane adapter | 0 LOC |
| 3 | **Collection · File / Artifact** | `services/artifact_intelligence/`, `services/ida/artifact_router.py`, `services/die/preprocessor/artifact_router.py`, `services/normalization/artifact_classifier.py` | ✅ FULL | Multiple existing routers — pick primary contract, don't duplicate | ❌ NO — lane adapter references existing router | ~20 LOC adapter |
| 4 | **Collection · Raw logs (JSON/NDJSON/CSV/XML)** | *(gap — no dedicated collector)* | — | Missing | ✅ GENUINELY NEW | ~80 LOC in `services/iue/collectors/log_collector.py`. Accepts uploaded file bytes; emits `RawPayload(bytes, mime, source_file_id, tenant_id)`. **Does not parse.** |
| 5 | **Parsing · HTML/DOM** | `services/ida/acquisition.py::_trafilatura_extract / _readability_extract / _bs4_heuristic_extract / _extract_structured_blocks` | ✅ FULL | None | ❌ NO — reuse | 0 LOC |
| 6 | **Parsing · Structured logs** | *(gap)* | — | Missing | ✅ GENUINELY NEW | ~180 LOC across `services/iue/parsers/{json_parser,ndjson_parser,csv_parser,xml_parser}.py`. Pure iterators. Emit `ParsedRecord(record_id, event_id, raw_fields, source_ref)`. **No security interpretation here.** |
| 7 | **Parsing · Commands / IOCs / Tokens** | `services/die/preprocessor/command_normalizer.py`, `services/die/ioc_semantic.py`, `services/normalization/artifact_classifier.py` | ✅ FULL | None | ❌ NO — reuse via adapter | ~15 LOC adapter |
| 8 | **Normalization · Vendor→Canonical fields (structured)** | *(partial — token classifier exists, structured field-map does not)* | ⚠️ PARTIAL | Field-alias map for structured events (`src_ip`, `sourceAddress`, `source_ip` → `canonical.source.ip`; equivalent for dst, host, user, process, command_line, action, category, timestamp) | ✅ GENUINELY NEW | ~140 LOC in `services/iue/normalizers/field_map.py`. Layered detection per v3 §6: exact schema → vendor mapping → dictionary → type-infer → regex → semantic → validation. Records `alias_source` provenance. |
| 9 | **Normalization · Existing normalizers** | `services/die/preprocessor/input_normalizer.py`, `services/die/preprocessor/command_normalizer.py`, `services/mitigation/evidence_driven/attack_posture_normalizer.py` | ✅ FULL | None | ❌ NO — reuse | 0 LOC |
| 10 | **Aggregation** — logical events as evidence boundary | *(gap)* | — | Missing dedicated aggregator | ✅ GENUINELY NEW | ~90 LOC in `services/iue/aggregator.py`. Groups `ParsedRecord`s into `LogicalEvent(event_id, timestamp, tenant, device, user, parent_process, child_process, command_line, source_ip, destination_ip, destination_port, domain, action, provenance)`. **Never splits fields into independent chunks.** |
| 11 | **IUE (semantic content understanding)** | `services/die/input_understanding.py::understand()` + inline block in `services/die/investigation_results.py::render()` L322-421 | ✅ FULL / EXTEND | Consolidate call-sites into one entry, accept the aggregated `LogicalEvent` envelope. **Do not create a second IUE.** | ⚠️ THIN CONSOLIDATION | ~80 LOC in `services/iue/understanding.py` — wraps existing `understand()` and dispatches to `_ida_extract` / structured-event semantic classifier. All heavy logic remains in existing modules. |
| 12 | **Recursive discovery (depth-capped, cycle-safe)** | `services/uaie/orchestrator.py` (`max_depth=12`) + `services/uaie/ledger.py` (`SKIP_DEPTH_CAP`, fingerprint dedupe) | ✅ FULL | Need a bridge facade so IUE re-entry uses the same ledger | **Facade only** | ~40 LOC in `services/iue/recurse.py::recurse(discovered, parent_id, depth)` — routes discovered content back through Intake Router, uses existing UAIE ledger for cycle detection. **No new recursion engine.** |
| 13 | **Native Evidence / Canonical SSOT** | `canonical/ssot/authoritative.py::AuthoritativeSSOT`, `canonical/ssot/models.py` (`Provenance`, `Source`, `GraphNode`, `GraphEdge`, `EvidenceGraph`, `ReasoningStep`, `Artifact`, `ExecutionStep`), `services/ssot_store.py` | ✅ FULL | None | ❌ NO — reuse; new IUE modules emit into existing schema | 0 LOC |
| 14 | **Specialized workers (W1..Wn)** | `services/uaie/orchestrator.py`, `services/ida/artifact_router.py::investigate_all()`, decoder plugins | ✅ FULL | None | ❌ NO — reuse | 0 LOC |
| 15 | **Central correlation** | `services/ice/correlate.py::_build_incident` | ✅ FULL | None — ICE already consumes `report_extraction` + techniques + IOCs from SSOT | ❌ NO — reuse | 0 LOC |
| 16 | **Explicit failure states** | Fix 1 `acquisition_failed` envelope + UAIE ledger skip codes | ⚠️ PARTIAL | Need one unified schema echoed at every new IUE module | ✅ SMALL | ~20 LOC in `services/iue/failure.py::IUEFailure(status, stage, error_code, recoverable, hint)`. **Extends the existing pattern, does not replace.** |
| 17 | **Provenance lineage** | `canonical/ssot/models.py::Provenance` + `Source` | ✅ FULL | Wire-through in every new IUE module (source → collect → parse → normalize → aggregate → IUE → evidence) | **Wire-through only** | ~15 LOC per module using existing `Provenance` dataclass |
| 18 | **Deduplication** | `services/uaie/ledger.py` fingerprint dedupe + `canonical/ssot/authoritative.py::sha256_hex` | ✅ FULL | Wire into new IUE modules | **Wire-through only** | ~10 LOC — use existing helpers, don't invent new hasher |
| 19 | **Multi-tenancy** (v3 §21) | `services/session/adapter.py` carries session/tenant context; `services/ssot_store.py` stamps tenant | ⚠️ PARTIAL | Enforce `tenant_id` on every new IUE payload envelope | ✅ SMALL | ~40 LOC in `services/iue/tenancy.py` — `TenantContext` propagator + isolation guard. **Uses existing tenant helpers.** |
| 20 | **Observability** (v3 §22) | UAIE ledger has depth/skip/fingerprint fields | ⚠️ PARTIAL | Emit `input_id / tenant_id / stage / parent_input_id / discovery_depth / content_fingerprint / record_count / processing_status / error_code / processing_time` at every new module boundary | ✅ SMALL | ~30 LOC in `services/iue/observability.py` — structured logger + span emitter. **Reuses UAIE ledger.** |
| 21 | **Security controls** (v3 §23) | `services/ida/acquisition.py` has SSRF/private-host guard + size limits; UAIE has `max_depth=12`; archive_recovery has `max_depth=3, max_children` | ⚠️ PARTIAL | Unified enforcement in new IUE modules (size caps · timeouts · decompression-bomb guard · path-traversal guard · tenant isolation) | ✅ SMALL | ~50 LOC in `services/iue/security.py` — **calls existing acquisition/archive guards where they exist; adds only the missing decompression-bomb and record-count caps.** |
| 22 | **Verdict Engine** | `services/die/canonical_bridge.py::render_verdict` | ✅ FULL | None | 🔒 **STAGE 2+** — audited, not touched | 0 LOC |
| 23 | **Native IOC disposition** | `services/mitigation/evidence_driven/*` | ✅ FULL | None | 🔒 **STAGE 2+** — audited, not touched | 0 LOC |
| 24 | **Evidence reconciliation (Native vs OSINT)** | Stub in `services/threat_intel/`; contract not wired | 🔒 STUB | Architecture boundary reserved | 🔒 **STAGE 2+** | 0 LOC |

## Aggregated LOC accounting

| Category | Files | Approx LOC |
|---|---|---|
| **Genuinely new** (log_collector, 4 parsers, field_map, aggregator, failure, tenancy, security) | 9 files | ~600 |
| **Thin facades / adapters** (intake, understanding consolidation, recurse) | 3 files | ~180 |
| **Wire-through** (provenance, dedupe, observability) | 1 file + inline | ~55 |
| **Existing reused** (acquisition, artifact routers, existing normalizers, SSOT, UAIE, ICE, verdict, mitigation) | many | 0 |
| **Deterministic tests** | 8 files | ~600 |
| **Total NEW code footprint** | **~880 code + ~600 tests** | — |

**Zero deletions. Zero renames. Zero contract breaks.**

## Anti-duplication guarantees

| Component forbidden to be re-invented | Existing owner (single source) |
|---|---|
| ❌ Another parser framework | Existing parsers + new `services/iue/parsers/*` only for structured logs. |
| ❌ Another normalization engine | `services/die/preprocessor/input_normalizer.py` + `command_normalizer.py` + new `field_map.py` (structured only). |
| ❌ Another IUE | `services/die/input_understanding.py::understand()` — new `services/iue/understanding.py` is a **thin consolidator**, not a replacement. |
| ❌ Another recursion engine | `services/uaie/orchestrator.py` — new `services/iue/recurse.py` is a **facade**. |
| ❌ Another evidence model | `canonical/ssot/models.py` — no new dataclasses for evidence. |
| ❌ Another correlation engine | `services/ice/correlate.py`. |
| ❌ Another SSOT | `canonical/ssot/authoritative.py::AuthoritativeSSOT`. |
| ❌ Another verdict engine | `services/die/canonical_bridge.py::render_verdict` — Stage 2+ scope. |

## Integration seam diagram

```
existing input paths ─────────► services/iue/intake.py (NEW facade)
                                        │
                                        ▼
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
services/ida/acquisition        services/artifact_intelligence   services/iue/collectors/
    (EXISTING · unchanged)          (EXISTING · unchanged)         log_collector.py (NEW)
        │                               │                               │
        ▼                               ▼                               ▼
existing HTML parsers            existing artifact analyzers    services/iue/parsers/ (NEW)
        │                               │                               │
        ▼                               ▼                               ▼
existing normalizers ◄────── services/iue/normalizers/field_map.py (NEW) ──────►
        │                                                               │
        └──────────────────────► services/iue/aggregator.py (NEW) ◄─────┘
                                        │
                                        ▼
                        services/iue/understanding.py (THIN consolidator)
                                        │
                                        ▼
                        existing report_extraction + canonical SSOT
                                        │
                                        ▼
                        services/ice/correlate.py (EXISTING · unchanged)
                                        │
                                        ▼
                        Investigation SSOT + IKG + Timeline (EXISTING · unchanged)
```

## Approval requirements before STEP 3 (implementation)

- ✅ This reuse matrix approved by owner
- ✅ Anti-duplication guarantees acknowledged
- ✅ Non-touchables (Fix 1, Fix 2, Prod Mode, Phase D, P1a, SSOT/IKG models, Verdict engine, Native IOC disposition) re-confirmed
- ✅ Feature-flag decision confirmed: structured-log lane behind `iue.structured_lane=off` initially

## Definition of "STEP 2 complete"

- ✅ Every Stage-1 capability mapped to existing component with explicit Reuse / Adapt / New classification
- ✅ LOC accounting produced (~880 code + ~600 tests total)
- ✅ Anti-duplication guarantees enumerated
- ✅ Integration seam diagram drawn
- ✅ Zero code changed

STOP per v3 §28. Await owner authorization for **STEP 3 (identify gaps in more detail)** or **STEP 6 (implementation begins)**.
