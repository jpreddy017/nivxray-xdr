# NivXRay Stage 1 · STEP 1 — Architecture Audit (v2, corrected)

**Date:** 2026-02-14  
**Correction (v2):** IUE is no longer the front door.  It now runs
**after** collection → parsing → normalization → aggregation.  A new
lightweight **Input Intake / Router** takes the front-door role — it
only recognises *what kind of thing the user submitted* (URL vs File
vs Raw JSON vs Text) and dispatches to the correct ingestion lane.
IUE remains recursive, but each recursion re-enters through the same
corrected pipeline (parse → normalize → aggregate → IUE).

---

## A. Corrected Stage-1 architecture

```
                       ANY INPUT
                            │
                            ▼
                  ┌───────────────────┐
                  │ INPUT INTAKE /    │  ← NEW · lightweight
                  │ ROUTER            │    kind-only classifier
                  └─────────┬─────────┘
                            ▼
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
     URL/DOMAIN           FILE               RAW LOG /
        │                   │              JSON / NDJSON /
        ▼                   ▼               CSV / XML
   ACQUISITION       ARTIFACT ROUTER            │
        │              + ANALYZER               ▼
        ▼                   │              COLLECTION
   PARSING (HTML/            │                   │
   DOM/JS/iframe)            ▼                   ▼
        │              PARSING /              PARSING
        ▼              EXTRACTION                │
   NORMALIZATION            │                   ▼
        │                   ▼             NORMALIZATION
        ▼              NORMALIZATION            │
   AGGREGATION              │                   ▼
        │                   ▼              AGGREGATION
        └─────────┬─────────┼─────────┬─────────┘
                  ▼         ▼         ▼
                  ┌───────────────────┐
                  │        IUE        │  ← runs on properly
                  │  Input + Content  │    parsed / normalized /
                  │  Understanding    │    aggregated content
                  └─────────┬─────────┘
                            ▼
                  SEMANTIC UNDERSTANDING
                            ▼
                  CANONICAL EVIDENCE
                            ▼
                  W1/W2/W3 parallel workers
                            ▼
                  CENTRAL CORRELATION
                            ▼
                  INVESTIGATION SSOT + IKG + Timeline
                            ▼
                  BEHAVIORAL REASONING
                            ▼
                  NATIVE IOC DISPOSITION
                            ▼
                  OSINT / External TI
                            ▼
                  EVIDENCE RECONCILIATION
                            ▼
                  RE-ANALYSIS · CROSS-VERIFICATION
                            ▼
                  DETERMINISTIC VERDICT
```

**Recursive IUE rule (unchanged):** when a stage discovers new content
(embedded URL / decoded payload / referenced file / new event), that
content re-enters at the correct lane's **collection/acquisition
head**, walks parse → normalize → aggregate, and only then hits IUE
again.  Never inject discovered content directly into IUE — it must
have been parsed and normalized first.

## B. Existing components mapped to the corrected architecture

| Corrected stage | Existing component | Notes |
|---|---|---|
| **Input Intake / Router** | `services/ida/input_classifier.py` (`IDA_INPUT_CLASSES`) + `services/die/input_understanding.py::classify()` | These already do kind-detection (URL / mixed_artifacts / ioc_list / yara / sigma / ruleset / none). We reduce their remit to lane-selection only. |
| **Collection · URL** | `services/ida/acquisition.py::acquire_url()` | Fix 1 preserved. Fix 2 deferred. **DO NOT TOUCH.** |
| **Collection · File / Artifact** | `services/artifact_intelligence/`, `services/ida/artifact_router.py`, `services/die/preprocessor/artifact_router.py`, `services/normalization/artifact_classifier.py` | Multiple artifact routers today — reuse, don't rewrite. |
| **Collection · Raw log** | *(gap)* | No dedicated JSON/NDJSON/CSV/XML collector. New: `services/iue/collectors/log_collector.py`. |
| **Parsing · HTML / DOM** | `services/ida/acquisition.py::_trafilatura_extract / _readability_extract / _bs4_heuristic_extract / _extract_structured_blocks` | Present. |
| **Parsing · Structured logs** | *(gap)* | New: `services/iue/parsers/{json_parser, ndjson_parser, csv_parser, xml_parser}.py`. Pure iterators. |
| **Normalization · Vendor→Canonical fields** | `services/normalization/artifact_classifier.py` (atomic tokens only), `services/die/preprocessor/input_normalizer.py`, `services/die/preprocessor/command_normalizer.py` | Present for tokens/commands. **Field-alias mapping for structured records is the main new work.** New: `services/iue/normalizers/field_map.py`. |
| **Aggregation · Events / Entities / Time windows** | *(gap)* | New: `services/iue/aggregator.py` — groups records into logical events preserving `event_id`, `source_file_id`, `record_id`, `timestamp`, `tenant`, `device`, `user`. |
| **IUE (Input + Content Understanding)** | Currently split across `services/die/input_understanding.py::understand()` and inline blocks in `services/die/investigation_results.py::render()` (L322-421) | Consolidate. Move to `services/iue/understanding.py::understand()` — accepts already-parsed/normalized/aggregated payload. |
| **Canonical evidence** | `canonical/ssot/authoritative.py`, `canonical/ssot/models.py`, `services/ssot_store.py` | Reuse as-is. |
| **Parallel workers** | `services/uaie/orchestrator.py` (`max_depth=12`), `services/uaie/ledger.py` | Recursion cycle-detection substrate. Reuse. |
| **Central correlation** | `services/ice/correlate.py` | Reuse. |
| **Verdict / OSINT / Reconciliation / Re-analysis / Cross-verification** | Distributed across `services/mitigation/`, `services/threat_intel/`, `services/die/canonical_bridge.py`, `services/die/mitre_evidence_chain.py` | Out of scope for Stage 1 — audited, not touched. |

## C. Gaps that Stage 1 must fill (revised)

| Spec | Gap | Effort |
|---|---|---|
| Intake router as *distinct* lightweight layer | Existing classifiers do the job but conflate intake with IUE. Split into `services/iue/intake.py::intake(payload) → IntakeDecision(kind, lane, reasons, confidence)`. Kind vocabulary is a **superset** of `IDA_INPUT_CLASSES` plus RAW_JSON / NDJSON / CSV / XML / EMAIL / SECURITY_ALERT / XDR_REPORT / EDR_REPORT / SIEM_EXPORT / CLOUD_LOG / NETWORK_LOG / UNKNOWN. | ~60 LOC |
| Structured-log **Collection → Parsing → Normalization → Aggregation** lane | Entirely new lane for RAW_JSON / NDJSON / CSV / XML. Preserves per-record provenance from the file. | ~300 LOC across 4 files |
| **Field-alias canonical map** (src_ip → canonical.source.ip, etc.) | New: `services/iue/normalizers/field_map.py` with layered detection (schema → vendor → dictionary → type-infer → regex → semantic → validation). | ~140 LOC |
| **Aggregator** — logical event/record as evidence boundary | New: `services/iue/aggregator.py`. Groups records into events preserving process/user/device/network fields. Never chunks by single field. | ~90 LOC |
| **IUE as post-normalization semantic layer** | Consolidate `understand()` into `services/iue/understanding.py::understand(payload_envelope) → ContentEnvelope`. Payload envelope must arrive **already parsed + normalized + aggregated**. | ~80 LOC (mostly wiring existing code) |
| **Recursive re-entry contract** | New: `services/iue/recurse.py::recurse(discovered, parent_id, depth)` → hands off to the correct lane's collection head, not directly to IUE. Cycle detection via existing UAIE ledger. | ~40 LOC |
| **Explicit failure envelope** | Extend Fix-1 `acquisition_failed` pattern to every layer: `IUEFailure(status, stage, error_code, recoverable, hint)`. | ~20 LOC + wiring |
| **Observability** | `input_id`, `parent_input_id`, `intake_kind`, `lane`, `stage`, `depth`, `content_fingerprint`, `record_count`, `processing_time` at every layer. Reuse UAIE ledger where possible. | ~30 LOC |
| **Tests** (deterministic, offline) | classification vocabulary · recursive PDF→URL→IUE · JSON/NDJSON/CSV/XML record splitting · field-map aliases · failure envelopes · aggregator preserves provenance · no field-chunking regression | ~500 LOC across 6 new test files |

**Total new LOC estimate:** ~760 code + ~500 tests. No deletions in Stage 1.

## D. Non-touchables (spec §18 + prior locks)

- ❌ `services/ida/acquisition.py`
- ❌ Fix 1 `acquisition_failed` envelope
- ❌ Fix 2 / CISA 403
- ❌ Prod Mode / `build_session`
- ❌ Phase D · InvestigationGraph lazy chunk
- ❌ Positioning v1.3.3 / Deck v1.4
- ❌ P1a projection logic (its behavior is fed by the corrected pipeline; contracts preserved)
- ❌ Investigation SSOT / IKG models — reused as-is
- ❌ Verdict / Native IOC disposition — Stage 2+ work

## E. Proposed Stage 1 file layout (no code yet)

```
backend/services/iue/                              ← NEW package
├── __init__.py
├── intake.py                                      ← lightweight front door (§B)
├── collectors/
│   ├── __init__.py
│   └── log_collector.py                           ← RAW_JSON/NDJSON/CSV/XML
├── parsers/
│   ├── __init__.py
│   ├── json_parser.py
│   ├── ndjson_parser.py
│   ├── csv_parser.py
│   └── xml_parser.py
├── normalizers/
│   ├── __init__.py
│   └── field_map.py                               ← src_ip → canonical.source.ip
├── aggregator.py                                  ← logical event boundaries
├── understanding.py                               ← IUE (post-normalization)
├── recurse.py                                     ← bounded recursion bridge
├── failure.py                                     ← IUEFailure schema
└── observability.py                               ← input_id / parent / depth

backend/tests/canonical/iue/
├── test_iue_intake_router_all_kinds.py            ← intake vocabulary
├── test_iue_recursive_reentry.py                  ← PDF→URL→acquire→parse→IUE
├── test_iue_record_boundaries.py                  ← JSON/NDJSON/CSV/XML
├── test_iue_field_map_aliases.py                  ← src_ip, sourceAddress, …
├── test_iue_aggregator_preserves_provenance.py    ← event_id / record_id / …
└── test_iue_failure_envelope.py                   ← explicit MISSING states
```

## F. Compatibility contract preserved

- `render()` still receives the same `_ida_classify(src)` shape — the new intake wraps it, no field removed
- `report_extraction` shape unchanged → Prod / ICE / SSOT consumers unaffected
- Fix 1 envelope unchanged
- P1a projection unchanged (it consumes the same augmented `techniques[]` regardless of whether IUE arrived pre- or post-normalization)
- Existing IDA input classifier remains callable during a deprecation window (removed only in a future stage after all consumers migrate)

## G. Key correction versus v1 of this audit

| v1 (wrong) | v2 (corrected) |
|---|---|
| IUE-1 was the front door | Front door is **Input Intake / Router**; IUE runs later |
| IUE-2 fired directly on acquired HTML / parsed JSON | IUE fires only after **normalization + aggregation**; parsed HTML/JSON must pass through the lane's normalizer + aggregator first |
| Structured logs classified as "one file, one event" | Structured logs pass **Collection → Parsing → Normalization → Aggregation** so each logical event is preserved with `event_id / record_id / source_file_id` |
| Field mapping loosely optional | Field mapping is the **entry criterion** to IUE — no unnormalized fields reach IUE |
| Recursion re-entered IUE directly | Recursion re-enters at the **lane's collection head**, not at IUE — every recursive round goes through parse → normalize → aggregate first |

## H. Risk register (v2)

| Risk | Mitigation |
|---|---|
| The new "collection→parse→normalize→aggregate→IUE" chain increases latency vs. today's shortcut path | Feature-flag the structured-log lane behind `iue.structured_lane=off` initially; URL and text paths unchanged so no regression on today's Prev/Prod flows |
| Field-alias map bakes in vendor assumptions | Layered detection per spec §8: exact-schema wins first, alias dict second, type/regex last; every mapping records `alias_source` provenance |
| Aggregation grouping could destroy provenance | Aggregator MUST attach the full parent record reference to every projection; test `test_iue_aggregator_preserves_provenance.py` locks this |
| Two IUE call-sites during migration (old inline + new module) | Old inline `understand()` remains callable; new module is only reached through `services/iue/intake.py` dispatch — one owner, one call site per lane |

## I. Definition of "STEP 1 (v2) complete"

- ✅ Corrected architecture drawn (IUE post-normalization)
- ✅ Existing components inventoried against the corrected roles
- ✅ Gaps re-identified against the corrected pipeline
- ✅ Non-touchables re-enumerated
- ✅ Proposed file layout drafted
- ✅ Compatibility contract stated
- ✅ Risk register drafted
- ✅ Zero code changed

STOP. Awaiting owner authorization to proceed to STEP 2 (module-by-module reuse matrix based on this corrected architecture).
