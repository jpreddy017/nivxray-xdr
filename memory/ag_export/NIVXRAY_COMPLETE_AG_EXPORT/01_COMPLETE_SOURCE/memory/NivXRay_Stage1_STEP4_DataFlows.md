# NivXRay Stage 1 · STEP 4 — Integration & Data-Flow Design

**Date:** 2026-02-14
**Prerequisites:** STEP 1 (v3) audit · STEP 2 (Reuse Matrix) · STEP 3 (Compatibility-Layer Design)
**Scope:** Concrete, per-lane data flows. Zero code.
**Gate:** STOP at end. STEP 6 (implementation) remains LOCKED.

---

## 0. Reading guide

Each lane is drawn as a **sequence** from user submission to `report_extraction` handoff.
Every arrow crosses a named boundary from STEP 3 §2.
Every stage carries the mandatory provenance quintuple: `tenant_id`, `input_id`, `parent_input_id`, `discovery_depth`, `content_fingerprint`.
"Existing" boxes are unchanged code paths; "NEW" boxes are Stage 1 additions.
Feature flag `IUE_STRUCTURED_LANE` is evaluated **once**, at Intake.

---

## 1. Lane A · Raw JSON / NDJSON / CSV / XML (the truly new path)

Trigger: user uploads or pastes a structured log file (EDR export, XDR alert dump, SIEM CSV, XML advisory feed, JSON alert bundle).

### 1.1 End-to-end sequence

```
1. USER  submits file (bytes, mime_hint, filename)
        │
        ▼
2. services/session/adapter.py  resolves tenant_id
        │  tenant_id  (or "__prev_public__" for Prev-mode)
        ▼
3. services/iue/intake.py::intake(payload)                             [NEW · thin facade]
   ├── calls services/ida/input_classifier.classify_artifact_input()   [EXISTING]
   ├── calls services/die/input_understanding.classify()               [EXISTING]
   ├── if IUE_STRUCTURED_LANE=="off" → demote lane to "raw_text" and jump to Lane D
   └── emits IntakeDecision(kind="raw_json"|"ndjson"|"csv"|"xml", lane="structured", …)
        │
        ▼
4. services/iue/collectors/log_collector.py::collect(payload)          [NEW]
   └── emits RawPayload(bytes, mime, encoding, source_file_id, …)
      – no parsing; only labels bytes
      – enforces services/iue/security.py size + decompression caps
        │
        ▼
5. services/iue/parsers/{json|ndjson|csv|xml}_parser.py::iter_records(raw) [NEW]
   └── yields ParsedRecord(record_id, raw_fields, parse_status, …) *N times*
      – pure iterator; one physical file → N logical records (v3 §10)
      – malformed records emitted with parse_status="malformed"
        │
        ▼
6. services/iue/normalizers/field_map.py::normalize(record)            [NEW]
   └── emits NormalizedRecord(canonical_fields, alias_map, unmapped_fields, …)
      – layered detection: schema → vendor → dictionary → type_infer → regex → semantic → validation
      – records alias_source per canonical field
        │
        ▼
7. services/iue/aggregator.py::aggregate(records: Iterable[NormalizedRecord]) [NEW]
   └── emits list[LogicalEvent]  where count >= 1 per event
      – groups on the fixed key set (STEP 3 §3.4)
      – preserves record_refs and variability
      – NEVER performs cross-record semantic reunification
        │
        ▼
8. services/iue/understanding.py::understand(logical_events, intake)   [NEW · thin consolidator]
   ├── dispatches structured-event → MITRE mapping via
   │     services/die/canonical.py + services/mitigation/evidence_driven/*  [EXISTING]
   ├── merges result into report_extraction using the frozen key set
   │     (commands, mitre_techniques, iocs, behaviors, …)
   └── attaches logical_events, intake_decision, iue_failures, content_fingerprint (additive)
        │
        ▼
9. report_extraction (dict)                                            [STABLE CONTRACT]
        │
        ▼
10. services/die/investigation_results.render()                        [EXISTING · unchanged]
    OR services/session/adapter.build_session()                        [EXISTING · unchanged]
        │
        ▼
11. services/ice/correlate._build_incident(ssot)                       [EXISTING · unchanged]
    ← *this* is where cross-event semantic reunification happens
        │
        ▼
12. canonical/ssot/authoritative.AuthoritativeSSOT.append(...)         [EXISTING · unchanged]
        │
        ▼
13. Frontend renders (Prev-mode WorkspacePage / Prod-mode ThreatAnalysis)
```

### 1.2 Illustrative micro-flow — 3 near-duplicate EDR records

Input (three NDJSON lines from an EDR export, same host, same process, same command_line, timestamps 12:00:00.010 / 12:00:00.240 / 12:00:00.870):

```
{"host":"srv-01","pid":1234,"CommandLine":"powershell -enc AAAA…","src_ip":"10.0.0.1","event_time":"2026-02-14T12:00:00.010Z"}
{"host":"srv-01","pid":1234,"CommandLine":"powershell -enc AAAA…","src_ip":"10.0.0.1","event_time":"2026-02-14T12:00:00.240Z"}
{"host":"srv-01","pid":1234,"CommandLine":"powershell -enc AAAA…","src_ip":"10.0.0.1","event_time":"2026-02-14T12:00:00.870Z"}
```

Trace:

| Stage | Output |
|---|---|
| Intake | `IntakeDecision(kind="ndjson", lane="structured", input_id="ab12…")` |
| Collect | `RawPayload(bytes=…, mime="application/x-ndjson", source_file_id="cd34…")` |
| Parse | 3 × `ParsedRecord(record_id="r1"|"r2"|"r3", parse_status="ok")` |
| Normalize | 3 × `NormalizedRecord` — each maps `CommandLine → canonical.process.command_line (alias_source="dictionary")`, `src_ip → canonical.source.ip (dictionary)`, `event_time → canonical.event.timestamp (schema)` |
| Aggregate | **1** × `LogicalEvent(count=3, first_seen="…010Z", last_seen="…870Z", record_refs=["r1","r2","r3"])` — grouping key equal (1-second bucket collapses .010 and .240; .870 forms a second event **if 1s bucket is walked strictly**) → design outcome: **2** events (000 bucket count=2, 001 bucket count=1). See STEP 3 §3.4. |
| Understand | `report_extraction["logical_events"]=[…]`, `report_extraction["commands"]=[…]` filled via existing `command_normalizer` and `mitre_techniques` via existing bridge. |
| ICE | Reunifies both events under one incident (same tenant/host/pid/process); this is the correlation layer, not aggregation. |

**Property preserved:** even though 3 records collapse into 2 events, the 3 raw `record_id`s are always retrievable via `LogicalEvent.record_refs`, and `variability` records the two distinct timestamps in the first event.

### 1.3 Failure paths (Lane A)

| Where | Trigger | IUEFailure | Downstream effect |
|---|---|---|---|
| Collect | File > `services/iue/security.py` size cap | `collect_size_exceeded` · terminal | `report_extraction = {"status":"iue_failed", "error":…, "iue_failures":[…]}` — Fix 1-style envelope, existing consumers see `status` and short-circuit |
| Parse | 1 of 10 000 NDJSON lines is malformed | `parse_malformed_record` · recoverable | 9 999 records continue; malformed one carried through with `parse_status="malformed"` and appears in `iue_failures[]` |
| Normalize | Unknown field `xyz_weird` | `normalize_unmappable_field` · recoverable | Field appears in `NormalizedRecord.unmapped_fields`; canonical fields still populated |
| Aggregate | Record missing `provenance` | `aggregate_provenance_missing` · terminal | Contract violation upstream — fails loudly |
| Understand | `services/die/input_understanding.understand()` raises | `understand_engine_error` · recoverable | `ContentEnvelope.understanding_status="partial"`; `report_extraction` still has `logical_events` + `commands` from IDA path |

---

## 2. Lane B · URL / domain (existing path re-wrapped, NOT rewritten)

Trigger: user submits a URL, domain, or IOC that resolves to a URL.

### 2.1 End-to-end sequence

```
1. USER  submits URL or IOC
        │
        ▼
2. services/session/adapter.py  resolves tenant_id
        │
        ▼
3. services/iue/intake.py::intake(payload)                             [NEW · facade]
   ├── calls services/ida/input_classifier.classify_artifact_input()   [EXISTING]
   │     → returns ida_class ∈ {threat_report_url, atomic_ioc_url, …}
   ├── calls services/die/input_understanding.classify()               [EXISTING]
   └── emits IntakeDecision(kind=<url-kind>, lane="url", …)
        │
        ▼
4. services/ida/acquisition.py::acquire_url()                          [EXISTING · Fix 1 preserved]
   ├── SSRF/private-host guard                                         [EXISTING]
   ├── on failure → returns AcquiredURL with acquisition_failed shape  [EXISTING · Fix 1]
   └── on success → HTML doc + article_text + structured_blocks
        │
        ▼
5. HTML parsing via existing acquisition helpers                       [EXISTING]
   (_trafilatura_extract / _readability_extract / _bs4_heuristic_extract /
    _extract_structured_blocks)
        │
        ▼
6. services/die/input_understanding.understand(article_text, acquired.to_dict())  [EXISTING]
   → document_profile
        │
        ▼
7. report_extraction produced by existing IDA path                     [EXISTING]
   (services/ida/report_extraction.extract() — commands, mitre, iocs, actors, …)
        │
        ▼
8. services/iue/understanding.py::understand(…)                        [NEW · thin passthrough]
   ├── receives report_extraction from step 7 verbatim
   ├── attaches intake_decision, content_fingerprint (additive keys)
   ├── does NOT re-run existing IDA extraction
   └── attaches iue_failures if IntakeDecision or upstream signalled any
        │
        ▼
9. report_extraction handoff — IDENTICAL SHAPE to today                [STABLE CONTRACT]
        │
        ▼
10. services/die/investigation_results.render()                        [EXISTING · unchanged]
11. services/ice/correlate._build_incident()                           [EXISTING · unchanged]
12. canonical/ssot/authoritative.AuthoritativeSSOT.append()            [EXISTING · unchanged]
```

### 2.2 What is NOT changed on Lane B

- Fix 1 `acquisition_failed` envelope produced at `investigation_results.py` L488–505 → **byte-identical** on-wire shape. `services/iue/understanding.py` MUST pass it through unmodified.
- P1a projection logic reading `report_extraction.mitre_techniques`, `.threat_actors`, `.malware_families`, `.behaviors` → unchanged. These keys still populated by the existing IDA path in step 7.
- CISA-403 diagnostic path → unchanged. Fix 2 remains DEFERRED.

### 2.3 Failure paths (Lane B)

| Where | Trigger | Envelope | Notes |
|---|---|---|---|
| Intake | Empty URL / malformed URL / SSRF-suspect URL rejected at intake | `IUEFailure(stage="intake", error_code="intake_unknown_kind"|"collect_denied_by_policy")` | Terminal; skips acquisition entirely |
| Collect | Existing `acquire_url()` failure (403/timeout/SSL) | Fix 1 `acquisition_failed` envelope | Zero change from today. `IUEFailure.to_report_extraction_fragment()` reproduces exactly. |
| Understand | (n/a on Lane B — IDA path fully in charge) | — | — |

---

## 3. Lane C · File / Artifact (existing path re-wrapped)

Trigger: user uploads a file (PDF report, EML, DOCX, ZIP archive, PE binary, script sample).

### 3.1 End-to-end sequence

```
1. USER  submits file (bytes, mime, filename)
        │
        ▼
2. services/session/adapter.py  resolves tenant_id
        │
        ▼
3. services/iue/intake.py::intake(payload)                             [NEW · facade]
   ├── calls services/ida/input_classifier.classify_artifact_input()   [EXISTING]
   ├── calls services/die/input_understanding.classify()               [EXISTING]
   └── emits IntakeDecision(kind="mixed_artifacts"|<file-kind>, lane="file", …)
        │
        ▼
4. Primary artifact contract: services/artifact_intelligence/          [EXISTING · authoritative]
   (Stage 1 STEP 3 §8 risk 6 explicitly commits to this as the single owner)
        │
        ▼
5. Existing artifact analyzers                                         [EXISTING]
   – PDF → text + IOCs
   – EML → headers + body + attachments (attachments trigger recursion)
   – ZIP → children (children trigger recursion)
   – PE → PE analyzer plugins under services/uaie/plugins/pe_*
        │
        ▼
6. Existing normalizers                                                [EXISTING]
   (command_normalizer, input_normalizer, attack_posture_normalizer)
        │
        ▼
7. Existing report_extraction produced by artifact path                [EXISTING]
        │
        ▼
8. services/iue/understanding.py::understand(…)                        [NEW · thin passthrough]
   ├── attaches intake_decision, content_fingerprint (additive keys)
   └── DOES NOT re-run existing analyzers
        │
        ▼
9. report_extraction handoff — IDENTICAL SHAPE to today                [STABLE CONTRACT]
        │
        ▼
10. services/die/investigation_results.render()                        [EXISTING · unchanged]
11. services/ice/correlate._build_incident()                           [EXISTING · unchanged]
12. canonical/ssot/authoritative.AuthoritativeSSOT.append()            [EXISTING · unchanged]
```

### 3.2 Recursive re-entry on Lane C (the critical case)

When an EML attachment yields another file, or a ZIP yields children, or a PDF yields a URL, discovered content re-enters via `services/iue/recurse.py::recurse()` (STEP 3 §5) which routes back to `intake()` — never directly into `understanding.py`.

```
services/uaie/orchestrator.py    [EXISTING]
    │  discovers new artifact / URL / decoded payload
    ▼
services/iue/recurse.py::recurse(discovered, parent_input_id, tenant_id, discovery_depth)  [NEW · facade]
    ├── checks UAIE ledger fingerprint for cycles (existing helper)
    ├── enforces UAIE_MAX_DEPTH=12 (existing constant)
    └── calls services/iue/intake.py::intake(discovered, parent_input_id=..., discovery_depth=depth+1)
        │
        └── re-enters at the correct lane's head (URL / FILE / STRUCTURED / RAW_TEXT)
```

**Property preserved:** discovered content walks the *full* Intake → Collect → Parse → Normalize → Aggregate → Understand chain every time. No lane shortcut is permitted.

### 3.3 Failure paths (Lane C)

| Where | Trigger | Envelope | Notes |
|---|---|---|---|
| Collect | Decompression-bomb / path-traversal detected in archive | `IUEFailure(stage="collect", error_code="collect_denied_by_policy")` · terminal | Reuses existing `archive_recovery` guards |
| Collect | File exceeds `services/iue/security.py` size cap | `collect_size_exceeded` · terminal | New guard, additive to existing checks |
| Recurse | Same fingerprint already seen at ancestor | `recurse_cycle_detected` · recoverable | Skips subtree; existing UAIE ledger handles this today |
| Recurse | Depth > 12 | `recurse_depth_exceeded` · recoverable | Skips subtree; matches existing UAIE cap |

---

## 4. Lane D · Raw text (fallback)

Trigger: user pastes plain text that is not a URL, not a structured log, not an artifact; OR `IUE_STRUCTURED_LANE=off` demoted a structured input.

```
1. USER submits raw text
        │
        ▼
2. services/session/adapter.py  resolves tenant_id
        │
        ▼
3. services/iue/intake.py::intake(payload)                             [NEW · facade]
   └── emits IntakeDecision(kind="ioc_list"|"unknown"|<text-kind>, lane="raw_text", …)
        │
        ▼
4. services/die/input_understanding.understand(text)                   [EXISTING · unchanged]
        │
        ▼
5. Existing IDA extraction path                                        [EXISTING]
        │
        ▼
6. report_extraction handoff (unchanged)                               [STABLE CONTRACT]
```

Lane D is exactly today's Prev-mode text-paste path with an intake wrapper. It is the path exercised whenever `IUE_STRUCTURED_LANE=off`, i.e. **all production traffic** on release day.

---

## 5. Cross-lane invariants (must hold on every path)

1. **Single stable contract.** All four lanes emit into the same `report_extraction` shape (STEP 3 §3.5). Downstream consumers (`render()`, `build_session`, ICE, SSOT) never branch on lane.
2. **Provenance quintuple present at every arrow.** `tenant_id`, `input_id`, `parent_input_id`, `discovery_depth`, `content_fingerprint` — no exceptions, no defaults.
3. **Aggregation only in Lane A.** Lanes B, C, D never invoke `services/iue/aggregator.py`. Aggregation is meaningful only for record-oriented sources.
4. **Correlation only in ICE.** No lane, no aggregator, no understanding module performs cross-event reunification. ICE is the sole owner.
5. **Recursion always re-enters at Intake.** No lane, no analyzer, no plugin may bypass Intake for discovered content.
6. **Feature flag gates ONLY Lane A.** Lanes B/C/D are always on; Lane A is off by default.
7. **Failure is data.** Every stage returns an envelope; no stage raises an unhandled exception into `render()` or `build_session`.
8. **Existing tests must not need modification.** New tests exercise new modules; existing tests remain green as-is.

---

## 6. Integration seam · call-site inventory (grep-verified)

| Existing call site | Today | After Stage 1 wiring |
|---|---|---|
| `services/die/investigation_results.py::render()` L307 `_ida_classify(src)` | direct call | still called; result *also* flows through `services/iue/intake.py` when Lane A is on |
| `services/die/investigation_results.py::render()` L332 `_ida_understand(article_text, acquired.to_dict())` | direct call | UNCHANGED (Lane B keeps this call verbatim) |
| `services/die/investigation_results.py::render()` L335 `_ida_extract(…)` | direct call | UNCHANGED (Lane B/C keep this call verbatim) |
| `services/die/investigation_results.py::render()` L488–505 Fix 1 envelope | inline dict | UNCHANGED; `IUEFailure.to_report_extraction_fragment()` reproduces exactly for parity tests |
| `services/session/adapter.py::build_session()` | reads `report_extraction` | UNCHANGED; sees the frozen key superset |
| `services/ice/correlate.py::_build_incident()` | reads `report_extraction` + `graph` | UNCHANGED |
| `canonical/ssot/authoritative.AuthoritativeSSOT.append()` | writes to SSOT tiers | UNCHANGED |
| `services/uaie/orchestrator.py` | invokes ledger for dedupe / depth | UNCHANGED; `services/iue/recurse.py` uses the same ledger helpers |

**Zero existing call sites are removed. Zero existing signatures change.** The only additions are new call sites *inside* the new IUE modules.

---

## 7. Contradictions surfaced (per owner directive)

| # | Where | Contradiction | Resolution proposed for STEP 5 sign-off |
|---|---|---|---|
| 1 | Lane A step 8 | `understanding.py` claims to be a "thin passthrough" on Lanes B/C but a "structured-event → MITRE dispatcher" on Lane A. Two responsibilities in one module. | Formalise `understanding.py` as a dispatch table keyed on `IntakeDecision.lane`. Passthrough for B/C/D; dispatch for A. Split into two files if the dispatcher grows > 40 LOC. |
| 2 | Lane A step 7 aggregator bucket | 1-second bucket may be too tight for slow-clock EDRs and too loose for high-frequency SIEMs. | Stage 1 pins 1s. A configurable bucket is a Stage-2 change. Documented explicitly to prevent quiet drift. |
| 3 | Lane C recursion | Existing `services/uaie/orchestrator.py` already handles recursion internally for artifact discovery. Introducing `services/iue/recurse.py` risks a **second** recursion driver. | `services/iue/recurse.py` is a **thin adapter** that the orchestrator calls when its own discovery yields content that must re-enter Intake (URL from PDF, attachment from EML). It does not schedule work independently. Explicit test: recursion counter matches UAIE ledger's depth counter after every re-entry. |
| 4 | Feature flag scope | If `IUE_STRUCTURED_LANE=off`, Lane A code is dead. Dead code decays. | STEP 5 mandates that Lane A is exercised by CI even with the flag off, via a *test-only* flag override in `test_iue_*` files. Production traffic remains gated. |
| 5 | Lane D demotion path | When `IUE_STRUCTURED_LANE=off` demotes structured → raw_text, users lose per-record events. | Documented as **intentional** for release day. Once the flag is flipped in production, structured lane activates. The demoted path is bit-identical to today's paste path. |
| 6 | Multi-tenant fallback | Prev-mode may have no tenant → we default to `__prev_public__` (STEP 3 §4). This weakens the "no tenant-less traffic" contract. | Explicit dispensation for Prev-mode. Prod-mode strictly enforces tenant presence. A test file `test_iue_tenant_isolation.py` proves Prod-mode never sees `__prev_public__`. |
| 7 | Reuse of existing `services/uaie/ledger.Ledger()` | If ledger instances are per-orchestrator, IUE recurse may not see UAIE's dedupe scope. | Verified in STEP 5 §3 regression coverage: dedicated test walks a PDF → URL → HTML → decoded-URL chain and asserts the ledger fingerprint is shared across the whole recursion. |

---

## 8. Definition of "STEP 4 complete"

- ✅ Four concrete lanes drawn: A (structured), B (URL), C (file), D (raw text).
- ✅ Every arrow crosses a named STEP 3 dataclass boundary.
- ✅ Existing call sites inventoried (§6) with a per-site "today vs. after" note.
- ✅ Cross-lane invariants stated (§5) — testable properties.
- ✅ Failure paths enumerated per lane.
- ✅ Recursive re-entry sequence drawn for Lane C.
- ✅ Aggregation vs. Correlation boundary stated three times: §1.2 (illustrative), §5 (invariant), §7 (contradiction resolution).
- ✅ Seven contradictions surfaced (§7) with STEP 5 resolution hooks.
- ✅ Zero code written.

**STOP.** STEP 5 proves compatibility and regression coverage against these flows.
