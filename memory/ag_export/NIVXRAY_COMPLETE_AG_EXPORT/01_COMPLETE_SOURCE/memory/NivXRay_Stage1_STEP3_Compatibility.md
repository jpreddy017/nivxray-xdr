# NivXRay Stage 1 · STEP 3 — Compatibility-Layer Design

**Date:** 2026-02-14
**Prerequisite:** STEP 1 (v3) audit + STEP 2 (Reuse Matrix)
**Scope:** Interface / contract / provenance / failure design **only**. Zero code.
**Gate:** STOP at end. STEP 6 (implementation) remains LOCKED until owner reviews Steps 3–5.

---

## 0. Design intent (locked)

Stage 1 introduces an **orchestration seam**, not a new platform. Every capability listed in this document must map to an existing NivXRay owner via the Reuse Matrix; a new dataclass/interface exists *only* to carry provenance across a boundary that today has no shared type. The compatibility layer is judged by three properties:

1. **Additive** — no existing field is removed or renamed.
2. **Reversible** — with `iue.structured_lane=off` (default) all existing call paths behave bit-identically.
3. **Traceable** — every payload crossing a boundary carries `tenant_id`, `input_id`, `parent_input_id`, `source_id`, `discovery_depth`, and a `content_fingerprint`.

---

## 1. Layer map · authoritative call sequence

```
        user submission
              │
              ▼
      services/iue/intake.py                  ← LIGHTWEIGHT ROUTER (facade)
              │                                  Reads services/ida/input_classifier.classify_artifact_input()
              │                                  AND services/die/input_understanding.classify()
              │                                  Emits IntakeDecision(kind, lane, confidence, reasons)
              ▼
     ┌────────┴──────────┬────────────────────┐
     ▼                   ▼                    ▼
  URL lane           FILE lane          STRUCTURED lane
 (existing)          (existing)         (NEW · gated by
                                        iue.structured_lane=off)
     │                   │                    │
     ▼                   ▼                    ▼
services/ida/       services/artifact_    services/iue/collectors/
acquisition.py      intelligence/*        log_collector.py
(FIX 1 preserved)   + artifact routers    (bytes + mime + tenant)
     │                   │                    │
     ▼                   ▼                    ▼
existing HTML       existing artifact     services/iue/parsers/
parsers             analyzers             {json|ndjson|csv|xml}_parser.py
     │                   │                    │
     ▼                   ▼                    ▼
existing            existing              services/iue/normalizers/
normalizers +       normalizers +         field_map.py
report_extraction   report_extraction     (vendor → canonical)
     │                   │                    │
     ▼                   ▼                    ▼
                     services/iue/aggregator.py
                     (collapses equivalent records; preserves refs)
                                │
                                ▼
                     services/iue/understanding.py
                     (THIN consolidator — dispatches to existing
                      services/die/input_understanding.understand())
                                │
                                ▼
              report_extraction  ← THE STABLE CROSS-LANE CONTRACT
                                │
                                ▼
     services/die/investigation_results.render()  (unchanged)
     canonical/ssot/authoritative.AuthoritativeSSOT (unchanged)
     services/ice/correlate._build_incident      (unchanged)
```

**Key invariant:** all three lanes converge on the existing `report_extraction: Dict[str, Any]` shape. New lanes may add keys; they may never drop keys the existing consumers read (`commands`, `command_investigations`, `investigation_summary`, `mitre_techniques`, `body_artifacts`, `threat_actors`, `malware_families`, `behaviors`, `iocs`, `evidence_source`, `evidence_source_url`, plus the `acquisition_failed` envelope).

---

## 2. Public interfaces (definitions only · no implementation)

All types live in the new `services/iue/` package. All are `@dataclass(frozen=True)` unless noted, JSON-serialisable via `dataclasses.asdict`, and inherit provenance via composition with existing `canonical/ssot/models.Provenance`.

### 2.1 `IntakeDecision` — output of `services/iue/intake.py::intake(payload)`

```
IntakeDecision:
    kind:            str          # superset vocabulary (see §3.1)
    lane:            Literal["url", "file", "structured", "raw_text"]
    confidence:      float        # 0.0..1.0 · from underlying classifiers
    reasons:         list[str]    # human-readable trail; ≥1 entry
    ida_class:       str | None   # verbatim from ida.input_classifier when applicable
    iue_type:        str | None   # verbatim from die.input_understanding when applicable
    input_id:        str          # sha256(payload_bytes)[:16] · stable per payload
    tenant_id:       str          # propagated from session/adapter
    parent_input_id: str | None   # set only on recursive re-entry
    discovery_depth: int          # 0 for user-submitted; ≤ UAIE max_depth=12
    provenance:      Provenance   # engine="iue.intake", version="1.0"
```

**Contract:**
- `intake()` MUST NOT fetch, parse, decode, or transform anything. It only *labels* and *routes*.
- If both underlying classifiers disagree, `ida_class` wins for `url|file` lanes; `iue_type` wins for `structured|raw_text`. This precedence is testable and documented; without it, a third classifier is de-facto born.
- If `lane == "structured"` and `os.environ.get("IUE_STRUCTURED_LANE", "off") == "off"`, `intake()` MUST demote to `lane="raw_text"` and record `reasons += ["structured_lane_disabled"]`. Feature flag is enforced at intake, not at the collector.

### 2.2 `RawPayload` — output of `services/iue/collectors/log_collector.py::collect()`

```
RawPayload:
    bytes:           bytes
    mime:            str          # detected (application/json, application/x-ndjson, text/csv, application/xml)
    encoding:        str          # 'utf-8' | detected fallback
    source_file_id:  str          # sha256 of bytes[:32] · content fingerprint
    input_id:        str          # inherited from IntakeDecision
    tenant_id:       str
    parent_input_id: str | None
    discovery_depth: int
    provenance:      Provenance   # engine="iue.collectors.log", version="1.0"
```

**Contract:** collectors DO NOT parse. They accept trusted local bytes (uploaded artifact) and emit a labeled envelope. No network I/O in Stage 1.

### 2.3 `ParsedRecord` — output of `services/iue/parsers/*.py::iter_records()`

```
ParsedRecord:
    record_id:        str          # deterministic per (source_file_id, offset)
    source_file_id:   str
    input_id:         str
    tenant_id:        str
    offset:           int          # byte offset or record index (parser-defined)
    raw_fields:       Mapping[str, Any]   # verbatim vendor fields · READ-ONLY
    parser_name:      Literal["json", "ndjson", "csv", "xml"]
    parse_status:     Literal["ok", "partial", "malformed"]
    parse_errors:     list[str]    # empty when parse_status == "ok"
    provenance:       Provenance
```

**Contract:**
- Parsers are pure iterators. They MUST NOT interpret any field semantically (that is normalization's job).
- Malformed records are yielded with `parse_status="malformed"`, never dropped silently.
- One physical file → many `ParsedRecord`s (v3 §10 requirement).

### 2.4 `NormalizedRecord` — output of `services/iue/normalizers/field_map.py::normalize()`

```
NormalizedRecord:
    record_id:        str          # inherited from ParsedRecord
    source_file_id:   str
    input_id:         str
    tenant_id:        str
    canonical_fields: Mapping[str, Any]   # canonical.* namespace only
    raw_fields:       Mapping[str, Any]   # unchanged reference from ParsedRecord
    alias_map:        Mapping[str, tuple[str, str]]
                     # canonical_key → (raw_key, alias_source)
                     # alias_source ∈ {"schema", "vendor", "dictionary",
                     #                 "type_infer", "regex", "semantic"}
    normalize_status: Literal["ok", "partial", "unmappable"]
    unmapped_fields:  list[str]
    provenance:       Provenance
```

**Contract:**
- Canonical namespace is FROZEN in this design (see §3.3). New aliases are additive.
- Layered detection order is normative: `schema → vendor → dictionary → type_infer → regex → semantic → validation` (v3 §6).
- Every canonical field records *how* it was resolved via `alias_source`. This is the sole guard against silent vendor bias.

### 2.5 `LogicalEvent` — output of `services/iue/aggregator.py::aggregate()`

```
LogicalEvent:
    event_id:         str          # sha256 of stable grouping key
    tenant_id:        str
    input_id:         str
    source_file_id:   str
    record_refs:      list[str]    # every collapsed ParsedRecord.record_id
    count:            int          # >= 1
    first_seen:       str          # ISO-8601 UTC
    last_seen:        str          # ISO-8601 UTC
    canonical_fields: Mapping[str, Any]   # the SHARED canonical fields
    variability:      Mapping[str, list[Any]]
                      # canonical_key → distinct values seen across collapsed records
    provenance:       Provenance
```

**Contract (aggregation ≠ correlation):**
- Aggregation ONLY collapses records that share every canonical grouping key in §3.4. It does not infer relationships across events.
- `count >= 1` — a single record still becomes a `LogicalEvent` (uniform envelope).
- `record_refs` MUST contain every collapsed `ParsedRecord.record_id`. No orphaning.
- Cross-record semantic reunification (tenant × device × process × user × session × artifact × timestamp × entity) is **owned by `services/ice/correlate.py`** and is explicitly OUT of scope for the aggregator.

### 2.6 `ContentEnvelope` — output of `services/iue/understanding.py::understand()`

```
ContentEnvelope:
    input_id:            str
    tenant_id:            str
    parent_input_id:      str | None
    discovery_depth:      int
    intake:               IntakeDecision
    lane_output:          list[LogicalEvent] | AcquiredHTMLDoc | ArtifactAnalysis
    report_extraction:    Mapping[str, Any]      # THE STABLE CONTRACT · see §3.5
    understanding_status: Literal["ok", "partial", "failed"]
    failures:             list[IUEFailure]
    provenance:           Provenance
```

**Contract:**
- `understanding.py` MUST call existing `services/die/input_understanding.understand()` for text semantics — not re-implement it. It only *adds* structured-event semantic classification (mapping canonical fields → MITRE tactics/techniques via existing bridges).
- `report_extraction` is the **only** field downstream consumers (`render()`, `build_session`, `ice._build_incident`, `AuthoritativeSSOT`) actually read. Everything else is provenance/observability.

### 2.7 `IUEFailure` — extended failure envelope

```
IUEFailure:
    status:       Literal["ok", "recoverable", "terminal"]
    stage:        Literal["intake", "collect", "parse", "normalize",
                          "aggregate", "understand", "recurse"]
    error_code:   str          # snake_case · stable vocabulary
    message:      str          # human-readable
    recoverable:  bool
    hint:         str          # remediation hint · may be empty
    input_id:     str
    tenant_id:    str
    provenance:   Provenance
    def to_report_extraction_fragment(self) -> dict:
        # Serialises to the exact Fix 1 acquisition_failed shape when
        # stage=="collect" and lane=="url", preserving the on-wire contract.
```

**Contract:**
- Failure is data, not exception (v3 §18). Every module returns an envelope even on error.
- Terminal failures short-circuit the lane; recoverable failures allow the lane to continue with partial results (e.g. one malformed record among 10 000).
- The Fix 1 envelope in `investigation_results.py` L488–505 is unchanged. `IUEFailure.to_report_extraction_fragment()` when stage=`"collect"` and lane=`"url"` produces **exactly** those fields.

---

## 3. Vocabularies (locked at design time)

### 3.1 Intake `kind` superset

Inherited unchanged from `IDA_INPUT_CLASSES`:
`threat_report_url`, `code_snippet_url`, `repository_url`, `file_resource_url`, `ioc_portal_url`, `atomic_ioc_url`, `mixed_artifacts`, `ioc_list`, `yara_ruleset`, `sigma_ruleset`.

Added by Stage 1 (superset only; nothing removed):
`raw_json`, `ndjson`, `csv`, `xml`, `edr_report`, `xdr_report`, `siem_export`, `email`, `cloud_log`, `network_log`, `security_alert`, `unknown`.

### 3.2 `lane` vocabulary

`url` · `file` · `structured` · `raw_text`. No other values permitted. Adding a lane is a Stage-2 change requiring a new design step.

### 3.3 Canonical field namespace (initial frozen set)

```
canonical.tenant.id
canonical.event.timestamp
canonical.event.action
canonical.event.category
canonical.event.severity
canonical.source.ip
canonical.source.port
canonical.source.host
canonical.source.user
canonical.destination.ip
canonical.destination.port
canonical.destination.host
canonical.destination.domain
canonical.destination.url
canonical.process.parent
canonical.process.name
canonical.process.command_line
canonical.file.path
canonical.file.hash.md5
canonical.file.hash.sha1
canonical.file.hash.sha256
canonical.registry.key
canonical.registry.value
canonical.network.protocol
canonical.email.sender
canonical.email.recipient
canonical.email.subject
canonical.email.attachment
```

**Aliases** (initial dictionary — additive across releases): `src_ip / sourceAddress / source_ip / sip → canonical.source.ip`; `dst_ip / destinationAddress / dest_ip / dip → canonical.destination.ip`; `cmd / process_command_line / CommandLine → canonical.process.command_line`; `sha256 / SHA-256 / fileHash → canonical.file.hash.sha256`. (Full dictionary is part of STEP 6 implementation and is not codified in this design.)

### 3.4 Aggregation grouping key

Two `ParsedRecord`s aggregate into one `LogicalEvent` iff **every** of these canonical fields (when present) match exactly:

`tenant.id` · `event.timestamp` (truncated to 1-second bucket) · `event.action` · `source.ip` · `destination.ip` · `destination.port` · `process.name` · `process.command_line` · `file.hash.sha256`.

If any of the above is present in one record and absent in the other, they do NOT aggregate. Semantic similarity is *never* used at aggregation time (that is ICE's job).

### 3.5 `report_extraction` contract (frozen keys · superset-only evolution)

Keys downstream consumers rely on today (grep-verified in `investigation_results.py`, `ice/correlate.py`, `session/adapter.py`):

`commands`, `command_investigations`, `investigation_summary`, `mitre_techniques`, `body_artifacts`, `threat_actors`, `malware_families`, `behaviors`, `iocs`, `evidence_source`, `evidence_source_url`, `status` (only when Fix 1 fires), `error`, `source`.

Stage 1 may add: `logical_events: list[LogicalEvent-as-dict]`, `intake_decision: IntakeDecision-as-dict`, `iue_failures: list[IUEFailure-as-dict]`, `content_fingerprint: str`. Nothing else. **No key above may change type or be removed.**

### 3.6 `error_code` vocabulary for `IUEFailure`

`intake_unknown_kind`, `collect_size_exceeded`, `collect_timeout`, `collect_denied_by_policy`, `parse_malformed_record`, `parse_encoding_failed`, `normalize_unmappable_field`, `normalize_alias_ambiguous`, `aggregate_provenance_missing`, `understand_engine_error`, `recurse_depth_exceeded`, `recurse_cycle_detected`, `tenant_context_missing`. Vocabulary is closed for Stage 1; new codes require a design amendment.

---

## 4. Provenance / tenant / observability contract

Every payload crossing a module boundary MUST carry, minimally:

`tenant_id` · `input_id` · `parent_input_id` (nullable) · `source_id` (== `input_id` at intake; == acquired URL/file for lanes) · `discovery_depth` · `content_fingerprint` (sha256 of the record/event's canonical bytes) · `provenance: Provenance` (existing dataclass, mandatory `engine`, `version`, `at`, optional `upstream_evidence_ids`).

**Wire-through rule:** each new IUE module writes exactly one new `Provenance` and appends the caller's `Provenance.upstream_evidence_ids` (which becomes the lineage chain). No module invents a new provenance schema.

**Tenant propagation** is enforced at intake — if `tenant_id` cannot be resolved from `services/session/adapter.py`, `intake()` MUST return `IUEFailure(status="terminal", error_code="tenant_context_missing")` and short-circuit. No lane runs tenant-less.

**Observability emission** (v3 §22): every module emits a structured log at boundary entry AND exit with the fields above plus `stage`, `record_count`, `processing_status`, `error_code`, `processing_time_ms`. Emission uses existing UAIE ledger helpers where they exist; new emission lives in `services/iue/observability.py` and is a thin adapter to `logging` + `services/uaie/ledger.py`.

---

## 5. Recursive re-entry contract

Recursion is bounded, cycle-safe, and re-enters at **Intake**, never at IUE.

```
def recurse(discovered_content, *, parent_input_id, tenant_id, discovery_depth):
    # 1. Cycle guard via existing UAIE ledger fingerprint
    if uaie_ledger.seen(sha256(discovered_content)):
        return IUEFailure(status="recoverable",
                          stage="recurse",
                          error_code="recurse_cycle_detected")

    # 2. Depth guard using existing UAIE.max_depth=12
    if discovery_depth + 1 > UAIE_MAX_DEPTH:
        return IUEFailure(status="recoverable",
                          stage="recurse",
                          error_code="recurse_depth_exceeded")

    # 3. Route back into intake — NOT into IUE
    return intake(discovered_content,
                  parent_input_id=parent_input_id,
                  tenant_id=tenant_id,
                  discovery_depth=discovery_depth + 1)
```

**Contract:**
- `services/iue/recurse.py` MUST NOT duplicate `services/uaie/orchestrator.py`. It is a facade using the same ledger, same depth cap.
- No lane may call `understanding.understand()` directly for discovered content — that would bypass parse+normalize+aggregate. All re-entry goes through `intake()`.

---

## 6. Failure-state matrix (per stage)

| Stage | Failure trigger | Status | Error code | Recoverable action | Terminal action |
|---|---|---|---|---|---|
| intake | unknown kind, empty payload, no tenant | terminal | `intake_unknown_kind` / `tenant_context_missing` | — | short-circuit; return failure |
| collect · URL | HTTP error, SSRF-blocked host, size cap | terminal | `collect_denied_by_policy` / `collect_size_exceeded` | — | emit Fix 1 `acquisition_failed` envelope |
| collect · URL | transient timeout under retry budget | recoverable | `collect_timeout` | retry within existing acquisition budget | — |
| collect · file | archive decompression bomb, path traversal | terminal | `collect_denied_by_policy` | — | short-circuit; emit failure |
| collect · structured | file too large, encoding undetected | terminal | `collect_size_exceeded` / `parse_encoding_failed` | — | short-circuit |
| parse | one malformed record among many | recoverable | `parse_malformed_record` | yield record with `parse_status="malformed"`; continue | — |
| parse | file entirely unparseable | terminal | `parse_malformed_record` | — | short-circuit lane |
| normalize | single field has no alias | recoverable | `normalize_unmappable_field` | append to `unmapped_fields[]`; continue | — |
| normalize | alias resolves to two canonical keys | recoverable | `normalize_alias_ambiguous` | choose highest-precedence source (schema > vendor > dictionary > …); log | — |
| aggregate | record missing provenance | terminal | `aggregate_provenance_missing` | — | fail loudly; contract violation upstream |
| understand | underlying `understand()` engine raises | recoverable | `understand_engine_error` | return `ContentEnvelope(understanding_status="partial")`; downstream still gets `report_extraction` from IDA path | — |
| recurse | cycle | recoverable | `recurse_cycle_detected` | skip this branch | — |
| recurse | depth cap | recoverable | `recurse_depth_exceeded` | skip this branch | — |

**No stage silently converts failure to success.** Every recoverable failure is preserved in `ContentEnvelope.failures[]` and surfaces in `report_extraction.iue_failures[]`.

---

## 7. Feature-flag gate

```
IUE_STRUCTURED_LANE = os.environ.get("IUE_STRUCTURED_LANE", "off")
```

Read once at intake dispatch (§2.1 contract). No other module reads the flag. When `off`:
- `lane="structured"` demotes to `lane="raw_text"`.
- `services/iue/collectors/`, `services/iue/parsers/`, `services/iue/normalizers/field_map.py`, `services/iue/aggregator.py` are code-present but unreached in production traffic.
- All existing Prev-mode + Prod-mode + Fix 1 + P1a paths execute bit-identically.

**Rollback:** remove the env var → default `"off"` → structured lane inert. No code change required.

---

## 8. Architectural contradictions surfaced (per owner's directive to expose risks)

| # | Contradiction / risk | Why it matters | Mitigation in this design |
|---|---|---|---|
| 1 | **Two pre-existing IUE modules already exist**: `services/die/input_understanding.py::understand()` and `nivxforge/investigation/input_understanding.py`. The Reuse Matrix names only the first. | Silent duplication risk. If we consolidate only one, the second becomes drift. | STEP 3 explicitly names `services/die/input_understanding.py` as the authoritative engine that `services/iue/understanding.py` wraps. `nivxforge/investigation/input_understanding.py` is flagged for **audit-only in STEP 5**; do not touch in Stage 1 but must be reconciled before Stage 2. |
| 2 | `render()` calls `_ida_classify(src)` at L307 **before** acquisition, and `_ida_understand()` at L332 **after** acquisition. The corrected pipeline says Intake → Collect → Parse → Normalize → Aggregate → IUE. | Existing code already does Intake-before-Collect and Understand-after-Parse for the URL lane. The "corrected" pipeline is compatible; the risk is claiming a change that isn't a change. | Design explicitly recognises `_ida_classify` at L307 as the **existing** intake, and `_ida_understand` at L332 as the **existing** IUE-URL. New `services/iue/intake.py` wraps L307's classifier; new `services/iue/understanding.py` wraps L332's `understand()`. Nothing moves. |
| 3 | `report_extraction` is the **de-facto** cross-lane contract but has never been formally frozen. New lanes could add or (worst case) reshape keys. | Silent contract drift breaks Prev-mode P1a, ICE `_build_incident`, and SSOT projections. | §3.5 freezes the key list explicitly. STEP 5 regression suite will assert every key still resolves after Stage 1 wiring. |
| 4 | Feature-flag `iue.structured_lane` was assumed but has **no existing config surface**. | Untestable and unenforceable if not declared. | §7 declares it as an env var read at exactly one location. |
| 5 | `services/uaie/ledger.py` uses `SKIP_DEPTH_CAP` semantics tied to UAIE's own orchestrator loop. Reusing it for IUE recursion assumes the ledger is orchestrator-agnostic. | If UAIE ledger is stateful per orchestrator instance, IUE recursion using it may see wrong dedupe scope. | STEP 6 must verify (via unit test) that `Ledger()` instances are safe to share across orchestrators OR that IUE creates its own ledger instance but uses the same `SKIP_*` vocabulary. Flagged for STEP 5 regression coverage. |
| 6 | Reuse Matrix Row 3 lists **four** distinct artifact routers. Design must pick one primary or the file-lane adapter becomes a fifth. | Genuine duplication risk. | §1 diagram commits to `services/artifact_intelligence/` as the primary contract; `services/ida/artifact_router.py` and `services/die/preprocessor/artifact_router.py` are treated as existing wrappers, not reimplemented. If they conflict, resolution is a STEP 5 pre-condition, not a STEP 6 implementation task. |
| 7 | Aggregation grouping in §3.4 uses `event.timestamp` truncated to 1-second buckets. Log volume at scale may need larger buckets. | Premature optimisation, but silently choosing 1s is opinionated. | Bucket size is fixed at 1s in Stage 1; changing it requires a design amendment. Tests will pin the value. |
| 8 | `understanding.py` is described as "thin consolidator" but must also do **structured-event semantic classification** (canonical field → MITRE). Non-trivial. | Risk: `understanding.py` grows into a second IUE. | Design bound: structured-event → MITRE mapping is *delegated* to the existing `services/die/canonical.py` and `services/mitigation/evidence_driven/*` bridges via a dispatcher in `understanding.py`. No MITRE logic lives in the new module. |
| 9 | `IUEFailure.to_report_extraction_fragment()` must produce exactly Fix 1's shape. Any drift breaks the URL lane. | On-wire contract fragility. | §2.7 makes this a testable equality. STEP 5 pins a golden `acquisition_failed` fixture. |
| 10 | `tenant_id` is currently propagated via `services/session/adapter.py` but not all existing call sites are tenant-aware (Prev-mode paste path). Enforcing `tenant_id` at intake may break unauthenticated Prev-mode. | Real regression risk. | §4 fallback: if session adapter returns no tenant, intake uses `tenant_id="__prev_public__"` and records `alias_source="session_default"`. Prev-mode behaviour preserved; multi-tenant enforcement lives in Prod-mode where session is guaranteed. |

Items 1, 5, 6, 10 are the four highest-severity risks. They MUST be resolved (or explicitly waived) before STEP 6 is authorised.

---

## 9. What this design deliberately does NOT introduce

- A new evidence dataclass (SSOT models are reused verbatim).
- A new correlation logic (ICE is untouched).
- A new verdict path (Stage 2+).
- A new tenant model (session adapter is source of truth).
- A new provenance schema (existing `Provenance` reused).
- A new recursion engine (UAIE ledger + depth cap reused).
- A new HTTP client (acquisition.py owns URL fetching).
- A new hasher (`sha256_hex` from `canonical/ssot/authoritative.py` reused).

Every new module in `services/iue/` is a **carrier**, not an engine.

---

## 10. Definition of "STEP 3 complete"

- ✅ Every boundary between existing components and new IUE modules has a named dataclass with explicit fields.
- ✅ Precedence rules for conflicting classifiers documented (§2.1).
- ✅ Canonical field namespace frozen (§3.3), alias-source vocabulary frozen (§2.4), error-code vocabulary frozen (§3.6).
- ✅ Failure-state matrix complete for all 7 stages (§6).
- ✅ Feature-flag surface named and located (§7).
- ✅ Ten architectural contradictions surfaced (§8) with concrete mitigations.
- ✅ Zero code written.

**STOP.** STEP 4 defines the three concrete data flows against these contracts. STEP 5 proves compatibility.
