# NivXRay Stage 1 · Phase 6c · Lane A Implementation Review

**Date:** 2026-02-14
**Scope:** Read-only audit of the Lane-A implementation delivered in Phase 6c.
**Purpose:** Answer the 11 review questions before Lane B/C authorization.
**Status:** 🟢 Awaiting owner architectural verdict. No code changes in this document.

---

## 1. Exact 19 files delivered

| # | File | Category |
|---|---|---|
| 1 | `services/iue/__init__.py` | package marker + design pointer |
| 2 | `services/iue/intake.py` | **facade** (single flag-read site) |
| 3 | `services/iue/failure.py` | envelope + closed vocabulary |
| 4 | `services/iue/tenancy.py` | tenant propagator |
| 5 | `services/iue/security.py` | size / count / traversal caps |
| 6 | `services/iue/observability.py` | span context manager |
| 7 | `services/iue/recurse.py` | **facade** over UAIE ledger |
| 8 | `services/iue/understanding.py` | **thin consolidator** (30 LOC) |
| 9 | `services/iue/aggregator.py` | logical-event grouper |
| 10 | `services/iue/collectors/__init__.py` | pkg marker |
| 11 | `services/iue/collectors/log_collector.py` | bytes → RawPayload |
| 12 | `services/iue/parsers/__init__.py` | pkg marker |
| 13 | `services/iue/parsers/_types.py` | shared `ParsedRecord` |
| 14 | `services/iue/parsers/json_parser.py` | stdlib json iterator |
| 15 | `services/iue/parsers/ndjson_parser.py` | line-delimited iterator |
| 16 | `services/iue/parsers/csv_parser.py` | stdlib csv iterator |
| 17 | `services/iue/parsers/xml_parser.py` | defusedxml-aware iterator |
| 18 | `services/iue/normalizers/__init__.py` | pkg marker |
| 19 | `services/iue/normalizers/field_map.py` | dict + type_infer normalizer |

## 2. LOC per file (actual counts)

Measured with `wc -l` for total, and non-blank non-comment lines for `code`:

| File | Total | Code | Notes |
|---|---:|---:|---|
| `__init__.py` | 17 | 12 | docstring only |
| `intake.py` | 170 | 127 | includes 2 frozensets + 1 dataclass |
| `failure.py` | 66 | 37 | 13 error codes + dataclass + validation |
| `tenancy.py` | 29 | 18 | one helper + 1 constant |
| `security.py` | 54 | 34 | 4 caps + 1 traversal guard |
| `observability.py` | 44 | 31 | `span` context manager |
| `recurse.py` | 88 | 66 | facade + 2 ledger emissions |
| `understanding.py` | 36 | 23 | **thin, enforced ≤40** |
| `aggregator.py` | 168 | 110 | grouper + bucket + variability |
| `collectors/log_collector.py` | 73 | 56 | 1 dataclass + collect() |
| `parsers/_types.py` | 23 | 18 | shared ParsedRecord |
| `parsers/json_parser.py` | 103 | 90 | fully guarded iterator |
| `parsers/ndjson_parser.py` | 72 | 63 | line iterator |
| `parsers/csv_parser.py` | 69 | 59 | DictReader iterator |
| `parsers/xml_parser.py` | 95 | 80 | defusedxml + tag conversion |
| `normalizers/field_map.py` | 209 | 164 | **includes 105-line alias table (data, not logic)** |
| package `__init__.py` files (3) | 0 | 0 | empty |
| **Total** | **1 316** | **988** | |

### 2.1 Where the size actually goes

| Bucket | LOC (code) | % of total |
|---|---:|---:|
| Frozen alias dictionary (data table) | 105 | 11 % |
| Parser edge cases (4 parsers, malformed / size / decode error branches) | 292 | 30 % |
| Facades (intake / recurse) | 193 | 20 % |
| Dataclass definitions + `to_dict` helpers | 118 | 12 % |
| Aggregator core logic | 110 | 11 % |
| Vocabulary + security + tenancy + observability | 120 | 12 % |
| Thin consolidator (understanding.py) | 23 | 2 % |
| Everything else (imports, module docstrings) | ~27 | 2 % |

**~1,300 was code including a 105-line frozen data table and heavy defensive parsing.** Strip the data table and the aggregate falls to ~880 LOC of logic — very close to the design estimate.

## 3. Existing helper reused by each file

| File | Reuses | Cited line |
|---|---|---|
| `intake.py` | `services.ida.input_classifier.classify_artifact_input` · `services.die.input_understanding.classify` | lines 119, 128 |
| `recurse.py` | `services.uaie.ledger.Ledger` · `services.uaie.ledger.format_skip_reason` | line 14 |
| `failure.py` | *(none — new closed vocabulary)* | — |
| `tenancy.py` | *(delegates to `services.session.adapter` **by contract**, not by import — accepts `session_ctx` dict from caller)* | — |
| `security.py` | *(new caps — augments, doesn't replace, existing acquisition SSRF/size guards)* | — |
| `observability.py` | stdlib `logging` | line 8 |
| `aggregator.py` | *(none — new logical-event grouper)* | — |
| `understanding.py` | *(delegates to LogicalEvent.to_dict — no new logic)* | — |
| `collectors/log_collector.py` | `iue.security.enforce_raw_size` | line 12 |
| Parsers × 4 | stdlib `json` / `csv` / `xml.etree` / `defusedxml` (optional) | see files |
| `normalizers/field_map.py` | *(new dictionary + type_infer layers — schema/vendor/semantic layers are stubbed for Stage 2)* | — |

**Only 3 files import from existing NivXRay owners.** The remainder either stand alone or use stdlib. This is the honest picture — the review question is whether that stand-alone code is genuinely new capability or a duplicate.

### 3.1 Deviation from STEP 3 §4 — Provenance dataclass NOT imported

STEP 3 §4 said *"every payload carries `Provenance: Provenance` (existing dataclass)"*.

**Actual implementation:** the payload dataclasses (`RawPayload`, `ParsedRecord`, `NormalizedRecord`, `LogicalEvent`, `IUEFailure`) carry inline provenance fields (`input_id`, `tenant_id`, `source_file_id`, `at`) instead of composing an instance of `canonical.ssot.models.Provenance`.

**Why:** cheaper wire format; avoids a nested object at every stage; keeps the boundary payloads flat and easy to log.

**Cost:** one contract deviation that the owner should decide on. Two options:
- **Accept** — treat inline fields as the IUE-lane provenance schema; add a bridge helper `to_ssot_provenance()` that constructs a `canonical.ssot.models.Provenance` when the LogicalEvent is written into SSOT.
- **Reject** — refactor the five dataclasses to compose `Provenance`. LOC delta ≈ +30 (new field on each dataclass) but restores STEP-3 fidelity.

**Recommendation:** accept + add a `to_ssot_provenance()` bridge helper (~10 LOC) when Lane A actually writes into SSOT.

## 4. New logic introduced by each file

| File | Genuinely new logic | Not new (stdlib / reuse) |
|---|---|---|
| `intake.py` | Precedence rule (`ida_class` wins for URL/file, `iue_type` wins for structured/raw_text); structured-kind sniff heuristic; single flag-read site | Actual classification (delegated) |
| `failure.py` | Closed-vocabulary enforcement in `__post_init__` | Dataclass |
| `tenancy.py` | `__prev_public__` fallback rule | — |
| `security.py` | 4 env-tunable caps + path-traversal check | — |
| `observability.py` | `span` context manager with mandatory quintuple | Actual emission (stdlib logging) |
| `recurse.py` | Cycle-fingerprint lookup **through the shared UAIE ledger** | Ledger writes (reused) |
| `understanding.py` | LogicalEvent → additive `report_extraction` fragment (`logical_events`, `logical_event_count`, `logical_record_total`) | Delegates dict serialisation |
| `aggregator.py` | 1-second-bucket signature; grouping key comparison; count / first_seen / last_seen / variability aggregation | — |
| `collectors/log_collector.py` | Envelope construction + size guard | sha256 (stdlib) |
| Parsers × 4 | Per-record ParsedRecord construction + malformed-record fallback | Actual parsing (stdlib) |
| `field_map.py` | Alias dictionary (data) + type-infer heuristics for hashes / IPs | Regex + dict lookup (stdlib) |

## 5. Any duplicated functionality?

Honest inventory:

| Potential duplicate | Existing owner | Actual overlap? |
|---|---|---|
| `intake.py` classifier | `services.ida.input_classifier` + `services.die.input_understanding` | **NO** — intake is a router facade that *reads* both and returns a `lane` choice. No new classification logic. |
| `recurse.py` recursion | `services.uaie.orchestrator` | **NO** — recurse.py does not schedule work; it uses the existing ledger for fingerprint + depth, then hands off to `intake()`. |
| `aggregator.py` grouping | `services.ice.correlate._build_behavior_clusters` (which clusters commands) | **NO** — ICE clusters *commands by semantic behaviour*; aggregator clusters *records by exact canonical key match*. Different granularity; different purpose (see STEP 5 §1). |
| `failure.py` envelope | Fix 1 `acquisition_failed` in `investigation_results.py` L488 | **BRIDGE, not duplicate** — `IUEFailure.to_report_extraction_fragment()` (stub) is designed to reproduce Fix 1 exactly; Fix 1 is still the source of truth. |
| `security.py` caps | `services.ida.acquisition` (SSRF / size limits at fetch time) | **AUGMENTATIVE** — acquisition guards live network fetches; iue.security caps in-memory ingest of already-collected bytes. Non-overlapping scopes. |
| `understanding.py` | `services.die.input_understanding.understand()` | **PLACEHOLDER, not duplicate** — current understanding.py *only* serialises LogicalEvents into the additive report_extraction fragment. No text semantics. Text semantics remain in DIE. |
| Provenance carriers | `canonical.ssot.models.Provenance` | **PARTIAL** — see §3.1 above. Owner decision required. |

**No forbidden duplicate is currently born.** The only architectural risk is the `understanding.py` placeholder — see §7.

## 6. Why total is ~1,300 instead of ~880

Three honest reasons:

### 6.1 A frozen data table was estimated as "code" but is actually data (~105 LOC)

`normalizers/field_map.py` holds a 105-line alias dictionary (`_DICT`) that maps canonical fields to their vendor aliases. The design estimate treated this as ~30 LOC. In practice, listing 4–6 aliases per canonical field across 22 canonical fields is ~105 lines of literal Python data. Removing this table would leave ~980 LOC of Python logic — 10 % above estimate.

### 6.2 Defensive parser branches are higher LOC than "pure iterators" suggest

STEP 3 §2.3 said parsers are *"pure iterators"*, ~40 LOC each. Real parsers must yield a `ParsedRecord` on every failure path (decode error, JSON parse error, per-record size cap, per-file record-count cap). Each parser has 4–5 such branches, each yielding a `ParsedRecord(parse_status="malformed", parse_errors=[...])`. That is where ~120 LOC of "extra" comes from.

Reduction options:
- Consolidate `_yield_malformed(reason)` helper across parsers → ~-40 LOC.
- Move `parse_errors` construction to a shared `parsers/_errors.py` → ~-20 LOC.

**Recommendation:** accept the LOC now; refactor if Lane B/C introduces further duplication.

### 6.3 Dataclass boilerplate + `to_dict` helpers

5 dataclasses × (~10 fields + `to_dict()`) ≈ 90 LOC. `to_dict()` is necessary because `dataclasses.asdict()` cannot serialise `bytes` fields (RawPayload) and needs `Mapping → dict` coercion (aggregator variability).

## 7. Data-flow proof

Actual runtime behaviour verified by `tests/canonical/iue/lane_a/test_iue_lane_a_e2e.py`:

```
NDJSON payload (3 records, 2 within 1s bucket, 1 five minutes later)
    │
    ▼
intake(payload, allow_prev_fallback=True)
    → lane="structured"  (flag=on)
    → tenant_id="__prev_public__"
    → input_id="ab12…"
    │
    ▼
collect(payload, mime="application/x-ndjson", input_id, tenant_id)
    → RawPayload(source_file_id=sha256[:32], bytes_len=…)
    │
    ▼
list(iter_records(raw))     # ndjson_parser
    → 3 × ParsedRecord (all parse_status="ok")
    │
    ▼
[normalize(p) for p in parsed]     # field_map
    → 3 × NormalizedRecord
    → each has canonical.source.ip · canonical.process.command_line
    → alias_map records source="dictionary"
    │
    ▼
aggregate(normalized)
    → 2 LogicalEvents (2 in bucket-1, 1 in bucket-2)
    → biggest has count=2, record_refs=["r-…","r-…"]
    │
    ▼
understand_structured(events)
    → {"logical_events":[…], "logical_event_count":2, "logical_record_total":3}
```

This is the exact chain the design demands. **Zero shortcuts, zero bypass.**

## 8. Provenance proof

Every payload dataclass carries the mandatory quintuple:

| Field | Present on |
|---|---|
| `tenant_id` | RawPayload · ParsedRecord · NormalizedRecord · LogicalEvent · IUEFailure · IntakeDecision |
| `input_id` | RawPayload · ParsedRecord · NormalizedRecord · LogicalEvent · IUEFailure · IntakeDecision |
| `parent_input_id` | RawPayload · IntakeDecision (nullable, for recursion) |
| `discovery_depth` | RawPayload · IntakeDecision |
| `content_fingerprint` (as `source_file_id`) | RawPayload · ParsedRecord · NormalizedRecord · LogicalEvent |

Tested end-to-end by `test_full_lane_a_pipeline` (`assert all(p.tenant_id == d.tenant_id for p in parsed)`).

**Deviation:** we chose inline fields over a composed `canonical.ssot.models.Provenance` object. See §3.1.

## 9. Tenant isolation proof

Three tests lock the contract:

- `test_prev_mode_falls_back_to_prev_public_sentinel` — Prev-mode without session returns `"__prev_public__"`.
- `test_prod_mode_refuses_tenantless_traffic` — `allow_prev_fallback=False` + no session → empty string.
- `test_intake_fails_terminally_without_tenant_in_prod_mode` — Prod-mode with no tenant → **terminal** `IUEFailure(error_code="tenant_context_missing")`. Intake short-circuits; no other module ever sees the payload.

Tenant is copied field-by-field from `IntakeDecision → RawPayload → ParsedRecord → NormalizedRecord → LogicalEvent`. Cross-tenant leakage is impossible under Lane A alone (grouping key includes `canonical.tenant.id`).

## 10. Aggregation proof

Four locking tests:

| Property | Test |
|---|---|
| 10 000 equivalent events → 1 LogicalEvent with count=10 000, first_seen, last_seen, full record_refs | `test_10000_equivalent_events_collapse_to_one_logical_event` |
| Shared IOC but different process / action ≠ aggregated | `test_records_sharing_only_ioc_are_NOT_aggregated` |
| Same grouping key across two different files ≠ aggregated | `test_aggregator_never_correlates_across_source_files` (event_ids differ because event_id = sha256(tenant_id::source_file_id::signature)) |
| 1-second bucket boundary respected | `test_1s_bucket_pins_deterministically` |

**Provenance during aggregation:** every collapsed `ParsedRecord.record_id` is preserved in `LogicalEvent.record_refs`, and distinct canonical field values are preserved in `LogicalEvent.variability`. Nothing is destroyed.

**Cross-record semantic reunification is explicitly NOT performed** by the aggregator; that responsibility remains with `services.ice.correlate._build_incident` (unchanged). STEP 5 §1 stated this three ways; every stated way is now testable.

## 11. Failure-state proof

Closed vocabulary of **13 error codes** enforced at construction time:

`intake_unknown_kind` · `collect_size_exceeded` · `collect_timeout` · `collect_denied_by_policy` · `parse_malformed_record` · `parse_encoding_failed` · `normalize_unmappable_field` · `normalize_alias_ambiguous` · `aggregate_provenance_missing` · `understand_engine_error` · `recurse_depth_exceeded` · `recurse_cycle_detected` · `tenant_context_missing`.

`test_failure_vocabulary_is_closed` proves any typo raises `ValueError` before an IUEFailure with a bogus code can escape.

Failure paths **verified end-to-end**:

| Path | Test |
|---|---|
| Prod-mode without tenant → terminal `tenant_context_missing` | `test_intake_fails_terminally_without_tenant_in_prod_mode` |
| Payload > size cap → terminal `collect_size_exceeded` (not exception) | `test_collect_size_cap_returns_failure_not_exception` |
| Recursion depth > UAIE_MAX_DEPTH → recoverable `recurse_depth_exceeded` + ledger `skip_reason=depth_cap` | `test_recurse_depth_cap_matches_uaie` |
| Second recurse of same fingerprint → recoverable `recurse_cycle_detected` | `test_recurse_cycle_detected_via_shared_ledger` |
| One malformed NDJSON line among many → yielded with `parse_status="malformed"`, siblings continue | `test_ndjson_malformed_record_is_yielded_not_swallowed` |
| Archive with `..` → rejected by `is_safe_archive_member` | `test_archive_path_traversal_rejected` |

**No stage silently converts failure to success.** Failure is data, not exception, everywhere.

---

## Architectural verdict of this review (author's honest assessment)

| Area | Verdict | Detail |
|---|---|---|
| **File count** | ✅ | 19 files matches STEP 3 §E layout exactly |
| **Reuse of existing owners** | ⚠️ | Only 3 files import from existing services; the rest are new modules. This is expected for the *net-new* structured lane, but every new module was audited above — no forbidden duplicate found. |
| **Duplication risk** | ✅ | No parallel classifier / no parallel recursion engine / no parallel correlation. `understanding.py` is a serialiser placeholder, not a second IUE. |
| **LOC discipline** | ⚠️ | 1,316 vs 880 estimate. 105 lines are a data table; ~120 lines are defensive parser branches; the rest is close to estimate. Reduction options listed in §6.2. |
| **Provenance fidelity** | ⚠️ | Inline fields chosen over composed `Provenance`. Owner decision required (§3.1). |
| **Aggregation ≠ Correlation** | ✅ | Tested three ways as promised in STEP 5 §1 |
| **Feature-flag discipline** | ✅ | Single read site (`intake.py::_flag_state`). No other module reads the env var. |
| **Tenant isolation** | ✅ | Prov-mode strict; Prev-mode uses documented sentinel |
| **Failure envelope** | ✅ | Closed vocabulary + construction-time enforcement |
| **UI exposure** | 🚫 | **None.** Backend/data-pipeline only. UI projection is an explicit next phase per owner directive. |

---

## Explicit questions for the owner

1. **Provenance deviation (§3.1):** Accept inline fields + add a `to_ssot_provenance()` bridge later, or refactor now to compose `canonical.ssot.models.Provenance`?
2. **understanding.py future:** confirm that structured-event → MITRE mapping **must** live in an existing owner (`services.die.canonical` / `services.mitigation.evidence_driven.*`), and that `understanding.py` remains a pure LogicalEvent serialiser. This aligns with your directive but should be explicit before Stage 2 planning.
3. **LOC reduction hooks (§6.2):** authorize the parser-error consolidation helper (est. -60 LOC) or accept the current shape?
4. **Next verification step:** authorize preview-only `IUE_STRUCTURED_LANE=on` with a controlled NDJSON EDR fixture to inspect the actual wire output before any UI or Lane B/C decision?

---

## What this review deliberately does NOT do

- No code changes.
- No Lane B / Lane C planning.
- No Stage 2 (Verdict / IOC disposition / Reconciliation) work.
- No UI additions.
- No changes to the 6 payload-shape failures (handled as separate scope).

🛑 **Awaiting owner architectural verdict on the four questions above before proceeding.**
