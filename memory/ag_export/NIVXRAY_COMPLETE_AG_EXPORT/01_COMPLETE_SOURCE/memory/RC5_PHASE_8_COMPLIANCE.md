# RC5 · Phase 8 · Explainability Compiler · Recommendation Compliance Report

**Date:** 2026-02-21
**Phase:** 8 — Deterministic Explainability Bundle + 3 analyst-facing add-ons
**Feature flag:** `SEMANTIC_ENGINE_V2` (unchanged; additive)

---

## 1 · Scope

Assemble the analyst-facing `explain` bundle per spec §11, extended with
three additional analyst-facing capabilities the user approved with
Phase 8:

1. **"Why NOT Malicious?"** — deterministic list of missing signals.
2. **Evidence Tree** — Verdict → Behavior → ExecNode → SIRNode → decode-layer → original input.
3. **Confidence Breakdown** — per-stage confidence (decode / semantic / behavior / mitre / verdict + weighted overall).

Plus the roadmap-item **X-Decode-Ms response header**.

---

## 2 · Approved Recommendations vs. Delivery

| # | Recommendation                                                            | Status | Notes |
|--:|---------------------------------------------------------------------------|:------:| ----- |
| 1 | Evidence Tree drill-down (Verdict → Behavior → ExecNode → SIR → layer)    |   ✅   | `EvidenceLink` model; each link carries `behavior_id`, `exec_node_ids`, `exec_node_kinds`, `sir_node_ids`, `decode_layers`, `source_spans`. Populated for every `verdict.top_reason`. |
| 2 | Confidence Breakdown per stage                                            |   ✅   | `ConfidenceBreakdown{decode, semantic_reconstruction, behavior, mitre, verdict, weighted_overall, weights}`. Weights sum to 1.00; each stage clamped to `[0, 100]`. |
| 3 | "Why NOT Malicious?" deterministic explanation                            |   ✅   | `WhyNotMalicious.missing_signals[]` — persistence, network, credential access, exfil, shellcode, reflection, AMSI/ETW, destructive impact, LOLBIN executed, low capability, low impact. Emits only for Benign/Suspicious verdicts; explicit `applicable=False` otherwise. |
| 4 | Narrative locked to `advisor` origin (§ 14 AI-boundary invariant)         |   ✅   | `Explanation.narrative` always emits empty; `narrative_origin="advisor"` locked. AI advisor can fill later out-of-band; deterministic values never change. |
| 5 | `X-Decode-Ms` response header                                             |   ✅   | Added to `/api/rc5/parse` via `Response.headers`. Live-verified: `X-Decode-Ms: 0.397`. |
| 6 | Deterministic (data-structure level)                                      |   ✅   | `test_explanation_deterministic_full_dump` — strips ephemeral uuid IDs and asserts full byte-equal JSON dump across runs. Scores/reasons/signals/confidence/tree structure all byte-stable. |
| 7 | Frozen / immutable                                                        |   ✅   | Pydantic `ConfigDict(frozen=True, extra="forbid")` on every model. |
| 8 | No AI import                                                              |   ✅   | `test_explanation_module_no_ai_imports` (docstring-stripped scan). |
| 9 | No regex on raw text                                                      |   ✅   | `test_explanation_module_no_regex_on_raw_text`. Compiler consumes structured objects only. |
| 10 | Consumes structured pipeline outputs only                                 |   ✅   | Signature: `compile_explanation(original_input, sir, graph, behaviors, mitre, lolbins, verdict)`. |
| 11 | Response wired into `/api/rc5/parse`                                      |   ✅   | New `explain{}` response field; `decode_chain[explainability]`; `plugin_versions.explainability`. |
| 12 | 40+ regression tests                                                      |   ✅   | **46** unit tests + **7** API tests + 1 decode-chain test. |
| 13 | Evidence Tree: every link resolves to real Behavior + ExecNode IDs        |   ✅   | Tests `test_evidence_tree_no_dangling_behavior_ids` and `test_evidence_tree_execnode_ids_all_resolve`. |
| 14 | Confidence stages weights sum to 1.0                                      |   ✅   | Test `test_confidence_weights_sum_to_one`. |
| 15 | Confidence penalises unresolved nodes                                     |   ✅   | Semantic-reconstruction stage subtracts `min(30, 5*unresolved_count)`. Test `test_confidence_penalises_unresolved_nodes`. |
| 16 | Why-not-malicious guardrails surface `cap_applied` / `floor_applied`      |   ✅   | `WhyNotMalicious.guardrails_applied` — populated when Verdict v2 applied a cap or floor. |
| 17 | Why-not-malicious summary is one line, human-readable                    |   ✅   | Concatenates first 4 missing_signals. Test `test_wnm_summary_populated_when_applicable`. |

---

## 3 · Files Added / Modified

**Added:**
- `backend/engine/detectors/explainability.py` — 320 lines. `EvidenceLink`, `ConfidenceBreakdown`, `WhyNotMalicious`, `Explanation`, `ExplainabilityCompiler`.
- `backend/tests/rc5/unit/explainability/test_explainability.py` — 46 tests.

**Modified:**
- `backend/routers/rc5_diag.py` — imports compiler, injects `Response` param, computes explanation, adds `X-Decode-Ms` header, `plugin_versions.explainability`, `decode_chain[explainability]`, new response field `explain{}`.
- `backend/tests/rc5/api/test_diag_endpoint.py` — shape check widened for `explain`; +7 API tests covering evidence tree / confidence / why-not-malicious / narrative lock / X-Decode-Ms header.

---

## 4 · Live Verification (2026-02-21)

Payload: `echo hi` (CMD)
Response headers: `X-Decode-Ms: 0.397`

`explain.narrative`: `""` · `explain.narrative_origin`: `"advisor"`

`explain.confidence_breakdown`:
```
decode=100 · semantic=100 · behavior=100 · mitre=100 · verdict=100 · weighted_overall=100
```

`explain.why_not_malicious`:
- `applicable`: `true`
- `verdict`: `"Benign"`
- `summary`: *"Verdict Benign because no persistence installed …; no credential access …; no network activity …; no data exfiltration channel."*
- 11 `missing_signals` covering the full deterministic-taxonomy checklist.

---

## 5 · Deviations from Recommendation

None. All 17 approved items delivered. The three user-added capabilities (Why-Not-Malicious, Evidence Tree, Confidence Breakdown) are all first-class response fields — no follow-up work required for backend surface.

## 6 · Known Follow-ups (deferred)

1. **AI narrative filling** — deferred to Phase 8.5 or a runtime advisor route. The current bundle exposes the `narrative` slot and marker; wiring the Emergent-LLM advisor call to populate it (without touching deterministic fields) is a separate, small additive feature.
2. **Analyst UI consumption** — Phase 11+ (Analyst UI backlog item). The response is now schema-complete for the SOC Prime-style dashboard, Navigator JSON download, "Open in ATT&CK Navigator" button, execution-graph viz, behavior timeline, MITRE evidence drill-down, and v1↔v2 diff view.
3. **Legacy scoring path removal** — deferred to Phase 10 cutover per kill-list §13.

---

## 7 · Phase 8 Exit Criteria — Met

- [x] Evidence Tree (verdict → behavior → node → SIR → layer)
- [x] Confidence Breakdown (5 stages + weighted overall)
- [x] Why-NOT-Malicious for non-malicious verdicts
- [x] Narrative locked to `advisor` origin (§ 14 invariant)
- [x] X-Decode-Ms response header
- [x] Byte-deterministic (structural)
- [x] Immutable / frozen
- [x] Zero AI imports
- [x] 40+ regression tests (delivered 53)
- [x] Response wired into `/api/rc5/parse`

**Phase 8 complete. Ready for Phase 9 (Shadow Run + A/B Toggle).**
