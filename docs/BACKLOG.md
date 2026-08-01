# NivXRay · Implementation Backlog

> **This is the ONE place to track work status. Do not generate ad-hoc "Next Action Items" in session summaries — update this file instead.**
> Read `/app/docs/architecture/README.md` first. The constitution is authoritative.

| ID | Priority | Task | Status | Notes / Blockers |
|----|----------|------|--------|------------------|
| P1-01 | P1 ⭐⭐⭐⭐⭐ | Live OSINT Wiring — X-Lab consumes Workspace's `_run_osint` (VT · AbuseIPDB · OTX · URLScan · URLhaus). 11-field IOC card. | ⏳ Pending | `/api/osint/lookup` endpoint exists (local corpus). Extend to invoke live providers. |
| P1-02 | P1 ⭐⭐⭐⭐⭐ | Verdict Parity CI — `test_verdict_parity_workspace_vs_xlab.py` on corpus. Fold `rules_hit` / `lolbas_hit` / `custom_recipes_matched` into `verdict_engine.compute_verdict()`. | ✅ Done | Shipped 2026-02-31 · 9/9 tests green. Three enforcement layers: determinism · engine-tag provenance · no-fork detection. BITS-downloader confidence gap remains (verdict engine gating unchanged) — track separately as P1-02b. |
| P1-02b | P1 ⭐⭐⭐ | Fold rules_hit / lolbas_hit / custom_recipes_matched into verdict contributors so BITS-downloader lands at Malicious. | ⏳ Pending | Requires WEIGHTS additions + gating tuning in `verdict_engine.py`. |
| P1-03 | P1 ⭐⭐⭐⭐ | Rules Lens — renderer over `cio.metadata.custom_recipes_matched`. | ✅ Done | Shipped 2026-02-31 · lens #6 · empty-state handled. |
| P1-04 | P1 ⭐⭐⭐⭐ | LOLBAS Lens — renderer over `cio.metadata.lolbas` / `lolbins_v2`. | ✅ Done | Shipped 2026-02-31 · lens #7 · empty-state handled. |
| P1-05 | P1 ⭐⭐⭐⭐ | TI-HITS Lens — renderer over `cio.metadata.ti_shield.layers`. | ✅ Done | Shipped 2026-02-31 · lens #8 · empty-state handled. |
| P1-06 | P1 ⭐⭐⭐⭐ | Manual Summary — analyst rewrites executive/story narrative · learner corpus. | ✅ Done | Shipped 2026-02-31. Endpoint `POST /api/corrections/summary-override` + `GET .../{cio_id}`. UI in Executive lens (collapsible). Writes to `analyst_corrections` (surface=`summary`) + `summary_overrides`. |
| P2-05 | P2 ⭐⭐⭐⭐⭐ | **IDI Engine — Investigation Document Intelligence.** Ingestion adapter layer for Cisco XDR / CrowdStrike / Defender / QRadar / Splunk / Sysmon / Windows Event / etc. Adapter contract: `detect() + normalise() + quality_report()`. Every quality report carries `normalization_version` + `schema_version` + three metrics (`coverage_pct` · `correctness_pct` · `completeness_pct`). NOT a parallel pipeline. See 04_INVESTIGATION_CONSTITUTION.md. | ⏳ Pending | Foundational P2 item · builds on P1-01 + P1-02. |
| P2-05a | P2 ⭐⭐⭐⭐ | Golden Corpus scaffold at `/app/backend/tests/parity/corpora/<vendor>/` — paired `input_*.json` + `expected_*.json`. 12-dimension CI check (detection · sections · entities · timeline · process hierarchy · relationship graph · TI normalisation · CIO serialisation · Executive Summary · Attack Story · verdict parity · NQR contents). | ⏳ Pending | Enables P2-05 adapters to be independently graded. |
| P2-05b | P2 ⭐⭐⭐⭐ | **Canonical Schema Stability Test (cross-vendor)** — equivalence corpora at `/app/backend/tests/parity/equivalence/<incident_id>/` with one file per vendor. CI asserts semantic parity across adapters: same host set · same primary detection · same execution chain · same ATT&CK techniques · same entity set · same verdict inputs · same verdict label · provenance-block existence. Prevents CIO from drifting toward the first-adapter shape. | ⏳ Pending | Blocks CIO drift as new vendors are added. |
| P2-05c | P2 ⭐⭐⭐⭐ | **Evidence Provenance** — every normalised entity carries `provenance = {adapter, vendor_field, raw_snippet?, raw_offset?, extraction_rule}`. Vendor content differs; block existence is universal. X-Lab Source & Evidence lenses render provenance chips + click-through to raw vendor snippet. NQR + parity CI both assert presence. | ⏳ Pending | Enables analyst traceback + cross-vendor parity governance. |
| P2-01 | P2 ⭐⭐⭐⭐ | 14-Section Executive Report Composer with `evidence_used[node_id]` per section. | ⏳ Pending | Structure locked in PRD. |
| P2-02 | P2 ⭐⭐⭐ | Report Composer multi-exporter (MD · PDF · STIX 2.1 · Navigator · JSON · Executive · Analyst). | ⏳ Pending | One template, seven exporters. |
| P2-03 | P2 ⭐⭐⭐ | Timeline Lens — renderer between Story and Behavior over `cio.reasoning_steps` + `cio.timeline`. | ⏳ Pending | |
| P2-04 | P2 ⭐⭐⭐ | Semantic Investigation Graph — typed nodes (FILE · SCRIPT · PROCESS · NETWORK · REGISTRY · USER · HOST · IOC · SERVICE · TASK · PIPE · CERTIFICATE · EMAIL · URL · DOMAIN · IP · MUTEX) + edge verbs (downloads · writes · launches · loads · injects · creates · modifies · contacts · drops · reads · deletes · beacons · executes). | ⏳ Pending | Requires backend schema change (node.object_type · edge.relation_verb). |
| P3-01 | P3 ⭐⭐⭐ | Investigation Memory — `cio.hypotheses[]` with Observation→Finding→Hypothesis→Validation→Decision→Recommendation chain. Executive Summary composes from this. | ⏳ Pending | |
| P3-02 | P3 ⭐⭐ | Investigation Completeness Score in `cio.metadata.completeness`. | ⏳ Pending | |
| P4-01 | P4 ⭐⭐ | Legacy Lab Deletion — `/lab` and `/nivxforge/investigate` redirect to `/nivxforge/x-lab`; delete every legacy Lab file. | 🚦 Blocked | Requires P1-01/02/03/04/05 green + Investigation Quality Gate green. |

## Status legend
- 🔄 In Progress — currently being implemented
- ⏳ Pending — approved, not started
- 🚦 Blocked — has explicit dependencies (listed in Notes)
- ✅ Done — shipped and verified

## Recently completed (for context)
- ✅ MDR-analyst summary composer (6 paragraphs · CIO-only · never quotes raw input).
- ✅ Universal Investigation Engine (UIE) — `/api/understand` · 17 canonical input types.
- ✅ Single INVESTIGATE button — auto-routes via UIE.
- ✅ Decoded output preview fix (fact_substrate `trace[]` fallback).
- ✅ MITRE list-shape adapter — Attack Chain lens now populates from `/decode/smart`.
- ✅ Case Spine + primary CTA beautification.
- ✅ Main navbar + branded logo restored in Lab 2.0.
- ✅ Nav rename `LAB` → `X-LAB` · new `/nivxforge/x-lab` route alias.
- ✅ NivXRay Constitution scaffolded at `/app/docs/architecture/`.
