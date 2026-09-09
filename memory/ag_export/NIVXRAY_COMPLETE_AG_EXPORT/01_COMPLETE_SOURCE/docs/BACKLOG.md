# NivXRay · Implementation Backlog

> ### 🟢 Architecture: **APPROVED · v1.0 Complete** (2026-02-31 sign-off)
> Future work executes against this backlog. No architectural expansion.
>
> ### 🚦 Every new request MUST first be classified (locked)
>
> Before touching code or opening a discussion, decide which of these four
> lanes the request belongs to:
>
> ```
> Implementation task      → Implement → Test → Measure → Merge
> Bug                      → Fix       → Test → Merge
> KPI improvement          → Optimize  → Measure → Merge
> Constitutional limitation → ADR REQUIRED (only path to a v1.1)
> ```
>
> **The Constitution is read-only** from this point forward. Do not re-open
> architectural debates for anything that fits in the first three lanes.
> Doing so is a code-review hard-fail.
>
> **Every PR must pass the four gates** (see `/app/docs/architecture/README.md`):
> 1. Preserves the CIO contract · 2. Improves a §13 KPI · 3. Adds no new layer · 4. Stays deterministic.
>
> **Every merged item MUST ship with a Completion Record** at
> `/app/docs/completions/<BACKLOG_ID>-<slug>.md` (template at
> `/app/docs/completions/TEMPLATE.md`). Objective · Implementation ·
> Tests · Golden Corpus · Parity · KPI Impact · Constitutional
> Compliance · Known Limitations.
>
> **Every release (RC / beta / GA / patch) MUST ship with a Release
> Validation Report** at `/app/docs/releases/<RELEASE>-<date>.md`
> (template at `/app/docs/releases/TEMPLATE.md`). Aggregates every
> Completion Record merged since the previous release into a single
> executive view: KPI board release-over-release · golden-corpus
> changes · parity status · constitutional compliance checklist.
>
> **Every release MUST also append one row to the KPI Trend Register**
> at `/app/docs/KPI_TRENDS.md`. Append-only. Regressions on Verdict
> Parity · Replay Determinism · Cross-vendor Equivalence are P0 bugs
> regardless of release size.
>
> **This is the ONE place to track work status. Do not generate ad-hoc "Next Action Items" in session summaries — update this file instead.**
> Read `/app/docs/architecture/README.md` first. The constitution is **FROZEN at v1.0** pending P1-01 close.
> **§10 SUPERSEDES ALL**: the CIO is the ONLY exchange contract between components. **§11**: no architectural change without a superseding ADR.

| ID | Priority | Task | Status | Notes / Blockers |
|----|----------|------|--------|------------------|
| P1-01 | P1 ⭐⭐⭐⭐⭐ | Live OSINT Wiring — X-Lab consumes Workspace's `_run_osint` (VT · AbuseIPDB · OTX · URLScan · URLhaus). 11-field IOC card. | ✅ Done | Shipped 2026-02 · shared `_osint_lookup` + `enrich_iocs` re-dispatched via `nivxforge/investigation/osint_enricher.py` · per-IOC-node 11-field cards on `attrs.enrichment.providers[]` · `cio.metadata.osint` raw bundle · 8/8 parity tests green. Completion: `/app/docs/completions/P1-01-live-osint-wiring.md`. |
| P1-02 | P1 ⭐⭐⭐⭐⭐ | Verdict Parity CI — `test_verdict_parity_workspace_vs_xlab.py` on corpus. Fold `rules_hit` / `lolbas_hit` / `custom_recipes_matched` into `verdict_engine.compute_verdict()`. | ✅ Done | Shipped 2026-02-31 · 9/9 tests green. Three enforcement layers: determinism · engine-tag provenance · no-fork detection. BITS-downloader confidence gap remains (verdict engine gating unchanged) — track separately as P1-02b. |
| P1-02b | P1 ⭐⭐⭐⭐⭐ | Tiered evidence-class verdict fold — Rules · LOLBAS · Recipes · YARA · Sigma · TI folded into `compute_verdict` via CRITICAL/HIGH/MEDIUM/LOW/CONTEXT classes + deterministic escalation rules + Noisy-OR monotonic confidence + attack-chain gating. | ✅ Done | Shipped 2026-02 · 41/41 parity + 6/6 tiered CI gates green · BITS-downloader Malicious @ 80% via escalation rule · encoded PS + IEX Malicious @ 100% · benign inputs demote correctly. Completion: `/app/docs/completions/P1-02b-tiered-verdict-fold.md`. |
| P1-02c | P1 ⭐⭐⭐⭐⭐ | Verdict engine polish (Sprints 1-4) + shellcode-parity hotfix — Graph-Aware Scoring · Temporal Correlation · Entity Correlation · Negative Evidence (MITIGATING class w=−1, cap-protected) · Dynamic Confidence Breakdown per class · Confidence Timeline · Verdict Explanation Card component · Shellcode analyzer stashed to `cio.metadata.shellcode` + synthetic CRITICAL `shellcode_detected` node + X-Lab shellcode banner. | ✅ Done | Shipped 2026-02 · 67/67 parity tests green · testing_agent_v3_fork 100% backend + frontend · MSFvenom payload with real C2 IP 149.28.81.19 → Malicious @ 100% with family/arch/size/C2 extracted in X-Lab (raw bytes suppressed). Completion: `/app/docs/completions/P1-02c-verdict-polish-plus-shellcode-parity.md`. |
| P1-02d | P1 ⭐⭐⭐⭐⭐ | Investigation Truth Model — canonical `Observation → Finding → Hypothesis → Validation → Decision → Recommendation` projection. Every downstream surface (Story · Executive Summary · Reports · Verdict · Timeline · Ledger · Notebook · Exports) reads one shape from `cio.truth`. Zero drift by construction. Plus a permanent Investigation Quality Benchmark (10-entry corpus + 8 CI-graded KPIs) at `/app/docs/benchmarks/`. | ✅ Done | Shipped 2026-02 · 74/74 parity + 2/2 benchmark tests green · BITS live E2E → 6 obs · 5 findings · 1 validated hypothesis · Decision Malicious @ 80% · 3 recs (contain/hunt/notify). Completion: `/app/docs/completions/P1-02d-investigation-truth-model.md`. |
| P1-03 | P1 ⭐⭐⭐⭐ | Rules Lens — renderer over `cio.metadata.custom_recipes_matched`. | ✅ Done | Shipped 2026-02-31 · lens #6 · empty-state handled. |
| P1-04 | P1 ⭐⭐⭐⭐ | LOLBAS Lens — renderer over `cio.metadata.lolbas` / `lolbins_v2`. | ✅ Done | Shipped 2026-02-31 · lens #7 · empty-state handled. |
| P1-05 | P1 ⭐⭐⭐⭐ | TI-HITS Lens — renderer over `cio.metadata.ti_shield.layers`. | ✅ Done | Shipped 2026-02-31 · lens #8 · empty-state handled. |
| P1-06 | P1 ⭐⭐⭐⭐ | Manual Summary — analyst rewrites executive/story narrative · learner corpus. | ✅ Done | Shipped 2026-02-31. Endpoint `POST /api/corrections/summary-override` + `GET .../{cio_id}`. UI in Executive lens (collapsible). Writes to `analyst_corrections` (surface=`summary`) + `summary_overrides`. |
| P2-05 | P2 ⭐⭐⭐⭐⭐ | **IDI Engine — Investigation Document Intelligence.** Ingestion adapter layer for Cisco XDR / CrowdStrike / Defender / QRadar / Splunk / Sysmon / Windows Event / etc. Adapter contract: `detect() + normalise() + quality_report()`. Every quality report carries `normalization_version` + `schema_version` + three metrics (`coverage_pct` · `correctness_pct` · `completeness_pct`). NOT a parallel pipeline. See 04_INVESTIGATION_CONSTITUTION.md. | ⏳ Pending | Foundational P2 item · builds on P1-01 + P1-02. |
| P2-05a | P2 ⭐⭐⭐⭐ | Golden Corpus scaffold at `/app/backend/tests/parity/corpora/<vendor>/` — paired `input_*.json` + `expected_*.json`. 12-dimension CI check (detection · sections · entities · timeline · process hierarchy · relationship graph · TI normalisation · CIO serialisation · Executive Summary · Attack Story · verdict parity · NQR contents). | ⏳ Pending | Enables P2-05 adapters to be independently graded. |
| P2-05b | P2 ⭐⭐⭐⭐ | **Canonical Schema Stability Test (cross-vendor)** — equivalence corpora at `/app/backend/tests/parity/equivalence/<incident_id>/` with one file per vendor. CI asserts semantic parity across adapters: same host set · same primary detection · same execution chain · same ATT&CK techniques · same entity set · same verdict inputs · same verdict label · provenance-block existence. Prevents CIO from drifting toward the first-adapter shape. | ⏳ Pending | Blocks CIO drift as new vendors are added. |
| P2-05c | P2 ⭐⭐⭐⭐ | **Evidence Provenance** — every normalised entity carries `provenance = {adapter, vendor_field, raw_snippet?, raw_offset?, extraction_rule}`. Vendor content differs; block existence is universal. X-Lab Source & Evidence lenses render provenance chips + click-through to raw vendor snippet. NQR + parity CI both assert presence. | ⏳ Pending | Enables analyst traceback + cross-vendor parity governance. |
| P2-05d | P2 ⭐⭐⭐⭐⭐ | **Deep Command Investigation** — every IDI adapter that discovers an embedded command line (Cisco XDR `command_line`, Sysmon EventID 1 CommandLine, Defender `processCommandLine`, PowerShell -EncodedCommand, script contents, etc.) MUST recursively feed it back into the smart-decoder + IOC-extractor + MITRE mapper. Analysts never copy/paste into CyberChef. Adapters that stop at "found a command" fail the Investigation Quality Gate. | ⏳ Pending | Blocked by P2-05. |
| P2-06 | P2 ⭐⭐⭐⭐ | **Evidence Correlation Engine (ECE)** — replaces event-based correlation with evidence-chain correlation: `PowerShell downloader + DNS lookup + Downloaded file + SHA256 in VT + Registry Run Key → Attack Story`. Deterministic reasoning over the evidence graph — includes temporal, causal, process-ancestry, enrichment, confidence-propagation, and evidence-weighting relationships. Called ECE internally (not "CRE++") to avoid QRadar association. | ⏳ Pending | Follows P2-05d. |
| P2-07 | P2 ⭐⭐⭐⭐ | **Recursive Investigation Queue** — every newly discovered artefact (URL / hash / script / command / archive / DLL / registry key / task / service / memory blob) enters a FIFO queue with dedup by artefact hash. Prevents infinite recursion, enables parallel execution later, keeps investigation deterministic and resumable. | ⏳ Pending | Blocks P2-05d + P2-07b (bundle upload). |
| P2-07b | P2 ⭐⭐⭐ | **Investigation Budget** — deterministic execution caps enforced per investigation: `max_recursion_depth=10 · max_decoded_artifacts=500 · max_urls=200 · max_ps_decodes=50 · max_wall_time=30s`. Overrun records a `budget_exhausted` warning in the Investigation Ledger and stops the queue gracefully — never crashes. Protects against pathological / adversarial inputs. | ⏳ Pending | Blocked by P2-07. |
| P2-08 | P2 ⭐⭐⭐⭐⭐ | **Investigation Ledger** — every reasoning step (adapter chosen · decoder applied · IOC extracted · MITRE mapped · verdict contributor added) recorded to `cio.metadata.investigation_ledger[]` with `{step_no, actor, input, output, evidence_ids, wall_ms}`. Answers "why did X-Lab conclude this?" for analyst · audit · debug. New Ledger Lens surfaces it. | ⏳ Pending | Foundational for explainability. |
| P2-09 | P2 ⭐⭐⭐⭐⭐ | **Investigation Package (Evidence Bundle)** — analyst uploads a bundle (Cisco XDR + Sysmon EVTX + Windows Security EVTX + Linux syslog + firewall logs + PCAP metadata + memory artefacts + threat-intel exports + IOC lists + analyst notes). Universal Detection Engine fans out per file, all outputs merge into ONE unified CIO. This is the final step to full enterprise investigation platform. | ⏳ Pending | Requires P2-05..08 first. |
| P2-10 | P2 ⭐⭐⭐⭐ | **Universal Investigation Ingestion (Phase 1)** — ship Adapters for: Windows Event Logs (.evtx) · Sysmon · Syslog (RFC3164/5424) · JSON/NDJSON · Cisco XDR · Defender XDR · CrowdStrike · SentinelOne. Each with its own golden corpus + cross-vendor equivalence corpus + Normalization Quality Report + provenance blocks. See §8 of 04_INVESTIGATION_CONSTITUTION.md. | ⏳ Pending | Sequenced roadmap · Phase 2/3/4 tracked separately. |
| P2-11 | P2 ⭐⭐⭐⭐⭐ | **Investigation State Machine** — every CIO carries `metadata.state` traversing `NEW → DETECTED → INGESTING → NORMALIZING → INVESTIGATING → CORRELATING → REASONING → READY → ANALYST_UPDATED → CLOSED`. Modules only execute in the correct state. Illegal transitions raise + log to Ledger. Persistent · resumable · distributable · auditable. | ⏳ Pending | Enables distributed execution and orchestration. |
| P2-12 | P2 ⭐⭐⭐⭐ | **Adapter Capability Registry** — `AdapterRegistry.register(adapter, supports[], priority, confidence_floor, version, dependencies, quality_floor)`. The Universal Detection Engine queries the registry instead of using hardcoded branches. Adapters become plug-ins. | ⏳ Pending | Prerequisite for scaling to hundreds of adapters. |
| P2-13 | P2 ⭐⭐⭐⭐⭐ | **Investigation Replay Engine** — read-only over the Investigation Ledger (P2-08). Step-by-step reconstruction of reasoning (Adapter → Decoder → Enrichment → Correlation → Verdict). Deterministic on identical inputs. Surfaced as a new **Replay Lens** in X-Lab. Enables training · validation · debugging · demos · audits. | ⏳ Pending | Blocked by P2-08 (Ledger). |
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
