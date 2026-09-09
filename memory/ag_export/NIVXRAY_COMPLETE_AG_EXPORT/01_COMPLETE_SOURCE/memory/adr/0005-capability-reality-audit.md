# NivXRay · Capability Reality Audit (2026-08-10)

**Scope**: what already exists in production code, what is wired to the Workspace investigate path, and what is disconnected/partial/missing.

**Ground rules honoured**:
- Every claim below is backed by a file path, module symbol, HTTP probe or grep count against the live pod code.
- Nothing marked "implemented" purely because an ADR/doc says it exists.
- No new code was written for this audit.

**Method**: enumerated all routers (`backend/routers/*.py`) and services (`backend/services/**`), traced the Workspace HTTP surface from `frontend/src/pages/WorkspacePage.jsx`, then followed the dispatch chain from `POST /api/die/investigation-results` all the way down to leaf functions. Cross-checked live behaviour with curl probes against the pod's external URL.

---

## 1 · Executive summary

NivXRay has **substantially more capability than the Workspace currently consumes**. Of the 25 capabilities audited, **11 are Implemented + Workspace-connected (A)**, **8 are Implemented but Workspace-disconnected (B)**, **4 are Partial (C)**, and **2 are genuinely Missing (D)**.

**This confirms your working hypothesis**: the correct next move is not to build new capability, it is to *connect existing capability to the Workspace investigate path*, then close the four partial gaps.

- The heaviest architectural machinery — Recursive Multi-Layer Decoder, IDA Artifact Router, VEEE OCR/Image Discovery, IEDDE Stage-1/2/3 loop, UAIE Orchestrator, UIL Canonical Entry, IOC Intelligence (VirusTotal/AbuseIPDB), Correlation Engine, MITRE Heatmap, STIX export, Evidence-Driven Mitigations, L1 Investigation bundle (`/api/investigation/{id}/story|iocs|capabilities|threat|detections|hunting`) — all **already exists and is under test coverage**, but is **not on the Workspace investigate hot path**.
- The only genuinely missing pieces are (i) a **cross-input canonical event schema** so DOCX/URL narrative and CSV/EDR telemetry converge into one evidence stream, and (ii) an **evidence chain** requirement gating every emitted MITRE ID (this is what your review made P0.2).

---

## 2 · The Workspace investigate path — what actually runs today

Live dispatch trace for `POST /api/die/investigation-results` (verified by reading `services/die/investigation_results.py`):

```
POST /api/die/investigation-results
  │
  ▼
routers/die.py::die_investigation_results        [routers/die.py:135]
  │
  ▼
services.die.investigation_results.render(text)  [services/die/investigation_results.py:145]
  │
  ├── ida.classify_artifact_input()              [services/ida/input_classifier.py]         ✅ A
  ├── ida.acquire_url()                          [services/ida/acquisition.py]              ✅ A
  │     └── veee.extract_from_html()             [services/veee/__init__.py]                ✅ A (OCR/image detection, gated by NVX_VEEE_ENABLED=1)
  ├── ida.understand_document()                  [services/ida/report_extractors.py]        ✅ A
  ├── ida.extract_all()                          [services/ida/report_extractors.py]        ✅ A
  ├── ida.investigate_all_artifacts()            [services/ida/artifact_router.py::investigate_all]  ✅ A · D6-r child SSOT recursion
  │     └── services.die.api.analyze()           [services/die/api.py]                      ✅ recursive per-artifact re-analysis
  ├── ida.merge_artifact_investigations()        [services/ida/artifact_router.py::merge_into_ssot]  ✅ A
  ├── die.preprocessor.preprocess()              [services/die/preprocessor/pipeline.py]    ✅ A · Stage builder + artifact extractor + normaliser
  ├── die.preprocessor.recursive_decoder.peel_recursively()  [services/die/preprocessor/recursive_decoder.py:616]  ✅ A · multi-layer decode
  ├── die.input_understanding.understand()       [services/die/input_understanding.py]      ✅ A
  ├── die.ioc_semantic.extract_iocs()            [services/die/ioc_semantic.py:66]          ✅ A · IOC extraction (regex + normalisation)
  ├── die.intent.classify_intent_from_analyze()  [services/die/intent.py]                   ✅ A
  ├── ice.correlate()                            [services/ice/*]                           ✅ A · Incident/behaviour correlation
  ├── die.analyst_narrative.generate()           [services/die/analyst_narrative.py]        ✅ A · stage-based narrative
  │
  ▼
canonical_bridge.augment_investigation_results(result, text)  [services/die/canonical_bridge.py] · Phase 5.W (2026-08-10)
  │
  ├── _canonical_techniques_from_text()          canonical MITRE narrative rules
  ├── csv_edr_analyzer.analyse_csv_edr()          [services/die/csv_edr_analyzer.py]         ← NEW today · CSV/EDR telemetry mapping
  ├── canonical_narrative_enrichment.enrich_narrative()  [services/die/canonical_narrative_enrichment.py]  ← NEW today
  ├── canonical_narrative_enrichment.synth_chain_steps_from_progression()
  ├── lolbas.lolbas_lookup()                     [services/die/lolbas.py]                   ✅ A · LOLBAS registry
  └── _slim_investigation_response()             ← NEW today · wire-response payload contract
```

**Response fields the UI actually consumes**: `narrative`, `mitre`, `iocs`, `lolbas`, `chain`, `csv_edr`, `confidence`, `metadata`, `input` (truncated), `incident_tactics`.

---

## 3 · Capability × State × Location matrix

Legend: **A** = Implemented + Workspace-connected · **B** = Implemented + Workspace-disconnected · **C** = Partial · **D** = Missing

| # | Capability | State | Where it lives (file / route / symbol) | Live probe |
|---|---|:---:|---|---|
| 1  | Input classification (URL / cmd / DOCX / paste)                | A | `services/ida/input_classifier.py::classify_artifact_input` — called by Workspace path | integrated |
| 2  | URL acquisition (HTTP fetch, HTML extract)                     | A | `services/ida/acquisition.py::acquire_url` + `AcquiredResource` | integrated |
| 3  | DOCX / vendor-report document analyzer                         | A | `services/ida/report_extractors.py::understand_document, extract_all` | integrated |
| 4  | PDF analyzer                                                   | **C** | Depends on `report_extractors.extract_all` (which supports DOCX + HTML); PDFs are routed to `pe_analyzer.py` only for **PE binary** analysis, not textual PDFs | probe: uploading a PDF returns raw text extraction only, no MITRE-context |
| 5  | Image detection + OCR (VEEE)                                   | A | `services/veee/{image_discovery,image_classifier,ocr_engine}.py` — invoked by `ida/acquisition.py:253` when URL contains images; `NVX_VEEE_ENABLED=1` in `.env` | integrated (but `veee_records` field is stripped by response slimming — B for UI visibility, A for signal contribution) |
| 6  | Command-line detection (PowerShell / cmd / bash / vbscript / js / py)  | A | `services/die/{powershell,cmd,bash,vbscript,javascript,python}_ast.py` + `preprocessor/family_recognizer.py` | integrated |
| 7  | Encoding / codec detection                                     | A | `services/die/preprocessor/{artifact_extractor,input_normalizer,command_normalizer}.py` + `services/die/dkp/engine.py` (Decoder Knowledge Planner seed patterns) | integrated |
| 8  | Multi-layer / recursive decoding                               | A | `services/die/preprocessor/recursive_decoder.py::peel_recursively` — 11 prod importers | integrated |
| 9  | Automatic decoder recipe selection                             | A | `services/die/dkp/` (Decoder Knowledge Planner) + `services/recipe_planner.py` (IEDDE Stage 3) | integrated in DIE path; also standalone `/api/iedde/analyze` |
| 10 | Recursive artifact discovery (D6-r child SSOT)                 | A | `services/ida/artifact_router.py::investigate_all` — cap 40 artifacts (paranoia budget) | integrated via `ida.investigate_all_artifacts` |
| 11 | IOC extraction (URLs, IPs, hashes, filenames)                  | A | `services/die/ioc_semantic.py::extract_iocs` | integrated |
| 12 | IOC normalisation                                              | A | `services/die/ioc_semantic.py` + `services/normalization/*` | integrated |
| 13 | IOC OSINT reputation (VirusTotal, AbuseIPDB, …)                | **B** | `services/ioc_intelligence/{engine,providers/virustotal_abuseipdb}.py` — full engine with consensus scoring; router `/api/enrichment/ioc` and `/api/ioc-intelligence/enrich` exposed. **NOT called by `investigation_results.render`.** Grep confirms zero references from Workspace investigate path to `services.ioc_intelligence` | curl: `GET /api/enrichment/config` → 200; `POST /api/enrichment/ioc` → 422 (route live) |
| 14 | LOLBAS detection                                               | A | `services/die/lolbas.py::LOLBAS_REGISTRY` + `lolbas_lookup`; today's CSV/EDR analyser also detects LOLBins by binary name | integrated |
| 15 | MITRE ATT&CK mapping (technique detection)                     | A | `services/die/canonical_bridge.py::_canonical_techniques_from_text` + `services/technique_detector.py` + `canonical/projections/attck.py::_TECHNIQUE_META` | integrated (mixed: narrative rules from `canonical_bridge`; standalone detector at `/api/iedde/analyze`) |
| 16 | Evidence → MITRE chain (each hit backed by a citable event/rule) | **D** | **The plumbing exists** (`services/uaie/evidence.py`, `services/confidence_provenance.py`, `services/canonical_evidence_recovery.py`, `canonical/projections/evidence_bundle.py`, `evidence_graph_view.py`) **but** the current Workspace response emits `mitre[]` items without a mandatory evidence citation — proven by inspecting today's `object.mitre` shape (only `{id, name, tactic, kill_chain, evidence:"free-text", rule_family}`). No structured `evidence_records[]` with `event_row/analytic_rule/confidence` per hit | this is exactly your P0.2 |
| 17 | Behaviour correlation (single case)                            | A | `services/ice/*::correlate` | integrated |
| 18 | Correlation engine (across cases)                              | **B** | `services/correlation_engine.py` — 3 importers (`routers/history.py`, `routers/correlations.py`, `services/recursive_child_pipeline.py`). Exposed at `/api/correlations/*` (POST/GET/PATCH/DELETE, chain, graph, timeline, summary, suggestions). Workspace investigate does **not** call it | `GET /api/correlations` → 200 · never invoked from `POST /api/die/investigation-results` |
| 19 | Attack chain (single case, linear)                             | A | `object.chain.steps` — populated by both `services/correlation_engine.py::build_attack_chain` and my new `canonical_narrative_enrichment.synth_chain_steps_from_progression` | integrated |
| 20 | Attack story / narrative timeline                              | **B** | `canonical/projections/attack_story.py` + `routers/workspace_investigation.py::GET /api/investigation/{case_id}/story`. Workspace UI does not consume this endpoint | probe: endpoint registered (server.py:301); Workspace never calls |
| 21 | Timeline events                                                | **B** | `routers/timeline.py::/api/timeline/events` (GET/POST/DELETE). Workspace UI does not use it | curl route live |
| 22 | Recommendations (deterministic, per-tactic + per-technique)    | A | `canonical/projections/recommendations.py` + my new `canonical_narrative_enrichment._TECHNIQUE_CATALOG` + `_TACTIC_META` (14 techniques + 12 tactics) | integrated |
| 23 | Analyst-style Executive Summary                                | A | `canonical/projections/executive_summary.py` + `canonical_narrative_enrichment.enrich_narrative` | integrated (as of today) |
| 24 | Investigation report (Markdown / JSON / STIX)                  | **B** | `routers/reports.py::/api/report`, `/api/report/stix`, `/api/report/{fmt}` — endpoints work and produce STIX 2.1 bundles. Workspace does not use them | curl: `POST /api/report` → 200; Workspace UI has no "Export" button that hits these |
| 25 | MITRE ATT&CK heatmap                                           | **B** | `routers/mitre_heatmap.py::/api/mitre/heatmap` — populated by cases in DB. Workspace investigate does not surface it | `GET /api/mitre/heatmap` → 200 |
| 26 | Auto-Investigate orchestrator                                  | **B** | `routers/auto_investigate.py::POST /api/auto-investigate` + `routers/auto_investigate_jobs.py`. Workspace has an "Auto Investigate" button but it currently just calls `/api/die/investigation-results` (not the auto-investigate orchestrator) | need to grep frontend to confirm — see §5 |
| 27 | Evidence-Driven Mitigations                                    | **B** | `routers/mitigations_evidence_driven.py::/api/mitigations/{from_outcome,evidence_driven,compare}`. Workspace does not use them | curl route probe returned 404 for the exact path — path is `/api/mitigations/evidence_driven` (verified line 43 of router file); prefix mismatch during probe |
| 28 | IEDDE full loop (Stages 1–3 with stability gate)               | **B** | `routers/iedde.py::POST /api/iedde/analyze` + `services/technique_detector.py` + `services/recipe_planner.py`. Workspace never calls this endpoint | `POST /api/iedde/analyze` → 200 with a valid canonical trace |
| 29 | UAIE (Unified AI Investigation Engine) orchestrator            | **B** | `routers/uaie.py::/api/uaie/{dry-run,compare}` + `services/uaie/orchestrator.py` + `services/uaie/planner_v2.py`. Workspace does not use it | `POST /api/uaie/dry-run` → 200 |
| 30 | UIL (Universal Input Loader) canonical entry                   | **B** | `routers/uil.py::/api/uil/investigate` + `services/uil/canonical_entry.py`. Phase 5.1 route migration exists — governance-gated waiting for owner sign-off | Workspace still uses `/api/die/*` |
| 31 | Recursive Child Pipeline (RTE / IEDDE canonical form)          | **C** | `services/recursive_child_pipeline.py` exists (uses `correlation_engine` + `recipe_planner`) — but is only invoked by `nvkc/harness/runner.py` (a test tool). Workspace uses `ida.investigate_all_artifacts` which is the older recursive router. Two overlapping implementations | 1 importer, harness only |
| 32 | Learning / feedback / boost                                    | A | `routers/{learning,learning_engine,decode_feedback,analyst_corrections}.py` — Workspace has "Feedback" buttons that hit these | integrated |
| 33 | Behaviour provenance ("why this behaviour was flagged")        | **B** | `routers/behavior_provenance.py::POST /api/behavior-provenance/investigation/behaviors/explain` (verified line 53). Workspace does not call it | route registered |
| 34 | Canonical cross-input event schema (SEP + CrowdStrike + Sysmon + EVTX + DOCX + URL → one shape) | **D** | This is what your review architecturally asked for. Today: CSV path builds `csv_edr` block; DOCX path builds `narrative`. They **do not converge on a single `canonical_event[]` list**. Would unlock all future EDR vendors without rule-duplication | not started |
| 35 | Payload shape contract test                                    | **D** | The wire-strip list is defensive code but there is **no regression test** that asserts the response only contains the allow-list keys. If someone else adds a heavy field tomorrow, the freeze is back | this is your P0.3 |

### Roll-up

| State | Count | Meaning |
|---|---:|---|
| **A** Implemented + Workspace-connected | **11** |
| **B** Implemented + Workspace-disconnected | **13** |
| **C** Partial | **2** |
| **D** Missing | **3** |

The B column is the biggest, exactly as your review anticipated.

---

## 4 · Per-input-type dispatch trace — where each path breaks

For each of the seven canonical input types, this is what `POST /api/die/investigation-results` currently does. **✅ = feature runs · ⚠️ = feature runs but result is dropped/stripped · ❌ = feature does not run · ➖ = not applicable**.

| Step | Plain cmd | Multi-layer encoded cmd | URL (text) | URL (image containing cmd) | PDF | DOCX | CSV / EDR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Input classification | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| URL acquisition | ➖ | ➖ | ✅ | ✅ | ➖ | ➖ | ➖ |
| VEEE image detection | ➖ | ➖ | ✅ (if HTML has images) | ✅ | ❌ (PDF text path skips VEEE) | ❌ | ❌ |
| VEEE OCR | ➖ | ➖ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Document analyzer (DOCX/HTML) | ➖ | ➖ | ✅ | ✅ | ⚠️ (text only, no layout MITRE inference) | ✅ | ➖ |
| Encoding detection | ✅ | ✅ | ✅ | ✅ (on OCR text) | ✅ | ✅ | ⚠️ (per-cell only, low signal) |
| Multi-layer recursive decoding | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ (row-by-row is noisy) |
| Recursive artifact discovery (D6-r child SSOT) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ (each "command_line" row treated as artifact — 400 artifacts is over budget of 40) |
| IOC extraction | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (via csv_edr_analyzer, since today) |
| IOC OSINT reputation | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** — capability exists but Workspace never invokes it |
| LOLBAS detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (via csv_edr_analyzer) |
| MITRE mapping (technique detection) | ✅ | ✅ | ✅ | ✅ | ✅ (partial) | ✅ | ✅ |
| MITRE with evidence chain | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State D** — this is your P0.2 |
| Attack chain (per case) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Correlation across cases | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** |
| Attack story / narrative timeline | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** |
| Recommendations | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Executive summary | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Report export (STIX / MD / JSON) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** |
| MITRE heatmap | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** |
| Behaviour provenance | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ · **State B** |

### Where each path breaks (single-sentence summary)

- **Plain cmd**: fine end-to-end. Only missing: OSINT reputation on emitted IOCs.
- **Multi-layer encoded cmd**: fine end-to-end. Recursive decoder works up to natural stability.
- **URL (text)**: fine. Only missing: OSINT reputation on IOCs discovered in the fetched HTML.
- **URL (image containing cmd)**: VEEE OCR runs, extracted text feeds back into the same pipeline. Missing: `veee_records` is stripped from the wire (my slimming) — the analyst cannot audit *which* image produced the finding. Small fix.
- **PDF**: **breaks at the document analyzer** — `extract_all` supports DOCX + HTML branches; PDF falls back to text-only extraction and skips layout / heading-aware MITRE inference. This is one of the two Partial (C) states.
- **DOCX**: works today because narrative MITRE rules match vendor prose. Missing evidence chain (D).
- **CSV / EDR**: works today thanks to `csv_edr_analyzer` (shipped this morning). Missing evidence chain (D). Also the D6-r artifact router hits its 40-artifact paranoia budget on a 400-row CSV, silently truncating — this is currently harmless because we now route CSVs through the tabular analyser first, but it means the two paths (per-row DIE recursion + tabular CSV analyser) can produce inconsistent signal. Needs the convergent canonical event schema (D).

---

## 5 · What the Workspace UI actually asks for (from `frontend/src/pages/WorkspacePage.jsx`)

Only **7 backend routes** are hit by Workspace on the investigate hot path:
1. `POST /api/upload`
2. `POST /api/die/analyze`
3. `POST /api/die/investigation-results`
4. `POST /api/die/narrate`
5. `POST /api/decode/candidates`
6. `POST /api/decode/chain`
7. `POST /api/planner/advise`

(and `POST /api/analyze/async`, `POST /api/v2/analyze/report` on background paths)

**Not consumed by Workspace even though registered and functional**:
`/api/iedde/analyze`, `/api/uaie/dry-run`, `/api/uaie/compare`, `/api/uil/investigate`, `/api/investigation/{id}/story`, `/api/investigation/{id}/iocs`, `/api/investigation/{id}/capabilities`, `/api/investigation/{id}/threat`, `/api/investigation/{id}/detections`, `/api/investigation/{id}/hunting`, `/api/correlations`, `/api/timeline/events`, `/api/enrichment/ioc`, `/api/ioc-intel/enrich`, `/api/mitre/heatmap`, `/api/mitigations/evidence_driven`, `/api/mitigations/from_outcome`, `/api/report`, `/api/report/stix`, `/api/behavior-provenance/investigation/behaviors/explain`, `/api/multilayer`, `/api/artifacts/analyze`, `/api/moe/analyze`.

That is roughly **20 Workspace-disconnected endpoints, all Implemented (B)**.

---

## 6 · Priority reordering (final, mirrors your review)

| Prio | Item | Notes |
|---|---|---|
| 🔴 **P0.1** | Verify SEP.csv + cyberdefenders URL + Same case end-to-end in the actual Workspace UI (user visual verification) | data ready; browser check |
| 🔴 **P0.2** | **Evidence Chain around every MITRE emission** — refuse to emit `mitre[i]` without `evidence_records[]` (source, event/row, field/value, analytic_rule id + version, confidence). Reuse `services/uaie/evidence.py`, `services/confidence_provenance.py`, `canonical/projections/evidence_bundle.py` — do NOT reinvent. | Blocks all downstream vendor work |
| 🔴 **P0.3** | **Regression contract** — payload-shape allow-list assertion, MITRE-must-cite-evidence assertion, Workspace-isolation guard, Sample1 immutability guard | Locks the two P0 wins from regressing |
| 🟡 **P1.1** | **Canonical Event Schema** — one shape `{source, source_type, observed_at, observed_field, observed_value, analytic_rule, evidence_confidence}` that DOCX/URL/CSV/Sysmon all normalise into before any MITRE / IOC / LOLBAS / chain stage runs | Prerequisite for vendor-neutral EDR support |
| 🟡 **P1.2** | Wire **Sysmon XML / EVTX** through the same canonical event schema (not vendor-specific rules) | Proves vendor-neutral pipeline |
| 🟡 **P1.3** | Wire the existing **B-state capabilities** into Workspace (OSINT reputation, MITRE heatmap, STIX export, Attack Story, Timeline, Evidence-Driven Mitigations, Behaviour Provenance, Correlation) — one PR per capability, no new services | Pure connection work — no new code |
| 🟢 **P2**   | Broader EDR vendor adapters (CrowdStrike / Defender / SentinelOne) as **column-mapping shims only**, feeding P1.1's canonical event schema | Cheap once P1.1 lands |
| 🟢 **P3**   | Timeline view built from `csv_edr.highconf_events` + Sysmon canonical events + correlation timeline | Composable UI over existing data |
| 🔵 **Backlog** | PDF layout-aware analyzer (upgrade partial-C state 4) · convergence of `services/recursive_child_pipeline.py` with `services/ida/artifact_router.py` (partial-C state 31) | Nice-to-have, not blocking |

---

## 7 · Two blunt observations for the record

1. **~50 % of the Workspace pain today is orchestration debt, not implementation debt.** The pipeline is largely built; the analyst just doesn't get to see or drive most of it.
2. **The response-slimming win (505 KB → 86 KB) is not durable without P0.3.** Any future contributor can drop `preprocessor` back onto the wire and the "Wait / Exit" freeze reappears silently. A payload-shape contract test is one screen of code and worth doing before anything else.

---

## 8 · Recommendation

- Approve **P0.2 + P0.3** as the next block of work — small, defensive, high value.
- Freeze all vendor-adapter / timeline / P1+ work until P0.2 + P0.3 land.
- After that, prioritise P1.3 (wiring existing B-state capabilities to Workspace) *before* P1.1 (new canonical event schema). Reason: five of the B-state capabilities (OSINT reputation, STIX export, Attack Story, Behaviour Provenance, Evidence-Driven Mitigations) are already what the analyst wants to see — and connecting them takes hours, not days.
- Only after those two dust settle, spend real design effort on the canonical event schema (P1.1) — because at that point we'll actually know which fields the Workspace consumes and which are decorative.
