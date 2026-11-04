# CAT-07 · Security Intelligence / IUE / Analysis Engines

> STRICT READ-ONLY deep-dive. Covers the **understanding plane** (IUE), the intelligence-overlay/policy plane, and — per the master reconciliation — the **UBAE/UEBA** gap.

## 1 · PRE-AG baseline (proven — this is core original NivXRay IP)

| Artifact | Evidence | Status |
|---|---|---|
| **IUE — Intelligent Understanding Engine (XDR lane)** | `backend/detection_content/xdr_iue.py`, **first added `fc33871c` (2026-08-31)**, 216 lines | IMPLEMENTED, PRE-AG |
| **IUE service package** | `backend/services/iue/` — **31 files at `5d67934e`**: `intake`, `aggregator`, `understanding`, `timeline`, `recurse`, `failure`, `security`, `tenancy`, `observability`, `_prov`, plus `lanes/`, `collectors/`, `normalizers/`, `parsers/`, `artifacts` | IMPLEMENTED, PRE-AG |
| IUE lanes A/B/C | `/api/iue/lane-a/{analyze,status}`, `/lane-b/analyze`, `/lane-c/{analyze,analyze-b64,status}`, `/api/iue/timeline/fuse` | IMPLEMENTED, PRE-AG |
| Intelligence overlays + policy | `routers/intelligence_overlay.py`, `routers/intelligence_policy.py` | IMPLEMENTED, PRE-AG |
| DIE (Deep Investigation Engine) | 22 `/api/die/*` paths incl. `/understand`, `/intent`, `/narrate`, `/timeline`, `/confidence`, `/dkp` | IMPLEMENTED, PRE-AG |
| Analysis core / reasoning | `backend/analysis_core.py`, `backend/reasoning/`, `backend/heuristics/`, `backend/learner_engine.py` | IMPLEMENTED, PRE-AG |
| Architecture docs asserting the boundary | `memory/IUE_ARCHITECTURE_V2.md`, `IUE_ARCHITECTURE_TRACE.md`, `IUE_INVESTIGATION_SSOT_RECONCILIATION.md` — all pre-AG | — |

## 2 · AG delta

| Change | Type |
|---|---|
| `backend/detection_content/xdr_iue.py` | **MODIFIED** by AG (capability PRE-AG; current content POST-AG) |
| `backend/v2/investigation/shadow_hook.py` | **ADDED** by AG |
| `backend/services/analyzers/security_controls.py` | **ADDED** by AG |
| `backend/services/artifact_intelligence/analyzers/{archive,shellcode}.py` | **ADDED** by AG |
| `backend/security_state/causal/engine.py`, `capability/engine.py`, `progression/engine.py` | **ADDED** by AG — a *new* reasoning plane, see CAT-08 |
| `backend/engine/models.py`, `backend/rc22_adapter.py` | **MODIFIED** by AG |

**AG did not create the understanding plane.** It extended analyzers and added an orthogonal reasoning plane.

## 3 · Current state (live)

**Pipeline binding (RUNTIME-PROVEN):** `xdr_pipeline.py:279` `iue = iue_understand(canonical, detection)`; stage record at `:280-287` emits `iue_id`, `entities`, `capability_tags`, `severity_hint`, `confidence`, `engine_id`.

**Ordering is deliberate and documented:** `xdr_pipeline.py:265` — *"Detection first (needed by IUE for capability_tags)"*. Detection → IUE → ICE → VEEE.

Runtime volumes: `xdr_iue_understanding` **219** · `xdr_intelligence_observations` 172 · `xdr_intelligence_overlays` 9 · `xdr_intelligence_overlay_audit` 12 · `xdr_intelligence_policy_audit` 251 · `xdr_intelligence_policy_global` 8 · `xdr_recommendations` 688 · `v2_shadow_observations` 622 · `v2_ai_jobs` 229.

| Dimension | Verdict |
|---|---|
| Implemented | ✅ deep (31-file service + XDR lane + DIE) |
| Registered | ✅ 22 `/api/die/*` + 7 `/api/iue/*` + overlay/policy paths |
| Executed | ✅ 219 understanding docs |
| Runtime-proven | ✅ pipeline `iue` stage `EXECUTED` |
| Production-ready | 🟡 — understanding is proven; **behavioural baselining is absent** |

## 4 · Industry benchmark

| Vendor | Analysis / intelligence engine |
|---|---|
| **SentinelOne** | **Purple AI Agentic Investigation** (2026-06-17 GA) — zero-click autonomous investigation, collects evidence, correlates cross-surface telemetry, emits TP/FP/Unknown with an **auditable evidence chain**; multi-model (Claude, GPT, proprietary Ultraviolet); reasons over OCSF-normalised Singularity Data Lake |
| **Cisco XDR** | Agentic AI in Incident Detail — evaluates TP/FP, constructs a threat narrative, AI summaries + attack graph + recommended response |
| **Trellix** | **Wise** — auto-correlates alerts/TTPs/breaches into graphs with machine-generated next steps; **Insights** predicts whether current countermeasures would stop an attack |
| **Cortex XDR** | **Analytics BIOCs (ABIOC)** — ML profiles tailored to the environment flag single suspicious events (this is the UEBA analogue) |
| **Microsoft** | Defender Queue Assistant ML prioritisation; Threat Analytics |
| **Splunk ES** | Risk-based alerting as the statistical analysis layer |
| **CrowdStrike** | Threat Graph analytics layer |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No UBAE / UEBA runtime** | **P1** | Explicit target in **both** PRE-AG and AG; **AG shipped spec docs only, no engine**. `/api/admin/behaviors`, `/api/behaviors/registry` exist; `v2_case_behaviors` = **0 docs**. Every benchmarked vendor ships a behavioural layer (Cortex ABIOC being the closest documented analogue) |
| No entity/environment baselining substrate | **P1** | Baselining needs retained telemetry; there is none (CAT-12). **Do not build UBAE before a real source is connected** — it would have nothing to baseline |
| No agentic/autonomous investigation loop | P2 | `/api/ai/auto-investigate`, `/api/v2/auto-investigate/jobs`, `routers/autonomous_investigator.py` exist (PRE-AG); `v2_ai_jobs` = 229. Positioning gap vs Purple AI / Cisco Agentic AI is **capability-shallow, not absent** |
| Understanding not exposed as an analyst-facing narrative in the XDR console | P2 | `/api/incidents/{id}/understanding` + `/api/narration/incident/{id}/*` exist and are not composed into a single AI-summary panel |

## 6 · Where NivXRay is ABOVE parity

- **Determinism + provenance.** `services/iue/_prov.py`, `observability.py`, `failure.py` and `tenancy.py` make understanding traceable and tenant-scoped by construction. Vendors document *outputs*; NivXRay documents *derivation*.
- **Intelligence policy plane** (`/api/intelligence/policy/{global,incident,scope}` + 251 audit docs) — per-incident, per-scope intelligence-application policy with history. No benchmarked vendor documents this level of intelligence-application governance.
- **`/api/iue/lane-*` explicit lane separation** with per-lane status — an auditable decomposition of "understanding" that vendors present as a black box.

## 7 · UNKNOWN

- U-07.1 — Whether AG's `xdr_iue.py` modification altered understanding semantics. Not claimed either way.
- U-07.2 — Whether `/api/ai/auto-investigate` currently produces investigation-grade output or is LLM-assisted narration. Requires execution.
- U-07.3 — `v2_shadow_observations` (622) and `verdict_shadow_observations` (280): whether shadow mode is currently active. Not determinable read-only.
