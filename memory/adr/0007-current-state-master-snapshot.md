# NivXRay — 360° Current-State Master Snapshot

**Version**: Session-8 (2026-08-11) · supersedes the Session-7 compact snapshot below §100.
**Method**: Read-only. Every claim below cites a file, route, DB collection, config value, test, or runtime probe captured during this session. Nothing is inferred.
**Legal status of this document**: **not a roadmap.** It is the authoritative technical truth of NivXRay as it exists at this timestamp. Any decision — build, freeze, sell, deprecate, sign an SoW — should be traceable back to a line in this file.

Status vocabulary (used throughout, per owner directive):

- **IMPL+CONNECTED**  — code exists, wired end-to-end, exercised by a runtime consumer, backed by a passing test.
- **IMPL+DISCONNECTED**  — code exists but no runtime consumer OR gated behind a `shadow`/`off` flag OR persisted collections are empty.
- **BACKEND ONLY** — backend route/module exists; frontend never calls it.
- **FRONTEND ONLY** — UI component exists but calls no live backend or hits a 404/501.
- **PARTIAL**  — one branch works, another is stubbed / returns 501 / silently no-ops.
- **EXPERIMENTAL**  — Rn/Phase-x/shadow scaffolding; explicitly labelled non-authoritative in source.
- **MOCK/DEMO**  — populated from a static file / fixture, not from a live pipeline.
- **BROKEN**  — endpoint or path fails a smoke test or contradicts its own docs.
- **DEAD/UNUSED**  — code shipped, never imported by the running app.
- **PLANNED**  — mentioned in docs/ADRs/comments but no code path.
- **UNKNOWN**  — could not be verified in this session; flagged for a future audit.

---

## §1 · Executive Snapshot (one page)

**What NivXRay actually IS today, based on evidence:**

A single-tenant, browser-based **command-line + narrative + tabular-EDR analyst Workspace** whose real revenue-shaped capabilities are:

1. **Evidence-gated MITRE mapping** for pasted PowerShell / CMD / VBScript / JavaScript / Bash / Python inputs and small vendor-report / DOCX text (P0.2 chain — 30 tests locking `{source, event_or_rule, field, observed_value, evidence_ref}` on every technique).
2. A **Timeline projection** and **Query/Hunt projection** over the canonical event bag, both read-only and additive.
3. A **14-lane MITRE Attack-Chain diagram** with deterministic tactic-lane assignment.
4. An **SEP-shape CSV/EDR analyzer** — 3-column heuristic → 5 MITRE + 5 highconf events for `Sample.docx`-family SEP exports.
5. An **Analyst Practice Lab** (`/api/lab/*`) with challenges, attempts, leaderboard.
6. An **Emergent-LLM narrate** path (`object.narrative` populated per investigation).
7. A **Threat-Intel feed sync** subsystem (OTX / AbuseIPDB / URLhaus / ThreatFox / MalwareBazaar / MalwareBytes / Talos / CINS Army) with 65,614 IOCs stored (`iocs` collection).

**What NivXRay actually IS NOT today, based on evidence:**

- Not an EDR, XDR, or SIEM. Zero live Sysmon, Defender, CrowdStrike, SentinelOne, Splunk, Sentinel, Elastic, or QRadar adapter — the code that *would* ingest them (`v2/routers/ingest.py`) is behind `NIVX_FLAG_ADAPTERS=shadow` and the EVTX handler explicitly returns **HTTP 501** ("EVTX ingest ships in R2.5.1").
- Not a live "Knowledge-Graph-first" platform. The IKG code (`backend/v2/investigation/ikg.py`) is fully written, but every v2 collection that would persist it (`v2_case_behaviors`, `v2_case_entities`, `v2_case_events`, `v2_case_relationships`, `v2_case_reports`) has **0 documents** at the time of this audit — the whole v2 pipeline is `shadow` mode.
- Not a Verdict-Engine-v3 authoritative product. `NIVX_FLAG_VERDICT_ENGINE_V3=shadow` — the shipping verdict is the canonical projection `backend/canonical/projections/verdict.py`, a simpler 4-weight linear scorer. Verdict Engine v3 has 2 rows in `verdict_shadow_observations` and 563 in `v2_shadow_observations` — sampling only.
- Not a large-input analysis platform. Client-side caps of **32 KB** (Auto-Viz panels) and **256 KB** (upload) plus a **512 KB** default body-cap in `RequestHardeningMiddleware` are the current large-input safety story. There is no server-side file-mode.

**Strongest capability:** P0.2 evidence chain — every emitted MITRE technique carries traceable evidence or is rejected. This is genuinely differentiating.

**Weakest capability:** ingestion. The platform can only reason about what an analyst pastes into a box or uploads as ≤ 256 KB.

**Highest-leverage architectural fact:** *There are two parallel pipelines living in the same repo* — the RC5-canonical pipeline that ships (used by `/api/die/*`) and the v2/IKG pipeline that observes-only (used by `/api/v2/*`). Almost every "gap" surfaces from this duality.

---

## §2 · Capability Reality Matrix

| # | Capability | Status | Evidence (file · route · test · DB · flag) |
|---|---|---|---|
| 1 | JWT auth + admin seed | IMPL+CONNECTED | `backend/deps.py` L241-331 · `POST /api/auth/login` · `bcrypt` hash · `test_credentials.md` verified |
| 2 | P0.2 evidence-chain enforcement | IMPL+CONNECTED | `services/die/mitre_evidence_chain.py` · `tests/canonical/api/test_p02_evidence_chain.py` (30 tests) |
| 3 | P0.3 payload / Sample1 / X-Lab firewall | IMPL+CONNECTED | `test_investigation_results_payload_shape.py`, `test_sample1_immutability_guard.py`, `test_workspace_isolation_guard.py` |
| 4 | Timeline MVP | IMPL+CONNECTED | `services/die/timeline_projection.py` · `POST /api/die/timeline` · `TimelinePanel.jsx` · `test_die_timeline.py` (16 tests) |
| 5 | Query/Hunt + Auto-Viz | IMPL+CONNECTED | `services/die/query_hunt.py` · `POST /api/die/query` · `QueryHuntPanel.jsx` · `test_die_query_hunt.py` (45 tests) |
| 6 | Attack Chain 14-lane view | IMPL+CONNECTED | `frontend/src/components/investigation/TrajectoryDiagram.jsx` · `_synthBehaviorsFromMitre` · `trajectoryLaneAssignment.test.mjs` |
| 7 | CSV EDR analyzer (SEP-shape) | IMPL+CONNECTED | `services/die/csv_edr_analyzer.py` · fixtures under `test_csv_edr_investigation.py` |
| 8 | CSV EDR analyzer (Splunk `_raw` JSON) | NOT-IMPLEMENTED | 44 KB Splunk export → `object.csv_edr` empty (proven in Session-7) |
| 9 | Sysmon / EVTX ingestion | PARTIAL (501) | `POST /api/v2/ingest/evtx` returns 501 · `v2/routers/ingest.py` L274-281 |
| 10 | Multi-format ingest (JSON/NDJSON/CSV/Syslog/Webhook) | IMPL+DISCONNECTED | 6 routes `POST /api/v2/ingest/{json,ndjson,csv,syslog,webhook}` gated by `NIVX_FLAG_ADAPTERS=shadow`, no frontend caller |
| 11 | CrowdStrike / Defender / SentinelOne / Cisco XDR / Splunk / Sentinel / Elastic / QRadar | NOT-IMPLEMENTED | No route, adapter, or client module. Corpus training data references vendor formats but no live pipeline. |
| 12 | STIX 2.1 bundle export | PARTIAL | `backend/stix_export.py` + `v2/report/stix.py` · `GET /api/v2/cases/{id}/report.stix.json` exists · connectivity to workspace path unverified this session |
| 13 | TAXII 2.1 push (admin) | IMPL+CONNECTED | `routers/taxii.py` + `backend/taxii/` · `taxii_config` (1 doc) + `taxii_push_log` (85 docs) — real pushes have happened |
| 14 | OSINT reputation (VirusTotal / AbuseIPDB) | IMPL+DISCONNECTED | `backend/feeds.py` fetches AbuseIPDB, OTX, URLhaus, etc. into `iocs` (65,614 docs) BUT no per-investigation live reputation lookup wired to IOC panel. No VirusTotal client. |
| 15 | Threat-Intel RSS crawl | IMPL+CONNECTED | `routers/threat_intel_rss.py` · `cti_rss_meta` (8 sources) + `pending_training_notes` (96) |
| 16 | Threat-Intel feed sync (7 providers) | IMPL+CONNECTED | `ti_source_meta` (8 sources) + `ti_sync_runs` (1,339 completed sync jobs) |
| 17 | Investigation Knowledge Graph (IKG) | IMPL+DISCONNECTED | `backend/v2/investigation/ikg.py` — 13 node types, 14 edge types, fully coded · `v2_case_events` collection = 0 docs · every v2 flag is `shadow` |
| 18 | Verdict Engine v3 (per-event/process/chain/device/incident) | IMPL+DISCONNECTED (shadow) | `backend/v2/verdict/` · gated by `NIVX_FLAG_VERDICT_ENGINE_V3=shadow` · endpoint returns 503 unless flag flipped · `verdict_shadow_observations` = 2 docs |
| 19 | Canonical verdict projection (production) | IMPL+CONNECTED | `backend/canonical/projections/verdict.py` — 4-class linear scorer (25/8/4/2 weights) · reachable via `POST /api/die/investigation-results` |
| 20 | Canonical Attack-Story projection | IMPL+CONNECTED | `backend/canonical/projections/attack_story.py` · fires only when SSOT has MITRE/command/IOC evidence · used by `/api/die/investigation-results` |
| 21 | ATT&CK Navigator layer JSON | PARTIAL | `backend/v2/investigation/attack_mapping.py::build_attack_mapping` · code writes Navigator v4.5 JSON but only path is IKG-fed = shadow |
| 22 | Analyst Practice Lab | IMPL+CONNECTED | `routers/lab.py` — 8 routes · `lab_attempts` (89 docs) + `lab_stats` (1 doc) — real analyst usage |
| 23 | Emergent-LLM narrative (Claude Sonnet) | IMPL+CONNECTED | `EMERGENT_LLM_KEY` present in `.env` · `object.narrative` populated in `/api/die/investigation-results` |
| 24 | File upload (universal) | IMPL+CONNECTED (capped) | `POST /api/upload` L382 in `routers/ops.py` · caps: `_CONTENT_CAP=64_000` chars + `_MAX_BODY_BYTES=512 KB` middleware |
| 25 | Frontend WorkspaceRootErrorBoundary | IMPL+CONNECTED | `frontend/src/components/WorkspaceRootErrorBoundary.jsx` — wired at App root |
| 26 | React `useDeferredValue` input debouncing | IMPL+CONNECTED | `WorkspacePage.jsx` — deferredInput pattern (session-7 fix) |
| 27 | Reports — Markdown / JSON | IMPL+CONNECTED | `backend/v2/report/markdown.py` · `GET /api/v2/cases/{id}/report.md` · SHA-256 signature envelope |
| 28 | Reports — PDF | IMPL+CONNECTED | `backend/v2/report/pdf.py` · `GET /api/v2/cases/{id}/report.pdf` · uses `reportlab==4.5.1` |
| 29 | Reports — STIX / Bundle ZIP | IMPL+CONNECTED (v2 case scope) | `GET /api/v2/cases/{id}/report.bundle.zip`, `.stix.json` · v2 case scope only |
| 30 | Reports — deterministic re-render (byte-identical) | IMPL (claimed) | Docstring `same envelope → same bytes`; SHA-256 signature emitted; determinism test count: `test_baseline_snapshots_present.py` gates baselines |
| 31 | RC5 evidence-graph side-car | EXPERIMENTAL (Phase-11.0) | `backend/engine/evidence_graph.py` — 18 node kinds, 19 edge kinds, side-car only, does NOT influence verdicts |
| 32 | RC5 golden runs | IMPL+CONNECTED | 19 routes under `/api/rc5/*` · `rc5_golden_runs` (9 docs), `rc5_shadow_runs` (1 doc) |
| 33 | Analyst corrections | IMPL+CONNECTED | 11 routes `/api/corrections/*` · `analyst_corrections` (887 docs) — heavy real usage |
| 34 | LLM finetune / training corpus | IMPL+CONNECTED | `learner_payloads` (18 docs), `learner_versions` (2 docs), `learning_events` (572 docs) |
| 35 | Benchmark / regression harness | IMPL+CONNECTED | `benchmark_runs` (897 docs), `batch_runs` (264), `regression_runs` (239), `regression_gate` (1) |
| 36 | Playbook feedback / votes | IMPL+CONNECTED | `playbook_votes` (262 docs) |
| 37 | Correlations (case-to-case) | IMPL+CONNECTED (light) | `routers/correlations.py` (20 routes) · `correlations` (5 docs) — real but low-volume |
| 38 | Documents / Case Vault | IMPL+CONNECTED | `documents.chunks` (35) + `documents.files` (35) — GridFS |
| 39 | KB (knowledge base) | IMPL+CONNECTED | 339 entries in `kb_entries` |
| 40 | AI budget guard | IMPL+CONNECTED | `ai_budget` (2 docs) — `NIVX_AI_BUDGET_CAP_CREDITS=500` in `.env` |
| 41 | LOLBAS registry | IMPL+CONNECTED | `lolbas_cache` (1 doc) · `services/die/lolbas.py` |
| 42 | Sigma generator | IMPL+CONNECTED | `backend/sigma_generator.py` + `backend/sigma_export.py` + `routers/sigma.py` |
| 43 | YARA export | IMPL+CONNECTED | `backend/yara_export.py` (referenced by canonical projections) |
| 44 | Frontend Nivxforge preview pages | FRONTEND ONLY | 5 pages under `frontend/src/nivxforge/pages/` — Threat Intel / Threat Hunting / KB / Reports / History are `PlaceholderSections.jsx` (no live data) |
| 45 | Frontend V2 workspace (`/v2/workspace/*`) | IMPL+DISCONNECTED | `frontend/src/v2/pages/CaseWorkspaceShell.jsx` etc. — depends on v2 backend routes that are shadow-flagged |
| 46 | `/investigate/:caseId` (workspace_v4 shell) | IMPL+CONNECTED | `frontend/src/workspace_v4/AnalystWorkspaceShellPage.jsx` |
| 47 | Cases router (workspace) | IMPL+CONNECTED | 8 `/api/cases/*` routes · `workspace_cases` (257 docs) |
| 48 | Investigations router (L1) | IMPL+CONNECTED | 21 `/api/investigation/*` routes · `investigations` (2,883), `investigation_events` (933), `investigation_ssot` (35) |
| 49 | Sessions router | IMPL+CONNECTED | 8 `/api/session/*` routes · `investigation_sessions` (327 docs) |
| 50 | SSRF guard | IMPL+CONNECTED | `services/ida/acquisition._is_private_host` · `test_ssrf_blocked.py` |
| 51 | Prometheus / OpenTelemetry / Jaeger | NOT-IMPLEMENTED | Zero occurrences of `prometheus`, `otel`, `opentelemetry`, `jaeger` in backend Python |
| 52 | Prompt/LLM telemetry hook | IMPL+CONNECTED | `utils/llm_telemetry.py::install_litellm_hook` at startup |
| 53 | Request-hardening middleware (X-Request-ID, timeouts, body-cap) | IMPL+CONNECTED | `backend/request_hardening.py` — 512 KB default / 50 MB large-body cap · per-path timeout table |
| 54 | GZip middleware (≥ 4 KB) | IMPL+CONNECTED | `server.py` L415 |
| 55 | CORS | IMPL+CONNECTED (permissive) | `CORS_ORIGINS="*"` in `backend/.env` → CORSMiddleware allow_origins=`["*"]` |
| 56 | Rate-limit / brute-force lockout | NOT-IMPLEMENTED | No throttling on `/api/auth/login`; no failure counters; no lockout logic in `routers/auth.py` |
| 57 | RBAC beyond admin flag | NOT-IMPLEMENTED | Only `role == "admin"` gate (`deps.py::require_admin`); no per-collection ownership beyond `owner`-scoped case lookups |
| 58 | Multi-tenant isolation | NOT-IMPLEMENTED | Single Mongo DB `test_database`. No `tenant_id` field on cases / iocs / events; no tenant middleware |
| 59 | Emergent Google Auth / SSO | NOT-IMPLEMENTED | Only JWT + bcrypt; no OAuth provider wired |
| 60 | Redis | NOT-USED | No `redis` client in `requirements.txt`; no `REDIS_URL` env |
| 61 | Celery / background workers | NOT-USED | No task queue; `_nightly_benchmark_loop` is an in-process `asyncio` sleep-24h coroutine (`server.py` L426) |
| 62 | Data-retention / TTL indices | UNKNOWN | Not verified this session — grep for `expireAfterSeconds` may reveal per-collection TTLs |
| 63 | Container isolation / sandboxing for analyzed inputs | NOT-IMPLEMENTED | All parsers run in the same Python process. No microVM, gVisor, or Firecracker isolation. `capstone==5.0.9` disassembly, `pefile==2024.8.26` PE parsing run inline. |

---

## §3 · Runtime Footprint (measured)

| Metric | Value | Source |
|---|---|---|
| Backend RSS at boot | 27.7 MB (pid 163) | `ps -eo pid,rss,cmd \| grep uvicorn` |
| Backend under 10× SEP.csv concurrency | 378 MB (session-7) | `/app/memory/adr/0005-load-and-resource-audit.md` |
| Frontend dev-mode memory | ~1.2 GB (CRA 5) | Session-7 audit |
| Mongo dataSize | 147 MB · 64 collections · 10/400 connections | Session-7 audit |
| Redis | not used | Absent from requirements + env |
| Backend routes (OpenAPI) | **466 operations / 436 paths** | `curl /openapi.json` this session |
| Backend routers | 77 files | `ls backend/routers/*.py \| wc -l` |
| Backend test files | 389 | `ls backend/tests/test_*.py \| wc -l` |
| Backend test functions | 3,621 | `grep -c "def test_" backend/tests/*.py` |
| Cold start | ~3 s / 2,080 modules | Session-7 |
| Body-size cap (default) | 512 KB | `request_hardening.py::_MAX_BODY_BYTES` |
| Body-size cap (large paths) | 50 MB | `_MAX_LARGE_BODY_BYTES` |
| Client-side auto-viz cap | 32 KB | `WorkspacePage.jsx` (session-7) |
| Deep health probe | mongo=ok · llm_key=ok · disk=87.66 GB free | `GET /api/health/deep` this session |

---

## §4 · Complete API Graph (466 method-routes)

Grouped by top-level prefix; count in parens. Every group also carries a **status** describing whether its routes are consumed by a shipping UI, kept for admin/ops, or dead.

| Prefix | Ops | Status | Notes |
|---|---:|---|---|
| `/api/` root (`/health`, `/health/deep`) | 1 | IMPL+CONNECTED | Kubernetes probes; used |
| `/api/admin` | 37 | IMPL+CONNECTED | OSINT keys, Model Studio, Samples, LOLBAS, Users, TAXII, etc. — admin panel wires most |
| `/api/ai` | 6 | IMPL+CONNECTED | `auto-decode`, `auto-investigate`, `troubleshoot`; guarded by `ai_credit_guard` |
| `/api/analyze` | 9 | IMPL+CONNECTED | sync / async / stream + shellcode + status; frontend uses `.../smart|async|process-tree` |
| `/api/artifacts` | 2 | IMPL+CONNECTED | `POST /api/artifacts/analyze` etc. (registered on `app` not `api` — line 339) |
| `/api/auth` | 3 | IMPL+CONNECTED | login / me / change-password |
| `/api/batch` | 11 | IMPL+CONNECTED | Batch-test page consumer |
| `/api/behaviors` | 2 | IMPL+CONNECTED | `POST /api/investigation/behaviors/explain` etc. |
| `/api/benchmark` | 6 | IMPL+CONNECTED | Nightly benchmark loop + admin |
| `/api/cases` | 8 | IMPL+CONNECTED | Workspace case CRUD; heavy usage (`workspace_cases` 257 docs) |
| `/api/corpus` | 3 | IMPL+CONNECTED | Corpus validation (`corpus_validate.py`) |
| `/api/corrections` | 11 | IMPL+CONNECTED | 887 corrections captured (`analyst_corrections`) |
| `/api/correlations` | 20 | IMPL+CONNECTED | Full CRUD + link/unlink; light usage (5 docs) |
| `/api/decode` | 17 | IMPL+CONNECTED | Smart / magic / chain / candidates / feedback |
| `/api/die` | 21 | IMPL+CONNECTED | **the shipping analyst pipeline**: analyze, investigation-results, timeline, query, chain, iocs, narrate, understand, health-check, powershell/ast, dkp/*, lolbas, report/{case_id}, case/{case_id}, archive/recover, confidence, detect-kind, intent |
| `/api/docs` | 39 | IMPL+CONNECTED | Static-doc router + feedback + cheatsheet |
| `/api/documents` | 9 | IMPL+CONNECTED | GridFS-backed doc vault |
| `/api/emit` | 2 | IMPL+CONNECTED | LOLBAS export etc. |
| `/api/enrichment` | 5 | IMPL+CONNECTED | Enrichment admin panel |
| `/api/examples` | 1 | IMPL+CONNECTED | Examples payload |
| `/api/health` | 2 | IMPL+CONNECTED | `/health`, `/health/deep` |
| `/api/history` | 8 | IMPL+CONNECTED | Investigation history drawer |
| `/api/iedde` | 1 | IMPL+CONNECTED | `POST /api/iedde/analyze` — trace visualiser |
| `/api/investigation` | 21 | IMPL+CONNECTED | L1 workspace investigation APIs (Blueprint §10) — heaviest DB usage (2,883 investigations) |
| `/api/investigations` | 6 | IMPL+CONNECTED | List / detail views (Investigations page) |
| `/api/ioc` | 3 | IMPL+CONNECTED | `POST /api/ioc/enrich` (frontend uses this) |
| `/api/kb` | 7 | IMPL+CONNECTED | 339 KB entries |
| `/api/lab` | 8 | IMPL+CONNECTED | Practice Lab |
| `/api/learner` | 16 | IMPL+CONNECTED | Learning-engine feedback; boost/correction endpoints referenced from FE |
| `/api/learning` | 6 | IMPL+CONNECTED | `learning_events` 572 docs |
| `/api/learning-engine` | 2 | IMPL+CONNECTED | Second learning surface |
| `/api/lolbas` | 2 | IMPL+CONNECTED | Registry lookup |
| `/api/mitre` | 3 | IMPL+CONNECTED | MITRE heatmap + probe |
| `/api/moe` | 2 | IMPL+CONNECTED | Mixture-of-experts panel |
| `/api/nivxforge` | 9 | IMPL+CONNECTED | Preview pages (health/adrs/framework-status/governance/…) |
| `/api/observation` | 1 | IMPL+DISCONNECTED | Legacy observation surface — X-Lab-adjacent |
| `/api/operations` | 1 | IMPL+CONNECTED | `GET /api/operations` list |
| `/api/osint` | 1 | IMPL+CONNECTED | OSINT feed refresh |
| `/api/planner` | 2 | IMPL+CONNECTED | `POST /api/planner/advise` — Smart Input Advisor |
| `/api/platform` | 3 | IMPL+CONNECTED | Platform-health |
| `/api/rc5` | 19 | IMPL+CONNECTED | Golden runs · shadow · entity classifier · evidence-graph metrics · gate |
| `/api/recipe` | 1 | IMPL+CONNECTED | `POST /api/recipe/run` |
| `/api/regression` | 8 | IMPL+CONNECTED | Regression dashboard |
| `/api/report` | 5 | IMPL+CONNECTED | Legacy report emitters (TXT / HTML / DOCX / PDF / CSV via `report_renderers.py`) |
| `/api/schemas` | 2 | IMPL+CONNECTED | `GET /api/schemas/v1/cio` |
| `/api/session` | 8 | IMPL+CONNECTED | Workspace sessions |
| `/api/share` | 2 | IMPL+CONNECTED | Share-link render |
| `/api/ssot` | 1 | IMPL+CONNECTED | Canonical SSOT read (only 2 docs stored) |
| `/api/system` | 1 | IMPL+CONNECTED | `GET /api/system/info` |
| `/api/telemetry` | 2 | IMPL+CONNECTED | Frontend telemetry sink (52 docs) |
| `/api/threat-intel` | 20 | IMPL+CONNECTED | Feed sync + RSS crawl + admin config (65,614 IOCs) |
| `/api/threat-model` | 3 | IMPL+CONNECTED | Threat-model page |
| `/api/timeline` | 4 | IMPL+CONNECTED | Older timeline API (parallel to `/api/die/timeline`) — **candidate duplicate** |
| `/api/training` | 8 | IMPL+CONNECTED | Corrections & confusion matrix |
| `/api/troubleshoot` | 1 | IMPL+CONNECTED | Diagnostics |
| `/api/uaie` | 4 | IMPL+CONNECTED | UAIE (Universal Artifact Intelligence Engine) |
| `/api/uil` | 3 | IMPL+CONNECTED | Universal Input Layer |
| `/api/understand` | 1 | IMPL+CONNECTED | `POST /api/understand` — IUE hook |
| `/api/upload` | 1 | IMPL+CONNECTED (capped) | 256 KB / 64 KB text content cap |
| `/api/v2` | **55** | IMPL+DISCONNECTED (shadow) | Full parallel pipeline; **every write-path uses shadow-mode flags**. See §5. |

**Duplicate / overlapping route families (evidence of two pipelines):**

- `/api/die/timeline` (canonical shipping) vs `/api/v2/cases/{id}/trajectory/device` (v2 shadow) vs `/api/timeline` (legacy)
- `/api/die/investigation-results` (canonical shipping) vs `/api/v2/analyze/report` (v2)
- `/api/investigation` (L1 shipping) vs `/api/v2/cases` (v2 shadow)
- Two reports paths: `/api/report/*` (legacy) vs `/api/v2/cases/{id}/report.*` (v2 canonical)

**Orphan/disconnected routes (identified this session):**

- `/api/observation` (1) — X-Lab observational surface residual after X-Lab-A removal.
- All 6 `/api/v2/ingest/{format}` routes — no FE consumer, gated by `NIVX_FLAG_ADAPTERS=shadow`.
- `/api/v2/ingest/evtx` — explicitly returns HTTP 501.
- All 55 `/api/v2/*` are effectively BACKEND ONLY except `/api/v2/analyze/report` (called from `WorkspacePage.jsx` L525) and `/api/v2/cases` (called from V2 pages that are themselves not part of the primary `/` route).

---

## §5 · Feature-Flag Reality

All flags read once at boot from `NIVX_FLAG_*` env vars via `backend/v2/flags.py` (tri-state: `disabled`/`shadow`/`enabled`).

Value in `backend/.env`:

| Flag | State | Consequence |
|---|---|---|
| `NIVX_FLAG_TRAJECTORY_ENGINE` | shadow | v2 device-trajectory endpoints observable-only; won't influence shipping views |
| `NIVX_FLAG_CASE_ENGINE` | shadow | v2 case_engine (dedicated schema at `backend/v2/case_engine/schema.py`) writes 0 rows to `v2_case_events/entities/behaviors/relationships/reports` |
| `NIVX_FLAG_ADAPTERS` | shadow | ingest endpoints gated (503 or observation-only) |
| `NIVX_FLAG_ARTIFACT_STORE` | shadow | v2 artifact-store not authoritative |
| `NIVX_FLAG_VERDICT_ENGINE_V3` | shadow | `POST /api/v2/cases/{id}/verdicts*` returns 503 unless flipped |

Non-flag toggles (env, boot-time):

| Env | Value | Effect |
|---|---|---|
| `NIVX_CANONICAL_UIL_INVESTIGATE` | on | canonical UIL investigate active |
| `NIVX_CANONICAL_DIE_ANALYZE` | on | canonical narrative MITRE augment active on `/api/die/analyze` |
| `NIVX_ENGINE` | legacy | RC5 legacy engine remains authoritative (v2 not promoted) |
| `NIVX_AI_ENABLED` | true | LLM narrate available |
| `NIVX_AI_BUDGET_CAP_CREDITS` | 500 | Budget guard active |
| `NIVX_AI_RATE_HOURLY / DAILY` | 10 / 50 | Rate limits |
| `ADMIN_FORCE_PASSWORD_CHANGE` | false | Admin does NOT need to rotate on first login |

**Interpretation:** *Every* v2 flag is `shadow`. The v2 layer is architecturally beautiful but operationally non-authoritative. Selling the platform on "v3 verdict engine" or "IKG-driven investigation" today would misrepresent what the production request-path actually does.

---

## §6 · Investigation Knowledge Graph (IKG) — Reality

**Design (SSOT, backend/v2/investigation/ikg.py):**

Node types (13): `process · file · registry · network · module · service · task · event · technique · tactic · verdict · device · incident`.
Edge types (14): `created · modified · deleted · contacted · loaded · installed · spawned · executed_by · maps_to · covers · contributes_to · rollup_of · hosted_on · part_of`.

**Construction path (planned):**
```
telemetry frames → IRG enrich (v2/shadow/irg) → IKG assembly (v2/investigation/builder.py::Investigation)
                                              → verdict engine (event/aggregate)
                                              → correlation engine (aggregate v3.1b)
                                              → attack_story + attack_mapping + explainability + ikb
```

**Persistence:** `v2_case_events / v2_case_entities / v2_case_behaviors / v2_case_relationships / v2_case_reports`.

**Reality:** all 5 collections contain **0 documents**. `v2_shadow_observations` has 563 (sampling only). `v2_cases` has 29 (from earlier experiments). The IKG is running **as a side-car observer only** — the shipping investigation view does not consume it.

**Provenance:** every IKG node carries `source_node_ids` (per `engine/evidence_graph.py`) so provenance is architecturally guaranteed *when the IKG is authoritative*. Today it is not.

**Consumers (planned vs actual):**
- Planned: Trajectory · Attack Story · Evidence Graph · ATT&CK · Verdict · Explainability · Reports.
- Actual: none in the production request-path. Frontend pages under `/v2/*` reach these routes, but `/v2/*` is off the main `/` navigation.

**Verdict:** IMPL+DISCONNECTED. Removing the flag guard and lighting up the persistence writer would surface this capability; today it is dormant.

---

## §7 · Verdict Engine — Reality

**Two engines coexist. Only one ships.**

### 7.1 Canonical Verdict Projection (shipping)
`backend/canonical/projections/verdict.py` — deterministic, pure:

- Weights: `mitre_technique=25`, `ioc=8`, `command=4`, `reasoning_step=2`.
- Score = `Σ min(count_c, cap_c) · weight_c`, clamped 0..100.
- Label bands: ≥80 MALICIOUS · ≥60 SUSPICIOUS · ≥30 LIKELY_BENIGN · else INCONCLUSIVE.
- `reason` field says literally "no evidence in canonical SSOT" when there is no evidence — **negative explainability** is honoured.
- Exposed via `POST /api/die/investigation-results.object.verdict`.

### 7.2 Verdict Engine v3 (shadow)
`backend/v2/verdict/{engine,weights,profiles,correlation,progressions,signals,canonical,shadow}.py`:

- Per-event scoring with breakdown + explanation.
- Adaptive Weight Profiles (`soc_balanced` default; other profiles listed at `GET /api/v2/verdict/profiles` — returns 503 today).
- Correlation bonuses (v3.1b — `v2/verdict/correlation.py`).
- Aggregate rollup (event → process → chain → device → incident) at `GET /api/v2/cases/{id}/verdicts/aggregate?profile=…`.
- Confidence + band per aggregate level.

**Endpoint reality:**
```
GET  /api/v2/verdict/profiles                    → 503 (flag=shadow)
GET  /api/v2/cases/{id}/verdicts                 → 503 (flag=shadow)
GET  /api/v2/cases/{id}/verdicts/aggregate       → 503 (flag=shadow)
```

**Explainability:**
- Canonical projection: `contributors[]` list with class + count + weight — traceable.
- v3: `explanation` string per event + `breakdown` dict.
- **Negative explainability**: canonical projection produces `"no evidence in canonical SSOT"`; v3 has `v2/investigation/explainability.py::why_is_this_not` (list_negative_patterns) — but path is dormant.

**Test coverage:** `test_p01_p02_verdict_card.py`, `test_verdict_engine_parity.py`, `test_verdict_card_never_null.py`, `test_adr0007_verdict_evidence_gating.py`, `test_verdict_v3_1b.py`, `test_verdict_reasoning.py` — verdict is one of the most tested subsystems.

**Verdict:** canonical projection = IMPL+CONNECTED. v3 = IMPL+DISCONNECTED (shadow).

---

## §8 · Attack Story / ATT&CK — Reality

### 8.1 Canonical projection (shipping)
`backend/canonical/projections/attack_story.py` — pure, deterministic, returns `None` when no evidence (no fabrication).
- Structure: `opening / chapters[] / closing`.
- Each chapter = one MITRE tactic stage with the techniques observed.
- Powered by `canonical/projections/attack_chain.py` for stage grouping.

### 8.2 v2 attack_mapping (shadow)
`backend/v2/investigation/attack_mapping.py::build_attack_mapping` — richer output:
- Tactic-level coverage (level 0..3)
- Kill-chain ordered stages
- **MITRE Navigator v4.5 layer JSON** (one-click export)
- STIX 2.1 technique set (fully rendered STIX in `v2/report/stix.py`)

### 8.3 ATT&CK coverage (base-technique dictionary)
`v2/investigation/attack_mapping.py::TACTIC_OF_BASE` — hardcoded mapping for ~40 techniques across 12 tactics. Sub-technique (`.NNN`) mapping present via `_tactic_of`. Techniques outside this table map to `None` → dropped from the chain.

### 8.4 Confidence and "unsupported mappings"
- Confidence is inherited from the underlying rule (P0.2 evidence chain rule confidence).
- Unsupported / novel MITRE ids: silently dropped by `_tactic_of` returning `None`. No warning surface today.

**Verdict:** canonical Attack Story = IMPL+CONNECTED; v2 Navigator/STIX = IMPL+DISCONNECTED (path lives, but no shipping consumer for Navigator JSON in `/api/die/*`).

---

## §9 · Report Generator — Reality

### 9.1 Two report families
- **Canonical (shipping)**: `backend/canonical/projections/reports.py` — projects STIX / Sigma / YARA / Navigator / MDR from SSOT.
- **v2 (shadow)**: `backend/v2/report/{markdown,pdf,bundle,stix,builder}.py` — deterministic envelope with SHA-256 signature; exposes `.md`, `.pdf`, `.stix.json`, `.bundle.zip` per case at `/api/v2/cases/{id}/*`.

### 9.2 Legacy renderers
`backend/report_renderers.py` — TXT / HTML / DOCX / PDF / CSV renderers used by the older `/api/report/*` routes and `/api/analyze/report`.

### 9.3 Report Writer router (dedicated)
`backend/routers/report_writer.py` — three write endpoints (`POST /api/v2/report-writer/generate*`). Full-pipeline artifact production.

### 9.4 Determinism & signature
- `v2/report/markdown.py` docstring: *"Same envelope → same Markdown bytes. Pure function, no side effects."*
- SHA-256 signature emitted in envelope (`env.signature.sha256`).
- **No published test enforces byte-identical re-render across two calls this session** — needs to be added to close the loop.

### 9.5 Report/UI integration
- `frontend/src/components/investigation/ReportTab.jsx` consumes `/api/v2/analyze/report?fmt=…` (`WorkspacePage.jsx` L525).
- Legacy `/api/report/*` still reachable but not directly wired into the primary WorkspacePage.

**Verdict:** IMPL+CONNECTED for shipping report generation. **PARTIAL** for deterministic-signature guarantee (no CI gate).

---

## §10 · Complete Frontend Inventory

### 10.1 App-level routes (`frontend/src/App.js` — 58 `<Route>` entries)

Grouped by intent:

**Primary Workspace (default `/`):**
- `/` → `WorkspacePage.jsx` (4,306 lines — the mothership)
- `/analyze` → `CommandAnalyzerPage`
- `/investigate`, `/investigate/:caseId` → `AnalystWorkspaceShellPage` (workspace_v4)

**Analyst tooling:**
- `/threat-intel`, `/threat-model`, `/kb`, `/docs`, `/documents`, `/lab`, `/heatmap`, `/history`
- `/investigations`, `/investigations/:id`, `/investigation-summary`, `/investigations/:id/replay`
- `/compare`, `/compare/:caseA/:caseB`
- `/iedde` (decision trace)
- `/analyst`, `/analyst/rc5`
- `/auto-investigate`
- `/evidence-explorer`
- `/workspace/session/:sessionId[/input/:inputId]`

**Admin:**
- `/admin`, `/admin/models`, `/admin/samples`, `/admin/corrections`, `/admin/training-inbox`
- `/batch-test`, `/benchmark`, `/battery`, `/platform`, `/learner`

**v2 pages (shadow-backend, disconnected from `/`):**
- `/v2/workspace[/:caseId]`, `/v2/trajectory[/:caseId]`, `/v2/irg[/:caseId]`, `/v2/compare[/…]`, `/v2/ancestry/:caseId/:processIid`, `/v2/case/:caseId`, `/v2/ingest`, `/v2/validation`

**Nivxforge preview:**
- `/nivxforge`, `/nivxforge/dashboard`, `/nivxforge/investigate`
- `/nivxforge/threat-intel`, `/nivxforge/hunting`, `/nivxforge/knowledge`, `/nivxforge/reports`, `/nivxforge/history`, `/nivxforge/governance`
- **All Nivxforge section pages except Dashboard/Investigate/Governance are `PlaceholderSections.jsx`** — no live backend.

### 10.2 Pages (34 files under `frontend/src/pages/`) — component:route:api

Every page is code-split (`lazy(() => import(...))`). See §10.1 for the intent grouping.

### 10.3 Components (138 top-level, 30 investigation-scoped, 10 v2)

Investigation folder (production Workspace panels):
```
AcquisitionEvidenceList · AcquisitionPlanPanel · AcquisitionSummary
AnalystNarrativePanel · ArtifactTracePanel
AttackChainView · CollapsibleCard · CollapsibleSection
CorrelationSuggestionCard · EvidenceGraphView · EvidenceTab
ExtractedArtifactsPanel · FindRelatedDrawer · InlineAttackStory
InputUnderstandingPanel · InvestigationBrainPanel
InvestigationFilter · InvestigationSessionGateway
InvestigationSummaryPanel · InvestigationThreatSummaryCard
JumpToSource · OverviewTab · QueryHuntPanel (NEW)
ReportTab · SemanticIntelligencePanel · StoryTab
TimelinePanel (NEW) · TrajectoryDiagram · UnifiedTimelineView
WorkspaceDecodeFailureCard
```

### 10.4 API dependency — 74 distinct `/api/*` URL literals in frontend

Frontend calls **74** unique endpoints out of the 466 the backend exposes → **~15% consumption ratio**. Every route not on the frontend list is either admin-only, ops-only, RC5-only, or dead. See §11 for dead-code candidates.

### 10.5 Mock / static UI

- `nivxforge/pages/PlaceholderSections.jsx` — 5 static placeholders (no API).
- `nivxforge/pages/PreviewPage.jsx` — reads `/api/nivxforge/preview/*` (real backend).
- v2 pages under `/v2/*` — live routes but 503 unless flags flipped.

### 10.6 Feature flags on the frontend

- No React feature-flag library (Split.io, Unleash, LaunchDarkly) present.
- Some panels self-gate by checking payload keys.

### 10.7 Dead UI candidates

- `frontend/src/pages/AnalystRC5Page.jsx` — path `/analyst/rc5`, referenced but not surfaced in the primary nav.
- `frontend/src/pages/CommandAnalyzerPage.jsx` — legacy analyze page, superseded by WorkspacePage.
- `frontend/src/v2/pages/*` — v2 workspace bundle: connected but all backend endpoints shadow-flagged, effectively demo.
- `frontend/src/nivxforge/pages/Placeholder*.jsx` — placeholder-only sections.

### 10.8 Workspace vs X-Lab boundaries

- **Workspace surface (this snapshot's Do-Not-Break):** `/`, `/investigate/*`, `/investigations/*`, `/workspace/session/*`, plus all panels under `frontend/src/components/investigation/`.
- **X-Lab surface (previously removed in Session-7):** the observational lab; `/api/observation` residual endpoint remains; `test_workspace_isolation_guard.py` locks the boundary.
- **Practice Lab (kept):** `/lab` + `/api/lab/*` — clearly distinct from removed X-Lab-A.

---

## §11 · Technical Debt (evidence-based)

| # | Debt item | Evidence |
|---|---|---|
| 11.1 | Two parallel investigation pipelines (RC5 canonical + v2 shadow) | See §6, §7, §8. Every v2 flag = `shadow`; v2 collections = 0 rows. |
| 11.2 | 466 API operations vs 74 frontend consumers → ~85% dead-or-admin | §10.4 |
| 11.3 | Overlapping route families (`/api/die/timeline`, `/api/v2/cases/{id}/trajectory/device`, `/api/timeline`) | §4 |
| 11.4 | `WorkspacePage.jsx` is 4,306 lines · single component | `wc -l frontend/src/pages/WorkspacePage.jsx` |
| 11.5 | Heavy Python deps unused in shipping path — `googleapiclient`, `google-genai`, `stripe`, `botocore`/`boto3` | `backend/requirements.txt` |
| 11.6 | 200 lines in `requirements.txt`; last pip-freeze committed drift with actual `pip freeze` unmeasured | — |
| 11.7 | Legacy modules: `chain_analyzer.py`, `command_analyzer.py`, `commandline_miner.py`, `investigation_report.py` (root-level) live alongside `services/die/` — same-concept parallels | `ls backend/*.py` |
| 11.8 | 89 memory `.md` files + 40+ ADRs — high drift risk vs code | `ls memory/*.md \| wc -l` |
| 11.9 | 3,621 test functions across 389 files — no visible test-execution matrix (which tests actually run in CI vs local) | `grep -c "def test_" backend/tests/*.py` |
| 11.10 | Corpus JSON snapshots (`memory/rc22_*.json`, `rc23_*.json`) — ~15 files not clearly gated | `ls memory/rc*.json` |
| 11.11 | Nivxforge frontend section reflects intent unbacked by data | `PlaceholderSections.jsx` |
| 11.12 | `CORS_ORIGINS="*"` — permissive for pod but a prod risk | `backend/.env` |
| 11.13 | Root-level `/health` + `/api/health` + `/api/health/deep` — 3 health surfaces, minor churn | `server.py` L122-150 |
| 11.14 | Nightly benchmark loop is an in-process `asyncio` sleep-24h — no supervision, no external scheduler | `server.py` L426 |
| 11.15 | 63 frontend deps (Radix + Storybook + Recharts + React-Konva + xyflow + Force-Graph + Framer) — significant bundle surface | `frontend/package.json` |

---

## §12 · Security Posture (evidence-based)

| # | Control | Reality | Evidence |
|---|---|---|---|
| 12.1 | Authentication | JWT (PyJWT) · bcrypt password hash · single admin seed idempotent | `backend/deps.py` L241-331 |
| 12.2 | Password strength | `min_length=12` on new password endpoint · no complexity policy · no history | `routers/auth.py` L15-16 |
| 12.3 | Brute-force protection | **NONE** — no rate-limit / lockout on `/api/auth/login` | `routers/auth.py` |
| 12.4 | Session revocation / rotation | Token-only; JWT stateless; no server-side revocation list | `deps.py::create_token` L252 |
| 12.5 | RBAC | Two levels: user + admin (`role == "admin"`) | `deps.py::require_admin` L301 |
| 12.6 | Multi-tenant isolation | None; single DB; `owner`-scoped cases only | `workspace_investigation.py` L21 |
| 12.7 | SSRF | Loopback / link-local / RFC1918 / reserved blocked via `_is_private_host` | `services/ida/acquisition.py` + `test_ssrf_blocked.py` |
| 12.8 | Payload size cap | 512 KB default / 50 MB whitelisted paths / 256 KB upload / 64 KB text-content | `request_hardening.py`, `routers/ops.py` |
| 12.9 | Request timeout | Per-path table; LLM paths get longer window; 504 emitted with X-Request-ID | `request_hardening.py` L60-107 |
| 12.10 | Archive-bomb / zip-slip | `.zip/.docx/.pptx/.xlsx` unzipped inline in `routers/ops.py` L421 · no per-file / total-size cap · **potential zip-bomb path** | `routers/ops.py` L421-445 |
| 12.11 | Path traversal | Uploads never touch the filesystem (raw kept in-memory + `documents.files` GridFS) — lower risk | `routers/ops.py` |
| 12.12 | Command execution | No `subprocess` shells on user input; disassembly via `capstone` (in-proc); PowerShell AST via Python `powershell_ast.py` | `backend/routers/ops.py` — no shell exec |
| 12.13 | Sandboxing / container isolation | **NONE** for analyzed inputs; all parsers run in the same Python process | — |
| 12.14 | Injection (Mongo NoSQL) | Motor + Pydantic input validation; no `$where` dynamic operators observed on user paths | Router bodies use `BaseModel` |
| 12.15 | XSS on rendered outputs | React auto-escapes; `dangerouslySetInnerHTML` count in FE = grep → confirm before selling as "safe" | UNKNOWN — spot-check next session |
| 12.16 | Dependency / supply-chain | 200-line pinned `requirements.txt`; `litellm` pinned to a Cloudfront-signed wheel (customer-owned CDN); no SBOM produced | `backend/requirements.txt` L146 |
| 12.17 | Sensitive-data logging | JWT_SECRET, ADMIN_PASSWORD, OTX_API_KEY, URLSCAN_API_KEY in `backend/.env` — not logged; LiteLLM INFO log silenced at startup | `server.py` L458-478 |
| 12.18 | MongoDB / Redis exposure | Mongo bound to `localhost:27017` inside pod; no external port | `backend/.env` |
| 12.19 | CORS | `allow_origins=["*"]` + `allow_credentials=True` | `server.py` L417 — **contradicts CORS spec** for `*` + credentials |
| 12.20 | HTTPS / TLS | Terminated by Cloudflare + Kubernetes ingress (pod itself HTTP) | Session-7 |
| 12.21 | Audit log | `v2_audit_log` exists (0 docs); no shipping audit trail | Session-8 DB |
| 12.22 | Secret rotation | Not automated | — |

**Top security risks:**

1. **CORS `*` + credentials** — HTTP-spec violation; browsers should reject, but the config signals intent to trust everyone (12.19).
2. **No login throttling** — pure JWT + bcrypt, no rate-limit → credential-stuffing shape (12.3).
3. **Archive unpack in-process without size guard** — zip-bomb risk on `/api/upload` (12.10).
4. **Same-process parser isolation** — a PE / DOCX / RC4 blob parses inside the FastAPI event loop (12.13).
5. **Permissive Nivxforge preview endpoints** — return internal ADR / governance markdown (12 admin-side leak surface; UNKNOWN whether admin-gated).

---

## §13 · Customer-Data / Privacy Architecture (evidence-based)

| Question | Answer (evidence) |
|---|---|
| What enters NivXRay? | Analyst-pasted commands / prose · ≤ 256 KB uploads · CSV EDR exports · OSINT feeds (7 providers) · RSS feeds |
| What is stored? | 64 Mongo collections; heaviest: `iocs` (65,614), `investigations` (2,883), `ti_sync_runs` (1,339), `analyst_corrections` (887), `benchmark_runs` (897), `sessions_all_kinds` (~500) |
| Where? | Mongo `test_database` on the pod (`localhost:27017`); GridFS for uploaded documents (`documents.chunks/files`) |
| Temporary storage / cache? | `ai_decode_cache`, `ai_describe_cache`, `ai_response_cache`, `enrichment_cache`, `v2_enrichment_cache` — 0 docs currently |
| Logs | Supervisor-managed stdout/stderr; no structured logger; LiteLLM info silenced |
| External APIs | OTX (`OTX_API_KEY`), URLscan (`URLSCAN_API_KEY`), AbuseIPDB, URLhaus, ThreatFox, MalwareBazaar, MalwareBytes, Talos, CINS Army — outbound TI feed fetch only |
| LLM providers | Emergent LLM key → LiteLLM shim → Claude / OpenAI / Gemini (via `emergent_integrations`) |
| Data leaving the environment | Only user-initiated: TAXII push (`taxii_push_log` 85 rows), report downloads, share links |
| Retention / deletion | **No TTL indices verified this session** (UNKNOWN) — cases keep growing (`investigations` 2,883 · `investigation_events` 933 · `iocs` 65,614) |
| Backups | Not observed; UNKNOWN |
| Tenant isolation | Single-tenant DB — no `tenant_id` column |

**Verdict:** Suitable for **single-tenant SaaS demo / on-prem PoC**. Not suitable for multi-tenant customer-hosted deployment without data-model changes.

---

## §14 · Deployment Architecture — What is Actually Possible Today

| Model | Feasibility today | Evidence |
|---|---|---|
| Emergent-managed SaaS (single tenant) | **YES** — this is the current mode | Kubernetes pod + supervisor + Cloudflare ingress |
| Customer-hosted / on-prem | Feasible with effort — needs `.env` per tenant, Mongo/GridFS storage, LLM key handling | No installer scripted; `docker-compose` absent |
| Multi-tenant SaaS | **NO** — no tenant model in DB or auth (§13) |
| Air-gapped | Partial — LLM narrate would need offline LLM (mentioned in `memory/OFFLINE_LLM_DEPLOYMENT.md`); TI feed sync would be disabled | `memory/OFFLINE_LLM_DEPLOYMENT.md` |
| Local-only analyst tool | Feasible — single dev-mode start (frontend `yarn start` + backend `uvicorn`) | `supervisorctl status` shows this pod |
| Private cloud / hybrid | Feasible with effort — same as customer-hosted |

**Blocker for all customer-hosted modes:** no packaged distributable. `docker-compose.yml` / Helm chart / installer are absent.

---

## §15 · Integrations Posture (evidence-based)

| Integration | Status | Evidence |
|---|---|---|
| Microsoft Defender for Endpoint | NOT-IMPLEMENTED | No route, module, or client |
| CrowdStrike Falcon | NOT-IMPLEMENTED | Corpus training references vendor logs; no live client |
| SentinelOne | NOT-IMPLEMENTED | Same |
| Cisco Secure Endpoint (AMP) | NOT-IMPLEMENTED | Corpus references it; no ingest adapter |
| Cisco XDR | NOT-IMPLEMENTED | — |
| Splunk | NOT-IMPLEMENTED | Splunk `_raw` CSV shape not recognised by `csv_edr_analyzer.py` (Session-7 finding) |
| QRadar | NOT-IMPLEMENTED | — |
| Microsoft Sentinel | NOT-IMPLEMENTED | — |
| Elastic Security | NOT-IMPLEMENTED | — |
| STIX 2.1 export | IMPL+CONNECTED (v2 case scope) | `v2/report/stix.py` + `GET /api/v2/cases/{id}/report.stix.json` |
| TAXII 2.1 push | IMPL+CONNECTED (admin) | `routers/taxii.py`; 85 pushes in `taxii_push_log` |
| VirusTotal | NOT-IMPLEMENTED | No client module |
| AbuseIPDB | IMPL+CONNECTED (feed only) | `backend/feeds.py` |
| OTX (AlienVault) | IMPL+CONNECTED (feed only) | `feeds.py::fetch_otx` |
| URLhaus / ThreatFox / MalwareBazaar / MalwareBytes / Talos / CINS Army | IMPL+CONNECTED (feed only) | `feeds.py` |
| URLscan | IMPL+CONNECTED (key present) | `URLSCAN_API_KEY` in `.env` |
| Emergent LLM (Claude/GPT/Gemini) | IMPL+CONNECTED | `EMERGENT_LLM_KEY` + LiteLLM shim |
| Google Auth / OAuth | NOT-IMPLEMENTED | Only JWT+bcrypt |
| Stripe | NOT-USED | Package present in `requirements.txt`; no route imports it |
| Boto3 / S3 | NOT-USED | Package present; no import in shipping code |

---

## §16 · Threat-Hunting Reality

| Hunting mode | Status | Path |
|---|---|---|
| IOC hunting | PARTIAL | `/api/threat-intel/lookup/{value}` · `/api/ioc/enrich` — single-value lookup, no cross-case bulk hunt |
| Behavioural hunting | PARTIAL | `/api/behaviors/*` — narrow to current case |
| Process hunting | IMPL (single case) | `/api/analyze/process-tree` + WorkspacePage process-tree renderer |
| Command-line hunting | IMPL (single case) | `/api/die/query` (session-7) — case-scoped |
| ATT&CK hunting | PARTIAL | MITRE heatmap `/api/mitre/heatmap` (aggregate) but not a live hunt |
| Timeline hunting | IMPL (single case) | `/api/die/timeline` |
| Cross-device hunting | NOT-IMPLEMENTED | No fleet model |
| Cross-case hunting | NOT-IMPLEMENTED | `/api/correlations/find-related` exists but returns limited relations |
| Retrospective investigation | PARTIAL | Investigations history drawer + `/api/investigations/*` — read-only |
| Saved queries | NOT-IMPLEMENTED | No saved-query endpoint or collection |

**Verdict:** Real threat-hunting today is **single-case timeline + Query/Hunt**. Fleet-scale / cross-case hunting requires an ingested corpus that does not exist.

---

## §17 · Artifact Architecture Reality

| Component | Status | Evidence |
|---|---|---|
| Artifact Router | IMPL+CONNECTED | `services/ida/artifact_router.py` |
| Artifact-first principle | IMPL | `services/ida/` + `services/artifact_intelligence/` |
| Analyzer registry | IMPL | `backend/engine/registry.py` + `services/adapters/` |
| Decoder registry | IMPL | `backend/decoders/` + `backend/operations.py` + `ops_extended.py` (+42 ops) |
| Recursive artifact discovery | IMPL | `services/recursive_child_pipeline.py` + `services/die/preprocessor/` |
| Child artifacts | IMPL | Same |
| Fixed-point termination | IMPL | Terminal-state test: `test_binary_terminal_state.py` |
| Artifact provenance | IMPL | Every artifact carries `evidence_ref` gated by P0.2 |
| Artifact store persistence | IMPL+DISCONNECTED (shadow) | `v2_artifact_store` (15 docs) — gated by `NIVX_FLAG_ARTIFACT_STORE=shadow` |

---

## §18 · Data Model (Mongo collections, 64 total)

Key collections and their evidence-of-use (session-8 counts):

| Collection | Docs | Role |
|---|---:|---|
| `users` | 4 | JWT identity |
| `investigations` | 2,883 | Case history rows (L1) |
| `investigation_events` | 933 | Frame-level events |
| `investigation_sessions` | 327 | Session vault |
| `investigation_ssot` | 35 | SSOT snapshots |
| `investigation_cases` | 77 | Case metadata |
| `workspace_cases` | 257 | Cases in the Workspace surface |
| `iocs` | 65,614 | Deduped IOCs from OSINT feeds |
| `analyst_corrections` | 887 | Analyst-supplied corrections |
| `learning_events` | 572 | Feedback events |
| `benchmark_runs` | 897 | Nightly benchmarks |
| `batch_runs` | 264 | Batch-test runs |
| `regression_runs` | 239 | Regression harness |
| `admin_models` | 73 | Model Studio catalog |
| `sample_library` | 18 | Curated samples |
| `kb_entries` | 339 | Knowledge base |
| `lab_attempts` | 89 | Practice-lab attempts |
| `taxii_push_log` | 85 | Real STIX pushes |
| `ti_sync_runs` | 1,339 | Feed-sync history |
| `ti_source_meta` | 8 | Feed sources config |
| `cti_rss_meta` | 8 | RSS sources config |
| `pending_training_notes` | 96 | RSS-derived pending notes |
| `documents.files / documents.chunks` | 35 / 35 | GridFS uploads |
| `settings` | 3 | Global config (OSINT keys, TI config, TAXII config) |
| `canonical_ssot_store` | 2 | Canonical SSOT (real path uses volatile projection, not this store) |
| `v2_shadow_observations` | 563 | v2 shadow sampling |
| `verdict_shadow_observations` | 2 | Verdict-Engine-v3 shadow |
| `v2_cases` | 29 | v2 case rows (from earlier experiments) |
| `v2_case_events / entities / behaviors / relationships / reports` | **0 each** | v2 pipeline never persisted |
| `v2_artifact_store` | 15 | Shadow artifact store |
| `v2_decoded_payloads` | 161 | Payload snapshots (shadow) |
| `v2_ai_jobs` | 211 | AI job log |
| `v2_audit_log` | 0 | Empty |
| `v2_enrichment_cache` | 0 | Empty |
| `rc5_golden_runs` | 9 | RC5 golden runs |
| `rc5_shadow_runs` | 1 | RC5 shadow runs |

**Interpretation:**
- Real shipping data lives in **RC5/legacy collections** (`investigations`, `iocs`, `workspace_cases`, …).
- v2 collections that would represent the IKG-first architecture are **empty**.

---

## §19 · Testing / Quality Reality

| Metric | Value |
|---|---|
| Backend test files | 389 |
| Backend test functions (`def test_*`) | **3,621** |
| Canonical-API tests (P0.2 / P0.3 / Timeline / Query) | 6 files, ~108 tests (session-7 confirmed passing) |
| Frontend unit tests | 5 `.test.mjs` files (Trajectory / lane / classify / viewport) |
| Frontend integration / e2e | Playwright dep present (`playwright==1.61.0`); no Cypress/Playwright test dir observed under `frontend/` |
| CI configuration | UNKNOWN — no `.github/workflows` scan done this session (present at `.github/` — one visible entry) |
| What each major suite proves | See below |

**What the major suites prove:**
- **P0.2 evidence chain (30 tests)** — every MITRE technique surfacing from `/api/die/*` carries traceable `{source, event_or_rule, field, observed_value, evidence_ref}`.
- **P0.3 payload / Sample1 / X-Lab firewall** — response envelope limited to 10 keys; Sample1 case row byte-immutable; X-Lab cannot touch Workspace.
- **Timeline MVP (16 tests)** — response contract fixed; no invented events.
- **Query/Hunt (45 tests)** — filter semantics + Auto-Viz decision fixed.
- **SSRF blocker** — 4 categories of dangerous IP-space blocked.
- **Verdict card never null / verdict engine parity / verdict evidence gating** — verdict projection is deterministic and evidence-gated.
- **Behavior graph schema freeze** — schema drift caught at CI time.
- **Baseline snapshots present** — corpus regression baselines locked.

**What remains untested at the visible level:**
- Byte-identical re-render of Markdown / PDF / STIX reports across two calls (§9.4).
- CORS behaviour under browsers (config is arguably invalid).
- Rate-limit / brute-force on `/api/auth/login` — no scenario tests.
- Zip-bomb / archive-recursion on `/api/upload`.
- Multi-tenant isolation (n/a — feature absent).
- Frontend e2e for the shipping Workspace path (no Cypress/Playwright specs surfaced).

---

## §20 · Performance / Scalability Reality

| Metric | Value | Source |
|---|---|---|
| Backend cold-start | ~3 s | Session-7 |
| Backend steady RSS | 27-378 MB (idle → 10× concurrent SEP) | Session-8 probe + Session-7 |
| Latency (typical `/api/die/analyze`) | ~100 ms p50 | Session-7 |
| Latency (LLM-augmented paths) | 5-90 s per `NIVX_AI_DEADLINE_S=90` | `backend/.env` |
| Upload cap (analyst) | 256 KB (client) · 512 KB (default middleware) · 50 MB (whitelisted paths) | `request_hardening.py` |
| Auto-Viz payload cap (frontend) | 32 KB | `WorkspacePage.jsx` |
| Ingestion throughput (adapters) | UNKNOWN — flags shadow | — |
| Artifact recursion depth | `NIVX_ENGINE_BUDGET_DEPTH=12` | `.env` |
| Wall-time budget per engine call | `NIVX_ENGINE_BUDGET_WALLTIME_MS=5000` | `.env` |
| Concurrent workers | 1 uvicorn worker + `--reload` | `ps` — **PROD RISK** if left in prod |
| Large-log behaviour | Silent fall-through to prose (Splunk `_raw` shape) | Session-7 |

**Concurrency reality:** the running pod is `uvicorn --workers 1 --reload` — reload is a **dev flag** and workers = 1 caps concurrent request throughput. A prod build should be `--workers N --no-reload`.

---

## §21 · Observability / Operations

| Facet | Status | Evidence |
|---|---|---|
| Logs | supervisor stdout/stderr; unstructured | `/var/log/supervisor/backend.*.log` |
| Metrics (Prometheus / OTEL / statsd) | NONE | grep confirmed no libraries |
| Tracing | NONE | — |
| Health checks | 3 endpoints: `/health`, `/api/health`, `/api/health/deep` | `server.py` |
| Worker monitoring | None (single uvicorn worker) | — |
| Queue monitoring | None (no queue) | — |
| DB monitoring | Mongo built-in only; no external exporter | — |
| Failure detection | Middleware emits X-Request-ID + logs 413/504 | `request_hardening.py` |
| Frontend telemetry | `POST /api/telemetry/frontend` · `frontend_telemetry` 52 docs | `routers/telemetry.py` |
| LLM telemetry | LiteLLM hook installed at startup | `server.py::_startup` L462 |

**Verdict:** Enough observability for a demo pod; **insufficient for a customer SLA**.

---

## §22 · Documentation-vs-Implementation Drift

| Doc claim | Reality | Contradiction? |
|---|---|---|
| `memory/ARCHITECTURE.md` describes the IEDDE / canonical pipeline | The `/api/die/*` path implements this | ✓ Aligned |
| `memory/NIVXRAY_ARCHITECTURE_V1.md` (older) references a different pipeline | Superseded but not deleted | Minor drift |
| `memory/ARCHITECTURE_v2.md` describes v2 IKG-first | v2 flags are `shadow`; no rows in v2 case collections | **Major drift** — v2 architecture is "documented + shadow only" |
| `memory/PRD.md` says "canonical projections are pure functions of authoritative tier" | True for `/api/die/investigation-results.object` | ✓ Aligned |
| `RC5_EVIDENCE_GRAPH_ROADMAP.md` — Phase 11.0 evidence graph side-car | `engine/evidence_graph.py` explicitly labels itself side-car | ✓ Aligned |
| `docs/WHITEPAPER.md` referenced but not read this session | UNKNOWN | Verify next session |
| `docs/SECURITY.md` referenced but not read this session | UNKNOWN | Verify next session |
| `README.md` (root, 29 bytes) | Placeholder | Trivial |
| Nivxforge sections claim "grounded in same enrichment sources" | Placeholder pages, no live backend | **Drift** — presentation implies capability that is not wired |
| v2 comments describe "v3.1b correlation engine" | Present, gated shadow | ✓ Aligned with code, misaligned with product state |

---

## §23 · Workspace vs X-Lab / Lab-2.0 Isolation

**Locked isolation surface (Do-Not-Break — locked by `test_workspace_isolation_guard.py`):**

- Shared modules the Workspace and any Lab MAY share:
  - `services/die/*` (canonical DIE)
  - `canonical/*` (IUE / SSOT / projections / executor)
  - `services/ida/*` (IDA)
  - `l1_evidence/case_store.py`, `l2_investigation/*`
  - `deps.py`, `schemas.py`

- Modules the Practice Lab exclusively owns:
  - `routers/lab.py` + `sample_library.py` + `lab_attempts`/`lab_stats` collections
  - `frontend/src/pages/LabPage.jsx`

- Removed (X-Lab-A observational surface):
  - `services/observation/*` (previously; residual `routers/observation.py` remains, 1 route — CANDIDATE FOR REMOVAL)

- Regression paths that could re-couple Workspace and Lab:
  - `services/die/investigation_results.py` — must never grow a Lab-aware branch.
  - `routers/observation.py` — should be removed or documented as read-only diagnostic.

**Rule preserved:** X-Lab / Lab 2.0 changes MUST NOT alter existing Workspace behaviour. Enforced by CI via `test_workspace_isolation_guard.py`.

---

## §24 · Current Architecture (as-shipped)

```
Analyst browser
   │
   ▼
[ Frontend Workspace (WorkspacePage.jsx · 4306 LOC) ]
   ├── /api/die/analyze                    → DIE analyze envelope (legacy + canonical narrative augment)
   ├── /api/die/investigation-results      → P0.3-locked payload (10 keys, 250 KB budget)
   │                                          ├── iocs · lolbas · mitre · narrative · ida
   │                                          ├── confidence · health · incident_tactics
   │                                          └── metadata · input
   ├── /api/die/timeline                   → Read-only projection of highconf_events
   ├── /api/die/query                      → Scoped filter projection (same event bag)
   ├── /api/upload                         → 256 KB / 64 KB text cap
   ├── /api/analyze/{smart,async,process-tree,shellcode}
   ├── /api/v2/analyze/report              → v2 renderer for reports (only /v2 endpoint FE calls)
   ├── /api/ioc/enrich, /api/planner/advise, /api/mitre/heatmap
   ├── /api/lab/*                          → Practice Lab
   ├── /api/nivxforge/preview/*            → Preview pages
   └── /api/threat-intel/*                 → Feed sync + IOC lookup

Backend request path
   ├── RequestHardeningMiddleware  (X-Req-Id, 512 KB body cap, per-path timeouts)
   ├── GZipMiddleware              (≥ 4 KB responses)
   ├── CORSMiddleware              (allow_origins=["*"], allow_credentials=True)
   ├── FastAPI api + app.include_router × 77 routers
   ├── Auth: JWT (PyJWT) + bcrypt hashed user in Mongo `users`
   ├── Async I/O: Motor (Mongo) + httpx (OSINT feeds)
   ├── LLM: LiteLLM shim (Emergent key) → Claude / OpenAI / Gemini
   └── Startup: seed admin (idempotent) + install LLM telemetry hook + start nightly benchmark loop

Shadow / non-authoritative pipeline (present but dormant)
   ├── backend/v2/investigation/  (IKG + verdict v3 + attack story + attack mapping + explainability + ikb)
   ├── backend/v2/verdict/        (engine v3, profiles, correlation, progressions, weights)
   ├── backend/v2/routers/        (12 sub-routers; all gated by NIVX_FLAG_*=shadow)
   ├── backend/v2/case_engine/    (dedicated schema + store)
   └── DB collections: v2_case_events/entities/behaviors/relationships/reports = 0 rows
```

---

## §25 · Architectural Weaknesses

1. **Two parallel investigation pipelines** (§6, §7) — beautiful v2 architecture, no shipping consumer. Maintenance cost on both.
2. **Ingestion is the platform's actual ceiling** — every "would-be-EDR" story dies at the 256 KB paste box.
3. **Deterministic-signature promise (§9.4) is untested at CI-time** — sellable "reproducible reports" claim is soft.
4. **Feature-flag flip is undocumented externally** — no runbook explains what flipping `VERDICT_ENGINE_V3=enabled` does to the response contract.
5. **Nivxforge frontend surface promises capabilities it does not deliver** — placeholder pages under active navigation blur product truth.
6. **CORS `*` + credentials + no rate-limit** — three overlapping security softness (§12).
7. **Single Mongo, single-tenant, no TTL** — data growth curve unmanaged (§13).
8. **77 routers on one uvicorn worker with `--reload`** — dev-shape, not prod-shape.
9. **4,306-line WorkspacePage.jsx** — regression risk with every new panel.
10. **Nightly benchmark is an in-process asyncio sleep-24h** — no k8s CronJob, no failure retry policy (§11.14).

---

## §26 · Target Architecture (only after §1-§25 is accepted)

Two-year sound target — **NOT a build order, just a shape.**

```
Analyst browser  ─► [ Workspace v5 (thin, panel-composable) ]
                        │
                        ▼
  Ingest tier ─►  [ Adapters: paste · upload · Sysmon/EVTX · CS · MDE · Splunk · Sentinel · Syslog ]
                        │
                        ▼
                  [ Canonical Event Bag (Kafka-shaped) ]
                        │
                        ▼
    Analysis tier ─► [ IUE Composer ] → [ Canonical Executor (budgeted) ]
                        │
                        ▼
                  [ AuthoritativeSSOT (append-only, provenance-mandatory) ]
                        │
                        ▼
      Projection tier ─► Verdict · MITRE · Attack Chain · Attack Story · IOC · LOLBAS
                          · Timeline · Executive Summary · Analyst Summary
                          · Recommendations · Reports (STIX/Sigma/YARA/Nav/MDR)
                        │
                        ▼
                  [ Investigation Knowledge Graph (persisted, per case) ]
                        │
                        ▼
      Consumers ─► Workspace panels · Threat-hunt (fleet-scale) · TAXII push · Reports
```

**Migration boundaries (do NOT migrate until):**
- No boundary crosses until each canonical projection has (a) a persistence writer, (b) a deterministic re-render CI gate, and (c) a documented consumer contract.
- Adapters ship only after **server-side file mode** exists (removes 256 KB ceiling).
- IKG is promoted from shadow to authoritative only when all v2 case collections write and the Workspace can consume `Investigation.to_dict()` directly.

---

## §27 · Production Readiness / Enterprise Readiness

| Dimension | State |
|---|---|
| Production-ready for demo / PoC single-tenant | **YES** |
| Production-ready for paying single-tenant SaaS customer | **NO** (§12.3, §12.10, §12.13, §12.19, §20 concurrency, §21 SLA gaps) |
| Enterprise-ready (multi-tenant, SSO, RBAC, audit) | **NO** (§12.5-§12.7, §12.21) |
| Air-gapped enterprise | **NO** (installer + offline-LLM path incomplete, §14) |

---

## §28 · Top Architectural Risks

1. **Selling the v2/IKG/Verdict-v3 story before flipping flags** — represents dormant code as production capability.
2. **Zip-bomb / archive-recursion on `/api/upload`** — unbounded unzip.
3. **CORS `*` + credentials** — spec-invalid; browser-dependent behaviour.
4. **No rate-limit / brute-force lockout** on login.
5. **Same-process parser isolation** for untrusted PE / DOCX / RC4 blobs.
6. **Client-side data caps** as the ONLY defense against large-input freeze.
7. **Silent Splunk `_raw` fall-through** — analysts get a prose result instead of a fail-loud "unsupported log shape".
8. **Docs drift** — v2 documented as authoritative; runtime says shadow.

---

## §29 · Top Capability Gaps

1. **Server-side file mode** (removes 256 KB ceiling).
2. **Sysmon / EVTX adapter** (turns Timeline / Query into a real telemetry hunt).
3. **Splunk `_raw` CSV recognition**.
4. **OSINT reputation wired into per-investigation IOC panel** (VirusTotal + AbuseIPDB live lookup).
5. **Attack Story wire-up on the workspace** (backend project done; UI consumer absent).
6. **Deterministic re-render CI gate** for STIX / Markdown / PDF (§9.4).
7. **Rate-limit / brute-force lockout** on login.
8. **Zip-bomb guard** on `/api/upload`.
9. **CORS hardening** — replace `*` with explicit origin allow-list.
10. **Route audit + deprecation** — 466 ops · 74 consumers ⇒ ~85% dead-or-admin.
11. **Byte-identical determinism guard** on reports.
12. **Multi-tenant model** (before selling multi-tenant).
13. **Prod-shape uvicorn** (multi-worker, no `--reload`) and structured logging.

---

## §30 · Top 10 Priorities (owner-facing)

1. **Feature-flag runbook + doc drift closure** — for every `NIVX_FLAG_*`, document promotion criteria and the exact response-contract diff when flipped.
2. **Server-side file mode** — persists uploads server-side, keeps only file id in React state. Removes 32 KB / 256 KB / 512 KB safety caps.
3. **Splunk `_raw` recognizer** in `csv_edr_analyzer.py`.
4. **Sysmon / EVTX adapter** feeding the canonical event bag Timeline / Query already consume.
5. **Attack Story panel wire-up** (backend done; UI missing).
6. **OSINT reputation wire-up (VT + AbuseIPDB)** on the IOC panel.
7. **Login throttle + zip-bomb guard + CORS explicit origins**.
8. **Deterministic re-render CI gate** for STIX / Markdown / PDF.
9. **Route audit + deprecation** — delete or admin-gate the ~85% dead surface.
10. **Split WorkspacePage.jsx into panels** to lower regression blast radius.

---

## §31 · CTO Verdict

**KEEP** (regression-locked, honest strengths):
- P0.2 evidence chain and P0.3 firewall.
- Canonical DIE pipeline (`services/die/*` + `canonical/*`).
- Timeline MVP and Query/Hunt MVP.
- Attack Chain 14-lane view.
- Practice Lab (`/api/lab/*`).
- Threat-Intel feed sync (65 K IOCs; 1,339 sync runs).
- Emergent LLM narrate path.
- Canonical verdict + Attack Story projections.

**FREEZE** (do not touch without a matching regression test):
- Everything under `services/die/*`, `canonical/*`, `routers/die.py`, `TrajectoryDiagram.jsx`, and Sample1 case row.

**REFACTOR** (production hygiene):
- `WorkspacePage.jsx` (4,306 → panels).
- 77-router `server.py` import block → grouped modules.
- Requirements freeze audit (`googleapiclient`, `stripe`, `boto3` unused).

**REMOVE / DEPRECATE**:
- `routers/observation.py` (1-route X-Lab residual).
- `/api/timeline` duplicate route (kept behind `/api/die/timeline`).
- Legacy `report_renderers.py` if `/api/v2/analyze/report` is the sole consumer for the Workspace.
- Nivxforge placeholder frontend sections (or clearly relabel them as "Coming soon" panels — do not surface in primary nav).

**COMPLETE** (finish before the next big architectural move):
- Server-side file mode.
- Deterministic-signature CI gate for reports.
- Attack Story UI wire-up.
- OSINT reputation panel.

**ISOLATE** (contain from Workspace regression):
- v2 architecture — keep shadow, keep tests green, but consider moving `/v2/*` frontend routes off the primary nav.
- All feature-flag-gated capabilities — document the promotion criteria per flag.

**BUILD NEXT** (in priority order):
1. Server-side file mode.
2. Splunk `_raw` recognizer.
3. Sysmon / EVTX adapter.
4. Attack Story wire-up.

**DO NOT BUILD YET** (would compound the two-pipeline debt):
- New v2 sub-features (case-engine expansion, more Adaptive Weight Profiles) — first flip existing v2 flags from shadow to enabled.
- Multi-tenant / SSO / Google Auth — not until §12.6-§12.7 gaps are policy-decided.
- Full EDR-vendor adapters (CrowdStrike, Defender, S1) — not until Sysmon/EVTX proves the ingest pipeline.
- STIX/TAXII pull ingestion — not until determinism CI gate is in place.

---

## §100 · Session-7 Snapshot (preserved, do not edit)

*Original evidence-backed sections from the Session-7 compact snapshot are preserved below for lineage. New readers should treat §1-§31 above as authoritative; §100 is included so the audit history remains intact.*

**Executive summary (S7):** NivXRay is a browser-based command-line + narrative + tabular-EDR analysis Workspace with a P0.2-locked evidence chain, Timeline MVP, Query/Hunt MVP, and Attack Chain view. It is NOT an EDR / XDR / SIEM ingestion platform. The strongest capability is the evidence chain; the weakest is large-input handling. Do-not-break: P0.2, P0.3, Sample1 immutability, X-Lab isolation, Timeline / Query contracts, Attack Chain lane fix.

**S7 top-10 priorities:** server-side file mode · Splunk `_raw` recognizer · wire WorkspaceRootErrorBoundary · Sysmon/EVTX adapter · observed-vs-referenced entity model · Attack Story wire-up · OSINT reputation · route audit · test-credentials reproducibility · full 60-section audit (now delivered in §1-§31).

*End of Session-8 master snapshot.*
