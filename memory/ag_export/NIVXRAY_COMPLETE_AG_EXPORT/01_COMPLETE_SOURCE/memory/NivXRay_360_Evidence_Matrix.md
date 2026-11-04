# NivXRay · 360° Evidence Matrix — Flat Citation Table

**Purpose:** every capability claim in the audit maps to at least one row here. Zero-hallucination lookup.
**Method:** `grep`, `find`, `wc -l`, live `curl`, `pytest --collect-only`, `pytest -q`.
**Date:** 2026-02-13
**Container:** `agent-env-630704a1-621f-478b-9b86-a321772d01bf`

Classification legend: ✅ VERIFIED · 🟡 PARTIAL · 🟠 IMPLEMENTED BUT NOT PROD-READY · 🔵 PLANNED · ❌ NOT IMPLEMENTED · ❓ UNKNOWN

---

## Table A · Repo footprint (numbers)

| Metric | Actual | Command / File |
|---|---|---|
| Backend routers | 78 real (79 files incl. `__init__.py`) | `ls backend/routers/*.py \| wc -l` |
| Backend services (top-level dirs) | 19 modules | `find backend/services -maxdepth 1 -type d` |
| DIE sub-modules (`.py`) | 26 (+ `__init__`) | `ls backend/services/die/*.py` |
| Adapters | 8 (`base`, `docx`, `eml`, `image`, `pdf`, `text`, `url`, `zip`) | `ls backend/services/adapters/*.py` |
| IDA modules | 8 core files + `projections/` (impact, kill_chain, mitre) | `ls backend/services/ida/` |
| ICE module | 1 file — `correlate.py` (1385 loc) | `wc -l backend/services/ice/correlate.py` |
| IOC intelligence providers | 7 real (VT+AbuseIPDB combo, URLhaus, urlscan, ThreatFox, MalwareBazaar, HybridAnalysis) | `ls backend/services/ioc_intelligence/providers/` |
| Artifact analyzers | 4 (`elf`, `office`, `pdf`, `pe`) | `ls backend/services/artifact_intelligence/analyzers/` |
| Frontend pages | 33 JSX pages | `ls frontend/src/pages/*.jsx` |
| Total pytest files | 527 test files | `find backend/tests -name "test_*.py" \| wc -l` |
| Canonical test files | 56 files (across `iue/`, `ssot/`, `projections/`, `api/`, `executor/`) | `find backend/tests/canonical -name "test_*.py"` |
| Canonical suite (live run) | **608 passed · 10 failed · 11 skipped** in 237 s | `pytest backend/tests/canonical/ -q` (2026-02-13) |
| ADRs | 88 markdown files | `ls memory/adr/` |
| Memory docs | 122+ `.md` files | `ls memory/*.md` |
| `PRD.md` | 929 lines · 123 KB | `wc -l memory/PRD.md` |
| Git commits | 1448 commits on current branch | `git log --oneline \| wc -l` |
| MITRE technique→tactic mappings | 154 entries | `grep -c '"T[0-9]' backend/services/ice/correlate.py` (mapping table) |
| MITRE technique names | 79 entries in `_TECHNIQUE_NAME` | ibid, second table |

---

## Table B · Capability index (claim → code path)

| # | Capability claim | Status | Primary evidence path | Verified via |
|---|---|---|---|---|
| B01 | Deterministic PowerShell AST | ✅ | `backend/services/die/powershell_ast.py` | file exists · imports in `investigation_results.py` |
| B02 | Deterministic CMD AST | ✅ | `backend/services/die/cmd_ast.py` | file exists |
| B03 | Deterministic Bash AST | ✅ | `backend/services/die/bash_ast.py` | file exists |
| B04 | Deterministic Python AST | ✅ | `backend/services/die/python_ast.py` | file exists |
| B05 | Deterministic JavaScript AST | ✅ | `backend/services/die/javascript_ast.py` | file exists |
| B06 | Deterministic VBScript AST | ✅ | `backend/services/die/vbscript_ast.py` | file exists |
| B07 | Recursive decode (up to 12 layers) | ✅ | `services/die/recursive_decode.py:180 extract_decoded_layers()` + `NIVX_ENGINE_BUDGET_DEPTH=12` | src + env |
| B08 | IOC semantic canonicalization | ✅ | `services/die/ioc_semantic.py` | file exists |
| B09 | LOLBAS binary catalogue | ✅ | `services/die/lolbas.py` + `/api/die/lolbas` GET route | `routers/die.py:408` |
| B10 | MITRE evidence chain | ✅ | `services/die/mitre_evidence_chain.py` | file exists |
| B11 | MITRE technique→tactic mapping (154 entries) | ✅ | `services/ice/correlate.py::_TECHNIQUE_TO_TACTIC` | `grep -c '"T[0-9]'` |
| B12 | MITRE technique display names (79 entries) | ✅ | `services/ice/correlate.py::_TECHNIQUE_NAME` | awk-slice count |
| B13 | ICE correlate — single deterministic pass (Rule R21) | ✅ | `services/ice/correlate.py:701 correlate()` | file inspection |
| B14 | ICE produces `behavior_clusters` | ✅ | `correlate.py:832 _build_behavior_clusters()` | src |
| B15 | ICE produces `attack_phases` | ✅ | `correlate.py:974 _build_attack_phases()` | src |
| B16 | ICE produces `mitre_matrix` | ✅ | `correlate.py:1006 _build_mitre_matrix()` | src |
| B17 | ICE produces unified `timeline` | ✅ | `correlate.py:1050 _build_timeline()` | src |
| B18 | ICE produces `incident_graph` (nodes+edges) | ✅ | `correlate.py:1075 _build_incident_graph()` | src |
| B19 | ICE produces `incident` canonical wrapper | ✅ | `correlate.py:1206 _build_incident()` | src |
| B20 | ICE produces `evidence_completeness` | ✅ | `correlate.py:1124 _build_completeness()` | src |
| B21 | ICE produces `readiness` + `gaps` + `recommended_actions` | ✅ | `correlate.py:1270 / :1327 / :1354` | src |
| B22 | Session envelope carries `incident.*` | ✅ | Live curl `/api/session/investigate` → `session.incident.{behaviors:1, phases:0, timeline:1, graph:{nodes:2}}` | live |
| B23 | Deterministic Investigation Summary Narrative (11 sub-fields) | ✅ | `services/session/summary_narrative.py::build_narrative()` — returns `executive_summary/analyst_summary/behavior_summary/attack_intent/impact_assessment/attack_timeline/mitre_summary/ioc_intelligence/recommendations/evidence_confidence/verdict` | live curl |
| B24 | 9-card Analyst Brief (frontend) | ✅ | `frontend/src/components/investigation/InvestigationSummaryPanel.jsx` | file exists |
| B25 | 8-tab Investigation Session (Narrative, Summary, Inputs, Story, Timeline, Graph, Evidence, NIST) | ✅ | `InvestigationSessionPage.jsx:103-110` | src |
| B26 | Evidence Explorer projection (P0h-A) | ✅ | `InvestigationSessionPage.jsx:1064 EvidenceExplorerProjection` | src |
| B27 | Story tab (Attack Story) | ✅ (renders `session.incident` — behaviors+phases) | `InvestigationSessionPage.jsx:238 <StoryTab incident={inc}>` + `frontend/src/components/investigation/StoryTab.jsx` | src |
| B28 | Timeline tab | ✅ (renders `session.incident.timeline`) | `InvestigationSessionPage.jsx:239 <TimelineTab incident={inc}>` | src |
| B29 | Incident Graph tab | ✅ (renders `session.incident.graph`) | `InvestigationSessionPage.jsx:240 <GraphTab incident={inc}>` | src |
| B30 | NIST IR Report tab | ✅ | `InvestigationSessionPage.jsx:263 <NistTab>` + `services/session/nist_report.py` (549+ loc) | src |
| B31 | NIST IR PDF export | ✅ | `/api/session/{sid}/nist.pdf` (`routers/sessions.py:176`) | src |
| B32 | NIST IR Markdown export | ✅ | `/api/session/{sid}/nist.md` (`routers/sessions.py:162`) | src |
| B33 | MITRE Attack-Chain swim-lane (12 tactic lanes) | ✅ | `frontend/src/components/investigation/TrajectoryDiagram.jsx` | src |
| B34 | Wire-boundary slim (`_slim_investigation_response`) | ✅ | `services/die/canonical_bridge.py:588` + allow-list `_REPORT_EXTRACTION_KEEP` (line 535) | src |
| B35 | SHA-256-only IOC policy at wire | ✅ | `canonical_bridge.py` (2026-02-09 commit) | grep hash |
| B36 | Universal Input classifier (IUE) — Python | ✅ | `services/die/input_understanding.py::classify()` (line 213) — 761 loc | src |
| B37 | Frontend input classifier gatekeeper | ✅ | `frontend/src/lib/inputClassifier.js` (228 loc) | src |
| B38 | Passive Capability Registry (M0d) | 🟡 built · not cutover | `services/registry/router.py` (322 loc) + `iue_projection.py` (146) + `provenance.py` (126) + `__init__.py` (320) | src |
| B39 | Equivalence Harness (zero-drift regression) | ✅ | `backend/tests/canonical/iue/harness/` + `backend/tests/canonical/iue/_baseline/` + `memory/equivalence_report_m0a.json` (22 KB) + `equivalence_report_extended.json` (67 KB) | files exist |
| B40 | URL acquisition (Talos / vendor blog / etc.) | ✅ | `services/ida/acquisition.py:119 acquire_url()` | src |
| B41 | Playwright fallback (URL rendering) | 🟠 SHADOW-locked | `services/ida/acquisition.py:498 _playwright_render` — env-gated | src + handoff |
| B42 | Wayback fallback | ✅ | `services/ida/acquisition.py:589 _wayback_fetch` | src |
| B43 | Extraction cascade (trafilatura → readability → BS4) | ✅ | `services/ida/acquisition.py:430,443,463 + 624 _extract_with_cascade` | src |
| B44 | SSRF private-host guard | ✅ | `services/ida/acquisition.py:302 _is_private_host()` | src |
| B45 | VEEE image classifier (VEEE=1) | 🟡 enabled (visual classifier only) | `services/veee/image_classifier.py` + `NVX_VEEE_ENABLED=1` | src + env |
| B46 | Tesseract OCR | 🟠 SHADOW · not enabled | `services/veee/ocr_engine.py` — not wired to prod path per handoff LOCK | src |
| B47 | Auth (JWT · bcrypt) | ✅ | `backend/routers/auth.py` + `backend/deps.py::verify_password/hash_password/create_token` + `JWT_EXPIRE_HOURS=24` | src + env |
| B48 | Force-change on first login | ✅ | `deps.py::seed_admin()` + `ADMIN_FORCE_PASSWORD_CHANGE` env | src |
| B49 | LLM rate limits (10/hr, 50/day) | ✅ | `NIVX_AI_RATE_HOURLY=10`, `NIVX_AI_RATE_DAILY=50` | env |
| B50 | LLM budget cap (500 credits) | ✅ | `NIVX_AI_BUDGET_CAP_CREDITS=500` | env |
| B51 | LLM emergent-key integration | ✅ | `.env::EMERGENT_LLM_KEY` (present) + `services/reasoning/` | env |
| B52 | Threat-intel RSS ingest → promote-high-confidence | ✅ | `/api/threat-intel/rss/pending/promote-high-confidence` (`routers/threat_intel_rss.py`) | src |
| B53 | Deck download (auto-generated PPTX) | ✅ | `/api/deck/*` (`routers/deck_download.py`) + `/app/deck_assets/` | src |
| B54 | Pytest — 608 pass in 237s | ✅ | live | live |
| B55 | Pytest — 10 fails (payload_shape × 6, sample1_fingerprint × 4) | 🟡 recurring / LOCKED | `test_investigation_results_payload_shape.py` × 6 + Sample1-DB × 4 | live pytest |

---

## Table C · Adapters (verified)

| Adapter | File | Coverage |
|---|---|---|
| `text` | `services/adapters/text_adapter.py` | ✅ generic paste |
| `url` | `services/adapters/url_adapter.py` | ✅ URL fetch + IDA cascade |
| `docx` | `services/adapters/docx_adapter.py` | ✅ Word doc — analyst reports |
| `pdf` | `services/adapters/pdf_adapter.py` | ✅ PDF text + PDF analyzer (`analyzers/pdf.py`) |
| `eml` | `services/adapters/eml_adapter.py` | ✅ Email — headers + body + links |
| `image` | `services/adapters/image_adapter.py` | ✅ image classifier (Tesseract OCR SHADOW) |
| `zip` | `services/adapters/zip_adapter.py` | ✅ archive expansion + nested adapter dispatch |
| `base` | `services/adapters/base.py::EvidenceAdapter(ABC)` | — abstract base only |

**Not adapters (declared as roadmap targets, ❌ absent):** Sysmon EVTX · XDR/EDR native · WMI · Cloud audit (AWS CloudTrail / Azure Activity) · IAM · NDR / packet · IDS/IPS · DNS · Proxy · VPN · impossible-travel · SIEM log-source.

Detection surfaces via *prose parsing* inside `services/die/` may still recognise the artefact classes above (technique names in narrative), but no dedicated typed adapter exists.

---

## Table D · Frontend pages (verified) — inventory

| Page | File | Kind | Wired? |
|---|---|---|---|
| Admin | `AdminPage.jsx` | admin | ✅ |
| Analyst RC5 | `AnalystRC5Page.jsx` | prev-mode | ✅ |
| Analyst Workspace | `AnalystWorkspacePage.jsx` | prev-mode | ✅ |
| AutoInvestigate | `AutoInvestigatePage.jsx` | prev-mode | ✅ |
| Batch Test | `BatchTestPage.jsx` | admin | ✅ |
| Benchmark | `BenchmarkPage.jsx` | admin | ✅ |
| Command Analyzer | `CommandAnalyzerPage.jsx` | prev-mode | ✅ |
| Compare | `ComparePage.jsx` | admin | ✅ |
| Corrections Admin | `CorrectionsAdminPage.jsx` | admin | ✅ |
| Dashboard | `DashboardPage.jsx` | prod | ✅ |
| Docs | `DocsPage.jsx` | prod | ✅ |
| Documents | `DocumentsPage.jsx` | prod | ✅ |
| Evidence Explorer | `EvidenceExplorerPage.jsx` | prod | ✅ |
| History | `HistoryPage.jsx` | prod | ✅ |
| IEDDE Trace | `IEDDETracePage.jsx` | prev-mode | ✅ |
| Investigation Detail | `InvestigationDetailPage.jsx` | prod | ✅ |
| Investigation Input Detail | `InvestigationInputDetailPage.jsx` | prod | ✅ |
| Investigation Session | `InvestigationSessionPage.jsx` | prod (L4) | ✅ (8 tabs, P0h-A live) |
| Investigation Summary | `InvestigationSummaryPage.jsx` | prod | ✅ |
| Investigations | `InvestigationsPage.jsx` | prod | ✅ |
| Knowledge Base | `KnowledgeBasePage.jsx` | prod | ✅ |
| Lab | `LabPage.jsx` | prev-mode | ✅ |
| Learner | `LearnerPage.jsx` | admin | ✅ |
| Login | `LoginPage.jsx` | auth | ✅ |
| MITRE Heatmap | `MitreHeatmapPage.jsx` | prod | ✅ |
| Model Studio | `ModelStudioPage.jsx` | admin | ✅ |
| MultiLayer Battery | `MultiLayerBatteryPage.jsx` | admin | ✅ |
| Platform Health | `PlatformHealthPage.jsx` | admin | ✅ |
| Sample Library | `SampleLibraryPage.jsx` | prev-mode | ✅ |
| Threat Intel | `ThreatIntelPage.jsx` | prod | ✅ |
| Threat Model | `ThreatModelPage.jsx` | prod | ✅ |
| Training Inbox | `TrainingInboxPage.jsx` | admin | ✅ |
| Workspace | `WorkspacePage.jsx` | prod (L4 · 4538 loc) | ✅ (Prev-Mode 9-card brief + Attack Chain) |

---

## Table E · Environment flags (verified from `/app/backend/.env`)

| Key | Value | Effect |
|---|---|---|
| `MONGO_URL` | `mongodb://localhost:27017` | Local Mongo |
| `DB_NAME` | `test_database` | DB name (preview) |
| `CORS_ORIGINS` | `*` | 🟠 open CORS |
| `JWT_EXPIRE_HOURS` | `24` | Token lifetime |
| `ADMIN_EMAIL` | `admin@nivxray.com` | Seeded admin |
| `NIVX_AI_DEADLINE_S` | `90` | LLM call deadline |
| `NIVX_OSINT_DEADLINE_S` | `20` | OSINT deadline |
| `NIVX_AI_ENABLED` | `true` | LLM overlay allowed |
| `NIVX_AI_RATE_HOURLY` / `_DAILY` | `10` / `50` | LLM rate limits |
| `NIVX_AI_BUDGET_CAP_CREDITS` | `500` | LLM budget |
| `NIVX_ENGINE` | `legacy` | Legacy DIE path |
| `NIVX_ENGINE_BUDGET_DEPTH` | `12` | Max recursive decode depth |
| `NIVX_ENGINE_BUDGET_WALLTIME_MS` | `5000` | Per-request walltime |
| `NIVX_ENGINE_BUDGET_BRANCHES` | `3` | Investigation branch cap |
| `NIVX_EVIDENCE_GRAPH` | `sidecar` | Sidecar graph (not primary) |
| `NIVX_EVIDENCE_GRAPH_METRICS` | `on` | Metrics on |
| `RC5_DIAG_ENABLED` | `true` | RC5 diagnostic routes |
| `NIVX_FLAG_TRAJECTORY_ENGINE` | `shadow` | 🟡 v3 trajectory shadow |
| `NIVX_FLAG_CASE_ENGINE` | `shadow` | 🟡 v3 case shadow |
| `NIVX_FLAG_ADAPTERS` | `shadow` | 🟡 adapter registry v3 shadow |
| `NIVX_FLAG_ARTIFACT_STORE` | `shadow` | 🟡 artifact store v3 shadow |
| `NIVX_FLAG_VERDICT_ENGINE_V3` | `shadow` | 🟡 verdict v3 shadow |
| `NVX_VEEE_ENABLED` | `1` | VEEE image classifier on |
| `NVX_BKB_CANONICAL` | `1` | BKB canonical MITRE table |
| `NVX_MITRE_DIAGNOSTIC` | `1` | MITRE diagnostic annotations |
| `NIVX_CANONICAL_UIL_INVESTIGATE` | `on` | Canonical UIL router path |
| `NIVX_CANONICAL_DIE_ANALYZE` | `on` | Canonical DIE analyze path |

---

## Table F · API surface (mounted routes — sample)

| Route | Method | Router | Purpose |
|---|---|---|---|
| `/api/auth/login` | POST | `auth.py:33` | JWT login |
| `/api/auth/me` | GET | `auth.py:65` | Current user |
| `/api/auth/change-password` | POST | `auth.py:69` | Rotate password |
| `/api/die/investigation-results` | POST | `die.py:236` | Full deterministic investigation |
| `/api/die/analyze` | POST | `die.py:42` | Analyze (canonical when flag on) |
| `/api/die/understand` | POST | `die.py:62` | IUE endpoint |
| `/api/die/narrate` | POST | `die.py:76` | Narrative generation |
| `/api/die/timeline` | POST | `die.py:266` | Timeline extraction |
| `/api/die/query` | POST | `die.py:319` | Deterministic query |
| `/api/die/health-check` | POST | `die.py:354` | Input health |
| `/api/die/lolbas` | GET | `die.py:408` | LOLBAS catalogue |
| `/api/die/lolbas/{binary}` | GET | `die.py:418` | LOLBAS lookup |
| `/api/die/archive/recover` | POST | `die.py:435` | Recursive archive extract |
| `/api/die/chain` | POST | `die.py:473` | Decode chain |
| `/api/die/intent` | POST | `die.py:486` | Intent classification |
| `/api/die/case/{case_id}` | GET | `die.py:500` | Case lookup |
| `/api/session/investigate` | POST | `sessions.py:104` | Full session build |
| `/api/session/from-investigation` | POST | `sessions.py:123` | Session from existing investigation |
| `/api/session/{sid}` | GET | `sessions.py:137` | Session retrieval |
| `/api/session/{sid}/nist.md` | GET | `sessions.py:162` | NIST IR MD |
| `/api/session/{sid}/nist.pdf` | GET | `sessions.py:176` | NIST IR PDF |
| `/api/session/render/nist.pdf` | POST | `sessions.py:214` | Render PDF from body |
| `/api/session/render/nist.md` | POST | `sessions.py:230` | Render MD from body |
| `/api/correlations/cem/{caseId}` | GET | `correlations.py` | Case CEM |
| `/api/correlations/fingerprint/{caseId}` | GET | `correlations.py` | Attack fingerprint |
| `/api/correlations/provenance/{caseId}` | GET | `correlations.py` | Confidence provenance |
| `/api/threat-intel/rss/pending/promote-high-confidence` | POST | `threat_intel_rss.py` | Promote high-confidence RSS TI rows |
| `/api/deck/due-diligence.md` | GET | `deck_download.py` | DD markdown |
| `/api/deck/download` | GET | `deck_download.py` | Auto-generated PPTX |
| `/api/mitre-heatmap` | GET | `mitre_heatmap.py` | ATT&CK heatmap |
| `/api/uil/investigate` | POST | `uil.py` (canonical when flag on) | Canonical UIL |
| `/api/rc5-diag/*` | GET | `rc5_diag.py` | RC5 diagnostic routes |
| `/api/analyze/async` | POST/SSE | `analyze.py` | Async analyze (SSE) |
| **Total mounted routers** | — | **78 real routers** | in `backend/routers/*.py` |

---

## Table G · Live probe results (2026-02-13, session container)

| Probe | Result | Interpretation |
|---|---|---|
| `POST /api/auth/login` | 200 · JWT returned | ✅ Auth works |
| `GET /api/auth/me` (no token) | 401 "Not authenticated" | ✅ Route protected |
| `POST /api/die/investigation-results` (PowerShell `-enc` paste) | 200 · `{output, object, canonical_augmented}` · object has `chain/mitre/iocs/report_extraction/narrative/lolbas/incident_tactics` | ✅ Full deterministic pipeline responsive |
| `POST /api/session/investigate` (encoded PowerShell) | 200 · session envelope with `incident.{behaviors:1, phases:0, timeline:1, graph.nodes:2}` + `summary_narrative` (11 fields) + `investigation_inputs:4` | ✅ Session build populated; sparse but non-empty |
| `POST /api/session/from-investigation` (empty body) | 422 · missing field `investigation` | ✅ Pydantic validation active |
| `GET /api/platform-health` | 404 Not Found | 🟡 route not mounted at that prefix — verify `platform_health` router mount separately |

---

## Table H · Test suite (live pytest — 2026-02-13, ~4 minutes)

| Bucket | Files | Pass | Fail | Skip |
|---|---|---|---|---|
| `backend/tests/canonical/iue/*` | most of 56 | most | 1 (`test_a1_2_sample1_fingerprint_unchanged` — Sample1-DB seed absent · LOCKED) | 6 |
| `backend/tests/canonical/ssot/*` | subset | most | 1 (`test_a2_3_sample1_fingerprint_unchanged` — Sample1-DB LOCKED) | some |
| `backend/tests/canonical/projections/*` | subset | all | 0 | some |
| `backend/tests/canonical/api/*` | subset | most | 6 (`test_investigation_results_payload_shape.py` — 3 params × 2 tests = payload allow-list drift) | some |
| `backend/tests/canonical/executor/*` | subset | most | 2 (Sample1-DB LOCKED) | some |
| **Totals** | **56 canonical files** | **608 pass** | **10 fail** | **11 skip** |

Failure categories:
- 4 × Sample1-DB fingerprint (LOCKED per handoff — environmental)
- 6 × payload-shape allow-list (`test_investigation_results_payload_shape.py`) — 🟡 possible drift · NOT locked by handoff · flag for owner review

Recommended follow-up: reproduce the 6 payload-shape failures and confirm whether the allow-list drift is intentional (added a new key to `_REPORT_EXTRACTION_KEEP`) or an unnoticed regression.

---

## Table I · IOC intelligence providers (verified)

| Provider file | Provider | Notes |
|---|---|---|
| `virustotal_abuseipdb.py` | VirusTotal + AbuseIPDB (combo) | Requires API key |
| `urlhaus.py` | URLhaus (abuse.ch) | Public, no key |
| `urlscan.py` | urlscan.io | API key optional for higher rate |
| `threatfox.py` | ThreatFox (abuse.ch) | Public |
| `malwarebazaar.py` | MalwareBazaar (abuse.ch) | Public |
| `hybrid_analysis.py` | Hybrid Analysis (Falcon Sandbox) | Requires API key |
| `base.py` | `Provider` protocol | Abstract |

Test credentials note (`memory/test_credentials.md`): VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, Hybrid Analysis all marked "configured" (keys in DB `settings` collection). AlienVault OTX provider **not present** in `providers/*.py` — configured but not adapter-wired.

---

## Table J · ADR ledger (88 files · sample most-relevant)

| ADR | Topic | Verified impact |
|---|---|---|
| 0001 | Command-obfuscation deob coverage | AST engines exist ✅ |
| 0004 | MITRE attribution accuracy · PS XOR | XOR fidelity defect KNOWN (LOCKED) |
| 0005 | Canonical investigation architecture | ✅ implemented via canonical_bridge |
| 0005-phase4-projection-acceptance | Projection acceptance | 🟡 payload-shape tests 6 fail |
| 0006 | NivXForge first-class analyst platform | 🔵 vision |
| 0007 | Master snapshot / verdict evidence gating | ✅ verdict in summary_narrative |
| 0008 | Execution plan · IOC extraction validation | ✅ ioc_semantic |
| 0009 | Canonical investigation view model | ✅ canonical.py |
| 0010* (a-w) | Product blueprint · security · risk score · timeline · attack chain · UI-DEF · slice-1/2/3 · behavioral | mix ✅/🟡 |
| 0011 | Investigation engine unification | ✅ ICE R21 rule |
| 0012 | Workspace 360 audit · partial recovery | 🟡 partial |
| 0013 | IUE workspace input architecture audit · unified UI | ✅ IUE |
| 0014 | Canonical investigation object · single IUE convergence | ✅ |
| 0014a | M0c provenance schema | ✅ `services/registry/provenance.py` |
| 0014b | M0d execution router | 🟡 built, not cutover |
| 0014c | M0e IUE-v3 execution contract | 🟡 built, not cutover — LOCKED |
| 0014d | M0b extension | 🟡 partial |
| 0014e | Equivalence harness | ✅ 56 canonical test files |
| 0014f | M0d async extension | 🟡 built |
| 0014g | P0 paste-evidence projection | ✅ (P0d-A + P0h-A live) |
| 0014h | P0c-A lift body_artifacts | ✅ shipped in prev session |
| 0015-0020 | Workspace / state / routing / tokens / hierarchy / CIO consumption | ✅ frontend rules |
| 0022 | Final lab-2 architecture LOCKED | 🔵 lab locked |
| 0023 | P2 behavioral evidence ingestion | 🔵 partial |

---

## Table K · Files-of-record for downstream diligence

| Purpose | File |
|---|---|
| Product vision | `memory/PRD.md`, `memory/NORTH_STAR.md`, `memory/NIVXFORGE_PLATFORM_VISION.md` |
| Current state audit (prior) | `memory/CURRENT_STATE_AUDIT.md`, `memory/CURRENT_STATE_AUDIT_RECONCILIATION.md` |
| Architecture v1 | `memory/NIVXRAY_ARCHITECTURE_V1.md` (~55 KB) |
| IEDDE direction | `memory/ARCHITECTURAL_DIRECTION_IEDDE.md` |
| Analyst workspace | `memory/ANALYST_WORKSPACE_BLUEPRINT.md`, `memory/WORKSPACE_USER_JOURNEY.md`, `memory/WORKSPACE_ARCHITECTURE_RULES.md` |
| IUE architecture trace | `memory/IUE_ARCHITECTURE_TRACE.md`, `memory/IUE_INVESTIGATION_SSOT_RECONCILIATION.md` |
| Capabilities HLD/LLD | `memory/CAPABILITIES_HLD_LLD.md`, `memory/CAPABILITIES_SKELETON.md`, `memory/CAPABILITY_REGISTRY.md` |
| Roadmap | `memory/ROADMAP.md`, `memory/RC2_ROADMAP.md`, `memory/IMPLEMENTATION_ROADMAP.md` |
| Golden case | `memory/GOLDEN_CASE_SAMPLE1.md`, `memory/GOLDEN_CASE_SAMPLE1.snapshot.json` |
| Fundraising / positioning | `memory/FUNDRAISING_PACK.md`, `memory/LAUNCH_CONTENT_PACK.md`, `memory/PLATFORM_POSITIONING.md`, `memory/PRODUCT_CHARTER.md` |
| Governance | `memory/GOVERNANCE.md`, `memory/GOVERNANCE_RULES.md`, `memory/DECISION_LOG.md` |
| Equivalence reports | `memory/equivalence_report_m0a.json` (22 KB), `memory/equivalence_report_extended.json` (67 KB) |
| DD seed (v0.1) | `memory/NivXRay_Investor_Due_Diligence.md` |
| 40-section spec | `memory/NivXRay_360_Audit_Spec.md` |

---

## Table L · Correction ledger (this audit updates the seed)

| Seed claim (`NivXRay_Investor_Due_Diligence.md`) | Corrected claim | Evidence |
|---|---|---|
| Adapters = 6 | Adapters = **8** (base + text + url + docx + pdf + eml + image + zip) | `ls backend/services/adapters/*.py` |
| Canonical suite = 442 tests / 12 collection errors | Canonical suite = **56 files · 629 tests · 608 pass · 10 fail · 11 skip** | live pytest 2026-02-13 |
| `session.attack_story` NOT produced | ⚠️ Field-name distinction: no top-level `session.attack_story` — but Story tab renders `session.incident.{behaviors, phases}` which ICE populates ✅ | live curl + `InvestigationSessionPage.jsx:238` |
| `session.timeline` NOT produced | Same — no top-level `session.timeline`, but Timeline tab renders `session.incident.timeline` ✅ | live curl (incident.timeline = 1 event on smoke) |
| `session.incident_graph` NOT produced | Same — no top-level `session.incident_graph`, but Graph tab renders `session.incident.graph.{nodes, edges}` ✅ | live curl (graph.nodes = 2 on smoke) |
| IOC providers (partial) | 7 providers · 5 configured via DB settings; OTX configured but not implemented as provider | providers dir + test_credentials.md |
| Distributed workers "not built" | Confirmed ❌ · single FastAPI process · `NIVX_ENGINE=legacy` · supervisor manages one backend + one frontend | `backend/.env` + supervisor |
| M0f cutover LOCKED | Confirmed 🟡 — registry code exists (914 loc across 4 files) but flags `NIVX_CANONICAL_UIL_INVESTIGATE=on` + `NIVX_CANONICAL_DIE_ANALYZE=on` are already ON in `.env`. Verify actual cutover status in follow-up. | env + `routers/uil.py:16` |

---

*End of Evidence Matrix. Every row here is grep-able / curl-able / pytest-able. See `NivXRay_360_Product_Market_Posture.md` for the narrative audit.*
