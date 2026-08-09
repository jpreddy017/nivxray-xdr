# NivXRay — 360° Current-State Audit
_Date: 2026-02-09 · Author: E1 (via factual repo inspection · no code changes)_

> **Rules followed**: files/paths/tests cited as evidence. `IMPLEMENTED / PARTIAL / STUB / DOC-ONLY` distinguished. Demo/seed behaviour separated from production. Where uncertain → marked `UNKNOWN`.

---

## Repository shape (raw baseline)

| Surface | Count | Evidence |
|---|---|---|
| Backend service dirs | 20 | `/app/backend/services/*/` |
| API routers | 75 files | `/app/backend/routers/*.py` |
| API endpoints (@router.*) | **401** | `grep -rE "@router\\.(get\|post\|put\|delete\|patch)" backend/routers/` |
| Backend Python test files | **372** | `/app/backend/tests/*.py` |
| Frontend pages | 34 | `/app/frontend/src/pages/` |
| Frontend components (.jsx) | 138 | `/app/frontend/src/components/` |
| Memory/docs (.md) | **89** | `/app/memory/*.md` |
| ADRs | 3 | `/app/memory/adr/` |
| Evidence adapters | 9 | `/app/backend/services/adapters/` |
| UAIE plugins/capabilities | 42 | `/app/backend/services/uaie/plugins/` |
| DIE modules | 21 | `/app/backend/services/die/*.py` |
| BKB behavior entries | 532 lines (108 documented entries) | `/app/backend/services/knowledge/behavior_registry.py` |

Sample regression run: **196/196 pass** on the classifier/BKB/quality-dashboard/input-understanding suite (fast subset, ~4 s).

---

## 1 · Executive Product Posture

**What NivXRay actually is TODAY:**
A **single-analyst DFIR workspace** that accepts pasted commands / URLs / small artifacts, decodes multi-layer obfuscation, extracts commands + IOCs + MITRE, and renders an Investigation SSOT with a Trajectory canvas and Kill-Chain narrative. It is **not** an EDR/XDR ingestion product, **not** a multi-tenant SaaS, **not** a real-time telemetry consumer.

| Question | Honest answer |
|---|---|
| Current product definition | A deterministic-first, evidence-driven "decoder + investigator" for individual DFIR analysts working from vendor reports & pasted telemetry |
| Problem solved today | "I have this weird PowerShell / base64 blob / URL — what does it do and where does it map on ATT&CK?" |
| Who can use it TODAY | A single trained SOC/DFIR analyst investigating one payload at a time |
| Strongest capabilities | (1) multi-layer decoder chain; (2) BKB-driven semantic classification (108 canonical behaviors); (3) Trajectory EDR canvas; (4) 372-test regression discipline |
| Weakest areas | (1) telemetry ingestion (none for real EDR feeds); (2) analyst UX under stress (freeze/black-screen SLA still fragile); (3) multi-tenant isolation; (4) real recursive-artifact fixed-point analysis |
| Genuinely differentiated | Deterministic-first pipeline with BKB as single source of truth (rare among competitors that rely on LLM opinions) |
| Partially implemented | Recursive artifact discovery, evidence graph, evidence delta engine, capability contracts (charter written, code not started) |
| Documented but NOT implemented | Multi-dimensional confidence (R28.9), goal-driven planner (R29), Investigation Knowledge Economy (R28.8), Investigation Playback UI |
| Demo/seed-only | Multi-command chain UX (works well on curated 3-5 stage inputs; degrades on real 20+ command telemetry) |
| Blocks calling this production-ready | (1) no real EDR/telemetry adapters; (2) freeze under 7 KB+ input on some browsers; (3) no multi-tenant model; (4) no audit log; (5) no rate limiting on decoder endpoints |

### Maturity Scores (0-10)

| Rung | Score | Evidence |
|---|---|---|
| Prototype | 10/10 | Every claimed feature has running code |
| Functional product | 8/10 | 401 endpoints, 34 pages, 372 tests, decoder chain proven end-to-end |
| Analyst-ready | 5/10 | Works for a trained analyst on curated inputs; UX freeze bugs still surface |
| Enterprise-ready | 2/10 | No RBAC beyond single admin; no audit log; no tenant isolation; no rate limits |
| Production-ready | 3/10 | Deploy works; observability minimal; no backup/restore proven; scaling story absent |

---

## 2 · Complete Architecture Inventory

| Component | Path | Status | Coupling risk |
|---|---|---|---|
| **Frontend** (React + CRA + Tailwind) | `/app/frontend/` | IMPLEMENTED | `WorkspacePage.jsx` is a 3,982-line monolith (SEVERE coupling) |
| **Backend** (FastAPI) | `/app/backend/server.py` + 75 routers | IMPLEMENTED | 401 endpoints, no versioning at path level |
| **API surface** | `/app/backend/routers/*.py` | IMPLEMENTED | Many overlapping decoder routers: `chain.py`, `iedde.py`, `decoded_artifacts.py`, `analyze.py`, `analyst_v2.py`, `auto_investigate.py` |
| **Database** (MongoDB) | Motor async client · `MONGO_URL` from `.env` | IMPLEMENTED | Single DB, no read-replica separation |
| **Storage** | (attachments in Mongo GridFS) | PARTIAL | UNKNOWN if files >16 MB are supported |
| **Queues / Workers** | *none* | NOT PRESENT | All work happens on request thread |
| **Redis** | *none* | NOT PRESENT | No cache layer |
| **Nginx / reverse proxy** | Emergent ingress | EXTERNAL | Not owned by NivXRay |
| **Docker** | Emergent-managed | EXTERNAL | Not owned |
| **Authentication** | `/app/backend/routers/auth.py` · JWT + bcrypt | IMPLEMENTED | Single admin, no user table workflow |
| **Authorization** | Admin flag only | PARTIAL | No RBAC roles beyond admin/user |
| **Logging** | Python `logging` module | PARTIAL | No structured JSON logs, no correlation IDs |
| **Configuration** | `/app/backend/.env` (20+ env keys) | IMPLEMENTED | No hot reload; no per-env override; secrets in plaintext env file |
| **Feature flags** | `NIVX_*` env vars (~10 flags) | PARTIAL | No runtime toggling; each requires backend restart |
| **External integrations** | OTX, URLScan, Emergent LLM Key | PARTIAL | Rate limits set but no circuit breaker |
| **Background jobs** | `auto_investigate_jobs.py` router | PARTIAL | In-process only; no persistence across restart |
| **Caching** | *none* | NOT PRESENT | Every decode is fresh |
| **Telemetry / Metrics** | `platform_metrics.py`, `coverage_metrics.py` | PARTIAL | Endpoints exist; no Prometheus scraper |
| **Error handling** | FastAPI exception handlers | PARTIAL | Frontend added global handler today (2026-02-09); backend still returns some 500s bare |

**SEVERE architectural debt (P0):**
- `WorkspacePage.jsx` = **3,982 lines** in one file → the freeze bugs you hit are architectural, not bugs
- Redundant decoder routers: 6 different endpoints do overlapping decoding
- `services/uaie/` (76 files) and `services/die/` (37 files) both host "the investigation engine" — unclear which is authoritative
- 89 `memory/*.md` docs → most are historical; hard to know which are current

---

## 3 · Capability Inventory

| Input type | Status | Evidence |
|---|---|---|
| **Command lines** (Windows/Unix) | IMPLEMENTED | `services/canonicalizer/`, `services/die/cmd_ast.py`, `services/die/bash_ast.py` |
| **PowerShell** (incl. -EncodedCommand) | IMPLEMENTED | `services/die/powershell_ast.py`, `uaie/plugins/powershell_encoded_command/` |
| **Base64** (single + multi-layer) | IMPLEMENTED | `services/die/preprocessor/recursive_decoder.py` (proven end-to-end today) |
| **VBScript** | PARTIAL | `services/die/vbscript_ast.py` exists; not exercised by workspace |
| **JavaScript** | PARTIAL | `services/die/javascript_ast.py` exists |
| **Python** | PARTIAL | `services/die/python_ast.py` exists |
| **URLs** (with acquisition) | IMPLEMENTED (today) | Wayback fallback shipped today; Imperva/Cloudflare interstitials bypassed |
| **PE (Windows executable)** | PARTIAL | `services/pe_analyzer.py` + `uaie/plugins/pe_analyzer/` — parses headers, no full disassembly |
| **ELF** | NOT SUPPORTED | No adapter |
| **Office (DOCX)** | IMPLEMENTED | `services/adapters/docx_adapter.py` |
| **PDF** | IMPLEMENTED | `services/adapters/pdf_adapter.py` |
| **EML (email)** | IMPLEMENTED | `services/adapters/eml_adapter.py` |
| **ZIP archives** | IMPLEMENTED | `services/adapters/zip_adapter.py` |
| **Images (screenshots / OCR)** | PARTIAL | `services/veee/` (Visual Evidence Extraction Engine) — OCR runs, not all downstream flows consume it |
| **Sysmon / Windows Events (EVTX)** | NOT SUPPORTED | No adapter, no parser |
| **JSON/NDJSON (telemetry)** | NOT SUPPORTED | No adapter |
| **CSV (SIEM export)** | NOT SUPPORTED | No adapter |
| **CrowdStrike/Defender/SentinelOne/Cisco/Wazuh/Elastic telemetry** | NOT SUPPORTED | No connectors |
| **Shellcode analysis** | IMPLEMENTED | `uaie/plugins/shellcode_analyzer/`, `shellcode_string_scan/` |
| **Cobalt Strike beacon config** | IMPLEMENTED | `uaie/plugins/cs_beacon_config_parser/` |
| **AES/RC4 crypto** | IMPLEMENTED | `uaie/plugins/crypto_aes_cbc/`, `crypto_rc4/`, `op_rc4_inline_decrypt/` |

**IOC extraction** (per `services/ioc_intelligence/`, 14 files): IPs, URLs, domains, hashes, emails — IMPLEMENTED. **Defanged form (`149[.]28[.]81[.]19`) — PARTIAL** (I confirmed today that the article's defanged IP was NOT extracted by the top-level IOC extractor; only surfaced from the chain decoder).

---

## 4 · Universal Input + Artifact Pipeline

Traced from actual code:

```
INPUT (WorkspacePage.jsx → /api/decode/*, /api/die/*, /api/auto-investigate)
  ↓
[Router] `services/adapters/*` .can_handle() vote — Ohly URL/text/PDF/DOCX/EML/IMG/ZIP paths implemented
  ↓
[Artifact identification] `services/die/input_understanding.py::classify()` — 12+ classifier branches
  ↓
[Analyzer selection] Fixed routing in autoInvestigate() (not a plugin system today)
  ↓
[Analysis] DIE (`services/die/api.py::analyze`) — AST + LOLBAS + MITRE + IOCs
  ↓
[Decoder] `services/die/preprocessor/recursive_decoder.py::peel_recursively`
     ↳ Layers proven today: base64 → utf-16-le → base64 → gzip → XOR-loop → shellcode
  ↓
[Recursive Artifact Discovery] — **PARTIAL / claimed but weak**
     ↳ `services/recursive_child_pipeline.py` exists (18 KB)
     ↳ Termination: `max_layers=8` (hard-coded) + `max_bytes=2 MB`
     ↳ Duplicate detection: content-hash check
     ↳ No true fixed-point convergence proof; no cycle detection beyond hash
  ↓
[Registry / Planner] `services/recipe_planner.py`, `uaie/planner.py`, `uaie/planner_v2.py` — 3 planners coexist
  ↓
[Correlation] `services/correlation_engine.py`, `services/ice/correlate.py` (BKB projection)
  ↓
[Evidence] `services/uaie/evidence.py`, `uaie/ledger.py`, `uaie/provenance.py` — IMPLEMENTED
  ↓
[IKG / Investigation Knowledge Graph] — **NOT IMPLEMENTED**
     ↳ Documented in `NIVXRAY_ARCHITECTURE_V1.md` and `RC5_SEMANTIC_ENGINE_SPEC.md`
     ↳ No graph store, no node/edge model persisted
  ↓
[Verdict] `services/die/investigation_results.py::render` + `services/uaie/orchestrator.py`
  ↓
[Attack Story] `services/reasoning/behavior_extractor.py`
  ↓
[ATT&CK] Static map in `services/knowledge/behavior_registry.py` (108 entries)
  ↓
[Report] rendered as text in `render()` output; no PDF/PPT generator exists (Emergent PPTX in `NIVXRAY_ENTERPRISE_DEMO.pptx` is static)
```

**Verdict on Recursive Artifact Discovery**: The **decoder** does recursive peeling (proven today). The **artifact** layer (a decoded artifact becoming its own new investigation with its own child artifacts) is **PARTIAL** — `recursive_child_pipeline.py` exists but has no visible activation from the workspace UI flow. **This is a documented capability that is not exercised in the analyst path today.**

---

## 5 · Investigation Engine Audit

| Component | What exists | Works? | Missing | Prod-capable? |
|---|---|---|---|---|
| **Investigation Knowledge Graph** | 0 files; only spec docs | ✗ | Whole thing | No |
| **Evidence Graph** | `uaie/ledger.py`, `uaie/provenance.py` | Partial — flat list, not a graph | Node/edge model, path queries | No |
| **Process Tree** | Not implemented (no telemetry ingest) | ✗ | Whole thing | No |
| **Device Trajectory** | `TrajectoryDiagram.jsx` (1,162 lines) | ✓ Renders BKB projections | Real host trajectory (needs telemetry) | Partial |
| **Attack Story** | `reasoning/behavior_extractor.py` (500+ lines) | ✓ For BKB inputs | LLM-narrative fallback exists but non-deterministic | Partial |
| **ATT&CK mapping** | Static in `knowledge/behavior_registry.py` | ✓ 108 entries → T-IDs | Sub-technique coverage sparse | Partial |
| **Negative Explainability** | UNKNOWN — searched, no dedicated module | ✗ | Whole thing | No |
| **Evidence Cards** | Rendered inline in output text | Partial | Interactive UI card component | No |
| **Verdict Engine** | `services/die/investigation_results.py` + `uaie/orchestrator.py` | Partial | See §6 | No |
| **Report Generator** | Plain-text `render()` output | Partial | PDF, HTML, DOCX export | No |
| **Correlation engine** | `correlation_engine.py`, `ice/correlate.py` | ✓ For BKB clusters | Cross-case correlation | No |
| **Timeline logic** | Trajectory canvas renders positional timeline | ✓ For inline analysis | Real timestamped event timeline | No |

Hard-coded: BKB mappings (108 entries), all MITRE technique names, XOR loop detection heuristics, most classifier branches. Seed-data-dependent: nothing critical — the BKB IS the seed data.

---

## 6 · Verdict Engine Audit

Traced from `services/uaie/orchestrator.py` + `services/die/investigation_results.py`:

- **Inputs**: {command_count, iocs_count, mitre_count, lolbas_count, obfuscation_score, dkp_family_match, chain_reached_shellcode}
- **Weights**: **hard-coded in Python** (`obfuscation_score >= 60 → +30`, `reached_shellcode → +40`, `dkp_match → +50`)
- **Thresholds**: Benign <40 · Suspicious 40-69 · Malicious ≥70 (approx — no single source of truth file)
- **Confidence**: derived from stage confidences (mean) in chain endpoint
- **Posture**: `attack_intent` field on each command; aggregated by `orchestrator.py`

**Realistic failure scenarios (10):**
1. **Legitimate administrator uses `-EncodedCommand` for a config script** → verdict "Malicious" (false positive)
2. **Ransomware note in a `.txt` file with no commands** → no verdict signal → "Benign" (false negative)
3. **PowerShell obfuscation for legitimate DLP tool (Deep Freeze, some EDRs)** → false positive
4. **Living-off-the-land: `certutil -decode legit.b64 legit.exe`** → LOLBAS hit → "Malicious" without context
5. **Analyst pastes a partial base64 blob (truncated)** — verdict inflates because reached_shellcode is false but pattern matches
6. **Attacker uses novel packer with unknown XOR key** — chain returns 0 layers → "Benign"
7. **Two chained but unrelated commands in same paste** — verdict aggregation may over-count MITRE
8. **URL that redirects to a benign KB article containing PowerShell examples** — extractor pulls "example" commands → false positive
9. **Base64 that base64-decodes to another base64 (nothing interesting)** — chain runs, "obfuscation_score" trips → false positive
10. **Threat intel report of a NEW variant** — no BKB entry → all techniques miss → verdict falls to "Suspicious" by default

**Hard-coded assumptions:** obfuscation always == malicious intent, LOLBAS presence always == suspicious. Neither is universally true.

---

## 7 · Detection + ATT&CK Coverage

**BKB entries: 108** (`services/knowledge/behavior_registry.py`, 532 lines).

Coverage distribution (approximate, from BKB entries):

| Tactic | Techniques covered | Notes |
|---|---|---|
| Execution (TA0002) | ~18 | Heavy: PS, WScript, MSHTA, WMI, scheduled tasks |
| Persistence (TA0003) | ~14 | Run keys, services, scheduled tasks, WMI subscription |
| Defense Evasion (TA0005) | ~22 | Obfuscation, encoded commands, hidden windows, DLL sideloading |
| Discovery (TA0007) | ~15 | whoami, net.exe, systeminfo, nltest, hostname, WMI discovery |
| Lateral Movement (TA0008) | ~8 | SMB admin share, WMI-exec, PsExec, RDP |
| Credential Access (TA0006) | ~6 | Mimikatz, LSASS, DPAPI, SAM/SYSTEM copy |
| C2 (TA0011) | ~9 | HTTPS beacon, DNS-tunnel, IEX-download |
| Exfiltration (TA0010) | ~4 | Web upload, DNS exfil |
| Impact (TA0040) | ~4 | Ransomware note, shadow copy delete, boot-record wipe |
| **Gaps** | | Cloud (TA0007.007), Container (TA0007.020), Mobile — **zero** |

Distinction:
- **Can identify** technique: 108
- **Can prove** with evidence chain: ~40 (those that have LOLBAS + BKB signature)
- **Can correlate** into an attack chain: ~15 (only clusters with multi-stage BKB entries)

---

## 8 · Recursive / Multi-Stage Analysis

**Decoder recursion (`preprocessor/recursive_decoder.py::peel_recursively`)**:
- max_layers=8, max_bytes=2 MB (hard caps)
- Duplicate detection: SHA-256 content hash of layer output
- Cycle detection: hash-set membership
- **Termination guaranteed**: yes (max_layers OR unchanged output)
- **Proven end-to-end today**: base64 → utf-16le → base64 → gzip → XOR-loop → shellcode (4-layer peel of Sophos payload)

**Artifact recursion** (`recursive_child_pipeline.py`):
- File exists, 18 KB
- **UNKNOWN** if the current workspace UI actually invokes it
- Provenance model exists in `uaie/provenance.py` but not wired to workspace `render()` output
- Parent-child relationships: PARTIAL (stored in chain response, not persisted across investigations)

---

## 9 · Testing + Quality Audit

- Total backend test files: **372**
- Sample subset run today: **196 passed, 0 failed** (fast tests)
- **UNKNOWN** for the full suite — I did not run all 372
- Golden corpus: `/app/backend/corpus/vendor/v1/reports/` (Talos/Sophos/Mandiant curated)
- CI gates locked (per PRD): generic_fallback ≤ 4, OCR confidence ≥ 0.72, BKB coverage ≥ 108
- E2E tests: `/app/test_reports/` exists but empty; some Playwright tests live under `backend/tests/`

**Distinction**: **Tests passing** ≠ **product validated on real telemetry**. The corpus covers ~20 curated reports. Zero validation against streaming Sysmon EVTX, Defender ATP, CrowdStrike Falcon telemetry.

---

## 10 · Real-World Readiness

| Source | Status | Adapter path |
|---|---|---|
| **CrowdStrike telemetry** | NOT SUPPORTED | — |
| **Microsoft Defender ATP** | NOT SUPPORTED | — |
| **SentinelOne** | NOT SUPPORTED | — |
| **Cisco XDR** | NOT SUPPORTED | — |
| **Wazuh** | NOT SUPPORTED | — |
| **Elastic Security** | NOT SUPPORTED | — |
| **Sysmon EVTX** | NOT SUPPORTED | — |
| **Windows Event Logs** | NOT SUPPORTED | — |
| **SIEM alerts** | NOT SUPPORTED | — |
| **Email (EML)** | READY | `services/adapters/eml_adapter.py` |
| **Malicious documents (DOCX, PDF)** | READY | `services/adapters/docx_adapter.py`, `pdf_adapter.py` |
| **Malware samples (PE headers)** | PARTIAL | `services/pe_analyzer.py` — parse only, no full disassembly |
| **Encoded command lines** | READY | fully proven today |
| **URLs** | READY (with Wayback fallback) | shipped today |

**Conclusion**: NivXRay today is a **payload / artifact analyzer**, not a **telemetry / EDR analyzer**. Every EDR/SIEM source requires a new ingestion adapter — none exist.

---

## 11 · Performance + Scalability

Measurements from today's session:
- `/decode/chain` on 7,624-char PowerShell blob: **~2 s** backend
- Full URL acquire + chain: **~11 s** (Wayback fetch is the slow part)
- Workspace tree reconciliation on 7 KB paste: **~3.6 s** (was 15+ s before today's fixes)
- 401 endpoints on FastAPI single worker

**Concurrency**: Single-worker uvicorn (per supervisor config). No horizontal scaling story.
**Redis/MongoDB usage**: No Redis. Mongo used for case storage, corpus, history.

**Bottlenecks by workload:**
| Workload increase | Breaks first |
|---|---|
| 10x concurrent analysts | Backend single-worker CPU-bound on decode |
| 100x | Mongo query load (case queries unindexed for some fields) |
| 1000x | Frontend WorkspacePage.jsx render cost dominates before backend does |

---

## 12 · Security of NivXRay Itself

| Risk | Status | P |
|---|---|---|
| Authentication | ✓ JWT + bcrypt | — |
| Authorization | Partial (admin flag only) | **P1** |
| Tenant isolation | **None** (single-tenant design) | **P0 for enterprise** |
| Input validation | Partial — decoder inputs are capped, but many endpoints trust body | P1 |
| File upload security | PARTIAL — no MIME/magic-byte re-verification post-upload | P1 |
| Command execution risks | Low — no `os.system` / `subprocess` on user input found | — |
| Sandboxing | **None** — decoder runs in-process, no VM/container isolation | **P0** for real malware |
| SSRF | URL fetcher fetches arbitrary user-supplied URLs → **YES SSRF possible** | **P0** |
| Path traversal | Attachments stored in Mongo GridFS — low risk | — |
| Injection | Mongo queries use parameterized calls | — |
| Secrets management | `.env` in plaintext, no vault | P2 |
| Rate limiting | AI rate limit set; decoder endpoints unlimited | **P1** |
| Malicious archive handling | ZIP adapter uses zipfile — vulnerable to zip-bomb if user uploads | **P1** |
| Resource exhaustion | max_layers=8, max_bytes=2 MB — some protection | Partial |
| Container isolation | Emergent pod = single container | External |

**P0 items requiring urgent attention if going enterprise:**
1. SSRF on URL acquisition endpoint (`/api/decode/*` and IDA acquisition can fetch internal 169.254.x.x metadata IPs)
2. Sandboxing for malware payload analysis
3. Multi-tenant isolation model

---

## 13 · Frontend / Analyst UX Audit

| Workflow stage | Status | Notes |
|---|---|---|
| INPUT | ✓ Works | Freeze under 7 KB+ shipped mitigation today |
| INVESTIGATE (Auto) | ✓ Works | Auto-chain routing added today |
| RESULTS text | ✓ Works | 200-line text panel |
| EVIDENCE | Partial | Rendered inline, no dedicated evidence explorer for the main workspace |
| ATT&CK panel | ✓ Works | Reads `analysis.mitre` |
| Attack Story | Partial | Prose in main output, no interactive story view |
| Trajectory | ✓ Works | EDR-style canvas, 14 lanes |
| Verdict card | Partial | Shows badge, but rationale is minimal |
| Report export | **Missing** | No PDF/DOCX/PPTX generator wired |

**Broken / confusing / debt UX:**
- `WorkspacePage.jsx` is a **3,982-line monolith** — the freeze bugs and race conditions are downstream of this
- Duplicate concepts across pages: Workspace, AnalystWorkspacePage, AnalystRC5Page, AutoInvestigatePage, InvestigationSessionPage all exist
- Placeholder / dead UI: TrainingInboxPage, LearnerPage, ModelStudioPage, SemanticMappingInspectorPage — **presence unclear if fully wired**
- Inconsistent terminology: "case" vs "investigation" vs "session" vs "workspace" — all overlap

**Verdict on: could an experienced SOC analyst investigate a real incident using this today, without external tools?**
- For a **pasted-blob** investigation: **Yes.**
- For a **real EDR ticket** with attached telemetry / EVTX / process trees: **No.** They'd need CyberChef + Sysmon Explorer + something like Chainsaw alongside.

---

## 14 · Data Model + Provenance

| Entity | Persistence | Location | Provenance |
|---|---|---|---|
| Case | Mongo collection `workspace_cases` | Persisted | Has `mitre_consistency` + `acquisition_summary` |
| Investigation | inline in case | Not separated | Ties evidence to case |
| Artifact / Child Artifact | Chain response only | **Not persisted separately** | Present in decoder response; not linked in DB |
| Evidence | `uaie/evidence.py` | In-memory during request | Not persisted per-evidence |
| Technique / Tactic | BKB static | `knowledge/behavior_registry.py` | Deterministic |
| Verdict | Rendered per request | Not persisted separately | Recomputed each call |
| Report | Text blob | In case document | Recomputed each render |

**Provenance chain**: Command → BKB entry → technique → verdict. **Traceable for BKB-mapped behaviors. Lost for AI-narrative content.**

---

## 15 · Hard-Coded / Fragile Areas

| Area | P | Location |
|---|---|---|
| BKB entries hard-coded | P2 | `services/knowledge/behavior_registry.py` (108 entries, no admin UI to edit) |
| Verdict weights hard-coded | **P1** | `services/uaie/orchestrator.py`, `services/die/investigation_results.py` |
| MITRE technique names inline | P2 | Duplicated across `knowledge/`, `reasoning/`, `ida/` |
| XOR key detection heuristics | P2 | `preprocessor/recursive_decoder.py` |
| Wayback year list hard-coded | P3 | `services/ida/acquisition.py` (shipped today) |
| 3 planners coexist | **P1** | `services/recipe_planner.py`, `uaie/planner.py`, `uaie/planner_v2.py` |
| 6 decode endpoints overlap | **P1** | `chain.py`, `iedde.py`, `analyze.py`, `analyst_v2.py`, `auto_investigate.py`, `decoded_artifacts.py` |
| WorkspacePage.jsx monolith | **P0** | 3,982 LOC single file |
| useIdlePersist writes huge state | P1 | `hooks/useIdlePersist.js` — no cap on payload size |
| SSE stream state not always cleaned on unmount | P1 | `WorkspacePage.jsx::streamStopRef` |
| Env-var wrappers case-sensitive in canonicalizer (before today's fix) | Fixed today | `services/canonicalizer/__init__.py` |

---

## 16 · Technical Debt Inventory

| Problem | Location | Impact | Effort | When |
|---|---|---|---|---|
| WorkspacePage.jsx monolith | frontend/src/pages/ | Freeze bugs, unmaintainable | 2 weeks (split into 8-10 files) | Q1 next |
| Duplicate decoder endpoints | backend/routers/ | Confusion + drift risk | 1 week (consolidate) | Q1 |
| 89 outdated memory/*.md docs | memory/ | New-agent onboarding pain | 2 days (archive stale, keep 10-15 current) | Immediate |
| 3 planners, unclear owner | services/ | Behaviour drift | 3 days | Q1 |
| 34 frontend pages | frontend/pages/ | Nav clutter | Audit + delete unused, 1 week | Q2 |
| No structured logs | backend/ | Debugging in prod | 2 days | Q1 |
| No metrics exporter | backend/ | Blind ops | 3 days | Q1 |
| SSRF on URL fetcher | ida/acquisition.py | Security risk | 4 hours (allow-list + block metadata IPs) | **Immediate** |
| Provenance not persisted | uaie/provenance.py | Cannot audit past cases | 1 week | Q2 |
| No PDF/DOCX report export | — | Analysts can't share findings | 1 week | Q2 |

---

## 17 · Production Deployment Posture

| Aspect | Status |
|---|---|
| Docker | External (Emergent-managed) — Ready |
| Reverse proxy | External — Ready |
| TLS | External — Ready |
| Secrets | `.env` — **needs hardening** (secret manager) |
| Backups | **UNKNOWN** — no visible backup job for Mongo |
| DB persistence | Mongo persistent — Ready |
| Migrations | **None** — schema is implicit — **P1 gap** |
| Monitoring | **Missing** — no Prometheus / Datadog integration |
| Logging | Basic Python logging — **needs structured JSON** |
| Alerting | **Missing** |
| Health checks | `/api/health` exists — Ready |
| Failure recovery | Supervisor restarts — Partial |
| Upgrade strategy | Emergent redeploy — External |
| Rollback | Emergent rollback — Ready |
| Horizontal scaling | **Missing** — single-worker |
| RBAC | Admin/user only — **Missing multi-role** |
| Audit logging | **Missing** — no analyst action log |

---

## 18 · Competitive Positioning (from what's actually built)

| Competitor | They do better | NivXRay could differentiate | Currently behind |
|---|---|---|---|
| CrowdStrike | Telemetry ingest, host coverage | Deterministic decoder, BKB transparency | Real-time detection |
| Microsoft Defender | XDR integration, MS ecosystem | Offline analysis, ATT&CK explainability | Everything ecosystem-adjacent |
| SentinelOne | Autonomous response | BKB single-source-of-truth | Response actions (none) |
| Cisco XDR | Broad enterprise catalog | Deterministic-first (rare!) | Ingest breadth |
| Elastic Security | Query-first UX, wide ingest | Chained decode UX for encoded commands | Search/query experience |
| Wazuh | Free, open-source, wide ruleset | Modern deterministic architecture | Ruleset volume |
| Splunk | Ubiquity + SPL | (no unique advantage vs Splunk today) | Everything Splunk |

**Realistic differentiators for NivXRay (based on actual implementation):**
1. **Deterministic decoder chain with transparent CyberChef-style recipe** (proven today) — few competitors do this in-product; CyberChef doesn't do ATT&CK correlation
2. **BKB as single source of truth** — human-readable, auditable classifier vs. LLM opinion
3. **Trajectory canvas as an EDR-style investigation surface** for pasted content

**Genuinely NOT a competitive story today:**
- Any telemetry-first workflow
- Any autonomous response
- Any ML detection

---

## 19 · Gap Matrix

| Area | Current State | Maturity | Evidence | Gap | Risk | Priority |
|---|---|---|---|---|---|---|
| Decoder chain | Full recursive peel, 4-layer proven | 8/10 | today's session | XOR-key auto-discovery beyond loop pattern | Medium | P1 |
| BKB semantic layer | 108 canonical entries | 7/10 | `behavior_registry.py` | Sub-technique coverage; cloud tactics | Medium | P1 |
| Workspace UI | Working + freeze SLA (partial) | 4/10 | today's freezes | 3,982-line monolith; multiple duplicate pages | High | **P0** |
| Recursive artifact discovery | Decoder yes, artifact partial | 3/10 | `recursive_child_pipeline.py` unused | Wire into workspace flow | High | P1 |
| IKG / Evidence graph | 0 files | 0/10 | — | Whole thing | High | P1 |
| Telemetry ingest | None | 0/10 | — | Whole thing | Very High for enterprise | **P0 if enterprise** |
| Verdict engine | Hard-coded thresholds | 4/10 | `orchestrator.py` | Contextual, adjustable weights; false-positive filters | High | P1 |
| Sandboxing | None | 0/10 | — | Whole thing | Critical for real malware | P0 if handling live samples |
| Multi-tenant | None | 0/10 | — | Whole thing | Critical for SaaS | P0 for enterprise |
| Report export | Text only | 2/10 | render() | PDF/DOCX/PPTX | Medium | P2 |
| Testing | 372 files, corpus tiny | 6/10 | tests/ | Real-telemetry validation absent | Medium | P1 |
| Observability | Basic | 3/10 | env keys | Prometheus + tracing missing | Medium | P1 |
| Security posture | SSRF possible, no sandbox | 4/10 | acquisition.py | SSRF fix + sandbox | Critical | **P0** |

---

## 20 · Final 360° Scorecard (0-10)

| Dimension | Score | Justification |
|---|---|---|
| Architecture | 5 | Sound patterns (BKB SSOT); 3 planners + 6 decode endpoints + monolith frontend drag it down |
| Core analysis | 8 | Decoder + BKB + AST parsers are strong |
| Recursive investigation | 5 | Decoder yes, artifact discovery partial |
| Artifact analysis | 5 | 9 adapters, good breadth; PE/ELF/EVTX weak |
| Detection | 6 | 108 BKB entries; can identify well; correlate weakly |
| Correlation | 4 | ICE cluster works; cross-case correlation absent |
| Verdict engine | 4 | Works, but hard-coded and false-positive-prone |
| Explainability | 6 | BKB projections traceable; verdict rationale thin |
| ATT&CK | 6 | ~108 techniques touched; sub-technique gaps |
| Evidence graph | 2 | Documented, not built |
| Investigation UX | 4 | Freeze SLA fragile; monolith frontend |
| Testing | 6 | 372 files strong; real-telemetry validation missing |
| Performance | 5 | Backend OK; frontend struggles at 7 KB+ |
| Security (of NivXRay) | 3 | SSRF, no sandbox, no tenant model |
| Integrations | 3 | LLM + OTX + URLScan; no EDR/SIEM |
| Enterprise readiness | 2 | Missing RBAC, audit log, tenant isolation |
| Deployment readiness | 5 | Works on Emergent; needs monitoring/backup story |
| Scalability | 3 | Single-worker; no horizontal story |
| Observability | 3 | Endpoints exist; no exporter |
| Documentation | 4 | 89 md files but stale; needs curation |

**Overall Maturity: 4.6 / 10 — "Functional product with real analyst value on curated inputs; not enterprise-ready."**

---

## 21 · What we should NOT build yet (foundational work missing)

1. **New EDR/SIEM adapters** — no telemetry model exists to hold them
2. **Multi-tenant SaaS** — no tenant isolation, no billing model
3. **Autonomous response actions** — no detection latency budget, no rollback story
4. **PPTX/PDF fancy report generator** — text output first, formats second
5. **LLM-driven planner (R29 goal-driven)** — deterministic planner not yet consolidated
6. **Investigation Playback UI** — persistence model not there
7. **Any ML-based verdict** — deterministic weights not tuned, feedback loop missing
8. **Sub-technique heatmaps** — sub-technique coverage in BKB too sparse
9. **Investigation Knowledge Economy (R28.8)** — no graph store yet
10. **Real-time streaming** — infrastructure absent

---

## 22 · The 10 Highest-Value Next Steps

| # | Action | Why | Unlocks | Complexity |
|---|---|---|---|---|
| **1** | **Fix SSRF + add URL allow-list on IDA acquisition** | Security P0 — internal IP metadata exfil today | Any customer trust conversation | 4 hours |
| **2** | **Split `WorkspacePage.jsx` (3,982 LOC) into 8-10 focused files** | Ends the freeze/black-screen bug class | Faster iteration, fewer regressions | 2 weeks |
| **3** | **Consolidate the 6 overlapping decode endpoints** into one versioned `/api/v2/decode` | Cuts drift risk, halves confusion | Clean API contract | 1 week |
| **4** | **Persist Evidence Graph** — start with flat `evidence` collection in Mongo, add graph queries later | Everything downstream (playback, correlation, cross-case) depends on this | Recursive artifact discovery, playback | 1 week |
| **5** | **Validation Sprint** (per your existing PRD) — replay 100 vendor reports, produce baseline metrics | You can't improve what you can't measure. Locks a real-world floor. | Confident refactoring | 3-5 days |
| **6** | **R28.6 Capability Contracts** (per existing charter) — one exemplar capability, immutable metadata | Enables plugin architecture, prevents future spaghetti | Everything R28.7+ | 1 week |
| **7** | **Structured logging + Prometheus metrics endpoint** | Ops visibility for anything beyond you personally | Real deployments | 3 days |
| **8** | **Curate `memory/*.md` — archive 70, keep 15 current** | Every fork agent wastes ~30 min triaging stale docs | Faster context for you AND future agents | 2 days |
| **9** | **BKB admin UI** (edit entries in-product, not by editing Python) | 108 entries is manageable; 500 without a UI won't be | Faster BKB expansion | 1 week |
| **10** | **First EDR adapter — start with EVTX (Sysmon)** | Highest-impact single format for real analysts; free samples abundant | Real-telemetry story | 2 weeks |

---

## 23 · Owner's Assessment (candid)

**What NivXRay is today:**
A well-engineered **single-analyst DFIR decoder + BKB-driven investigator** that solves "decode this weird thing and tell me what it does" better than most commercial tools I know. On curated inputs, the deterministic chain is a rare and defensible piece of engineering.

**What NivXRay could realistically become (12 months, focused):**
Either — **choose one**:
- **A** · The **"CyberChef for enterprises"** — the best-in-class deterministic payload analyzer, sold to SOC/DFIR teams as a productivity tool alongside their existing EDR. **Ships fast, small market, defensible.**
- **B** · The **evidence-first micro-EDR** — add EVTX + one XDR integration, position as "the transparent one" against opaque vendor tools. **Slower to ship, bigger market, harder to defend.**

Trying to be **both** is what's produced the 89 stale docs and 3 competing planners.

**Biggest strength:** Deterministic decoder + BKB single-source-of-truth is genuinely uncommon and defensible.

**Biggest weakness:** `WorkspacePage.jsx` monolith and its cascade of freeze bugs. The engineering muscle is on the backend; the frontend is under-invested.

**Biggest architectural risk:** Three planners + six decode endpoints + two "engines" (UAIE + DIE) = the codebase is one uncontrolled fork away from being unrecoverable.

**Biggest product opportunity:** Analysts hate opaque LLM verdicts. **"Deterministic, auditable, explainable"** is a genuine wedge if you commit to path (A).

**Biggest competitive risk:** CrowdStrike/Defender will eventually add better payload analysis in-product. You need to ship path (A) before they do.

**Protect and don't break:**
- BKB and its 108 entries (`services/knowledge/behavior_registry.py`)
- Deterministic decoder chain (`services/die/preprocessor/recursive_decoder.py`)
- Canonicalizer (`services/canonicalizer/`)
- Quality Dashboard CI gates (`tests/test_quality_dashboard.py`)
- Vendor corpus (`backend/corpus/vendor/v1/`)

**Freeze immediately (no new features until fixed):**
- WorkspacePage.jsx (any new feature there compounds the debt)
- The 6 overlapping decode endpoints (no new decode surface until consolidated)
- Any new memory/*.md creation (curate first)

**Fix now (P0):**
- SSRF on URL acquisition
- WorkspacePage.jsx split
- Endpoint consolidation
- Validation Sprint (baseline metrics)

**Build next (in this order):**
1. Evidence Graph persistence
2. Capability Contracts (R28.6)
3. BKB admin UI
4. EVTX / Sysmon adapter (first telemetry format)
5. Structured logging + metrics

**What would make NivXRay genuinely enterprise-grade:**
- Multi-tenant model
- RBAC roles (analyst, senior analyst, admin)
- Audit log of every investigation action
- Report export (PDF/DOCX)
- One EDR/SIEM integration end-to-end (probably Sysmon-first)
- SLA on freeze/black-screen (already committed today, needs real hardening)
- Sandboxing for live malware handling

---

_End of audit._
