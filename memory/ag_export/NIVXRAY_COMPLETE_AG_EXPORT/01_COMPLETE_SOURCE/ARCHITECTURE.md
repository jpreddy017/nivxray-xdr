# NivXRay — Architecture (Living Document)

> **Status:** Living document. Updated after every completed milestone.
> **Last update:** 2026-07-19 · post-RC2.4 UI polish
> **Current release tag:** `v1.0.0-RC2.3` (GitHub Latest) · `v1.0.1-RC2.4` pending

---

## 1. Project Overview

### Purpose
**NivXRay** (branding: *NivXForge* project) is a **Malware Command Intelligence Platform (MCIP)** — a deterministic, offline-first analyst tool that ingests heavily-obfuscated malware commandlines, recursively decodes them through a plugin pipeline, extracts IOCs and MITRE ATT&CK mappings, correlates against families / LOLBAS / OSINT, and produces analyst-ready reports.

### Goals
1. **Deterministic-first.** Every core decode is math-based. AI is opt-in analyst assistance, never in the critical path.
2. **Recursive & explainable.** Never stop after one decode. Every layer + every decision is captured in the trace.
3. **Analyst-trustable.** Prefer *"Partial decode with reason"* over fabricated plaintext. Precision > coverage.
4. **Offline-capable.** Works without any external API when the Universal LLM Key is unavailable.
5. **Enterprise-integrable.** STIX 2.1 bundle export → SIEM / TIP compatible.

---

## 2. Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React 19 + Vite + shadcn/ui)                     │
│  Port 3000 · nivxray.nivxforge.com                          │
└──────────────────────┬──────────────────────────────────────┘
                       │ REACT_APP_BACKEND_URL (all /api routes)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend (FastAPI + Uvicorn)                                │
│  Port 8001 · /api/* prefix                                  │
│  ├── routers/          → 40+ route modules                  │
│  ├── engine/           → deterministic decode orchestrator  │
│  ├── decoders/         → 26 self-registering plugins        │
│  ├── decoders/families/→ 9 behavioural family matchers      │
│  └── stix_export.py    → STIX 2.1 bundle builder            │
└──────────────┬──────────────────────────────────┬───────────┘
               │                                  │
               ▼                                  ▼
    ┌──────────────────────┐          ┌──────────────────────┐
    │ MongoDB (Motor async)│          │ Emergent Universal   │
    │ MONGO_URL / DB_NAME  │          │ LLM Key (opt-in AI)  │
    │ 23 collections       │          │ Claude / GPT / Gemini│
    └──────────────────────┘          └──────────────────────┘
```

### Frontend
- **Stack:** React 19 · React Router · shadcn/ui · Lucide icons · Tailwind
- **Build:** Vite dev server (`yarn start` → port 3000, hot-reload)
- **Auth:** JWT bearer via `Authorization` header (managed by `LoginPage.jsx`)
- **All API calls** use `process.env.REACT_APP_BACKEND_URL`

### Backend
- **Stack:** FastAPI 0.110 · Pydantic 2.13 · Motor 3.3 (async MongoDB) · Python 3.11
- **Router prefix:** every route starts with `/api/` (K8s ingress requirement)
- **Supervisor-managed:** `sudo supervisorctl restart backend|frontend`

### Database
- **MongoDB.** Access via `MONGO_URL` + `DB_NAME` from `backend/.env`.
- No document is returned raw — all pass through Pydantic models (ObjectId → PyObjectId string).

### AI Components (opt-in only)
- Provider: **Emergent Universal LLM Key** (Claude Sonnet 4.5 · GPT-5.2-mini · Gemini)
- Used by: `ai_describe_and_verdict` (post-decode narrative), `enrich_iocs` (OSINT narrative), threat-model UI
- **Wrapped in strict try/except** — if the LLM key is absent or the budget is 0, deterministic pipeline continues normally

---

## 3. Features

### ✅ Completed (as of RC2.4 · 2026-07-19)

| Category | Feature |
|---|---|
| Decoders | Base64 · UTF-16 · Hex · URL · Gzip · Deflate · **Brotli** · **LZMA/XZ** · **Zstd** · Base32 · Base58 · Base85 · Base91 · ROT13 · ROT47 · **Caesar (1-25)** · ASCII85 · JWT · Data-URI · custom-hex-slash · nibble-swap · reverse-string · **XOR (1-8 byte, frequency-polished)** · extract-wrapper · IOC extractor |
| PS reconstruction | `[char]` (dec + hex) · backticks · string concat · `.Replace()` · `$var` expansion · `-join` array · `-f` format op |
| Families (behavioural) | Meterpreter · AsyncRAT · Lumma · DarkGate · Remcos · AgentTesla · QuasarRAT · Cobalt Strike · Snake Keylogger |
| Orchestrator | Recursive depth-20 · loop detection · per-plugin budget · fingerprint-gated candidate selection · tail-trim · post-decode intelligence pass |
| Confidence | Risk breakdown with per-source contributions · **Network+LOLBAS combo bump (+15)** · verdict floors (benign / needs_review / suspicious / malicious) |
| Export | JSON · Markdown · Text · PDF · **STIX 2.1 bundle** |
| CI/CD | `.github/workflows/rc23_quality_gate.yml` — blocks any PR that drops chain-completeness below 77.4% or introduces false-positive IOCs |
| Benchmark | `/app/backend/tests/rc23_benchmark/` — 31 curated samples across 12 categories · profiler · CI gate |
| UI (RC2.4) | Terminal-decode banner · confidence display fix |

### 🚧 In Progress
- Deployment verification of RC2.4 changes on prod

### 📋 Planned (from `/app/memory/ROADMAP.md`)
- **RC2.5** — Recovered-Payload panel split · Recovered-Commands with copy button · full Decode vs Threat confidence separation
- **RC2.6** — Intelligent command-line classifier · recursive layer explanation UI
- **RC2.7** — PowerShell P0.3 (`[char]` polish · ScriptBlock · IEX-of-var) · CMD reconstruction (`!DELAYED!` · `%VAR%` · `SET` / `CALL` / `FOR /F`)
- **RC2.8** — JavaScript reconstruction (`atob` · `String.fromCharCode` · `unescape` · `eval`) · VBScript (`Chr` · `Execute` · `CreateObject`)
- **RC2.9** — Threat Intelligence Correlation (MITRE + LOLBAS + Sigma + YARA + reputation + campaign indicators)
- **RC3.0** — XOR 9-16 byte extension · new families (XWorm · NjRAT · RedLine · FormBook · Emotet)

---

## 4. Key Design Decisions

| Decision | Rationale | Trade-off |
|---|---|---|
| **Deterministic-first, AI opt-in** | Analysts must trust output; hallucinated decodes destroy trust faster than partial ones | Some novel obfuscators need human analyst instead of AI catch-all |
| **Plugin self-registration** (`DecoderRegistry.register()`) | Zero manual routing; new plugins drop into `decoders/` and appear automatically | Load-order matters; circular imports possible if not careful |
| **Cost-gated candidate selection** | With 26+ plugins, blind execution → exponential blowup | Requires each plugin to have a fast, precision-first `detect()` |
| **Fingerprint pre-filter** | Cheap payload profiling (entropy / english / printable ratio / hex-density) short-circuits expensive plugins | Adds ~1ms per layer; worth it |
| **PS reconstruction as a separate plugin** (not orchestrator logic) | Composable with other decoders; benchmark-testable independently | Detection must be careful not to fire on non-PS payloads |
| **Frontend tail-trim heuristic (RC2.4)** | Analyst UX fix without touching engine; preserves raw bytes in HEX/B64 | Duplicates backend heuristic → RC2.5 should surface engine's `terminal` field to UI |
| **Emergent Universal LLM Key** | Zero API keys for user; single balance for all providers | Balance can hit zero → we handle gracefully with try/except |
| **STIX 2.1 as export format** | Industry standard; imports directly into OpenCTI / MISP / Sentinel / Splunk ES | Larger output than JSON; must maintain SDO/SCO structural correctness |
| **31-sample chain-completeness benchmark** | Objective, per-category regression signal — proves changes are improvements | Curated corpus grows slowly; supplementary unit tests still needed |
| **CI quality gate at 77.4% floor** | Any regression fails the build automatically | Floor rises with every release → future work can't cheat |

---

## 5. File Map

### `/app/backend/`
| Path | Purpose |
|---|---|
| `server.py` | FastAPI app factory · lifespan · MongoDB client · router registration |
| `.env` | `MONGO_URL`, `DB_NAME`, `EMERGENT_LLM_KEY`, admin bootstrap password |
| `requirements.txt` | Python deps (fastapi, motor, pymongo, brotli, zstandard, stix2, etc.) |

### `/app/backend/engine/`
| File | Purpose |
|---|---|
| `orchestrator.py` | **Core recursive loop.** Depth-limited plugin selection, loop detection, tail-trim, intelligence pass, verdict computation |
| `models.py` | Pydantic schemas — `AnalystReport`, `Findings`, `IOCBundle`, `LolbasHit`, `MitreHint`, `FamilyMatch`, `RiskContribution`, `TraceStep`, `Budget`, `Fingerprint` |
| `registry.py` | `DecoderRegistry` — plugin registration + `candidates()` cost-sorted selection |
| `decoder_base.py` | Base classes for decoder plugins |
| `fingerprint_util.py` | Fast payload profiling (entropy, printable ratio, english density, hex density) |
| `report.py` | JSON / Markdown / Text formatters |
| `report_pdf.py` | PDF renderer |
| `stix_exporter.py` | AnalystReport → STIX 2.1 bundle adapter |
| `config.py` | Default budgets |

### `/app/backend/decoders/`
26 plugin files, one per encoding. Each `import decoders` triggers registration.
| File | Encoding |
|---|---|
| `base64.py` · `base32.py` · `base58.py` · `base91.py` · `ascii85.py` | Base-N encodings |
| `hex.py` · `custom_hex_slash.py` · `nibble_swap.py` | Hex family |
| `url.py` · `data_uri.py` · `jwt.py` | URL / URI / JWT |
| `utf16.py` | UTF-16LE (PS EncodedCommand) |
| `gzip_stream.py` · `zlib_deflate.py` · `brotli_stream.py` · `lzma_stream.py` · `zstd_stream.py` | Compression |
| `rot13.py` · `rot47.py` · `caesar.py` | Rotation ciphers |
| `xor_brute.py` | XOR 1-8 byte with frequency scoring + iterative polish |
| `reverse_string.py` | Reversed strings |
| `ps_reconstruct.py` | PowerShell string reconstruction (backticks, `[char]`, `.Replace`, `$var`, `-join`, `-f`) |
| `extract_wrapper.py` | Strip wrapping quotes / parens / prefixes to reveal payload |
| `ioc_extractor.py` | Terminal pass — URL / IP / hash / domain extraction |

### `/app/backend/decoders/families/`
9 behavioural signature-scanners (not signature-only — weighted evidence):
`meterpreter.py` · `asyncrat.py` · `lumma.py` · `darkgate.py` · `remcos.py` · `agenttesla.py` · `quasarrat.py` · `cobalt_strike.py` · `snake_keylogger.py`

### `/app/backend/routers/` (40+ files)
Every FastAPI route module. Key ones:
| Router | Purpose |
|---|---|
| `auth.py` | Login / JWT / password change |
| `analyst_v2.py` | Primary decode endpoint (`POST /api/v2/analyze`, `POST /api/v2/analyze/report?fmt=…`) |
| `chain.py` | Multi-stage chain decoder |
| `batch_test.py` | Batch analyst with universal file ingest |
| `taxii.py` | TAXII feed source config |
| `sigma.py` · `mitre_heatmap.py` · `lolbas_export.py` | Analyst overlays |
| `threat_intel*.py` | OSINT enrichment + RSS ingestion |
| `admin.py` · `docs.py` · `learner.py` | Admin panel + docs + ML learner ops |

### `/app/backend/tests/`
| Path | Purpose |
|---|---|
| `test_engine_phase_a.py` · `test_rc22_workspace_adapter.py` etc. | Unit tests (200+) |
| `test_rc22_xor8_lolbas_stix.py` | RC2.2+ delta unit tests (15) |
| `rc23_benchmark/__init__.py` | **31-sample chain-completeness corpus** |
| `rc23_benchmark/run_benchmark.py` | Benchmark runner + JSON export |
| `rc23_benchmark/profile_latency.py` | p50/p95/p99 profiler |
| `rc23_benchmark/ci_gate.py` | Release gate — fails CI on regression |

### `/app/frontend/src/`
| Path | Purpose |
|---|---|
| `pages/WorkspacePage.jsx` | **Primary analyst workspace** — flat + chain decode, OUTPUT panel, MITRE / IOC / LOLBAS overlays |
| `pages/AnalystWorkspacePage.jsx` | v2 workspace (RC2.1a Analyst Report UX) |
| `pages/CommandAnalyzerPage.jsx` | Single-command deep analysis |
| `pages/BatchTestPage.jsx` | Batch corpus + universal file ingest |
| `pages/LoginPage.jsx` | JWT login |
| `pages/{ThreatIntel,MitreHeatmap,Docs,Admin,Learner,ModelStudio,…}Page.jsx` | Specialised views |
| `components/OutputView.jsx` | **OUTPUT card — HEX/B64/DIFF toggle, terminal-decode banner (RC2.4), shellcode banner** |
| `components/ChainStageEditor.jsx` · `ChainReplayView.jsx` | Multi-stage decode chain UI |
| `components/CandidateExplorer.jsx` | Ranked encoding-candidate explorer |
| `components/DecodingTracePanel.jsx` | Per-layer decode trace |

### `/app/.github/workflows/`
| File | Purpose |
|---|---|
| `rc23_quality_gate.yml` | CI — runs unit tests + benchmark; blocks merge on regression |

### `/app/memory/`
| File | Purpose |
|---|---|
| `PRD.md` | Product requirements + release timeline |
| `ROADMAP.md` | Prioritised backlog RC2.4 → RC3.0 |
| `CHANGELOG.md` | Date-ordered change list |
| `test_credentials.md` | Admin login for test agents |
| `rc22_pre_changes.json` · `rc23_baseline.json` · `rc23_after_*.json` | Benchmark result artifacts |

---

## 6. API Endpoints

### Auth
- `POST /api/auth/login` → `{ access_token, token_type, email }`
- `POST /api/auth/change-password`

### Analyst v2 (primary)
- `POST /api/v2/analyze`  Body: `{ input: str, budget?: {…} }` → full `AnalystReport` JSON
- `POST /api/v2/analyze/report?fmt=md|json|txt|pdf|stix`
- `GET  /api/v2/plugins` → `{ count, plugins: [{id, name, category, cost, tags, schema_version}] }`

### Multi-stage chain
- `POST /api/chain/analyze` — auto-splits blank-line separated stages, returns aggregated verdict
- `POST /api/chain/replay`

### Batch / files
- `POST /api/batch_test` — accepts multipart files or newline-separated commandlines

### Cases / history
- `GET  /api/investigations`
- `POST /api/investigations`
- `GET  /api/history`

### Enrichment / intel
- `POST /api/enrichment/ioc`  (OSINT — uses Universal LLM Key if available)
- `GET  /api/threat_intel/feeds`
- `GET  /api/threat_intel/rss`

### Overlays
- `GET  /api/sigma/{report_id}`
- `GET  /api/lolbas_export/{report_id}`
- `GET  /api/mitre_heatmap`

Full list: 40+ router modules; see `/app/backend/routers/`.

---

## 7. Data Models

### Backend Pydantic schemas (`backend/engine/models.py`)

```python
class AnalystReport(BaseModel):
    output: str                          # final decoded content
    terminal: str                        # stop reason: "family-identified"|"no-candidate"|"budget"|…
    stopped_reason: Optional[str]
    engine: str                          # "orchestrator-v1"
    findings: Findings
    executive_summary: str
    confidence_breakdown: ConfidenceBreakdown
    trace: List[TraceStep]
    plugin_report: PluginExecutionReport

class Findings(BaseModel):
    iocs: IOCBundle
    lolbas: List[LolbasHit]
    mitre_techniques: List[MitreHint]
    family: FamilyMatch
    verdict: str                         # "benign"|"needs_review"|"suspicious"|"malicious"
    risk_score: int                      # 0-100

class ConfidenceBreakdown(BaseModel):
    total: int
    verdict: str
    contributions: List[RiskContribution]  # explainable per-source scoring

class TraceStep(BaseModel):
    layer: int
    decoder: str
    confidence: float                    # 0.0-1.0
    why: str
    in_len: int · out_len: int · exec_ms: int
    preview: str · args: Dict
```

### MongoDB collections (23)

| Collection | Purpose |
|---|---|
| `users` | JWT auth |
| `workspace_cases` | Saved analyst cases |
| `investigations` | Long-lived case tracking |
| `analyze_jobs` · `batch_runs` | Job history |
| `ai_response_cache` · `ai_describe_cache` · `ai_decode_cache` | LLM response cache |
| `iocs` | Extracted IOC index |
| `kb_entries` | Knowledge base articles |
| `sample_library` · `samples` | Curated samples for training |
| `learner_payloads` · `learner_versions` · `admin_models` | ML learner state |
| `decode_feedback` · `pending_training_notes` | Analyst corrections |
| `lab_attempts` · `lab_stats` | Public lab telemetry |
| `ti_source_meta` · `cti_rss_meta` | Threat intel feed metadata |
| `settings` · `shares` · `com` | App config + sharing links |

---

## 8. AI Prompts & Pipelines

### Universal LLM Key wiring
- **Import surface:** `from emergentintegrations.llm.chat import LlmChat, UserMessage`
- **Providers:** Claude Sonnet 4.5 (default) · GPT-5.2-mini · Gemini 3.1 Pro
- **Never in decode critical path** — decoding completes fully deterministically first, THEN AI can add narrative

### Pipelines
| Pipeline | Trigger | LLM used | Purpose |
|---|---|---|---|
| `ai_describe_and_verdict` | Analyst clicks "AI Describe" on Workspace | Claude Sonnet 4.5 | 3-paragraph plain-English narrative of the decode chain + verdict |
| `enrich_iocs` | Analyst clicks "OSINT Enrich" | Claude Sonnet 4.5 | Per-IOC reputation narrative |
| `threat_model` | Threat Model page | Claude Sonnet 4.5 | Attack graph + kill chain narrative |
| `analyst_correction` | Analyst submits a bad-decode note | Claude Sonnet 4.5 | Learn from corrections into `pending_training_notes` |

### Decoder heuristics (NON-AI)
- **XOR frequency scoring:** ASCII space + all lowercase letters + digits + shell punctuation → weighted density per column
- **Family behavioural matching:** weighted signatures across 9 families with min-evidence thresholds; if no family clears 0.6 confidence → `family="unknown"` (never forced)
- **Tail-trim heuristic:** clean-head + binary-tail detection with Unicode preservation

---

## 9. Known Issues & Limitations

### Current (as of RC2.4)
| Issue | Severity | Notes |
|---|---|---|
| `xor-11byte-b64` benchmark sample fails | Low | Needs XOR 9-16 byte extension (RC3.0) |
| JS `atob` / `String.fromCharCode` not reconstructed | Medium | RC2.8 scope |
| VBS `Chr` / `Execute` not reconstructed | Medium | RC2.8 scope |
| CMD `!DELAYED!` expansion missing | Medium | RC2.7 scope |
| PS `[char]` in complex chains — partial | Low | RC2.7 P0.3 |
| Admin password committed in 5 test files | Low | Repo is Private — recommend rotation in RC2.5 |
| Prod domain hardcoded in 2 files (`lab.py`, `stix_export.py`) | Low | Pre-existing; cleanup in RC2.5 |
| 2 pre-existing test failures (`test_ps_ascii_xor_iex.py`, `test_meterpreter_b64xor.py`) | Low | Unrelated to RC2.x work; documented as baseline |

### Architectural limits
- **Recursion depth:** 20 layers (configurable via `Budget.max_depth`)
- **Wall-time:** 5000ms default, 8000ms for benchmark
- **Per-plugin output cap:** 4 MB
- **Cumulative cap:** 32 MB
- **Loop detection:** identical-hash + plugin-payload seen set
- **Memory:** no hard RSS cap (documented decision — cumulative bytes cap covers the practical risk)

---

## 10. TODO / Next Milestones

Prioritised per `/app/memory/ROADMAP.md`:

1. **RC2.4 verification** — user re-tests on prod after redeploy, confirms both fixes work
2. **RC2.5** (analyst UX polish continuation):
   - Separate Recovered Payload panel from Investigation Summary
   - Recovered Commands card with copy button
   - Full Decode Confidence vs Threat Confidence display split
   - Surface engine `terminal` + `stopped_reason` to frontend (removes duplication with `detectTerminalTail`)
3. **RC2.6** — Intelligent command-line classifier + recursive layer-explanation UI
4. **RC2.7** — PowerShell P0.3 + CMD reconstruction
5. **RC2.8** — JavaScript / VBScript reconstruction
6. **RC2.9** — Threat Intel Correlation (Sigma / YARA / reputation / campaigns)
7. **RC3.0** — XOR 9-16 byte + new families (XWorm, NjRAT, RedLine, FormBook, Emotet)

**Cross-cutting cleanup:**
- Purge legacy `operations.py` · `wrapper_archetypes.py` · `hexfamily_*`
- Rotate admin password + remove hardcoded strings from 5 test files
- Remove hardcoded prod domain from `lab.py` + `stix_export.py`

---

## 11. Changelog

### 2026-07-19 · RC2.4 · UI Polish
- **UI ONLY** — engine untouched
- `OutputView.jsx`: new `detectTerminalTail()` heuristic + amber "TERMINAL DECODE STATE" banner replaces binary garbage in TEXT view (raw preserved in HEX / B64)
- `WorkspacePage.jsx`: fixed misleading `conf 0/100` display — now shows `conf=n/a · decoded` when engine returned content without explicit confidence
- Docs: `/app/memory/ROADMAP.md` created · `PRD.md` updated · **this** `ARCHITECTURE.md` created

### 2026-07-19 · RC2.3 · Stable · TAGGED `v1.0.0-RC2.3`
- **10 atomic commits**, all benchmark-verified, zero regressions
- New decoders: Brotli · LZMA/XZ · Zstd · Caesar (1-25)
- PowerShell reconstruction: P0.1 (`.Replace()` + `$var`) · P0.2 (`-join` + `-f`)
- Perf: XOR polish-pass gating (-8ms avg)
- CI: `.github/workflows/rc23_quality_gate.yml` — enforces 77.4% chain-completeness floor
- Benchmark: 31 curated samples · profiler · CI gate
- **Deployed** to `nivxray.nivxforge.com`
- Chain-completeness: **77.4%** (up from 61.3% pre-changes = **+16.1pp**)
- False-positive IOCs: **0**
- p95 latency: 784 ms (97% under 3s target)
- Unit tests: 48/48 pass

### 2026-07-19 · RC2.2+ · XOR polish + tail-trim + STIX
- XOR extended from 4-byte to 8-byte keys with frequency-weighted per-column scoring
- Iterative polish pass (256 × keylen × 3 sweeps) recovers near-miss columns
- Network+LOLBAS combo — new `network-lolbas-combo` RiskContribution (+15) for T1105 download-and-execute pattern
- Residual-obfuscation tail-trim (`_trim_tail_garbage`) — clean head + binary tail retry-then-truncate
- STIX 2.1 export endpoint (`?fmt=stix`) — 11-object OASIS bundle: identity, malware, attack-patterns, indicators, SCOs, observed-data, relationships, note, report

### Pre-2026-07-19 · Prior RC series (from PRD)
- **RC2.2** — Universal File Ingest (34+ formats) · 9 additional decoders · Workspace unified through Orchestrator (`rc22_adapter.py`) · orchestrator hard 15s ceiling · XLSX noise filter
- **RC2.1b** — STIX 2.1 export foundation
- **RC2.1a** — Analyst Verdict Panel · Sigma / YARA generation · MITRE Navigator export · IOC CSV export
- **RC2.0** — Deterministic-first pivot · L0→L3 plugin architecture · 214-test regression suite

---

*This document is auto-maintained. After every completed milestone, update sections 3, 9, 10, and 11.*
