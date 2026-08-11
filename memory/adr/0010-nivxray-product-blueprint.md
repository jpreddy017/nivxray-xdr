# NivXRay — Product & Architecture Blueprint

**Purpose**: a plain-language, human-readable synthesis of what NivXRay actually is TODAY, derived exclusively from the evidence gathered in [`0007-current-state-master-snapshot.md`](./0007-current-state-master-snapshot.md), [`0008-execution-plan-from-audit.md`](./0008-execution-plan-from-audit.md), and [`0009-route-classification.md`](./0009-route-classification.md).

**Status**: 2026-08-11 · Session-9 · read-only synthesis. No code changed. No roadmap. No proposal.
**Method**: interpretation, not new discovery. Everything below is traceable to the three prior ADRs.
**Legend used throughout**:
- 🟢 **LIVE** — code exists, wired end-to-end, exercised by a runtime consumer, backed by a passing test.
- 🟡 **SHADOW** — code exists, gated behind a `NIVX_FLAG_*=shadow` feature flag, observes without influencing outputs.
- 🟠 **DISCONNECTED** — backend code exists, no frontend or downstream consumer today.
- 🔵 **PARTIAL** — some branches live, some stubbed / 501 / silently no-op.
- 🧪 **EXPERIMENTAL** — Rn/Phase-x scaffolding, explicitly labelled non-authoritative in source.
- ⚪ **PLANNED** — mentioned in docs/ADRs/comments but no code path.
- ⚫ **DEAD** — code shipped, never imported by the running app.

---

## §0 · Table of Contents

1. Product Definition
2. Product Boundaries
3. Complete Input Types (what can I give NivXRay?)
4. Capability Inventory (what NivXRay can DO today)
5. Every Major Engine (component inventory)
6. Actual Execution Pipelines
7. Universal Input Router
8. Recursive Artifact Discovery
9. Canonical Evidence Model
10. Investigation Knowledge Graph (IKG)
11. Correlation Engine
12. Verdict Engine — live vs shadow
13. ATT&CK Mapping
14. Attack Story
15. Negative Explainability
16. Mitigation
17. Threat Intelligence
18. Threat Hunting / Query
19. Timeline
20. Device Trajectory
21. Reports
22. Workspace — analyst workflow
23. Frontend Architecture
24. Backend Architecture
25. API Architecture
26. Data Model
27. Runtime Architecture
28. Configuration & Feature Flags
29. Workspace vs X-Lab Isolation
30. External Integrations
31. Customer Data Flow
32. Security Posture
33. Deployment Models
34. Testing / Quality
35. Performance
36. Scalability
37. Observability
38. Documentation
39. Technical Debt
40. Current Limitations
41. Production Readiness
42. Enterprise Readiness
43. Architecture Diagrams (A-H)
44. NivXRay in Plain English

---

## §1 · Product Definition

**NivXRay is a browser-based, single-tenant SOC-analyst investigation Workspace that transforms pasted or uploaded analyst inputs (command lines · scripts · narrative reports · small tabular EDR exports · documents) into evidence-gated MITRE ATT&CK mappings, Timelines, Query/Hunt views, Attack Chain diagrams, and downloadable reports.**

Everything else — v2 IKG, Verdict Engine v3, adapters, artifact store — exists in the repo but is shadow-observed, not part of the shipping request path.

**One-sentence template filled in:**

> NivXRay is a **command-line & narrative & small-CSV-EDR** security investigation platform that accepts **analyst-pasted text and ≤ 256 KB uploads**, transforms them into **P0.2-evidence-gated MITRE technique mappings + canonical events**, correlates **through deterministic projections (verdict / attack-chain / attack-story / IOC / timeline / query)**, produces **Markdown / STIX / (v2 case-scope) PDF reports with SHA-256 signatures**, and presents **panels inside a single React Workspace at `/`**.

---

## §2 · Product Boundaries

**Inside the boundary (NivXRay's responsibility):**
- Receiving analyst-pasted or uploaded input at `/api/upload` (256 KB cap), `/api/analyze/*`, `/api/die/*`.
- Deterministic decoding, MITRE mapping, evidence-chain enforcement, projection to Verdict / Timeline / Query / Attack Chain.
- Analyst Workspace UI (React, single-page).
- Threat-Intel feed sync (7 providers → 65,614 IOCs in `iocs` collection).
- Analyst Practice Lab (challenges + scoring).
- Reports (Markdown / STIX / PDF for v2 case scope).

**Outside the boundary today:**
- Live EDR / XDR / SIEM ingestion (no adapter live).
- Multi-tenant / SSO / RBAC beyond `role == "admin"`.
- Fleet-scale or cross-case hunt.
- Automated response / SOAR.
- Sandbox / detonation of malware payloads.
- Any subprocess or container-isolated parser.

---

## §3 · Complete Input Types

Every input the platform can receive today, from the analyst's point of view.

| Input | Supported? | How | Output produced |
|---|---|---|---|
| Command line (PowerShell) | 🟢 LIVE | `/api/die/analyze`, `/api/decode/smart`, `/api/analyze/async`, WorkspacePage paste box | Decode chain, LOLBAS, MITRE, verdict, timeline, attack-chain |
| Command line (cmd.exe) | 🟢 LIVE | Same as above | Same |
| Command line (bash) | 🟢 LIVE | Same | Same |
| JavaScript | 🟢 LIVE | Same | Same |
| VBScript | 🟢 LIVE | Same | Same |
| Python | 🟢 LIVE | Same | Same |
| Base64 / hex / URL-encoded / rot13 / brotli / lzma / gzip | 🟢 LIVE | `/api/decode/*` (200+ decoders under `backend/decoders/`) | Recursive decode chain |
| PowerShell `-EncodedCommand` multi-layer | 🟢 LIVE | RC4.0 decoder — `decoders/ps_encodedcommand_multilayer.py` | Peeled + normalized + AST |
| Narrative vendor report (prose) | 🟢 LIVE | `/api/die/analyze` + canonical narrative augment (`NIVX_CANONICAL_DIE_ANALYZE=on`) | Narrative MITRE techniques with evidence |
| Small tabular EDR CSV (Symantec-SEP shape, 3-col) | 🟢 LIVE | `services/die/csv_edr_analyzer.py` — pattern-matched header | `csv_edr.highconf_events` bag → Timeline / Query |
| Splunk `_raw`-in-cell CSV | ⚫ NOT-IMPLEMENTED | Silently falls into prose path | (nothing useful) |
| Sysmon EVTX | 🔵 PARTIAL / 501 | `POST /api/v2/ingest/evtx` returns HTTP 501 explicitly | (nothing) |
| Raw JSON / NDJSON records | 🟡 SHADOW | `POST /api/v2/ingest/{json,ndjson}` gated by `NIVX_FLAG_ADAPTERS=shadow` | (nothing until flag flipped) |
| Raw CSV telemetry (generic) | 🟡 SHADOW | `POST /api/v2/ingest/csv` — same gate | (nothing) |
| Syslog (RFC-5424 / RFC-3164) | 🟡 SHADOW | `POST /api/v2/ingest/syslog` | (nothing) |
| Webhook payload (generic) | 🟡 SHADOW | `POST /api/v2/ingest/webhook` | (nothing) |
| Document · DOCX / PPTX / XLSX | 🟢 LIVE (text-only) | `/api/upload` unzips + concatenates XML strings (Phase 5.W) | text → prose path |
| Document · PDF | 🟢 LIVE (text-only) | `services/adapters/pdf_adapter.py` | text → prose path |
| Document · EML (email) | 🟢 LIVE | `services/adapters/eml_adapter.py` | body → prose path |
| Image | 🟢 LIVE (metadata) | `services/adapters/image_adapter.py` | strings/metadata |
| ZIP archive | 🟢 LIVE (unzip + concat) | `/api/upload` unpacks + concatenates member text | text → prose path (NO size guard — see §32) |
| PE (Windows executable) | 🟢 LIVE | `services/pe_analyzer.py` + `pefile==2024.8.26` | Sections, imports, entropy, indicators |
| ELF | 🟢 LIVE (light) | `frontend/src/components/ELFAnalysisPanel.jsx` | Panel |
| Shellcode | 🟢 LIVE | `services/shellcode_analyzer.py` + `capstone==5.0.9` disassembly | Panel |
| URL | 🟢 LIVE | `services/adapters/url_adapter.py` + SSRF guard | Header/content fetch (blocked for private IPs) |
| Hash (MD5 / SHA-1 / SHA-256) | 🟢 LIVE | `/api/ioc/enrich`, `/api/threat-intel/lookup/{value}` | OSINT match against `iocs` (65,614) |
| IP / domain | 🟢 LIVE | Same | OSINT match |
| Email address | 🟢 LIVE | `services/die/ioc_semantic.py` | IOC extraction |
| Sigma rule input | 🟢 LIVE (light) | `backend/sigma_generator.py` + `routers/sigma.py` | Sigma emission |
| YARA rule input | 🟢 LIVE (light) | `backend/yara_export.py` | YARA emission |

**Bottom line:** NivXRay accepts pasted text, small documents, hashes, IOCs, URLs, and small tabular EDR CSVs. It does **not** accept live EDR/XDR/SIEM telemetry today — the routes exist but are shadow-flagged or 501.

---

## §4 · Capability Inventory

Every capability, one label, one truth.

| # | Capability | Status |
|---|---|---|
| 1 | Deterministic multi-layer decoding (200+ decoders) | 🟢 LIVE |
| 2 | PowerShell AST + normalization + alias/backtick unwrap | 🟢 LIVE |
| 3 | LOLBAS lookup + registry | 🟢 LIVE |
| 4 | MITRE ATT&CK technique mapping (P0.2 evidence-gated) | 🟢 LIVE |
| 5 | 14-lane MITRE Attack Chain diagram | 🟢 LIVE |
| 6 | Timeline projection over canonical events | 🟢 LIVE |
| 7 | Query / Hunt filter + Auto-Viz | 🟢 LIVE |
| 8 | Canonical Verdict projection (4-weight linear scorer) | 🟢 LIVE |
| 9 | Canonical Attack Story projection | 🟢 LIVE |
| 10 | IOC extraction (URL / IP / domain / hash / email) | 🟢 LIVE |
| 11 | LLM-narrate (`object.narrative`) — Emergent LLM key | 🟢 LIVE |
| 12 | Analyst Practice Lab (challenges + leaderboard) | 🟢 LIVE |
| 13 | Threat-Intel feed sync (7 providers) | 🟢 LIVE |
| 14 | TAXII 2.1 push (admin) | 🟢 LIVE |
| 15 | Threat-Intel RSS crawl → pending training notes | 🟢 LIVE |
| 16 | Analyst Corrections | 🟢 LIVE |
| 17 | Documents / Case Vault (GridFS) | 🟢 LIVE |
| 18 | Knowledge Base | 🟢 LIVE |
| 19 | Nightly Benchmark & Regression | 🟢 LIVE |
| 20 | Reports (Markdown, STIX bundle, PDF, ZIP) | 🟢 LIVE (v2 case scope) |
| 21 | Report signature (SHA-256, deterministic — Markdown/STIX byte-locked in CI) | 🟢 LIVE |
| 22 | PDF byte-determinism | ⚪ PLANNED (needs normaliser) |
| 23 | Investigation Knowledge Graph (v2/investigation/ikg.py) | 🟡 SHADOW |
| 24 | Verdict Engine v3 (per-event/process/chain/device/incident) | 🟡 SHADOW |
| 25 | Adaptive Weight Profiles | 🟡 SHADOW |
| 26 | Correlation Engine v3.1b | 🟡 SHADOW |
| 27 | Negative Explainability (`why_is_this_not`) | 🟡 SHADOW |
| 28 | Case Engine (dedicated schema at v2/case_engine/) | 🟡 SHADOW |
| 29 | Artifact Store (persisted) | 🟡 SHADOW |
| 30 | Multi-format ingest (JSON/NDJSON/CSV/Syslog/Webhook) | 🟡 SHADOW |
| 31 | Sysmon / EVTX ingest | 🔵 PARTIAL (501) |
| 32 | CrowdStrike / Defender / SentinelOne / Splunk / Sentinel / QRadar / Elastic adapters | ⚪ PLANNED |
| 33 | OSINT reputation live lookup on IOC panel (VT/AbuseIPDB per-investigation) | 🟠 DISCONNECTED |
| 34 | Attack Story wire-up on Workspace | 🟠 DISCONNECTED |
| 35 | Mitigation recommendations | 🟢 LIVE (`services/mitigation`) |
| 36 | JWT auth + admin seed | 🟢 LIVE |
| 37 | SSRF guard | 🟢 LIVE |
| 38 | Body-size cap (512 KB default / 50 MB large paths) | 🟢 LIVE |
| 39 | GZip response middleware (≥ 4 KB) | 🟢 LIVE |
| 40 | Login rate-limit / brute-force lockout | ⚪ PLANNED (P0 gate) |
| 41 | Archive-bomb guard on `/api/upload` | ⚪ PLANNED (P0 gate) |
| 42 | CORS explicit-origin allow-list | ⚪ PLANNED (P0 gate) |
| 43 | Same-process parser isolation | ⚫ NOT-IMPLEMENTED (residual risk) |
| 44 | Multi-tenant isolation | ⚪ PLANNED |
| 45 | SSO / OAuth | ⚪ PLANNED |
| 46 | Redis / queue / worker fleet | ⚪ PLANNED |
| 47 | Prometheus / OTEL / tracing | ⚪ PLANNED |
| 48 | Server-side file mode | ⚪ PLANNED (P1) |
| 49 | Cross-case hunt / fleet hunt | ⚪ PLANNED |
| 50 | Saved queries | ⚪ PLANNED |

---

## §5 · Every Major Engine

Every engine or major service module, one row each.

| # | Engine / Module | Path | Role | Status |
|---|---|---|---|---|
| E1 | Input Understanding Engine (IUE) | `services/die/input_understanding.py` + `canonical/iue/composer.py` | Classifies pasted input (language / encoding / decode-decision) | 🟢 LIVE (canonical composer via `NIVX_CANONICAL_UIL_INVESTIGATE=on`) |
| E2 | Input Health | `services/die/input_health.py` | Pre-flight validation (size, printable-ness, encoding) | 🟢 LIVE |
| E3 | Preprocessor | `services/die/preprocessor/` | Per-command stages + families + tactics | 🟢 LIVE |
| E4 | Smart Decoder | `backend/smart_decoder.py` + `backend/decoders/` (>50 modules) | Multi-layer deterministic decode | 🟢 LIVE |
| E5 | Magic Decoder | `backend/magic_decoder.py` | Byte-magic detection | 🟢 LIVE |
| E6 | Recipe Engine | `backend/operations.py` + `ops_extended.py` + `ops_base_family.py` | Composable decode operations (250+) | 🟢 LIVE |
| E7 | Chain Analyzer | `services/die/chain.py` + `backend/chain_analyzer.py` | Stitches multi-stage decode chains | 🟢 LIVE |
| E8 | Semantic Engine (PowerShell) | `backend/v2/semantic/ps_*.py` | PS AST → behaviors → storyline | 🟢 LIVE |
| E9 | PowerShell AST | `backend/powershell_ast.py` + `services/die/powershell_ast.py` | Deterministic PS parsing | 🟢 LIVE |
| E10 | LOLBAS Registry | `services/die/lolbas.py` + `lolbas_cache` collection | Living-off-the-land binary lookup | 🟢 LIVE |
| E11 | MITRE Mapper + Evidence Chain (P0.2) | `services/die/mitre_evidence_chain.py` | Every technique gated by `{source, event_or_rule, field, observed_value, evidence_ref}` | 🟢 LIVE |
| E12 | IOC Semantic Extractor | `services/die/ioc_semantic.py` | URL/IP/domain/hash/email extraction | 🟢 LIVE |
| E13 | Investigation Results Renderer | `services/die/investigation_results.py` | Emits P0.3-locked payload (10 keys, 250 KB) | 🟢 LIVE |
| E14 | Canonical Bridge | `services/die/canonical_bridge.py` | Augments legacy DIE with canonical narrative MITRE | 🟢 LIVE |
| E15 | Canonical IUE Composer | `canonical/iue/composer.py` + adapters | Two-tier SSOT builder | 🟢 LIVE |
| E16 | Canonical Executor | `canonical/executor/executor.py` + capabilities/ | Runs the plan, produces AuthoritativeSSOT | 🟢 LIVE |
| E17 | Canonical SSOT (AuthoritativeSSOT) | `canonical/ssot/authoritative.py` | Append-only, provenance-mandatory | 🟢 LIVE (in-memory per-request) |
| E18 | Canonical Projections | `canonical/projections/{verdict,attack_chain,attack_story,iocs,timeline,recommendations,reports}.py` | Pure functions over SSOT | 🟢 LIVE |
| E19 | Timeline Projection (MVP) | `services/die/timeline_projection.py` | Read-only projection of `highconf_events` | 🟢 LIVE |
| E20 | Query/Hunt (MVP) | `services/die/query_hunt.py` | Read-only scoped filter | 🟢 LIVE |
| E21 | CSV EDR Analyzer | `services/die/csv_edr_analyzer.py` | SEP-shape CSV parser | 🟢 LIVE |
| E22 | Universal Input Router | ⚪ PLANNED per ADR-0008 §5.2 | Would sit between file store and analyzer | ⚪ NOT-IMPLEMENTED |
| E23 | Artifact Router | `services/ida/artifact_router.py` | Routes each artifact to right analyzer | 🟢 LIVE |
| E24 | Artifact Splitter | `services/ida/artifact_splitter.py` | Decomposes container documents | 🟢 LIVE |
| E25 | Intelligent Document Analyzer (IDA) | `services/ida/` | Document understanding | 🟢 LIVE |
| E26 | Recursive Child Pipeline | `services/recursive_child_pipeline.py` + `services/die/preprocessor/` | Fixed-point recursive artifact discovery | 🟢 LIVE |
| E27 | Evidence Graph (side-car, RC5 Phase 11.0) | `backend/engine/evidence_graph.py` | 18 node kinds, 19 edge kinds; does NOT influence verdicts | 🧪 EXPERIMENTAL |
| E28 | Investigation Knowledge Graph (IKG) | `backend/v2/investigation/ikg.py` | 13 node types + 14 edge types | 🟡 SHADOW |
| E29 | Correlation Engine (v3.1b) | `backend/v2/verdict/correlation.py` | Event → Process → Chain → Device → Incident | 🟡 SHADOW |
| E30 | Verdict Engine v3 | `backend/v2/verdict/engine.py` + weights/profiles/progressions/signals | Adaptive Weight Profile scoring | 🟡 SHADOW |
| E31 | Canonical Verdict (production) | `canonical/projections/verdict.py` | 4-weight linear scorer | 🟢 LIVE |
| E32 | Attack Mapping (ATT&CK Navigator + STIX) | `backend/v2/investigation/attack_mapping.py` | Navigator v4.5 layer JSON + tactic coverage | 🟡 SHADOW |
| E33 | Attack Story (canonical) | `canonical/projections/attack_story.py` | Prose narrative reconstruction | 🟢 LIVE |
| E34 | Attack Story (v2 IKB-driven) | `backend/v2/investigation/attack_story.py` | Richer narrative from IKG | 🟡 SHADOW |
| E35 | Negative Explainability | `backend/v2/investigation/explainability.py::why_is_this_not` | "Why is this NOT malicious?" | 🟡 SHADOW |
| E36 | Threat Intelligence — feed fetch | `backend/feeds.py` | 7 provider fetches (OTX/AbuseIPDB/URLhaus/ThreatFox/MalwareBazaar/MalwareBytes/Talos/CINS Army) | 🟢 LIVE |
| E37 | Threat Intelligence — enrichment cache | `backend/threat_intel_enrich/` | Per-IOC cache | 🟢 LIVE (light) |
| E38 | Threat Intelligence — RSS crawl | `backend/routers/threat_intel_rss.py` | RSS → pending training notes | 🟢 LIVE |
| E39 | TAXII Push | `backend/taxii/` + `routers/taxii.py` | STIX bundle → TAXII 2.1 collection | 🟢 LIVE |
| E40 | Sigma Generator | `backend/sigma_generator.py` + `routers/sigma.py` | Rule emission | 🟢 LIVE |
| E41 | YARA Export | `backend/yara_export.py` | Rule emission | 🟢 LIVE |
| E42 | STIX Export | `backend/stix_export.py` + `v2/report/stix.py` | STIX bundle | 🟢 LIVE (v2 canonical) |
| E43 | Mitigation Engine | `backend/services/mitigation/` + `routers/mitigations.py` (`/api/decode/mitigations`) | Deterministic recommendations | 🟢 LIVE |
| E44 | Report Engine (v2 canonical) | `backend/v2/report/{schema,markdown,pdf,stix,bundle,builder,hashing}.py` | Deterministic envelope + signature | 🟢 LIVE |
| E45 | Legacy Report Renderers | `backend/report_renderers.py` | TXT/HTML/DOCX/PDF/CSV | 🟠 DEPRECATED (per ADR-0009) |
| E46 | Session / Workspace State | `backend/l1_evidence/case_store.py` + `l2_investigation/workspace_state.py` + `routers/sessions.py` | Case + Workspace state persistence | 🟢 LIVE |
| E47 | Analyst Corrections | `backend/analyst_corrections.py` + `routers/analyst_corrections.py` | Feedback loop capture | 🟢 LIVE (887 rows) |
| E48 | Learner / Finetune | `backend/learner_engine.py` + `backend/finetune/` + `routers/learner.py` | LLM feedback pipeline | 🟢 LIVE |
| E49 | Benchmark harness | `backend/tests/*` + `routers/benchmark.py` + `_nightly_benchmark_loop` | Corpus regression | 🟢 LIVE |
| E50 | Regression harness | `backend/regression/` + `routers/regression.py` | Continuous regression | 🟢 LIVE |
| E51 | Corpus | `backend/corpus/` + `routers/corpus_validate.py` | Fixture library | 🟢 LIVE |
| E52 | Knowledge Base | `backend/knowledge_base/` + `routers/kb.py` | 339 entries | 🟢 LIVE |
| E53 | Documents / Case Vault | `routers/documents.py` + GridFS | Uploaded doc store | 🟢 LIVE |
| E54 | LLM shim | `backend/llm_provider.py` + `backend/llm_decoder.py` + LiteLLM | Emergent-key routing | 🟢 LIVE |
| E55 | AI budget guard | `backend/ai_credit_guard.py` | Rate + budget enforcement | 🟢 LIVE |
| E56 | Frontend Telemetry | `routers/telemetry.py` + `frontend_telemetry` collection | UI event capture | 🟢 LIVE |
| E57 | Analyst Practice Lab | `routers/lab.py` + `lab_attempts` (89) | Challenge / attempt / leaderboard | 🟢 LIVE |
| E58 | Request Hardening | `backend/request_hardening.py` | X-Request-ID + timeouts + body cap | 🟢 LIVE |
| E59 | GZip + CORS middleware | `server.py` | Compression + CORS | 🟢 LIVE (CORS permissive) |
| E60 | Auth + admin seed | `backend/deps.py` (JWT + bcrypt) | JWT auth + idempotent admin seed | 🟢 LIVE |

**Note on E22 (Universal Input Router):** the audit reveals NivXRay has an **Artifact Router (E23)** for classifying an artifact once it exists, but it does NOT have a **Universal Input Router** at the ingestion boundary. ADR-0008 §5.2 makes this the P1 deliverable. Today, every input path enters the analyzer directly through its endpoint (`/api/die/*`, `/api/analyze/*`, `/api/upload`).

---

## §6 · Actual Execution Pipelines

The four execution paths NivXRay actually runs today.

### 6.1 · Command-line / Prose Pipeline (default) — 🟢 LIVE

```
Analyst pastes text into WorkspacePage
        │
        ▼
POST /api/die/analyze          ← DIE analyze envelope (legacy + canonical narrative augment)
        │
        ├── Input Understanding (IUE) — classify language / encoding
        ├── Input Health check
        ├── Preprocessor — split into stages
        ├── Smart Decoder — multi-layer decode
        ├── Chain Analyzer — stitch chain
        ├── LOLBAS lookup
        ├── IOC extraction
        ├── MITRE Evidence Chain (P0.2) — {source, rule, field, value, evidence_ref}
        ├── Canonical Bridge — narrative MITRE augment
        ├── Confidence + intent
        └── Attack Fingerprint
        │
        ▼
POST /api/die/investigation-results  ← P0.3-locked payload (10 allow-listed keys)
        │
        ▼
WorkspacePage renders:
  · Overview
  · Attack Chain (14 lanes)
  · Timeline (via /api/die/timeline)
  · Query/Hunt (via /api/die/query)
  · IOCs
  · LOLBAS
  · MITRE
  · Narrative (LLM-augmented)
  · Confidence + Health
  · Metadata
```

### 6.2 · Artifact-Analysis Pipeline (document / archive / PE) — 🟢 LIVE

```
Analyst uploads file → POST /api/upload  (≤ 256 KB · ≤ 512 KB body cap)
        │
        ├── SHA-256 / MD5 / SHA-1 hashed in-memory
        ├── _detect_file_type — bytes-magic
        ├── If UTF-8 / UTF-16 decodable → text
        ├── If PK header (ZIP/DOCX/PPTX/XLSX) → unzip inline, concat text (NO SIZE GUARD)
        ├── Hex dump (first 512 bytes)
        └── Strings extract (limit 400)
        │
        ▼
Text branch feeds into 6.1 (command-line/prose pipeline)
Bytes branch feeds into artifact analyzers:
  · PE — services/pe_analyzer.py + pefile
  · Shellcode — services/shellcode_analyzer.py + capstone
  · PDF — services/adapters/pdf_adapter.py
  · DOCX/PPTX/XLSX — services/adapters/docx_adapter.py
  · Image — services/adapters/image_adapter.py
  · Email (EML) — services/adapters/eml_adapter.py
        │
        ▼
Artifact Router (IDA) → child artifact discovery → recursive
        │
        ▼
Same investigation-results output as 6.1
```

**Security gap here** — the ZIP unpack step has NO member-count / size / recursion / ratio guard (see §32).

### 6.3 · IOC / Reputation Pipeline — 🟢 LIVE (single-value lookup only)

```
Analyst enters hash / IP / domain / URL
        │
        ▼
POST /api/ioc/enrich
        │
        ▼
services/ioc_intelligence/ + `iocs` collection (65,614 rows)
        │
        ├── Match against local IOCs from OSINT feed sync
        └── Threat-intel enrichment cache
        │
        ▼
Frontend renders reputation card
```

**Gap** — no live VirusTotal / AbuseIPDB per-investigation lookup (E14 §14 in ADR-0007).

### 6.4 · Raw Telemetry Pipeline — 🟡 SHADOW (not live)

```
Would-be flow (currently gated shadow):

Any of:
  POST /api/v2/ingest/{json,ndjson,csv,syslog,webhook}
  POST /api/v2/ingest/evtx  ← returns 501
        │
        ▼
[ADAPTERS shadow gate — NIVX_FLAG_ADAPTERS=shadow]
        │
        ▼
v2.shadow.observe_all → v2.shadow.persist
        │
        ▼
Canonical event bag  (would populate v2_case_events — currently 0 docs)
        │
        ▼
IKG builder (v2/investigation/builder.py)  ← shadow
Verdict Engine v3                          ← shadow
Correlation Engine                         ← shadow
```

**Interpretation:** the whole raw-telemetry story is architecturally coded but operationally dormant. Every `v2_case_*` collection has 0 documents. See ADR-0008 §4 for promotion criteria.

---

## §7 · Universal Input Router — ⚪ NOT-IMPLEMENTED

**What exists today:** each input path enters the analyzer through its own endpoint. There is no single "input router" that sees every input regardless of shape.

**Consequence:** no unified provenance envelope across paste vs upload vs (future) adapter ingest.

**Planned (per ADR-0008 §5.2):** the P1 Server-Side File Mode introduces `services/input_router.py` between the file store and the analyzers.

---

## §8 · Recursive Artifact Discovery — 🟢 LIVE

**Code**: `services/recursive_child_pipeline.py` + `services/die/preprocessor/` + `services/ida/artifact_splitter.py`.

**Flow:**
```
Parent artifact
   │
   ▼
Preprocessor detects children (base64 embedded scripts, unpacked DOCX members, PS-encoded blobs)
   │
   ▼
Artifact Router dispatches each child to its analyzer
   │
   ▼
Fixed-point termination (NIVX_ENGINE_BUDGET_DEPTH=12 · NIVX_ENGINE_BUDGET_WALLTIME_MS=5000)
   │
   ▼
Every child artifact carries evidence_ref back to parent
```

**Test coverage:** `test_binary_terminal_state.py` locks termination.

---

## §9 · Canonical Evidence Model — 🟢 LIVE (in-memory) / 🟡 SHADOW (persisted)

Two tiers per ADR-0005:

**Tier 1 — AuthoritativeSSOT (authoritative graph):** `canonical/ssot/authoritative.py`. Append-only, provenance-mandatory, fingerprint-addressable. Populated per-request; not persisted to Mongo except in `canonical_ssot_store` (2 rows).

**Tier 2 — Projections (pure functions of Tier 1):** `canonical/projections/{verdict,attack_chain,attack_story,iocs,lolbas,timeline,executive_summary,analyst_summary,recommendations,reports}.py`.

**Evidence contract (P0.2 — 30 locked tests):** every emitted MITRE technique must carry:
```
{
  source: "die.narrative" | "csv_edr" | "iue.rule" | ...,
  event_or_rule: <rule-id>,
  field: <field-name-on-rule>,
  observed_value: <what-triggered-the-rule>,
  evidence_ref: <stable-ref-back-to-input>
}
```

If provenance is absent → the technique is **rejected**. No exception.

---

## §10 · Investigation Knowledge Graph (IKG) — 🟡 SHADOW

**Full design** — `backend/v2/investigation/ikg.py`:

**Node types (13):**
```
process   file      registry   network   module   service   task
event     technique tactic     verdict   device   incident
```

**Edge types (14):**
```
created    modified   deleted    contacted   loaded    installed
spawned    executed_by maps_to   covers      contributes_to
rollup_of  hosted_on  part_of
```

**Node model:** `{ id, type, label, attrs{} }` — ids are stable IIDs, content-addressed where possible.

**Edge model:** `{ source, target, type, attrs{} }` — deduped by `(src, tgt, type)`.

**Builder path:** `v2/investigation/builder.py::Investigation.build_from_observations` — telemetry frames → IRG (Investigation Relationship Graph) enrichment → IKG assembly → verdicts + correlation + attack story + attack mapping + explainability + IKB (Investigation Knowledge Base).

**Persistence collections (all 0 rows today):**
- `v2_case_events` — event nodes
- `v2_case_entities` — process / file / network / registry / module / service / task
- `v2_case_behaviors` — behavior extractions
- `v2_case_relationships` — edges
- `v2_case_reports` — case-scoped reports

**Consumers (all planned, none live):** Trajectory · Attack Story · Evidence Graph · ATT&CK view · Verdict roll-up · Explainability · Reports.

**Why 0 rows today:** `NIVX_FLAG_CASE_ENGINE=shadow`. The IKG is architecturally beautiful and completely dormant until promoted.

**Provenance guarantee (when live):** every node carries `source_node_ids` back to the events that produced it (mirrors `ExecGraph`'s discipline in `engine/evidence_graph.py`).

---

## §11 · Correlation Engine — 🟡 SHADOW

**Path**: `backend/v2/verdict/correlation.py`.

**Model:** layered aggregation on top of per-event scoring —
```
Event → Process → Chain → Device → Incident
```

**Substrate:** the Attack Graph produced by `v2/shadow/irg.enrich` — grouping by `entity.iid` + `parent.iid` + `root.iid`, **not** timestamps and **not** PIDs. This is deliberate to prevent unrelated coincident activity from inflating a score.

**Determinism guarantees:**
- Same input frames → byte-identical output.
- Same evidence → same explanation.
- No LLM. No binary-name reputation. No external TI.

**Anti-inflation:** signals de-duplicated per layer (a signal fired by 5 events of the same process contributes ONCE at the process layer).

**Live equivalent today:** none — the shipping verdict is the simpler `canonical/projections/verdict.py` linear scorer.

---

## §12 · Verdict Engine — Live vs Shadow

### 12.1 · Canonical Verdict Projection — 🟢 LIVE (shipping)

**Path**: `canonical/projections/verdict.py`. Consumed via `POST /api/die/investigation-results.object.verdict`.

**Flow:**
```
AuthoritativeSSOT
        │
        ▼
count(mitre_nodes)    × 25 (cap 4)
count(ioc_nodes)      ×  8 (cap 8)
count(command_nodes)  ×  4 (cap 8)
count(reasoning_steps)×  2 (cap 10)
        │
        ▼
score = clamp(0..100)
        │
        ▼
label bands:
  ≥ 80  MALICIOUS
  ≥ 60  SUSPICIOUS
  ≥ 30  LIKELY_BENIGN
  else  INCONCLUSIVE
        │
        ▼
contributors[] { class, count, weight }
reason: "canonical score derived from N×class + …"
        OR
        "no evidence in canonical SSOT"   ← negative explainability
input_completeness: complete | minimal | unknown
```

**Test coverage:** `test_p01_p02_verdict_card.py`, `test_verdict_engine_parity.py`, `test_verdict_card_never_null.py`, `test_adr0007_verdict_evidence_gating.py`.

### 12.2 · Verdict Engine v3 — 🟡 SHADOW

**Path**: `backend/v2/verdict/{engine,weights,profiles,correlation,progressions,signals,canonical,shadow}.py`. Endpoints `GET /api/v2/cases/{id}/verdicts*` return 503 unless `NIVX_FLAG_VERDICT_ENGINE_V3=enabled`.

**Flow:**
```
Event (frame)  →  signals[] (v2/verdict/signals.py)
                  weights   (v2/verdict/weights.py, per profile)
                  profile   (v2/verdict/profiles.py, default = soc_balanced)
                  progressions (v2/verdict/progressions.py)
                        │
                        ▼
                  event score + band + explanation + breakdown
                        │
                        ▼   (correlation aggregates on IRG)
              Process score + band + confidence
                        │
                        ▼
                Chain score + band + confidence
                        │
                        ▼
               Device score + band + confidence
                        │
                        ▼
              Incident score + band + confidence
```

**Explainability:** every event carries `explanation: str` + `breakdown: dict`. Aggregate levels carry `confidence`. `why_is_this_not` (§15) covers negative explainability.

**Adaptive Weight Profiles:** `soc_balanced` (default), plus other profiles registered in `list_profiles()`. Currently all shadow.

---

## §13 · ATT&CK Mapping

### 13.1 · Canonical ATT&CK — 🟢 LIVE

`canonical/projections/attck.py` — dictionary of observed techniques + tactics + coverage stats.

### 13.2 · v2 ATT&CK Mapping — 🟡 SHADOW

`backend/v2/investigation/attack_mapping.py::build_attack_mapping`:
- Tactic-level coverage (deterministic level 0..3).
- Per-tactic technique list.
- Kill-chain ordered stages.
- **MITRE Navigator v4.5 layer JSON** — one-click export.
- STIX 2.1 technique set (fully rendered in `v2/report/stix.py`).

**Base-technique dictionary:** `TACTIC_OF_BASE` — ~40 techniques across 12 tactics, hardcoded. Techniques outside this table map to `None` and drop from the chain (silent).

**14-lane Attack Chain diagram** (frontend) — `TrajectoryDiagram.jsx` — assigns each behavior to one of 14 MITRE tactic lanes using canonical tactic mappings from the backend. Regression-locked by `trajectoryLaneAssignment.test.mjs`.

---

## §14 · Attack Story

### 14.1 · Canonical Attack Story — 🟢 LIVE

`canonical/projections/attack_story.py`. Pure, deterministic. Returns `None` when no evidence — **never fabricates a story**.

**Structure:** `{ opening, chapters[], closing }`.
**Chapter shape:** `{ stage, title, techniques[], narrative }`.

**Consumer:** `POST /api/die/investigation-results.object.attack_story` — but Workspace does not currently render it as a dedicated panel (see §22 · Attack Story wire-up = DISCONNECTED).

### 14.2 · v2 IKB-driven Attack Story — 🟡 SHADOW

`backend/v2/investigation/attack_story.py::build_attack_story` — reads from IKG + IKB (Investigation Knowledge Base). Awaits IKG promotion.

---

## §15 · Negative Explainability — 🟡 SHADOW

**Path**: `backend/v2/investigation/explainability.py::why_is_this_not` + `list_patterns`.

**Purpose:** answer "why is this NOT malicious?" — the mirror of the verdict explanation. Registered negative patterns include e.g. `SUSPICIOUS_PARENT` → *"remotely-launched process"* etc.

**Live equivalent today:** the canonical verdict projection prints `"no evidence in canonical SSOT"` when no positive evidence exists — a minimal form of negative explainability. Full pattern-based negative explanations are shadow.

---

## §16 · Mitigation — 🟢 LIVE

**Path**: `backend/services/mitigation/` + `routers/mitigations.py`.

**Endpoint:** `POST /api/decode/mitigations` — accepts the same body as `/api/decode/smart`, returns deterministic mitigation recommendations (schema documented in `services.mitigation.derive_mitigations`).

**Wire status:** endpoint LIVE; Workspace consumer per ADR-0007 §2 = DISCONNECTED (backlog).

---

## §17 · Threat Intelligence

**Provider inventory:**

| Provider | Route into NivXRay | Status |
|---|---|---|
| AlienVault OTX | `feeds.py::fetch_otx` (`OTX_API_KEY`) | 🟢 LIVE |
| AbuseIPDB | `feeds.py::fetch_abuseipdb` | 🟢 LIVE |
| URLhaus | `feeds.py::fetch_urlhaus` | 🟢 LIVE |
| ThreatFox | `feeds.py::fetch_threatfox` | 🟢 LIVE |
| MalwareBazaar | `feeds.py::fetch_malwarebazaar` | 🟢 LIVE |
| MalwareBytes | `feeds.py::fetch_malwarebytes` | 🟢 LIVE |
| Talos | `feeds.py::fetch_talos` | 🟢 LIVE |
| CINS Army | `feeds.py::fetch_cins_army` | 🟢 LIVE |
| URLscan | `URLSCAN_API_KEY` in env | 🟢 LIVE |
| VirusTotal | — | ⚪ NOT-IMPLEMENTED |

**Persistence:**
- `iocs` — 65,614 deduped IOCs.
- `ti_sync_runs` — 1,339 feed-sync runs.
- `ti_source_meta` — 8 provider configs.
- `cti_rss_meta` — 8 RSS sources.
- `pending_training_notes` — 96 RSS-derived pending notes (analyst-approvable).

**RSS crawl:** `routers/threat_intel_rss.py` — crawls, extracts, promotes high-confidence notes.

**Threat-intel enrichment cache:** `backend/threat_intel_enrich/` + `v2_enrichment_cache` (0 docs today).

**TAXII 2.1 push:** `routers/taxii.py` — admin-only. `taxii_push_log` = 85 real pushes.

---

## §18 · Threat Hunting / Query — 🟢 LIVE (single-case)

**Endpoint:** `POST /api/die/query` + `QueryHuntPanel.jsx`.

**Filter dictionary (all optional, per `services/die/query_hunt.py`):**
```
host / src_host     · substring, case-insensitive
user                · substring, case-insensitive
action              · exact match, case-insensitive
category            · substring, case-insensitive
process / file_name · substring, case-insensitive
parent / parent_process · substring, case-insensitive
file_path           · substring, case-insensitive
file_hash           · exact match, case-insensitive
mitre               · exact MITRE technique id (T####)
event_type          · substring, case-insensitive
date_from / date_to · ISO-8601, inclusive range
confidence          · high | medium | low
```

**Auto-Viz decision (Session-7):** if the filtered event set has parent/child relations → Process Tree; else → Timeline. Payload safety ceiling: 32 KB.

**Cross-case hunting:** ⚪ NOT-IMPLEMENTED. Every query is scoped to the current investigation's canonical events.

---

## §19 · Timeline — 🟢 LIVE

**Endpoint:** `POST /api/die/timeline` + `TimelinePanel.jsx`.

**Source:** `services/die/timeline_projection.py` — read-only projection over `object.csv_edr.highconf_events`.

**Rules:**
- Only events with a real timestamp emit.
- Narrative MITRE mentions (no timestamp) do NOT appear.
- Every event carries the P0.2 evidence_ref.
- No fabrication.

**Long-term** (per module docstring): when Sysmon / EVTX / CrowdStrike / Defender feed the canonical event bag, this projection picks them up automatically.

---

## §20 · Device Trajectory — 🟡 SHADOW

**Endpoint:** `GET /api/v2/cases/{case_id}/trajectory/device` — gated by `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`.

**Live equivalent today:** the 14-lane Attack Chain diagram in `TrajectoryDiagram.jsx` — which is technically a per-case tactic-lane trajectory, not a device-fleet trajectory. Sufficient for single-case; not fleet-scale.

---

## §21 · Reports — 🟢 LIVE

### 21.1 · v2 Report Envelope (shipping)

`backend/v2/report/{schema,builder,markdown,pdf,stix,bundle,hashing}.py`.

**Envelope** (`ReportEnvelope`) has 10 canonical section IDs:
```
executive_summary   case_metadata          verdict_rollup
mitre_coverage      process_ancestry       top_entities
chronological_timeline  commandline_decoding
enrichment          signature
```

**Determinism:** every field except `signature` participates in the SHA-256 hash. Same input → same hash. **CI-locked by** `backend/tests/canonical/api/test_report_determinism.py` (6 pass, PDF explicitly deferred).

**Endpoints:**
- `POST /api/v2/analyze/report?fmt={md|json|pdf|stix|bundle}` — the FE consumer.
- `GET /api/v2/cases/{id}/report.{md|pdf|stix.json|bundle.zip}` — v2 case scope.
- `POST /api/v2/report-writer/generate*` — dedicated report-writer.

### 21.2 · Legacy Reports — 🟠 DEPRECATED

`backend/report_renderers.py` + `/api/report/*` (5 routes) — TXT/HTML/DOCX/PDF/CSV renderers superseded by the v2 envelope. Sunset candidates per ADR-0009 §5.1.

### 21.3 · Canonical Reports Projection

`canonical/projections/reports.py` — projects STIX / Sigma / YARA / Navigator / MDR from SSOT. Machine-schema outputs (byte-identity for structured fields).

---

## §22 · Workspace — Analyst Workflow

The primary product surface. Route: `/` → `WorkspacePage.jsx` (4,306 lines).

**Layout (top → bottom):**

```
┌─────────────────────────────────────────────────────────────┐
│ Header · Nav · CasesDrawer · HistoryDrawer                  │
├─────────────────────────────────────────────────────────────┤
│ Input toolbar (paste box) + Upload + Smart-Input Advisor    │
├─────────────────────────────────────────────────────────────┤
│ Analyst Quick Actions                                        │
├─────────────────────────────────────────────────────────────┤
│ Tabs (dynamic per available payload):                        │
│                                                              │
│  Overview                        · OverviewTab.jsx           │
│  Attack Chain (14 lanes)         · TrajectoryDiagram.jsx     │
│  Timeline                        · TimelinePanel.jsx (NEW)   │
│  Query / Hunt                    · QueryHuntPanel.jsx (NEW)  │
│  Evidence                        · EvidenceTab.jsx           │
│  Attack Story                    · InlineAttackStory.jsx     │
│  IOC Panel                       · (integrated)              │
│  MITRE / ATT&CK                  · (integrated)              │
│  LOLBAS                          · (integrated)              │
│  Verdict Card                    · SocVerdictPanel.jsx +     │
│                                    VerdictCard.jsx           │
│  Narrative (LLM)                 · AnalystNarrativePanel.jsx │
│  Semantic Intelligence           · SemanticIntelligencePanel │
│  Investigation Brain             · InvestigationBrainPanel   │
│  Extracted Artifacts             · ExtractedArtifactsPanel   │
│  Artifact Trace                  · ArtifactTracePanel.jsx    │
│  Acquisition (plan · evidence)   · AcquisitionPlan/Evidence  │
│  Report Tab                      · ReportTab.jsx             │
│  Threat Analysis                 · ThreatAnalysis.jsx        │
│  Correlations                    · CorrelationSuggestionCard │
│  Decode Failure                  · WorkspaceDecodeFailureCard│
│  Chain Replay                    · ChainReplayView.jsx       │
│  Process Tree                    · ProcessTreeView.jsx       │
│  Evidence Graph                  · EvidenceGraphView.jsx     │
│  Recovery Ribbon                 · RecoveryStatusRibbon.jsx  │
└─────────────────────────────────────────────────────────────┘
```

**Analyst flow (happy path):**
```
1. Analyst pastes a suspicious command line into the input box
2. WorkspacePage debounces (useDeferredValue) and calls /api/die/analyze
3. On result, calls /api/die/investigation-results (the P0.3-locked payload)
4. Optionally calls /api/die/timeline and /api/die/query for the additive panels
5. Optionally calls /api/v2/analyze/report?fmt=md to generate a Markdown report
6. Analyst saves the case via /api/cases/* → workspace_cases (257 rows today)
7. Analyst can add corrections via /api/corrections → analyst_corrections
8. Analyst can retrieve the same case later from /api/investigations + drawer
```

**Additive surfaces (non-destructive projections):** Timeline · Query/Hunt · Auto-Viz. These MUST NOT mutate the baseline `investigation-results` payload — locked by `test_workspace_isolation_guard.py`.

**Every interactive element carries a `data-testid`** for automated testing.

---

## §23 · Frontend Architecture

**Tech stack:**
- React 19 · react-router-dom 7 · react-scripts 5 (CRA)
- Radix UI (26 primitives) + Tailwind 3 + tailwindcss-animate
- Framer Motion 11
- `@xyflow/react` + `react-force-graph-2d` + `react-konva` — graph rendering
- `recharts` — charts
- `@tanstack/react-query` — server-state cache (light usage)
- Storybook 8 · Playwright 1.61 · vitest-style `.test.mjs`

**File layout:**
```
frontend/src/
├── App.js                   58 routes
├── pages/                   34 top-level pages (lazy-loaded)
├── components/              138 top-level + investigation/ + attackStory/ + ui/
│   ├── investigation/       30 panels (production Workspace)
│   └── ui/                  40+ Radix + Shadcn primitives
├── v2/                      Parallel v2 workspace (10 pages) — SHADOW backend
├── workspace_v4/            AnalystWorkspaceShellPage (route /investigate/*)
├── nivxforge/               Preview surface (5 pages, 3 placeholder)
├── lib/                     Auth + utilities
├── hooks/                   React hooks
└── constants/, index.js, index.css
```

**Frontend calls 74 unique `/api/*` URL literals** against 466 backend routes. Per ADR-0009, tight matching upgrades this to 84 ACTIVE-UI + 141 ACTIVE-API confirmed live.

**Feature-flag library on FE:** ⚪ NONE (no Split.io / Unleash / LaunchDarkly). Panels self-gate by inspecting payload keys.

---

## §24 · Backend Architecture

**Tech stack:**
- FastAPI 0.110.1 · Uvicorn 0.25.0 (1 worker + --reload in current pod)
- Motor 3.3.1 async MongoDB driver · pymongo 4.6.3
- Pydantic 2.13.4
- LiteLLM 1.80 (customer wheel) · OpenAI 1.99 · Anthropic (via Emergent key)
- httpx (feed fetch) · bcrypt · PyJWT
- Capstone 5.0.9 (disassembly) · pefile 2024.8.26 (PE parsing)
- reportlab 4.5.1 (PDF)
- Playwright 1.61 (test only)

**Module layout (source of truth for `services/*` responsibility):**
```
backend/
├── server.py                 FastAPI wiring + 77 router.include_router()
├── deps.py                   DB / auth / LLM / settings helpers
├── request_hardening.py      Middleware (body cap, timeout, X-Request-ID)
├── canonical/                ADR-005 canonical pipeline
│   ├── iue/                  IUE Composer + adapters
│   ├── executor/             Canonical Executor + capabilities
│   ├── ssot/                 AuthoritativeSSOT (append-only, provenance)
│   └── projections/          verdict, attack_chain, attack_story, iocs,
│                             lolbas, timeline, executive_summary,
│                             analyst_summary, recommendations, reports,
│                             attck, evidence_bundle, evidence_graph_view,
│                             activity, canonical
├── services/die/             DIE — 30+ modules (analyze, chain, cmd_ast,
│                             confidence, csv_edr_analyzer, input_health,
│                             input_understanding, intent, investigation_results,
│                             ioc_semantic, javascript_ast, lolbas,
│                             mitre_evidence_chain, narrative, powershell_ast,
│                             preprocessor/, python_ast, query_hunt (NEW),
│                             timeline_projection (NEW), vbscript_ast,
│                             analyst_narrative, archive_recovery, bash_ast,
│                             behavior_explainer, canonical, canonical_bridge,
│                             canonical_narrative_enrichment, dkp/)
├── services/ida/             Intelligent Document Analyzer
├── services/adapters/        docx/eml/image/pdf/text/url/zip adapters
├── services/uaie/            Universal Artifact Intelligence Engine
├── services/ice/             Intelligent Correlation Engine
├── services/mitigation/      Mitigation recommendations
├── services/veee/            Visual Evidence Extraction Engine
├── services/uil/             Universal Input Layer
├── services/reasoning/       Behavior extraction, investigation composer
├── services/knowledge/       Behavior registry
├── services/ioc_intelligence/ IOC intelligence
├── services/canonicalizer/   Canonicalisation
├── services/normalization/   Post-decode normalization
├── services/artifact_intelligence/
├── services/attack_fingerprint.py
├── services/correlation_engine.py
├── services/technique_detector.py
├── engine/                   RC5 pipeline (evidence_graph, orchestrator,
│                             exec_graph, semantic_ir, plugin_api, registry)
├── decoders/                 50+ decoder modules (ps_encoded, batch_envvar,
│                             ps_reverse_swap, rc4_inline, ascii85, base32,
│                             base58, base91, brotli, caesar, cobaltstrike, …)
├── nivxforge/                nivxforge platform surface (backend)
├── v2/                       Shadow pipeline (see §10, §11, §12)
│   ├── investigation/        IKG + verdict + correlation + attack_story
│   ├── verdict/              Engine v3
│   ├── case_engine/          v2 case schema + store
│   ├── shadow/               Shadow observations (IRG enrich, persist)
│   ├── artifact_store/       v2 artifact store
│   ├── report/               v2 report envelope
│   ├── ingestion/            multi-format ingest
│   ├── validation/           validation datasets
│   ├── semantic/             PS semantic engine
│   ├── ikb/                  Investigation Knowledge Base entries
│   ├── flags.py              NIVX_FLAG_* registry
│   ├── routers/              12 sub-routers under /api/v2/*
│   └── (11 more sub-dirs for cem, cre, iu, intent, trust, behavior, rte, graph, jobs)
├── routers/                  77 router modules (§25)
├── models/                   Pydantic models
├── knowledge_base/           KB builder/schema/synthesizer
├── threat_intel_enrich/      TI enrichment cache
├── training/                 Training corpus / seed dataset
├── finetune/                 LLM finetune
├── learner_engine.py         Learner
├── operations.py + ops_extended.py + ops_base_family.py  250+ decode ops
├── feeds.py                  7 OSINT feed fetches
├── taxii/                    TAXII 2.1 push
├── ti_feed_sync.py
├── stix_export.py + sigma_export.py + yara_export.py
├── evidence_extractor.py + investigation_report.py + chain_analyzer.py
├── command_analyzer.py + commandline_miner.py (legacy siblings — tech debt)
├── privacy.py + payload_sanitizer.py + request_hardening.py
├── troubleshoot_engine.py + layer_validator.py + layer_360.py
├── llm_provider.py + llm_decoder.py + ai_credit_guard.py
├── magic_decoder.py + smart_decoder.py + shellcode_analyzer.py
├── pe_analyzer.py + amsi_detector.py + crypto_hints.py
├── heuristics/ + normalizers/ + extractors/ + reasoning/
├── static_docs/ + docs/ + baselines/ + corpus/
└── tests/                    389 test files · 3,621 test functions
```

---

## §25 · API Architecture

**Total**: 466 method-routes across 436 paths (ADR-0007 §3), 77 routers (ADR-0007 §24).

**Classification per ADR-0009:**
- 🟢 ACTIVE-UI 84 · ACTIVE-API 141 (together = 48.3 % confirmed live)
- 🔵 INTERNAL 95 (20.4 %)
- 🧪 EXPERIMENTAL 49 (all `/api/v2/*` + 2 `/api/nivxforge/preview/*`)
- 🟠 DEPRECATED 6 (5 legacy `/api/report/*` + 1 `/api/observation/*` residual)
- 🟠 DUPLICATE 4 (`/api/timeline/*` overlaps `/api/die/timeline`)
- ❓ UNKNOWN 87 (research backlog, not deletion backlog)

**Key namespaces:**

| Prefix | Ops | Role |
|---|---:|---|
| `/api/die/*` | 21 | **The shipping analyst pipeline** |
| `/api/investigation/*` | 21 | L1 workspace investigation APIs (heaviest DB usage) |
| `/api/correlations/*` | 20 | Case-to-case correlation |
| `/api/threat-intel/*` | 20 | Feed sync + IOC lookup + RSS |
| `/api/rc5/*` | 19 | RC5 golden runs + shadow + entity classifier |
| `/api/learner/*` | 16 | Learning engine |
| `/api/decode/*` | 17 | Deterministic decoders |
| `/api/admin/*` | 37 | Admin ops surface (OSINT keys, samples, models, users, TAXII) |
| `/api/docs/*` | 39 | Static docs + feedback + cheatsheet |
| `/api/v2/*` | 55 | Parallel shadow pipeline (see §10-§12) |
| `/api/analyze/*` | 9 | Sync / async / stream + shellcode + status |
| `/api/lab/*` | 8 | Analyst Practice Lab |
| `/api/cases/*` | 8 | Workspace case CRUD |
| `/api/history/*` | 8 | Investigation history drawer |
| `/api/session/*` | 8 | Session vault |
| `/api/timeline/*` | 4 | Legacy timeline (DUPLICATE) |
| Other 30+ prefixes | ~200 | Health, telemetry, docs, planner, ioc, mitre, moe, uaie, uil, kb, corrections, sigma, share, taxii, artifacts, benchmark, batch, coverage, correlations, enrichment, finetune, planner, telemetry, threat-intel-rss, threat-intel-enrich, training, understand, upload, iedde, moe, observation, nivxforge/preview, platform, corpus, rc5-*, static-docs, mitigations, schemas, examples, ssot |

---

## §26 · Data Model

**Mongo DB:** `test_database` (single, on `localhost:27017`).
**64 collections.** Grouped by concern.

### Auth
| Collection | Docs |
|---|---:|
| `users` | 4 |

### Cases & investigations (RC5 / L1)
| Collection | Docs | Meaning |
|---|---:|---|
| `investigations` | 2,883 | Case history rows |
| `investigation_events` | 933 | Frame-level events |
| `investigation_sessions` | 327 | Session vault |
| `investigation_ssot` | 35 | Canonical SSOT snapshots |
| `investigation_cases` | 77 | Case metadata |
| `workspace_cases` | 257 | Cases in Workspace surface |
| `canonical_ssot_store` | 2 | Canonical SSOT persistent (rarely used — projection is volatile) |

### v2 shadow pipeline (all 0 or low)
| Collection | Docs |
|---|---:|
| `v2_cases` | 29 |
| `v2_case_events` | **0** |
| `v2_case_entities` | **0** |
| `v2_case_behaviors` | **0** |
| `v2_case_relationships` | **0** |
| `v2_case_reports` | **0** |
| `v2_shadow_observations` | 563 |
| `verdict_shadow_observations` | 2 |
| `v2_artifact_store` | 15 |
| `v2_decoded_payloads` | 161 |
| `v2_ai_jobs` | 211 |
| `v2_enrichment_cache` | 0 |
| `v2_audit_log` | 0 |

### Threat intel
| Collection | Docs | Meaning |
|---|---:|---|
| `iocs` | **65,614** | Deduped IOCs from OSINT feeds |
| `ti_source_meta` | 8 | Provider config |
| `ti_sync_runs` | 1,339 | Feed sync history |
| `cti_rss_meta` | 8 | RSS sources |
| `pending_training_notes` | 96 | RSS-derived pending notes |
| `enrichment_cache` | 0 | (cache) |
| `enrichment_config` | 1 | Config |
| `taxii_config` | 1 | TAXII target |
| `taxii_push_log` | 85 | Real STIX pushes |

### Corpus / regression / benchmark
| Collection | Docs |
|---|---:|
| `sample_library` | 18 |
| `admin_models` | 73 |
| `analyst_corrections` | 887 |
| `benchmark_runs` | 897 |
| `batch_runs` | 264 |
| `regression_runs` | 239 |
| `regression_gate` | 1 |
| `regression_corpus` | 56 |
| `playbook_votes` | 262 |
| `rc5_golden_runs` | 9 |
| `rc5_shadow_runs` | 1 |
| `learner_payloads` | 18 |
| `learner_versions` | 2 |
| `learning_events` | 572 |
| `learning_feedback` | 3 |
| `decode_feedback` | 3 |

### Lab / KB / documents
| Collection | Docs |
|---|---:|
| `lab_attempts` | 89 |
| `lab_stats` | 1 |
| `kb_entries` | 339 |
| `documents.chunks` | 35 |
| `documents.files` | 35 |
| `frontend_telemetry` | 52 |
| `platform_metrics_snapshots` | 1 |

### AI budgeting
| Collection | Docs |
|---|---:|
| `ai_budget` | 2 |
| `ai_call_log` | 5 |
| `ai_decode_cache` | 4 |
| `ai_describe_cache` | 10 |
| `ai_response_cache` | 4 |

### Miscellaneous
`correlations` (5), `analyze_jobs` (0), `lolbas_cache` (1), `settings` (3), `summary_overrides` (2), `sessions_all_kinds` (~500).

**No `tenant_id` column exists anywhere.** Single-tenant.

**No TTL indices verified** (ADR-0007 §13).

---

## §27 · Runtime Architecture

```
Cloudflare edge ── HTTPS terminated
        │
        ▼
Kubernetes ingress ── routes /api/* → :8001, everything else → :3000
        │
        ▼
Emergent pod
        │
        ▼
Supervisor
        │
        ├── mongodb (bound :27017 localhost)     RUNNING
        ├── backend  (uvicorn --workers 1 --reload :8001)  RUNNING
        ├── frontend (react-scripts start :3000)  RUNNING
        └── nginx-code-proxy (dev-editor proxy)   RUNNING
```

**Backend footprint (measured this session):**
- RSS at boot: **27.7 MB**
- RSS under 10× SEP CSV concurrency: **~378 MB** (Session-7)
- Cold start: ~3 s / 2,080 modules
- Deep health: mongo=ok · llm_key=ok · disk=87.66 GB free.

**No Redis. No queue. No workers.** One asyncio background loop (`_nightly_benchmark_loop`) sleeps 24 h.

---

## §28 · Configuration & Feature Flags

**`.env` (per ADR-0007 §5, verified this session):**

Auth / infrastructure:
```
MONGO_URL     = mongodb://localhost:27017
DB_NAME       = test_database
CORS_ORIGINS  = "*"                    ← permissive
JWT_SECRET    = <96-char random>
JWT_EXPIRE_HOURS = 24
ADMIN_EMAIL   = admin@nivxray.com
ADMIN_PASSWORD = <redacted>
ADMIN_FORCE_PASSWORD_CHANGE = false
```

Integrations / LLM:
```
EMERGENT_LLM_KEY = sk-emergent-…
OTX_API_KEY      = <redacted>
URLSCAN_API_KEY  = <redacted>
```

Behaviour toggles (non-flag env):
```
NIVX_AI_DEADLINE_S           = 90
NIVX_OSINT_DEADLINE_S        = 20
NIVX_AI_ENABLED              = true
NIVX_AI_RATE_HOURLY          = 10
NIVX_AI_RATE_DAILY           = 50
NIVX_AI_BUDGET_CAP_CREDITS   = 500
NIVX_ENGINE                  = legacy
NIVX_ENGINE_BUDGET_DEPTH     = 12
NIVX_ENGINE_BUDGET_WALLTIME_MS = 5000
NIVX_CANONICAL_UIL_INVESTIGATE = on
NIVX_CANONICAL_DIE_ANALYZE   = on
```

Tri-state feature flags (`disabled | shadow | enabled`) — all currently `shadow`:
```
NIVX_FLAG_TRAJECTORY_ENGINE  = shadow
NIVX_FLAG_CASE_ENGINE        = shadow
NIVX_FLAG_ADAPTERS           = shadow
NIVX_FLAG_ARTIFACT_STORE     = shadow
NIVX_FLAG_VERDICT_ENGINE_V3  = shadow
```

**Effect of shadow state:** each flagged subsystem runs side-by-side with the live pipeline but **must not influence outputs**. Endpoints under the flag return 503 unless the flag is promoted. See ADR-0008 §4 for promotion criteria.

---

## §29 · Workspace vs X-Lab Isolation

**History:** X-Lab was previously two things — Practice Lab (kept) and X-Lab-A (Observational surface, removed in Session-7).

**Shared modules that Workspace and any Lab MAY use:**
```
services/die/*    canonical/*    services/ida/*
l1_evidence/*     l2_investigation/*
deps.py           schemas.py
```

**Practice Lab exclusive ownership:**
```
routers/lab.py + sample_library.py + lab_attempts + lab_stats
frontend/src/pages/LabPage.jsx
```

**Removed / vestigial:**
```
routers/observation.py    ← 1-route X-Lab-A residual (DEPRECATED per ADR-0009)
```

**CI-locked isolation:** `test_workspace_isolation_guard.py`.

**Rule (regression-locked, ADR-0008 P2):** any Lab-adjacent change MUST NOT alter existing Workspace behaviour.

---

## §30 · External Integrations

| Integration | Direction | Status |
|---|---|---|
| Emergent LLM key (Claude/GPT/Gemini via LiteLLM) | outbound | 🟢 LIVE |
| AlienVault OTX | inbound (feed pull) | 🟢 LIVE |
| AbuseIPDB | inbound (feed pull) | 🟢 LIVE |
| URLhaus / ThreatFox / MalwareBazaar / MalwareBytes / Talos / CINS Army | inbound (feed pull) | 🟢 LIVE |
| URLscan.io | outbound (per-URL) | 🟢 LIVE |
| TAXII 2.1 server | outbound (STIX push) | 🟢 LIVE |
| VirusTotal | — | ⚪ NOT-IMPLEMENTED |
| Microsoft Defender for Endpoint / CrowdStrike / SentinelOne / Cisco XDR / Cisco AMP | — | ⚪ NOT-IMPLEMENTED |
| Splunk / Sentinel / QRadar / Elastic | — | ⚪ NOT-IMPLEMENTED |
| Google OAuth / SSO / SAML | — | ⚪ NOT-IMPLEMENTED |
| Slack / Teams / PagerDuty | — | ⚪ NOT-IMPLEMENTED |
| Stripe | package present, unused | ⚫ DEAD (dependency) |
| boto3 / S3 | package present, unused | ⚫ DEAD (dependency) |
| googleapiclient / google-genai | package present, unused | ⚫ DEAD (dependency) |

---

## §31 · Customer Data Flow

```
Analyst
  │  paste / upload (≤ 256 KB · 512 KB body cap · 50 MB whitelisted)
  ▼
Cloudflare → K8s ingress → uvicorn (1 worker)
  │
  ▼
FastAPI route handlers
  │
  ├── /api/upload         → in-memory raw bytes → GridFS `documents.*` (if saved)
  │                                              → hash + text-extract only
  │                                              → does NOT persist raw uploads
  ├── /api/die/*          → in-memory analysis, projection → `workspace_cases`
  ├── /api/analyze/*      → same
  ├── /api/investigation/* → `investigations` + `investigation_events` + `investigation_ssot`
  ├── /api/cases/*        → `workspace_cases`
  ├── /api/session/*      → `investigation_sessions`
  └── /api/threat-intel/* → outbound httpx to OSINT providers
                            → `iocs` (deduped, capped)
  │
  ▼
LLM narrate → Emergent LLM key (LiteLLM shim) → Claude / OpenAI / Gemini
                                                (analyst input text CROSSES the
                                                 boundary to the LLM provider)
```

**What enters:** analyst-pasted commands / prose · ≤ 256 KB uploads · CSV EDR exports · OSINT feeds.

**What is persisted:** case rows · events · SSOT snapshots · IOCs · analyst corrections · benchmark/regression runs · lab attempts · uploaded documents (GridFS if the analyst saves).

**What leaves the environment:**
- LLM prompt (contains user's pasted input) → LLM provider (Emergent key).
- URL-fetch on IOC enrichment (behind SSRF guard) → target URL.
- TAXII push (user-initiated) → configured TAXII collection.
- Report download (user-initiated) → analyst browser.

**Retention / TTL:** ⚪ NOT VERIFIED (ADR-0007 §13). Cases accrue indefinitely.

**Backups:** NOT OBSERVED. ⚪ UNKNOWN.

**Tenant isolation:** ⚪ NONE — single Mongo DB, no `tenant_id`.

---

## §32 · Security Posture

Full details in ADR-0007 §12. Summary here.

| Control | Reality |
|---|---|
| Authentication | 🟢 JWT + bcrypt admin (`role == "admin"`) |
| Password strength | 🔵 min 12 chars, no complexity policy, no history |
| Brute-force protection | ⚪ NOT-IMPLEMENTED |
| Session revocation | ⚪ NOT-IMPLEMENTED |
| RBAC | 🔵 admin/user only |
| Multi-tenant isolation | ⚪ NOT-IMPLEMENTED |
| SSRF | 🟢 Loopback/link-local/RFC1918/reserved blocked; tested |
| Body size cap | 🟢 512 KB default / 50 MB large / 256 KB upload / 64 KB text |
| Request timeout | 🟢 Per-path table; 504 emitted with X-Request-ID |
| Archive-bomb / zip-slip | ⚪ NOT-IMPLEMENTED (unbounded unzip in /api/upload) |
| Path traversal | 🟢 In-memory only; no FS write on user input |
| Command execution | 🟢 No subprocess shell on user input |
| Parser isolation | ⚫ NOT-IMPLEMENTED (PE / DOCX / RC4 / capstone all in-process) |
| Injection (NoSQL) | 🟢 Motor + Pydantic input validation |
| XSS | ❓ React auto-escapes; `dangerouslySetInnerHTML` count UNKNOWN |
| Supply-chain | 🔵 pinned requirements.txt; no SBOM; LiteLLM via customer CDN wheel |
| Sensitive-data logging | 🟢 secrets not logged; LiteLLM INFO silenced |
| MongoDB/Redis exposure | 🟢 Mongo bound localhost; Redis not used |
| CORS | ⚠️ `allow_origins=["*"]` + `allow_credentials=True` (spec-invalid) |
| HTTPS / TLS | 🟢 terminated at Cloudflare + K8s |
| Audit log | ⚪ `v2_audit_log` collection exists but 0 docs |
| Secret rotation | ⚪ NOT-AUTOMATED |

**Top risks (unchanged from ADR-0007 §28):**
1. CORS `*` + credentials.
2. No login rate-limit.
3. Unbounded archive unpack.
4. Same-process parser isolation for untrusted binaries.

---

## §33 · Deployment Models

| Model | Feasibility today |
|---|---|
| Emergent-managed SaaS (single tenant) | 🟢 CURRENT MODE |
| Customer-hosted / on-prem | 🔵 Feasible with effort — no packaged distributable, no Helm/compose |
| Multi-tenant SaaS | ⚪ NOT-POSSIBLE without tenant model + DB schema changes |
| Air-gapped | 🔵 Partial — offline-LLM path exists in docs; TI feed sync would be disabled |
| Local-only analyst tool | 🟢 Feasible — dev-mode start (uvicorn + yarn) |
| Private cloud / hybrid | 🔵 Feasible with effort — same as customer-hosted |

---

## §34 · Testing / Quality

- **Backend test files:** 389
- **Backend test functions:** 3,621 (`grep -c "def test_" backend/tests/*.py`)
- **Canonical API suite (P0.2 · P0.3 · Timeline · Query · Determinism · Sample1 · X-Lab isolation):** 114 passed · 5 skipped this session.
- **Frontend unit tests:** 5 `.test.mjs` files (Trajectory / lane / classify / viewport).
- **Frontend e2e:** Playwright dep present, no active `frontend/tests/` seen.
- **CI configuration:** `.github/` present, workflow inventory not audited this session.

**What each major suite proves (evidence-based):**
- **P0.2 evidence chain:** every technique on `/api/die/*` carries traceable `{source, event_or_rule, field, observed_value, evidence_ref}`.
- **P0.3 firewall:** response envelope limited to 10 keys; Sample1 case row byte-immutable; X-Lab can't touch Workspace.
- **Timeline MVP:** response contract fixed; no invented events.
- **Query/Hunt:** filter semantics + Auto-Viz decision fixed.
- **Determinism (Session-8):** Markdown / STIX / envelope-signature byte-identical across re-renders.
- **SSRF:** 4 categories of dangerous IP-space blocked.
- **Verdict card:** never null; evidence-gated.
- **Behavior graph:** schema frozen at CI time.
- **Baseline snapshots:** corpus regression baselines locked.

**Not tested yet:**
- Login brute-force resistance.
- Zip-bomb / archive recursion.
- PDF byte-determinism.
- CORS behaviour under browsers.
- Cross-case hunt (feature absent).
- Multi-tenant isolation (feature absent).
- Frontend e2e for shipping Workspace path.

---

## §35 · Performance

- Latency `/api/die/analyze` p50: ~100 ms (Session-7).
- Latency LLM-augmented paths: up to `NIVX_AI_DEADLINE_S=90`.
- Uvicorn workers: 1 (with `--reload` — dev shape).
- Wall-time budget per engine call: 5,000 ms (`NIVX_ENGINE_BUDGET_WALLTIME_MS`).
- Recursion depth cap: 12 (`NIVX_ENGINE_BUDGET_DEPTH`).
- Body-size cap effective ceiling: 512 KB default, 50 MB large paths.
- Client-side auto-viz cap: 32 KB.
- Silent Splunk `_raw` fall-through: performance degrades to prose path (Session-7 finding).

---

## §36 · Scalability

- **Single-process, single-worker, single-DB.** Real concurrency ceiling is per-worker asyncio contention.
- **No horizontal scaling story** (no session affinity issues but no fleet).
- **No queue / worker fleet** — LLM narrate is inline.
- **No CDN** in front of `/api/*`.
- **Nightly benchmark** blocks the event loop briefly (but only if it runs, and only every 24h).

**Bottom line:** NivXRay today is a **single-workstation-shaped analyst platform** in scale terms. It is not designed to serve many analysts on the same pod at high concurrency.

---

## §37 · Observability

| Facet | Status |
|---|---|
| Logs | supervisor stdout/stderr; unstructured |
| Metrics | ⚪ NONE (no Prometheus / OTEL / statsd) |
| Tracing | ⚪ NONE |
| Health checks | 3: `/health`, `/api/health`, `/api/health/deep` |
| Worker monitoring | N/A (single worker) |
| DB monitoring | Mongo built-in only |
| Failure detection | Middleware emits X-Request-ID + logs 413/504 |
| Frontend telemetry | 🟢 LIVE (`frontend_telemetry` — 52 docs) |
| LLM telemetry | 🟢 LiteLLM hook installed at startup |

Sufficient for a demo pod. Insufficient for a customer SLA.

---

## §38 · Documentation

- `memory/*.md` — **89 files** (drift risk).
- `memory/adr/*.md` — 40+ ADRs (0001 – 0009).
- `docs/*.md` — SECURITY, WHITEPAPER, OPERATIONS, DEPLOYMENT, CHECKLIST, ADR-001, ADR-002.
- `README.md` (root) — 29 bytes placeholder.
- ARCHITECTURE.md (root) — 22.9 KB.

**Drift verdict (per ADR-0007 §22):**
- `PRD.md` + `ARCHITECTURE.md` mostly aligned with `/api/die/*`.
- `ARCHITECTURE_v2.md` describes v2 IKG-first as authoritative — **major drift** since v2 is shadow.
- Nivxforge section pages describe capabilities they do not deliver — **drift.**
- `WHITEPAPER.md`, `SECURITY.md` — UNKNOWN (not read this session).

---

## §39 · Technical Debt

From ADR-0007 §11:
1. **Two parallel investigation pipelines** — RC5 live + v2 shadow.
2. **466 API operations vs 74 direct FE consumers** (corrected: ~48 % live surface per ADR-0009).
3. Overlapping route families (`/api/die/timeline` vs `/api/v2/cases/{id}/trajectory/device` vs `/api/timeline/*`).
4. **`WorkspacePage.jsx` = 4,306 lines** — single component.
5. Heavy Python deps unused (`googleapiclient`, `google-genai`, `stripe`, `botocore`/`boto3`).
6. Legacy root-level `.py` siblings to `services/die/*` (chain_analyzer, command_analyzer, commandline_miner, investigation_report).
7. 89 memory `.md` docs — drift risk.
8. Nightly benchmark = in-process asyncio sleep-24 h (no k8s CronJob).
9. Dev-shape uvicorn (`--workers 1 --reload`).
10. `CORS_ORIGINS="*"`.

---

## §40 · Current Limitations

1. Cannot accept live EDR/XDR/SIEM telemetry.
2. Cannot recognise Splunk `_raw`-in-cell CSV (silently prose).
3. Cannot handle uploads > 256 KB reliably.
4. Cannot serve multi-tenant customers.
5. Cannot SSO / OAuth.
6. Cannot rate-limit login attempts.
7. Cannot protect against zip-bombs.
8. Cannot cross-case hunt.
9. Cannot save queries.
10. Cannot re-render deterministic PDF byte-for-byte.
11. Cannot horizontally scale.
12. Cannot promote v2 IKG / Verdict-v3 / Case Engine / Adapters / Artifact Store without meeting ADR-0008 §4 criteria first.

---

## §41 · Production Readiness

| Dimension | Verdict |
|---|---|
| Demo / PoC single-tenant | 🟢 YES |
| Paying single-tenant SaaS customer | 🔵 NOT YET (§32.3, 32.10, 32.13, 32.19; §36 concurrency; §37 SLA gaps) |

---

## §42 · Enterprise Readiness

| Dimension | Verdict |
|---|---|
| Multi-tenant | ⚪ NO |
| SSO / SAML | ⚪ NO |
| RBAC beyond admin | ⚪ NO |
| Audit trail | ⚪ NO |
| Air-gapped enterprise | 🔵 PARTIAL (needs installer + offline LLM) |

---

## §43 · Architecture Diagrams

### A · Complete NivXRay Architecture (as-shipped)

```
                              CLOUDFLARE
                                  │
                                  ▼
                        K8S INGRESS  (Emergent pod)
                                  │
              ┌───────────────────┼───────────────────┐
              │                                       │
              ▼                                       ▼
     :3000 React (CRA)                     :8001 FastAPI uvicorn 1w
     WorkspacePage.jsx + 33 pages          77 routers · 466 method-routes
     138 components + 30 investigation     Middleware: X-Req-Id, timeout,
     v2/ + workspace_v4/ + nivxforge/        body-cap, GZip, CORS(*)
                                          │
                                          ├── Motor → :27017 MongoDB (64 collections)
                                          ├── httpx → OSINT feed providers (7)
                                          └── LiteLLM → Emergent LLM key
                                                       (Claude / GPT / Gemini)
```

### B · Complete Input-to-Verdict Execution Flow

```
Analyst pastes / uploads
        │
        ▼
POST /api/die/analyze  (or /api/analyze/{smart|async|shellcode})
        │
        ▼
┌──────────────────────────────────────────────────────┐
│ Input Health check                                    │
│ Input Understanding Engine                            │
│ Preprocessor (stages + families + tactics)            │
│ Smart Decoder chain (recursive to fixed-point)        │
│ Semantic Engine (PS AST · normalization)              │
│ LOLBAS lookup                                         │
│ IOC extraction                                        │
│ MITRE Evidence Chain (P0.2)                           │
│ Canonical Bridge — narrative augment                  │
│ Confidence + intent                                   │
│ Attack Fingerprint                                    │
└─────────────────────┬────────────────────────────────┘
                      │
                      ▼
       AuthoritativeSSOT (in-memory, per request)
                      │
    ┌─────────────────┴──────────────────┐
    │                                    │
    ▼                                    ▼
POST /api/die/investigation-results   POST /api/die/timeline
(P0.3-locked, 10 keys, 250 KB budget)    ↓
    │                                Timeline projection
    │                                    ↓
    ▼                                Analyst UI panel
┌──────────────────────────┐
│ Verdict projection       │
│ Attack Chain projection  │
│ Attack Story projection  │
│ IOCs / LOLBAS projection │
│ Recommendations          │
│ Reports (v2 envelope)    │
└──────────────────────────┘
    │
    ▼
Analyst UI (WorkspacePage panels)
```

### C · Artifact Analysis Flow

```
Upload (≤ 256 KB) → /api/upload
        │
        ▼
Bytes-magic → file type
        │
        ├── PK (ZIP/DOCX/PPTX/XLSX) → unzip inline (⚠ NO SIZE GUARD)
        ├── PE header → services/pe_analyzer.py
        ├── PDF → services/adapters/pdf_adapter.py
        ├── EML → services/adapters/eml_adapter.py
        ├── Image → services/adapters/image_adapter.py
        └── Shellcode-shape → services/shellcode_analyzer.py
        │
        ▼
IDA (Intelligent Document Analyzer)
        │
        ▼
Artifact Router → dispatch per artifact
        │
        ▼
Recursive Child Pipeline (depth ≤ 12, wall-time ≤ 5s)
        │
        ▼
Text feeds back into Diagram B (command-line/prose pipeline)
Bytes-only artifacts stop with their analyzer output
```

### D · Raw Telemetry Flow (SHADOW)

```
POST /api/v2/ingest/{json|ndjson|csv|syslog|webhook}   ← NIVX_FLAG_ADAPTERS=shadow
POST /api/v2/ingest/evtx                               ← returns 501
        │
        ▼
v2.shadow.observe_all  (records but does NOT influence output)
        │
        ▼
v2.shadow.persist → v2_shadow_observations (563 docs)
        │                    │
        ▼                    ▼
(would-be)              v2_case_events / entities / behaviors / relationships
                        currently 0 docs — pipeline not authoritative
```

### E · IKG / Data Model

```
                         Investigation
                              │
       ┌──────────────────────┼────────────────────────┐
       │                      │                        │
       ▼                      ▼                        ▼
     Device               Incident                   IKG
       │                                              │
       │ hosted_on                                    │
       │                                              ▼
       ▼                                    ┌──────────────────┐
   Everything                                │ Nodes (13 types) │
       (process/file/                        │  process file    │
        registry/network/                    │  registry network│
        module/service/                      │  module service  │
        task/event)                          │  task event      │
                                             │  technique tactic│
                                             │  verdict device  │
                                             │  incident        │
                                             │                  │
                                             │ Edges (14 verbs) │
                                             │  created modified│
                                             │  deleted contact-│
                                             │  ed loaded       │
                                             │  installed spawn-│
                                             │  ed executed_by  │
                                             │  maps_to covers  │
                                             │  contributes_to  │
                                             │  rollup_of       │
                                             │  hosted_on       │
                                             │  part_of         │
                                             └──────────────────┘

Persistence: v2_case_events / entities / behaviors / relationships / reports
Status: SHADOW · all 0 docs today
```

### F · Workspace Data Flow

```
WorkspacePage.jsx (React 19, one 4,306-line component)
      │
      │  1. Analyst paste → useDeferredValue → debounce
      │  2. axios POST /api/die/analyze
      │  3. axios POST /api/die/investigation-results
      │  4. axios POST /api/die/timeline (additive)
      │  5. axios POST /api/die/query (additive, on demand)
      │  6. axios POST /api/v2/analyze/report?fmt=md (on report request)
      │  7. Case save → /api/cases/*
      │
      ├── Tabs / panels resolve from the same investigation-results payload
      │   (Overview, Attack Chain, Timeline, Query, IOC, MITRE, LOLBAS,
      │    Verdict, Narrative, Semantic, Extracted Artifacts, …)
      │
      ├── WorkspaceRootErrorBoundary  ← catches panel crashes, prevents
      │                                 workspace blank-screen
      │
      └── PanelErrorBoundary  ← per-panel guard
```

### G · Backend / Frontend / API Dependency Graph (top level)

```
Frontend (74 URL literals · 84 ACTIVE-UI routes)
        │
        ▼
API (466 method-routes · 77 routers)
        │
        ▼
Services layer
        ├── services/die/     (30+ modules) ◄── shipping
        ├── canonical/*        (ADR-005 canonical) ◄── shipping
        ├── services/ida/      (IDA) ◄── shipping
        ├── services/uaie/     ◄── partial
        ├── services/mitigation/  ◄── shipping
        ├── services/ioc_intelligence/ ◄── shipping
        ├── services/knowledge/  ◄── shipping
        ├── services/reasoning/  ◄── shipping
        └── engine/            (RC5 pipeline) ◄── shipping
        │
        ▼
Data / integrations
        ├── Motor / MongoDB / 64 collections
        ├── httpx → OSINT (7 providers)
        ├── LiteLLM → Emergent LLM key
        ├── SSRF-guarded URL fetch
        └── TAXII 2.1 push (outbound)

Parallel SHADOW stack (unconnected to primary):
        v2/*  (55 routes)
        ├── v2/investigation/     IKG + attack_story + explainability + IKB
        ├── v2/verdict/           Engine v3
        ├── v2/case_engine/       dedicated schema
        ├── v2/shadow/            IRG enrich + persist
        ├── v2/artifact_store/    persistent artifact store
        └── v2/report/            deterministic envelope
```

### H · Current vs Target Architecture

```
                       CURRENT (2026-08)                          TARGET (post-ADR-0008)

Paste / upload → /api/die/*                        Any input → /api/files → Input Router
                       │                                          │
                       ▼                                          ▼
              in-process analyze                         Adapter (Sysmon / EVTX / paste /
                       │                                  upload / webhook)
                       ▼                                          │
              AuthoritativeSSOT                                   ▼
              (in-memory, per-request)                    Canonical Event Bag
                       │                                          │
                       ▼                                          ▼
              Canonical Projections                      Recursive Discovery
              (verdict, timeline,                                 │
               attack_chain, attack_story,                        ▼
               iocs, lolbas, reports)                     IKG (persisted)
                       │                                          │
                       ▼                              ┌───────────┼───────────┐
              Workspace panels                       ▼           ▼           ▼
                                                Correlation   Verdict v3   ATT&CK
              [SHADOW: v2 IKG, Verdict v3,               │           │           │
               Case Engine, Adapters,                    └───────────┼───────────┘
               Artifact Store — 0 docs,                              ▼
               same-repo, different rail]                        Attack Story
                                                                     │
                                                                     ▼
                                                                Mitigation
                                                                     │
                                                                     ▼
                                                            Report (STIX/Sigma/YARA/
                                                             Navigator/MDR/MD/PDF)
                                                                     │
                                                                     ▼
                                                                 Workspace
```

---

## §44 · NivXRay in Plain English

Read this out loud in 10-15 minutes to explain NivXRay to a first-time listener.

---

### What is NivXRay, really?

NivXRay is a browser-based analyst workstation. A SOC analyst pastes something suspicious — a PowerShell one-liner, a base64 blob, a vendor incident report, a small CSV export from an endpoint tool — and NivXRay tells them:

- what it decoded,
- what MITRE ATT&CK techniques it saw,
- what IOCs it extracted,
- what the timeline looks like,
- what the verdict is,
- and it produces a report they can hand off.

Every claim it makes is backed by evidence. There is a rule called **P0.2** hardwired into the codebase that refuses to emit a MITRE technique unless it can point back to the exact rule, field, value, and source that triggered it. If it can't, it stays silent. That's the honest strength.

### What is NivXRay NOT?

It is not an EDR. It is not an XDR. It is not a SIEM. It has never received live Sysmon logs from a Windows endpoint, never pulled data from CrowdStrike or Microsoft Defender, never queried Splunk. The code that would do that (`/api/v2/ingest/*`) is written and shadow-observed, and one of its endpoints — EVTX — explicitly returns HTTP 501 saying "ships in R2.5.1."

The analyst can hand it up to 256 KB of text at a time. That is the ceiling today.

### What is running today?

The **RC5 canonical DIE pipeline**. That's `services/die/*` + `canonical/*` + about 20 endpoints under `/api/die/*` + one 4,300-line React file called `WorkspacePage.jsx` that talks to them. This is what your 108-plus regression tests protect. It ships. It works. It is honest about what it can and cannot see.

### What is coded but NOT running?

The **v2 pipeline**. That's `backend/v2/*` — an Investigation Knowledge Graph with 13 node types and 14 edge types, a Verdict Engine v3 with per-event/process/chain/device/incident aggregation and Adaptive Weight Profiles, a Correlation Engine, a Case Engine with its own Mongo schema, five ingestion adapters, and a persistent Artifact Store. All of it is written. All of it is fully covered by tests when the flags are flipped. But right now, five environment variables — `NIVX_FLAG_TRAJECTORY_ENGINE`, `NIVX_FLAG_CASE_ENGINE`, `NIVX_FLAG_ADAPTERS`, `NIVX_FLAG_ARTIFACT_STORE`, `NIVX_FLAG_VERDICT_ENGINE_V3` — are all set to `shadow`. Which means the code runs *side-by-side* but is not allowed to influence any output. And the collections that would hold its data (`v2_case_events`, `v2_case_entities`, `v2_case_behaviors`, `v2_case_relationships`, `v2_case_reports`) are all empty.

That is the single most important fact about NivXRay today: **two realities living in one repo.**

### What is dormant is NOT bad architecture

The v2 pipeline is the target architecture. It's the direction NivXRay should evolve. Its problem is not design — it's connection. It observes but does not participate.

### What are NivXRay's engines?

The audit surfaced 60 discrete engines and modules, but the ones an owner needs to remember are:

1. **The Input Understanding Engine (IUE)** — decides "what is this? command line? script? prose? CSV?"
2. **The Smart Decoder + 200+ decoders** — peels base64/hex/URL/rot13/brotli/lzma/PowerShell-EncodedCommand chains recursively to a fixed point.
3. **The Semantic Engine (PowerShell AST)** — deobfuscates and reasons about PowerShell like a compiler would.
4. **The MITRE Evidence Chain (P0.2)** — the gate. No evidence, no technique.
5. **The Canonical SSOT + projections** — the append-only truth graph the analyst sees.
6. **The IKG** — the target replacement for the SSOT, currently shadow.
7. **The Verdict Engine v3** — the target replacement for the linear scorer, currently shadow.
8. **The Correlation Engine** — layers Event → Process → Chain → Device → Incident, currently shadow.
9. **The Threat-Intel feed system** — pulls 7 providers into 65,614 deduped IOCs, live.
10. **The Analyst Practice Lab** — a teaching surface that has hosted 89 real analyst attempts.

### What can an analyst DO on the screen?

They see a single-page Workspace at `/`. They paste. They see:
- an Overview tab with the verdict
- a 14-lane MITRE Attack Chain diagram
- a Timeline of the highconfidence events
- a Query/Hunt panel for filtering those events with 12 different filter keys
- an IOC panel
- a LOLBAS panel
- a MITRE panel
- a narrative LLM-generated summary
- an Extracted Artifacts panel
- an Evidence Graph view
- and a Reports tab with Markdown, STIX, PDF, and ZIP-bundle downloads

Every button carries a `data-testid`. Every panel has an error boundary. If a panel crashes on bad data, the Workspace does not blank-screen.

### Where does data live?

64 collections in one Mongo database. The busy ones are `iocs` (65,614), `investigations` (2,883), `investigation_events` (933), `analyst_corrections` (887), `benchmark_runs` (897), `workspace_cases` (257). The shadow ones (`v2_case_*`) are all zero. There is one tenant. There is no TTL enforcement observed. There is no backup arrangement observed.

### Where does data go OUT?

Only in three ways: (1) LLM narrate — the analyst's pasted text goes to Claude/GPT/Gemini through the Emergent LLM key; (2) URL enrichment — SSRF-guarded httpx calls; (3) analyst-initiated TAXII push and report download. Nothing else leaves the pod.

### Where are the security holes?

Four architectural softnesses:
1. **CORS `*` + credentials** — a spec-invalid combination.
2. **No login rate-limit** — brute-force is possible.
3. **Unbounded ZIP unpack in `/api/upload`** — zip-bomb risk.
4. **Same-process parsers for hostile files** — PE, DOCX, RC4, capstone all run inside the FastAPI event loop.

For a normal CRUD app, these are ugly. For a **cybersecurity analysis platform that deliberately receives hostile input**, they are architectural risks.

### Where can NivXRay be deployed today?

Only in Emergent-managed single-tenant SaaS mode. There is no packaged installer, no Helm chart, no docker-compose. Customer-hosted on-prem is feasible but not scripted. Multi-tenant is impossible without a schema change. Air-gapped is partially documented (`OFFLINE_LLM_DEPLOYMENT.md`).

### How healthy is the code?

Very healthy on the RC5 spine: 3,621 test functions across 389 files. 114 tests in the canonical-API gate pass. Six new determinism tests were added this session — Markdown, STIX, and the report signature are now byte-locked in CI.

Less healthy: `WorkspacePage.jsx` is 4,306 lines. There are 89 memory `.md` docs drifting against 40 ADRs. Five heavy Python packages (`googleapiclient`, `google-genai`, `stripe`, `boto3`, `botocore`) are shipped but never imported.

### What is genuinely differentiating?

The **enforced evidence-chain provenance.** In a market full of security tools that hallucinate, NivXRay refuses to make a MITRE claim it cannot trace back to a rule, a field, and an observed value. That is a strong, sellable, defensible property — and it is CI-locked by 30 tests.

### What is the honest headline?

> NivXRay is an evidence-provenanced analyst investigation Workspace for pasted commands, narrative reports, and small tabular EDR exports. It has a beautiful, shadow-observed next-generation architecture (IKG · Verdict v3 · Correlation · Case Engine · Adapters · Artifact Store) sitting in the same repo, waiting for connection. Its next transformative step is not another engine — it is turning the ingestion boundary from "paste box" into "server-side file store + adapter tier", closing four security softnesses, and then flipping the shadow subsystems one at a time under measured replay parity.

That is what NivXRay is today.

*End of Product & Architecture Blueprint. Companion documents: ADR-0007 (evidence), ADR-0008 (execution strategy), ADR-0009 (route reality).*
