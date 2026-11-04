# NivXRay · 360° Architecture — Current + Target

**Status:** v1.0 · evidence-backed · zero-hallucination
**Date:** 2026-02-13
**Verified against:** live `/app/backend`, `/app/frontend`, `/app/memory/adr/`, live API on `preview.emergentagent.com`

---

## Reading rules
- `A` = TODAY (implemented + reproducible)
- `B` = TARGET (declared in `PRD.md` / ADRs)
- `C` = MARKET VISION (long-term)
- Every arrow / block cites a code path.

---

## 1 · Current architecture (A · TODAY)

### 1.1 Physical / runtime shape
- **Single FastAPI process.** No worker pool, no queue, no distributed executor.
  - Evidence: `backend/server.py`, `/etc/supervisor/conf.d/*.conf`, `NIVX_ENGINE=legacy` in `backend/.env`.
- **MongoDB persistence.** Local Mongo on `mongodb://localhost:27017`, DB `test_database`.
  - Evidence: `MONGO_URL`, `DB_NAME` in `backend/.env`.
- **React 19 SPA.** Preview URL from `REACT_APP_BACKEND_URL`.
  - Evidence: `frontend/package.json`, `frontend/.env`.

### 1.2 Request flow — deterministic paste → 9-card brief

```
[VERIFIED · reproducible curl in § 5.2 of Product_Market_Posture]

Frontend paste (WorkspacePage.jsx)
   └─→ POST /api/die/investigation-results       (backend/routers/die.py:248)
         └─→ _render_ssot()                       (backend/services/die/investigation_results.py)
               ├─ Input classification            (services/die/input_understanding.py — 761 loc)
               ├─ IDA acquisition                 (services/ida/acquisition.py — Talos / vendor URLs)
               │    · Playwright fallback SHADOW  (services/ida/acquisition.py:498 `_playwright_render` — locked)
               │    · Wayback fallback            (services/ida/acquisition.py:589 `_wayback_fetch`)
               │    · Trafilatura + Readability + BS4 cascade (lines 430–498)
               ├─ Report extractors               (services/ida/report_extractors.py — 1213 loc)
               ├─ DIE AST engines                 (services/die/{powershell,cmd,bash,python,javascript}_ast.py)
               ├─ Recursive decode                (services/die/recursive_decode.py — 266 loc)
               ├─ IOC semantic + LOLBAS           (services/die/ioc_semantic.py, services/die/lolbas.py)
               ├─ MITRE evidence chain            (services/die/mitre_evidence_chain.py)
               └─ ICE correlate (single pass, R21)(services/ice/correlate.py — 1385 loc)
                     ├─ behavior_clusters         (line 832)
                     ├─ attack_phases             (line 974)
                     ├─ mitre_matrix              (line 1006)
                     ├─ timeline                  (line 1050)
                     ├─ incident_graph            (line 1075)
                     ├─ completeness              (line 1124)
                     ├─ incident (canonical)      (line 1206)
                     ├─ readiness                 (line 1270)
                     ├─ gaps                      (line 1327)
                     └─ recommendations           (line 1354)
         └─→ _slim_investigation_response()       (services/die/canonical_bridge.py:588)
               · drops acquired_document.raw_html, preprocessor caches
               · keeps _REPORT_EXTRACTION_KEEP allow-list (line 535)
               · policy: SHA-256 only at wire (MD5/SHA-1 dropped, ADR-005-phase4)
         └─→ 200 { output, object, canonical_augmented }

Frontend renders:
   · InvestigationSummaryPanel — 9 cards
     (frontend/src/components/investigation/InvestigationSummaryPanel.jsx)
   · TrajectoryDiagram — 12-lane MITRE swim-lane
     (frontend/src/components/investigation/TrajectoryDiagram.jsx)
```

### 1.3 Session flow — L4 Analyst Workspace

```
POST /api/session/investigate                     (backend/routers/sessions.py:104)
      └─→ same _render_ssot() as above
      └─→ build_session(input, ssot)              (services/session/adapter.py:315)
            · session_id (deterministic short-id)
            · original_input, document_profile, acquired_document
            · investigation_inputs  ← promote_investigation_inputs(ssot)
            · incident              ← ssot.incident (from ICE)
            · summary
            · summary_narrative     ← services/session/summary_narrative.py::build_narrative()
                (executive_summary · analyst_summary · behavior_summary · attack_intent ·
                 impact_assessment · attack_timeline · mitre_summary · ioc_intelligence ·
                 recommendations · evidence_confidence · verdict)
            · raw_investigation     ← full pre-slim SSOT

Frontend Session tabs                             (frontend/src/pages/InvestigationSessionPage.jsx:100-110)
      · narrative → session.summary_narrative           (implemented · verified live)
      · summary   → SummaryTab(session)                  (implemented)
      · inputs    → InputsTab(session)                   (implemented)
      · story     → StoryTab(incident=session.incident)  (renders behaviors/phases from ICE)
      · timeline  → TimelineTab(incident=…)              (renders incident.timeline from ICE)
      · graph     → GraphTab(incident=…)                 (renders incident.graph from ICE)
      · evidence  → EvidenceExplorerProjection(inputs=…) (P0h-A · verified — line 1064)
      · nist      → NistTab(session)                     (renders NIST IR MD/PDF)
```

**Correction to seed:** ICE `correlate()` DOES emit `behaviors`, `phases`, `timeline`, and `graph`. The Story/Timeline/Graph tabs are wired to `session.incident.*`, so they are NOT unimplemented — they render whatever ICE produced. Whether the ICE output is *rich enough* for a given input is a separate question addressed in `NivXRay_360_Product_Market_Posture.md § 15`.

### 1.4 Feature flags (verified from `backend/.env`)

| Flag | Value | Effect |
|---|---|---|
| `NIVX_ENGINE` | `legacy` | Legacy DIE path (M0f cutover NOT active) |
| `NIVX_CANONICAL_UIL_INVESTIGATE` | `on` | Canonical UIL router serves `/api/uil/investigate` |
| `NIVX_CANONICAL_DIE_ANALYZE` | `on` | Canonical DIE router path enabled on `/api/die/analyze` |
| `NIVX_FLAG_TRAJECTORY_ENGINE` | `shadow` | Trajectory engine v3 shadow only |
| `NIVX_FLAG_CASE_ENGINE` | `shadow` | Case engine v3 shadow only |
| `NIVX_FLAG_ADAPTERS` | `shadow` | Adapter registry v3 shadow only |
| `NIVX_FLAG_ARTIFACT_STORE` | `shadow` | Artifact store v3 shadow only |
| `NIVX_FLAG_VERDICT_ENGINE_V3` | `shadow` | Verdict engine v3 shadow only |
| `NVX_VEEE_ENABLED` | `1` | VEEE image classifier on (Tesseract wrapper SHADOW-locked) |
| `NVX_BKB_CANONICAL` | `1` | BKB canonical MITRE table active |
| `NVX_MITRE_DIAGNOSTIC` | `1` | MITRE diagnostic annotations emitted |
| `NIVX_AI_ENABLED` | `true` | LLM overlay allowed (Emergent LLM Key) |
| `NIVX_AI_DEADLINE_S` | `90` | LLM call deadline |
| `NIVX_OSINT_DEADLINE_S` | `20` | OSINT enrichment deadline |
| `NIVX_AI_RATE_HOURLY` / `_DAILY` | 10 / 50 | LLM rate limits |
| `NIVX_AI_BUDGET_CAP_CREDITS` | `500` | LLM credit budget |
| `NIVX_ENGINE_BUDGET_DEPTH` | `12` | Recursive decode max depth |
| `NIVX_ENGINE_BUDGET_WALLTIME_MS` | `5000` | Per-request walltime budget |
| `NIVX_EVIDENCE_GRAPH` | `sidecar` | Evidence graph as sidecar (not primary store) |
| `NIVX_EVIDENCE_GRAPH_METRICS` | `on` | Metrics emitted |
| `RC5_DIAG_ENABLED` | `true` | RC5 diagnostic routes active |

---

## 2 · Target architecture (B · declared in `PRD.md`, ADRs 0014a–0014h, 0011)

```
                                 ┌────────────────────────────┐
                                 │  UNIVERSAL EVIDENCE LAYER  │  ← 6 principles
                                 └────────────┬───────────────┘
                                              │
      ┌───────────────┬──────────────┬────────┴───────┬───────────────┬─────────────┐
      ▼               ▼              ▼                ▼               ▼             ▼
   Sysmon EVTX    XDR/EDR         Prose report     Atomic IOC       Archive       URL fetch
   Adapter        Adapter         Adapter (impl.)  Adapter (impl.)  Adapter (impl.) Adapter (impl.)
      │               │              │                │               │             │
      ▼               ▼              ▼                ▼               ▼             ▼
              ┌──────────────────────────────────────────────────────────┐
              │  IUE · Input Understanding (services/die/input_understanding.py) │
              │  · classifier · lineage · shape guards                          │
              └──────────────────────────┬───────────────────────────────┘
                                         │
              ┌──────────────────────────▼───────────────────────────────┐
              │  DIE · Deterministic Investigation Engine                │
              │  (services/die/*)  → per-artifact investigations         │
              └──────────────────────────┬───────────────────────────────┘
                                         │  Rule R21 (correlation ONCE)
              ┌──────────────────────────▼───────────────────────────────┐
              │  ICE · Investigation Correlation Engine                  │
              │  (services/ice/correlate.py)                             │
              │  · behavior clusters · attack phases · kill-chain        │
              │  · MITRE matrix · unified timeline · incident graph      │
              └──────────────────────────┬───────────────────────────────┘
                                         │
              ┌──────────────────────────▼───────────────────────────────┐
              │  Canonical Investigation Object (single SSOT)            │
              │  (ADR-0014 · services/die/canonical.py)                  │
              └──────────────────────────┬───────────────────────────────┘
                                         │
                       ┌─────────────────┼─────────────────┐
                       ▼                 ▼                 ▼
             Evidence Explorer    Attack Story        NIST IR Report
             Timeline             Incident Graph      MITRE Heatmap
             Trajectory           Process Tree        Analyst Brief
             (all projections · zero re-analysis)
```

### 2.1 Target — what the target adds beyond today

| Target capability | Where declared | Delta vs today |
|---|---|---|
| Distributed worker pool | `PRD.md` (search: "distributed") + `memory/NIVXFORGE_PLATFORM_VISION.md` | ❌ not built (single process) |
| Universal adapter set (EVTX / cloud / IAM / NDR / EDR native) | `memory/CAPABILITIES_HLD_LLD.md` § adapters | ❌ 8 adapters today (base + text + url + docx + pdf + eml + image + zip) |
| Multi-tenant SaaS | `memory/NIVXFORGE_PLATFORM_VISION.md` | ❌ no tenant model in `backend/models/` |
| Investigation Knowledge Graph (persistent graph DB) | ADR-0009, `memory/BEHAVIOR_GRAPH_SCHEMA.md` | 🟡 in-memory dict (`incident.graph`) — sidecar Mongo persistence via `NIVX_EVIDENCE_GRAPH=sidecar` |
| Passive Capability Registry + thin router cutover | ADR-0014b (M0d) + 0014c (M0e) | 🟡 built (`services/registry/router.py` 322 loc) · **not cutover** (M0f LOCKED) |
| Equivalence harness zero-drift proof | ADR-0014e | ✅ implemented — `backend/tests/canonical/iue/` (56 test files) |
| Sysmon Event 22 (DNS) / Event 11 (File Create) adapters | ADRs 0010q, 0010r, 0010s | ❌ absent from `backend/services/adapters/` — LOCKED |
| Negative explainability (why a technique was NOT chosen) | `PRD.md` | 🔵 not verified in code |
| Playwright rendering + Tesseract OCR | `services/ida/acquisition.py:498`, `services/veee/ocr_engine.py` | 🟠 code present · SHADOW-locked (won't fire in prod path) |

---

## 3 · Data / evidence lifecycle (single-piece trace)

**Trace:** an obfuscated PowerShell paste →

1. **Ingress** — `POST /api/session/investigate` → `sessions.py:104`
2. **Classification** — `input_understanding.classify(raw)` — 761 loc, produces `{input_type, label, confidence, structured_evidence?}`
3. **Acquisition** — n/a for direct paste (skipped); URL paths hit `ida/acquisition.py::acquire_url()` (line 119)
4. **Preprocess** — line joining, folding via `services/normalization/powershell_folding.py`
5. **AST** — `powershell_ast.py::analyze()` → command intents + IOCs
6. **Recursive decode** — `recursive_decode.py::extract_decoded_layers()` (line 180) → up to 12 layers (`NIVX_ENGINE_BUDGET_DEPTH=12`)
7. **IOC semantic** — `ioc_semantic.py` → URL/IP/domain/hash canonicalisation
8. **MITRE mapping** — `mitre_evidence_chain.py` → per-command technique list; `ice/correlate.py::name_for()` / `tactic_for()` resolve names+tactics (79 entries in `_TECHNIQUE_NAME`, 154 in `_TECHNIQUE_TO_TACTIC`)
9. **Correlation** — `ice/correlate.py::correlate()` (line 701) → single R21 pass:
    - `_build_behavior_clusters()` (832)
    - `_build_attack_phases()` (974)
    - `_build_mitre_matrix()` (1006)
    - `_build_timeline()` (1050)
    - `_build_incident_graph()` (1075)
    - `_build_incident()` canonical wrapper (1206)
10. **Session wrap** — `session/adapter.py::build_session()` (315)
11. **Slim** — `canonical_bridge.py::_slim_investigation_response()` (588) at the wire
12. **Persist** — `sessions.py::_persist_session()` (67) → Mongo collection `investigation_sessions`
13. **Render** — React tabs read `session.incident.*` + `session.summary_narrative.*` + `session.investigation_inputs`

**Provenance:** every projection cites its origin (`ice.provenance`, `report_extraction.source`, `investigation_inputs[].source`). Verified in live envelope at `§ 1.3`.

---

## 4 · Storage inventory (verified)

| Store | Kind | Content | Evidence |
|---|---|---|---|
| MongoDB `investigation_sessions` | primary | Wrapped session envelopes | `backend/routers/sessions.py:67` |
| MongoDB `admin_models` (training_notes) | primary | RSS threat-intel promoted rows | `backend/routers/threat_intel_rss.py` |
| MongoDB `workspace_cases` | primary | Case/investigation catalogue | `backend/models/workspace_case.py` (if present) |
| MongoDB `evidence_graph` (sidecar) | secondary | Graph metrics + edge sidecar | `NIVX_EVIDENCE_GRAPH=sidecar` |
| Filesystem `/app/uploads/` | user files | Uploaded documents | supervisor volume |
| Filesystem `/app/uploaded_cases/` | case snapshots | Snapshots per case | dir listing |
| Filesystem `/app/evidence/` | corpus fixtures | Reference decode fixtures | dir listing |
| Filesystem `/app/deck_assets/` | pitch deck | Generated PPTX + screenshots | `backend/routers/deck_download.py` |

**No S3, no external blob store, no Redis, no queue.** Everything lives on the pod filesystem + Mongo.

---

## 5 · Security surface (verified)

| Control | Implementation | Evidence |
|---|---|---|
| Auth | JWT bearer, HS256, 24h expiry | `backend/deps.py::create_token()`, `JWT_EXPIRE_HOURS=24` |
| Password hashing | bcrypt via `passlib` | `backend/deps.py::hash_password()` + `verify_password()` |
| Admin seed | env-driven, force-change on first login (production) | `backend/deps.py::seed_admin()` + `ADMIN_FORCE_PASSWORD_CHANGE` |
| CORS | `*` (open) | `backend/.env::CORS_ORIGINS="*"` — 🟠 open; ADR-005 note |
| SSRF | private-host blocklist in acquisition | `services/ida/acquisition.py::_is_private_host()` (line 302) |
| Rate limits (LLM) | 10/hr, 50/day | `NIVX_AI_RATE_HOURLY`, `_DAILY` |
| LLM budget cap | 500 credits | `NIVX_AI_BUDGET_CAP_CREDITS` |
| Wire-response slim | allow-list at boundary | `_REPORT_EXTRACTION_KEEP` in `canonical_bridge.py:535` |
| Hash policy at wire | SHA-256 only | `canonical_bridge.py` (ADR-005-phase4) |

**Not verified / missing:**
- ❌ RBAC beyond `admin` role (`backend/routers/auth.py` supports only `admin`).
- ❌ Tenant isolation.
- ❌ Encryption at rest (Mongo default only).
- ❌ Evidence-integrity hash chain (declared in ADR-0010b as gate, verify separately).
- ❌ Dependency vulnerability scanner in CI.

---

## 6 · Deployment & observability (verified)

| Aspect | Today | Evidence |
|---|---|---|
| Deployment | Supervisord managed FastAPI + React dev server | `/etc/supervisor/conf.d/*` |
| HA | ❌ single pod | dir listing |
| DR | ❌ no cross-region replication, no snapshot job in-repo | grep |
| Observability | Structured logs (backend) + `/api/platform-health` (returns 404 — see below) | live curl |
| Metrics | `services/platform_metrics.py` + `RC5_DIAG_ENABLED=true` diag routes | `backend/routers/rc5_diag.py` |
| SLA | none declared | grep |
| Upgrade | code-hot-reload; no blue/green | supervisor |
| Rollback | git revert only | `.git/` |

**Gap:** live curl on `/api/platform-health` returned `{"detail":"Not Found"}` in this session — route may be defined at different prefix; verify separately (see `NivXRay_360_Evidence_Matrix.md § platform-health`).

---

## 7 · Where the target architecture principles live (do NOT delete)

- `/app/memory/PRD.md` (929 lines) — full principle statements + intended architecture
- `/app/memory/adr/0014a…0014h.md` — M0a-M0h migration ADRs (target passive registry + thin router + provenance + equivalence)
- `/app/memory/ARCHITECTURAL_DIRECTION_IEDDE.md` — IEDDE direction
- `/app/memory/NIVXRAY_ARCHITECTURE_V1.md` — architecture v1 (~55 KB reference)
- `/app/memory/NIVXFORGE_PLATFORM_VISION.md` — long-term platform vision
- `/app/memory/CAPABILITIES_HLD_LLD.md` — HLD/LLD capability tree

This document tells us which of those principles are realised TODAY vs still intent-side.

---

*End of Architecture doc. See `NivXRay_360_Product_Market_Posture.md` for the full 40-section audit and `NivXRay_360_Evidence_Matrix.md` for a flat evidence lookup table.*
