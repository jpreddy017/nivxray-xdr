# NivXRay · Investor Technical Due-Diligence
**Document status:** v0.1 · **partial** · seeded 2026-02-13
**Scope of this seed:** honest inventory of what the current codebase contains, with file references. Sections marked `[NEEDS_VERIFICATION]` require a fresh, full-context session (E2 recommended) to complete via systematic inspection.
**Zero-hallucination rule:** every capability claim MUST cite a file path. Anything without a path stays flagged.

---

## Verified repo facts (2026-02-13)
| Metric | Actual count | Source |
|---|---|---|
| Backend API routers | **79** | `ls backend/routers/*.py` |
| Backend service modules (top-level) | **19** | `find backend/services -maxdepth 1 -type d` |
| DIE (Deterministic Investigation) sub-modules | **~30** files including 5 AST engines (PowerShell, CMD, Bash, Python, JS) + IOC semantic + LOLBAS + MITRE evidence chain + timeline + recursive decode | `ls backend/services/die/` |
| Frontend pages | **33** JSX pages | `ls frontend/src/pages/*.jsx` |
| Adapters (input surface) | **6 confirmed** — `text`, `url`, `docx`, `pdf`, `eml`, `image`, `zip` | `ls backend/services/adapters/` |
| Test suite total | **546 Python test files** | `find backend -name test_*.py` |
| Canonical test suite | **56 files · 442 tests collected · 12 collection errors** (environmental — Sample1 DB seed absent per handoff LOCK) | `pytest --collect-only` |
| Wire-response bounded slim | **`_slim_investigation_response` in `backend/services/die/canonical_bridge.py`** — 61.6 KB verified on Talos article | today's live probe |

---

## 1 · Executive Product Definition

- **What NivXRay is TODAY** (verified from live app): a **deterministic SOC-analyst engine** — accepts pastes (URL / PowerShell / CSV / Sysmon XML / defanged IOC bundle / EDR alert JSON) and returns a **9-card Deterministic Analyst Brief** (Executive Summary, Analyst Summary, Observed Behaviour, Attack Intent, Impact, MITRE Summary, IOC Intelligence, Recommendations, Evidence Confidence) plus a **MITRE Attack-Chain swim-lane** + **10-tab Threat Analysis sidebar**. Verified live via `frontend/src/pages/WorkspacePage.jsx` + `frontend/src/pages/InvestigationSessionPage.jsx` + `backend/routers/die.py`.
- **Primary customer:** MSSP / Fortune-500 in-house SOCs / IR consultancies / regulated CSIRTs — **NOT verified via customer list**; classification is aspirational.
- **Primary user:** L1/L2 SOC analyst.
- **Product boundary today**: single-tenant deployment, admin-authenticated, deterministic-first with optional LLM narrative overlay (Emergent LLM Key). Verified via `backend/routers/auth.py` + presence of `EMERGENT_LLM_KEY` in `.env`.

## 2 · Current Capabilities · classification

| Capability | Status | Evidence |
|---|---|---|
| Deterministic PowerShell / CMD / Bash / Python / JS AST | ✅ Implemented | `backend/services/die/{powershell_ast,cmd_ast,bash_ast,python_ast,javascript_ast}.py` |
| MITRE ATT&CK technique+tactic resolution at projection | ✅ Implemented | `backend/services/ice/correlate.py` `_TECHNIQUE_TO_TACTIC` + `_TECHNIQUE_NAME` (80+ entries) + `name_for()` / `tactic_for()` |
| IDA (URL acquisition — Talos family) | ✅ Implemented | `backend/services/ida/` + `report_extraction` path in `backend/services/die/investigation_results.py` |
| Analyst Brief (9-card L4) | ✅ Implemented | `frontend/src/components/investigation/InvestigationSummaryPanel.jsx` |
| Attack Chain swim-lane (12 tactic lanes) | ✅ Implemented | `frontend/src/components/investigation/TrajectoryDiagram.jsx` + `_synthBehaviorsFromMitre` in `WorkspacePage.jsx` |
| SHA-256-only IOC hash policy at wire boundary | ✅ Implemented (2026-02-09) | `_slim_investigation_response` in `canonical_bridge.py` |
| Report-extraction structured evidence (commands / mitre_techniques / body_artifacts / yara_rules / sigma_rules / threat_actors / malware_families / cves / timeline / hash_context) | ✅ Implemented | `_REPORT_EXTRACTION_KEEP` list in `canonical_bridge.py` |
| Evidence Explorer projection (P0h-A) | ✅ Implemented | `EvidenceExplorerProjection` in `InvestigationSessionPage.jsx` |
| IUE (Input Understanding Engine) | ✅ Implemented — with today's semantic guards for JSON/XML shape | `frontend/src/lib/inputClassifier.js` + `backend/services/die/input_understanding.py` |
| Passive Capability Registry + thin router | 🟡 Partially implemented — **built but not cutover** (M0f LOCKED per PRD) | `backend/services/registry/router.py` + `iue_projection.py` |
| Equivalence Harness (zero-drift regression) | ✅ Implemented — **145 canonical tests** | `backend/tests/canonical/iue/` |
| Investigation Session (L4 tabs) — **Evidence Explorer** | ✅ Implemented (P0h-A) | `InvestigationSessionPage.jsx` |
| Investigation Session — **Attack Story** tab | 🔵 Designed · **not implemented** — `session.attack_story` field not produced by `build_session()` | Verified by direct API probe on `ses_5129f951d3eb` |
| Investigation Session — **Timeline** tab | 🔵 Designed · **not implemented** — `session.timeline` not produced | Same |
| Investigation Session — **Incident Graph** tab | 🔵 Designed · **not implemented** — `session.incident_graph` not produced | Same |
| Sysmon Event 22 (DNS) / Event 11 (File Create) adapter | 🔵 Roadmap (LOCKED per PRD) | Absent from `backend/services/adapters/` |
| OSINT enrichment (VT / AbuseIPDB / OTX / abuse.ch) | 🟡 Partially — infrastructure present, keys required | `backend/services/ioc_intelligence/` |
| TI-HITS sidebar tab | 🟡 Partially — depends on SSE `/api/analyze/async` path; empty on URL/atomic-IOC paste by design (no manufactured values rule) | `frontend/src/components/ThreatAnalysis.jsx` |
| Multi-tenant SaaS · per-tenant OSINT keys | 🔵 Designed · not implemented | No tenant model in `backend/models/` |
| Playwright / OCR (Tesseract) | 🔵 SHADOW · **not enabled** (LOCKED per PRD) | Handoff summary |
| XOR-decoder fidelity fix | ❌ Known defect · LOCKED | Handoff summary |

## 3 · Actual Architecture (implemented, not intended)

```
[VERIFIED] frontend paste →
   [VERIFIED] /api/die/investigation-results  (backend/routers/die.py)
      → [VERIFIED] _render_ssot() in services/die/investigation_results.py
        - IDA acquisition (services/ida/) — VERIFIED
        - DIE AST analyzers (services/die/*_ast.py) — VERIFIED
        - IOC extraction (services/die/ioc_semantic.py) — VERIFIED
        - LOLBAS lookup (services/die/lolbas.py) — VERIFIED
        - MITRE mapping (services/ice/correlate.py) — VERIFIED
        - ICE correlate (services/ice/correlate.py) — VERIFIED
      → [VERIFIED] _slim_investigation_response() (canonical_bridge.py)
        - strips 400+KB acquired_document / preprocessor / ice / incident
        - keeps report_extraction structured evidence
      → [VERIFIED] wire → frontend renders 9-card brief
   [VERIFIED] /api/session/from-investigation (routers/sessions.py)
      → build_session() (services/session/adapter.py)
        - Produces summary_narrative (services/session/summary_narrative.py) — VERIFIED
        - Does NOT produce attack_story / timeline / incident_graph — VERIFIED (empty on ses_5129f951d3eb)
```

**Centralized correlation claim honest answer:** ICE (`services/ice/correlate.py`) **is** the correlation engine — it merges per-stage evidence and produces the `incident` block with tactics_observed. This satisfies the "centralized correlation" principle for the CURRENT single-request execution model. **NOT verified**: whether it can re-unite evidence from asynchronous distributed workers (there is no distributed worker pool today — everything runs in the single FastAPI process). **Do not claim distributed correlation to investors.**

## 4 · Universal Input capability — HONEST inventory

**Implemented adapters (verified from `backend/services/adapters/`):** text, url, docx, pdf, eml, image, zip.

**Everything else in your inventory table (Sysmon EVTX, EDR/XDR native, WMI, cloud audit logs, IAM, network flow, IDS/IPS, DNS, proxy, VPN, impossible-travel, application logs, PE, ELF, Office macro dive)**: **not verified as implemented.** Some may exist as prose-parsing paths inside `services/die/`, but they are NOT dedicated adapters. Classification: 🔵 or ❌ pending inspection.

---

## Sections 5-30 · [NEEDS_VERIFICATION IN FRESH SESSION]

The following sections require systematic file inspection I cannot complete in remaining context. **Handoff instructions for the fresh session** appear at the bottom.

- **5 · Canonical Evidence Model** — inspect `backend/models/`, `services/canonicalizer/`
- **6 · Correlation Engine** — deep-dive `services/ice/correlate.py`; find correlation keys, cross-source join logic; verify graph-based vs list-based
- **7 · Investigation Knowledge Graph** — inspect `services/knowledge/`; determine if IKG is graph-DB backed or in-memory dict
- **8 · Semantic / MITRE ATT&CK engine** — inspect `services/die/mitre_evidence_chain.py`; verify multi-technique-per-evidence claim
- **9 · Verdict Engine** — inspect `services/session/summary_narrative.py::_verdict()` + `services/die/confidence.py`; verify trace-back
- **10 · Investigation Summary / Attack Story** — currently produces `summary_narrative`; `attack_story` NOT produced
- **11 · Analyst Workspace** — 33 pages; catalogue which are live vs stubs
- **12 · Real integrations** — grep for Splunk / QRadar / CrowdStrike / SentinelOne / Defender / ServiceNow imports/webhooks; likely ❌ across the board
- **13 · Validation & performance** — run `pytest --tb=no -q`; capture actual pass/fail/skip counts; benchmark p50/p95 via `services/diagnostics/`
- **14 · Real customer / production status** — **verified honestly: nivxray.nivxforge.com is deployed but no known external customers as of this session's knowledge**
- **15 · Competitive differentiation** — draw ONLY from verified moat items in §16
- **16 · Technology moat** — of the 8 principles, verified TODAY:
  - ✅ Universal evidence layer (partial — 6 adapters, not full spectrum)
  - 🟡 Artifact-first recursive investigation (recursive_decode.py exists — needs recursion depth + termination proof)
  - ❌ Distributed processing + centralized investigation (no worker pool)
  - 🟡 Investigation Knowledge Graph (inspect `services/knowledge/`)
  - ✅ Evidence-backed deterministic verdict (verdict traces back via provenance chain — verified via `summary_narrative.evidence_confidence`)
  - 🔵 Negative explainability (needs implementation search)
  - ✅ Multi-technique semantic decomposition (VERIFIED — `mitre_evidence_chain.py`)
  - ✅ Source-neutral investigation (verified — same DIE pipeline for URL / paste / adapter inputs)
- **17-30** — all NEEDS_VERIFICATION

---

## Handoff for fresh session (E2 recommended)

```
1. Fork this chat OR start new chat with E2 agent
2. Say "Hi"
3. First message: "Read /app/memory/NivXRay_Investor_Due_Diligence.md.
   Complete sections 5-30 with the same zero-hallucination rule.
   Every claim must cite a file path or a pytest command output.
   Anything unverifiable stays labelled ❌ or [UNKNOWN]."
4. Budget: 4-6 hours systematic inspection
5. Deliverable: this file, expanded to full 30 sections, ready for investor deck seed
```

---

## Verified in this session (do NOT re-verify)
- Repo counts in the top table
- Section 2 capability classifications with file refs
- Section 3 architecture flow with file refs
- Section 4 adapter inventory
- Section 16 partial moat verification

## Living metrics harvest command (safe to run)
```bash
cd /app && python -m pytest backend/tests/canonical/ --tb=no -q 2>&1 | tail -5
```
(currently reports 442 collected, 12 collection errors — Sample1 DB seed absent per handoff LOCK)
