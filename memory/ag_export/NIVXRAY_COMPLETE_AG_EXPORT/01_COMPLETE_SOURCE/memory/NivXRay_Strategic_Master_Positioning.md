# NivXRay · Strategic Master Positioning Document

**Status:** v1.3 · **LOCKED** · permanent NivXRay positioning
**Date:** 2026-02-13 (v1.0 initial · v1.1 platform-vision · v1.2 moat refinement · **v1.3 deterministic-first, AI-optional lock**)

## 🔒 Permanent Positioning Rule (v1.3 · LOCKED · owner-authored)

**Core positioning statement (never rewritten · never abbreviated · never AI-branded):**

> **NivXRay — Evidence-Driven Security Investigation Platform.**
> **Deterministic-first. AI-optional.**

**Battle-cry (unchanged):**
> **"Verdict, cited. Every time."**

### Naming rule (permanent · no exceptions)

NivXRay is **NEVER** called any of the following in any comms artefact — investor deck, landing page, sales collateral, blog, PR, analyst briefing, job posting, GitHub description:

- ❌ AI Investigation
- ❌ AI SOC
- ❌ AI SOC Investigation
- ❌ AI NivXRay
- ❌ NivXRay AI
- ❌ LLM-powered anything
- ❌ Any phrase where "AI" or "LLM" appears in the primary product identity

### The AI-optional principle

- **AI/LLMs are optional augmentation.**
- **AI/LLMs are never the foundation of NivXRay's identity.**
- **AI/LLMs are never in the critical security decision path.**
- If the LLM overlay hallucinates, changes behaviour, becomes unavailable, becomes expensive, or produces an inconsistent answer — the fundamental NivXRay investigation still works, identically.
- LLM overlay is a **capability**, not a **category**.

### Deterministic-Core-vs-Optional-AI architecture (canonical diagram · v1.3)

```
                     NivXRay
                        │
           ┌────────────┴────────────┐
           │                         │
   DETERMINISTIC CORE           OPTIONAL AI
    (evidence-driven)           (augmentation)
           │                         │
       Detection                Summarisation
      Correlation           Analyst assistance
     Investigation          Hunting assistance
        ATT&CK               Report drafting
        Verdict         Natural-language queries
      Provenance      Investigation suggestions
```

**Reading rule:** the left column is what makes NivXRay's identity and category. The right column is added value, rate-capped and budget-capped (see `NIVX_AI_RATE_HOURLY=10`, `NIVX_AI_BUDGET_CAP_CREDITS=500`). If the entire right column is removed, the product still ships its 9-card brief, 8-tab session, and NIST IR report — all deterministically.

### Canonical evidence-flow diagram (v1.3 · use across all comms)

```
             SECURITY EVIDENCE
                    ↓
          Parse / Normalise
                    ↓
          Canonical Evidence
                    ↓
        Deterministic Analysis
                    ↓
              Correlation
                    ↓
          Investigation Graph
                    ↓
        Attack Reconstruction
                    ↓
        Evidence-backed Verdict
                    ↓
                Incident
                    ↓
                Response
```

Every stage in this pipeline is deterministic. AI does not appear in the diagram — that is intentional.


**Basis:** 360° audit trio — every strategic claim cites the corresponding audit line
- `NivXRay_360_Product_Market_Posture.md` (40 sections + Executive Scorecard) — abbreviated **[POSTURE]**
- `NivXRay_360_Evidence_Matrix.md` (12 flat evidence tables) — abbreviated **[EVIDENCE]**
- `NivXRay_360_Architecture.md` (current + target diagrams) — abbreviated **[ARCH]**

**Enforced discipline:**
- 🟢 = say freely (verified in audit)
- 🟡 = qualify carefully
- 🔴 = do NOT say (fabrication)
- ★ = strategic priority

**All downstream artefacts (pitch deck · landing page · customer decks · investor 1-pager · sales collateral) generate FROM this document, not around it.**

---

## Table of Contents

1. Executive One-Liner
2. Product Definition · Category · Positioning
3. TODAY — What NivXRay Actually Is
4. WEDGE — Where We Enter the Market
5. COMPETITIVE BATTLE — Who We Fight and How
6. PRODUCT ROADMAP — The Path from Wedge to Platform
7. MOAT — Why NivXRay Wins Long-Term
8. BUSINESS MODEL — How We Monetise
9. 3-YEAR VISION — What NivXRay Becomes
10. Investor Narrative Skeleton (10-slide flow)
11. Language Discipline — Green · Yellow · Red
12. Metrics Fact Sheet
13. What This Document Governs

---

## 1 · Executive One-Liner

### 1.1 TODAY · what NivXRay actually is (verified · say freely)

**Master positioning statement (current wedge — use verbatim across all channels TODAY):**

> **NivXRay is an Evidence-Driven Security Investigation Platform.**
> **Deterministic-first. AI-optional.**
> It sits on top of any organisation's existing security stack — SIEM, XDR, EDR, cloud, identity, network — and turns fragmented evidence into a fully-cited, deterministic, ATT&CK-mapped attack reconstruction with an evidence-backed verdict.

**Two-line elaboration:**

> Core security analysis, correlation, investigation and verdicts remain reproducible and evidence-backed **without requiring an LLM in the critical path**. If the LLM hallucinates, changes behaviour, becomes unavailable, or produces an inconsistent answer — NivXRay still works, identically. AI is an optional augmentation for analyst productivity — never the foundation of the product's identity or security decisions.
>
> We do not replace Splunk. We do not replace CrowdStrike. We plug into what you already own and give your analysts something they have never had — a deterministic, evidence-cited investigation layer that reconstructs what actually happened.

### 1.2 TOMORROW · what NivXRay evolves into (target · clearly labelled 🔵 PLANNED · do NOT claim as today)

**Long-term platform statement (target category · use with a "vision" or "roadmap" label):**

> **NivXRay is evolving into a full Evidence-Driven Security Operations Platform.**
> **Deterministic-first and AI-optional at every stage.**
> The initial Investigation wedge expands into a unified Prevent · Detect · Correlate · Investigate · Decide · Respond · Learn platform, absorbing the workloads of SIEM, EDR, XDR and SOAR under a single canonical evidence + investigation-graph spine — while preserving deterministic-first architecture, evidence provenance, and the AI-optional principle as invariants.

**Reading rules (non-negotiable):**
- 🟢 § 1.1 (TODAY) — cite freely, backed by the 360° audit trio
- 🔵 § 1.2 (TOMORROW) — label as vision/roadmap in every use; never mix into a "today" sentence
- 🔴 Do NOT write a sentence that reads *"NivXRay does A, B and C"* where A is verified and C is § 1.2 platform territory
- 🔴 Do NOT use "AI SOC" or "AI Investigation" as NivXRay's identity — permanent naming rule (see top-of-doc)


---

## 2 · Product Definition · Category · Positioning

### 2.0 · The Frozen Strategic Hierarchy (v1.3 · LOCKED · owner-authored)

**This hierarchy is the load-bearing spine of every NivXRay investor / product / GTM narrative. Do not rewrite. Do not paraphrase away from it. Do not re-introduce "AI SOC" naming.**

```
                    NivXRay TODAY
        Evidence-Driven Security Investigation
              (Deterministic-first · AI-optional)
                          ↓
                       WEDGE
     Investigate evidence from the customer's
              existing security stack.
                          ↓
                  DIFFERENTIATION
   Deterministic + evidence-cited + correlated
          + explainable investigation.
                          ↓
                     EXPANSION
        Native telemetry → broader detection
          → threat hunting → response.
                          ↓
                     PLATFORM
   SIEM + EDR + XDR + SOAR / XSOAR + Investigation
                          ↓
                      VISION
     A unified evidence-driven Security
              Operations Platform.
```

**Battle-cry (never changes):**
> **"Verdict, cited. Every time."**

**Reading discipline:**
- TODAY + WEDGE + DIFFERENTIATION are 🟢 investable facts (verified in 360° audit trio)
- EXPANSION + PLATFORM + VISION are 🔵 roadmap · **always label as roadmap / vision / target** when quoted
- No comms artefact skips a step. The investor / customer / partner must see the whole arc — not just today, not just vision — because credibility lives in the connection between them.
- NivXRay's identity never contains "AI" — deterministic-first, AI-optional (see top-of-doc naming rule).

### 2.1 Category — dual layer

NivXRay operates a **two-tier category strategy**:

| Tier | Category label | Timing | Status |
|---|---|---|---|
| **Wedge (TODAY)** | Evidence-Driven **Security Investigation** Platform · Deterministic-first · AI-optional | current + 12 months | 🟢 verified via 360° audit |
| **Platform (TOMORROW)** | Evidence-Driven **Security Operations** Platform · Deterministic-first · AI-optional | 12-36 months | 🔵 vision · explicitly labelled roadmap |

> **Category strategic principle:** we enter the market as the **evidence-driven, deterministic-first, AI-optional** alternative — explicitly distinct from LLM-powered AI SOC copilots. We own the wedge by executing the *Security Operations Platform* vision behind it. Both labels live under the same brand promise — **"Verdict, cited. Every time."**

### 2.2 What NivXRay is NOT (existing categories — relationships)

This is distinct from — and complementary to — existing categories:

| Existing category | NivXRay is NOT (TODAY) | Relationship TODAY | Relationship TOMORROW (🔵 target) |
|---|---|---|---|
| SIEM (Splunk · Sentinel · QRadar · Elastic) | not a log platform | ingests from it | 🔵 absorbs Correlation + Investigation workloads |
| XDR (Palo Alto XSIAM · CrowdStrike Falcon · Sentinel XDR) | not a telemetry platform | ingests alerts + artefacts | 🔵 absorbs cross-domain correlation |
| EDR (CrowdStrike · SentinelOne · Defender) | not an endpoint agent | consumes its detections | 🔵 consumes + reasons over endpoint telemetry natively |
| SOAR (XSOAR · Torq · Tines) | not orchestration | can feed verdicts into it | 🔵 SOAR-lite response gated on verdict-confidence |
| AI SOC copilot (Dropzone AI · Prophet · Radiant) | not an LLM chatbot | competes as *deterministic-first alternative* | 🔵 expands into full Investigation Platform |
| Sandbox (Any.Run · Joe · VMRay) | not a detonation platform | complements as *paste-time deterministic reasoning* | 🔵 hosts artefact analysis pipeline natively |
| Investigation platforms (IBM Resilient · D3) | not case-mgmt SaaS | complements with evidence-driven reasoning | 🔵 absorbs case-management |

### 2.3 Strategic hierarchy — canonical diagram (owner-authored · reuse across all comms)

```
                              NivXRay
                                 │
                        Evidence-Driven
                       Security Operations
                            Platform
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
        PREVENT               DETECT                RESPOND
       (🔵 roadmap)          (🔵 roadmap)           (🔵 SOAR-lite roadmap)
          │                      │                      │
          │                    SIEM                  SOAR / XSOAR
          │                    EDR                   Automation
          │                    XDR                   Actions
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 ↓
                    INVESTIGATE / CORRELATE
                          (🟢 TODAY · wedge)
                                 │
                       Evidence Intelligence
                                 │
                       Investigation Graph
                                 │
                       Attack Reconstruction
                                 │
                          Verdict / Risk
                                 │
                           Analyst / AI

Security domains that flow into the platform (🔵 target — none universally covered as native adapters today):
  Identity · Network · Cloud / IAM · Web / API / OWASP · Database · Email · Endpoint · Malware
```

### 2.4 The Product Loop (canonical · reuse across all comms)

```
   Collect  →  Detect  →  Correlate  →  Investigate  →  Decide  →  Respond  →  Learn
   🔵 target   🔵 target    🟡 partial     🟢 TODAY       🟢 TODAY   🔵 roadmap   🔵 roadmap
```

- **Collect (🔵 target)** — native ingest from SIEM · EDR · XDR · cloud audit · identity · network · email · web · malware · database
- **Detect (🔵 target)** — native YARA/Sigma execution · rule-authoring · in-stream detection
- **Correlate (🟡 partial)** — ICE Rule R21 already correlates per-request; cross-session Investigation Knowledge Graph is Phase 3
- **Investigate (🟢 TODAY)** — 9-card brief · 8-tab L4 · Evidence Explorer · NIST IR export — verified in 360° audit
- **Decide (🟢 TODAY)** — evidence-backed Verdict + Confidence Provenance (Rule R22) — verified
- **Respond (🔵 roadmap)** — SOAR-lite webhook actions gated on verdict-confidence threshold (Phase 4)
- **Learn (🔵 roadmap)** — cross-session Investigation Knowledge Graph · behaviour registry · opt-in cross-tenant intel (Phase 3-4)

> **Every product decision must slot into a specific loop stage. Every investor slide must state which stage(s) the pitched capability lives in.**

### 2.5 Security domain coverage — honest matrix

Cross-reference: **[POSTURE § 5, 17]** for the today-column · this table extends with target columns for the platform vision.

| Security domain | TODAY (verified) | 12-mo target | 36-mo target |
|---|---|---|---|
| **Endpoint** (PS · CMD · Bash · Python · JS · VBS AST · LOLBAS) | 🟢 deep on paste | + Sysmon EVTX · Event 11 · Event 22 adapters | + native EDR agent stream |
| **Malware artefact** (PE · ELF · Office macro · PDF · recursive decode) | 🟢 4 analyzers + 12-layer decode | + YARA/Sigma execution engine | + full detonation-alternative reasoning |
| **Identity** (Okta · Entra · AD · valid-account abuse) | 🟡 MITRE mapping only · no IAM adapter | + Okta + Entra adapter | + identity-graph correlation |
| **Network** (DNS · proxy · NetFlow · IDS/IPS · NDR) | 🟡 IOC-level only | + DNS Event 22 adapter | + native NetFlow / Zeek log ingest |
| **Cloud / IAM** (CloudTrail · Azure Activity · GCP Audit) | ❌ no adapter | + CloudTrail adapter | + full cross-cloud audit |
| **Web / API / OWASP** (WAF · access logs · API abuse) | ❌ | 🔵 Phase 3 | + full web-attack replay |
| **Database** (DB audit · anomalous query) | ❌ | 🔵 Phase 3 | + DB-audit correlation |
| **Email** (`.eml` adapter) | 🟢 headers + body + links | + phishing-URL enrichment | + inline mailbox integration |
| **Security-product ingest** (XDR JSON · EDR alert JSON · CSV EDR) | 🟡 CSV ✅ · XDR JSON semantic hardening pending (Issue #1) | + native XDR connector #1 + #2 | + 6-10 native connectors |

**Reading rule:** the "TODAY" column is investable evidence. The "12-mo / 36-mo target" columns are the platform roadmap. Never conflate.

### 2.6 Canonical architecture example — the evidence-spine principle (owner-authored)

**The same evidence + investigation spine that serves the wedge today serves the platform tomorrow.** This is the technical credibility argument that makes the platform vision believable — not vaporware.

#### 2.6a · Near-term Windows / Sysmon / EDR path (target · 3-6 months)

```
   Windows / Sysmon / EDR
             ↓
     Canonical Evidence
             ↓
       Event Semantics
             ↓
  4625 / 4624 / 4688 / 4104 · …
             ↓
User + Device + Session + Process
             ↓
    Behavior Correlation
             ↓
    Attack Progression
             ↓
    Investigation Graph
             ↓
 Evidence-backed Verdict
             ↓
          Incident
```

#### 2.6b · Long-term multi-domain platform path (vision · 18-36 months)

```
   Windows · Identity · Network · Cloud/IAM
Web/API/OWASP · Database · Email · Endpoint · Malware
                        ↓
                Canonical Evidence
                        ↓
                   Correlation
                        ↓
                  Investigation
                        ↓
                     Verdict
                        ↓
                    Response
```

**Reading rule:** the same **Canonical Evidence → Correlation → Investigation → Verdict** spine runs top-to-bottom in both diagrams. Only the *inputs* on top expand as adapters land. That is why the platform vision is credible — the spine already exists (verified in `services/ice/correlate.py:701` + `services/session/summary_narrative.py`), and every future adapter feeds into it without rearchitecting anything below.

**Investable framing:** "We have built the investigation foundation. Our wedge is Evidence-Driven AI SOC Investigation. Our roadmap expands that same evidence and investigation spine into a broader Security Operations Platform."

### 2.7 Ideal-customer-profile lens

See **[POSTURE § 27]** for the full four-segment expansion. Priority order:
1. **MSSP L1/L2 analyst leverage** — highest immediate demand, easiest proof
2. **IR / consulting boutiques** — NIST IR export is a natural wedge
3. **Mid-market SOC (200-2000 endpoints)** — analyst-productivity fit
4. **Analyst-side layer on enterprise XDR** — Series-A expansion segment

### 2.8 Category battle-cry (candidate — use across all comms)
> **"Verdict, cited. Every time."**

Sub-taglines by audience:
- Investor: *"Deterministic AI SOC today. Evidence-Driven Security Operations Platform tomorrow."*
- CISO / SOC Director: *"Every finding your analysts write is now defensible in evidence — and every domain you own will one day flow into the same investigation graph."*
- MSSP: *"Junior analyst throughput, senior analyst quality — without the LLM liability."*
- IR consultant: *"Reconstruct any incident from evidence. Export a NIST-standard report."*

---

## 3 · TODAY — What NivXRay Actually Is

Cross-reference: **[POSTURE § 1-4, 15, 16, 24]** · **[EVIDENCE Tables A, B, D, F, G, H]** · **[ARCH § 1]**

### 3.1 Verified capability inventory (10 pillars we can pitch)

| # | Pillar | Verified evidence |
|---|---|---|
| 1 | **Deterministic-first architecture (Rules R21 · R22)** | `services/ice/correlate.py:701` · `services/session/summary_narrative.py` — zero LLM in critical path **[EVIDENCE B13, B23]** |
| 2 | **Multi-language deterministic AST engines** (PowerShell · CMD · Bash · Python · JS · VBS) | `services/die/*_ast.py` — 6 engines **[EVIDENCE B01-B06]** |
| 3 | **Recursive 12-layer decode + 12-codec try-list** | `services/die/recursive_decode.py:180` + `NIVX_ENGINE_BUDGET_DEPTH=12` **[EVIDENCE B07]** |
| 4 | **ICE Rule R21 · single deterministic correlation pass** | 1385 loc · `correlate()` builds behaviours + phases + timeline + graph + MITRE + completeness + readiness + gaps + recommendations in one pass **[EVIDENCE B13-B21]** |
| 5 | **MITRE ATT&CK · 154 technique→tactic mappings + 79 display names** | code-frozen in `ice/correlate.py` **[EVIDENCE B11, B12]** |
| 6 | **11-field deterministic Investigation Summary Narrative** | `summary_narrative.py::build_narrative()` — Executive · Analyst · Behaviour · Intent · Impact · Timeline · MITRE · IOC Intel · Recommendations · Evidence Confidence · Verdict **[EVIDENCE B23]** |
| 7 | **8-tab L4 Investigation Session workspace + 9-card Analyst Brief** | `InvestigationSessionPage.jsx` (1298 loc) + `WorkspacePage.jsx` (4538 loc) + `InvestigationSummaryPanel.jsx` **[EVIDENCE B24-B33]** |
| 8 | **Evidence Explorer projection with source citations per row** (P0h-A) | `InvestigationSessionPage.jsx:1064` **[EVIDENCE B26]** |
| 9 | **NIST IR Report export (MD + PDF)** | `services/session/nist_report.py` (549+ loc) + `/api/session/{sid}/nist.{md,pdf}` **[EVIDENCE B30-B32]** |
| 10 | **Wire-boundary discipline** — `_slim_investigation_response` + `_REPORT_EXTRACTION_KEEP` allow-list + SHA-256-only IOC policy | `services/die/canonical_bridge.py:535,588` **[EVIDENCE B34, B35]** |

### 3.2 Verified quality/velocity/discipline metrics

| Metric | Number | Source |
|---|---|---|
| Git commits (current branch) | **1448** | `git log \| wc -l` |
| Backend routers | **78 real** | `ls backend/routers/` |
| Service modules | **19 top-level** | `find backend/services -maxdepth 1 -type d` |
| Frontend pages | **33 JSX** | `ls frontend/src/pages/` |
| ADRs (architectural decisions ledger) | **88 files** | `ls memory/adr/` |
| Canonical test files | **56** | `find backend/tests/canonical -name test_*.py` |
| Canonical suite live (2026-02-13) | **608 pass / 10 fail / 11 skip · 237 s** | `pytest backend/tests/canonical/ -q` |
| Equivalence-harness proofs (JSON reports) | 2 (`m0a` + `extended`) totalling **~90 KB** | `memory/equivalence_report_*.json` |
| Deterministic evidence bundles preserved | 20+ (RC22-RC29 corpus) | `memory/rc*_*.json` |

### 3.3 Verified adapter surface (universal on paste, growing on structured logs)

Adapters shipping today (**[EVIDENCE Table C]**):
- `text` · `url` · `docx` · `pdf` · `eml` · `image` · `zip` — plus `base` abstract = **8**
- Prose recognition (via IUE 761 loc) additionally handles: Sysmon XML · EDR alert JSON · atomic IOC · encoded blobs · CSV EDR
- **Universal on paste; adapter roadmap for structured logs** — this is the honest framing

### 3.4 Verified OSINT + threat-intel surface

**[EVIDENCE Table I]** — 7 real providers:
- VirusTotal + AbuseIPDB (combo)
- URLhaus (abuse.ch) · urlscan.io · ThreatFox · MalwareBazaar · Hybrid Analysis
- OTX: configured in DB `settings` but not yet adapter-wired
- Plus RSS threat-intel ingest → high-confidence promotion (`/api/threat-intel/rss/pending/promote-high-confidence`)

### 3.5 Verified honest gaps (do NOT pitch these as done)
- ❌ Single FastAPI process — no distributed workers
- ❌ Single-tenant only — no multi-tenant model
- ❌ 0 native EDR/XDR/SIEM connectors
- ❌ Sysmon EVTX · DNS Event 22 · File-Create Event 11 adapters (LOCKED)
- 🟠 Playwright + Tesseract SHADOW (code present, not wired)
- 🟠 XOR fidelity defect (Layer-1 display, LOCKED)
- 🟡 6 payload-shape canonical tests failing (allow-list drift · P0 to triage)
- 🟡 Top-level `session.attack_story` / `session.timeline` / `session.incident_graph` projections not populated (tabs render from `session.incident.*` which ICE does populate — user-visible parity but not the target schema)
- ❌ No RBAC beyond `admin` · no SSO · no audit trail · no SOC-2 · no encryption at rest
- ❌ No verified paying customers · no verified design-partner LOIs

---

## 4 · WEDGE — Where We Enter the Market

Cross-reference: **[POSTURE § 25-27, 33]**

### 4.1 The wedge statement (v1.3 · owner-authored — architecture-correct)

> **NivXRay is an independent security analysis and investigation platform.**
>
> **Collect directly. Investigate independently. Integrate everywhere.**
>
> NivXRay ingests telemetry, logs, artefacts and security events **directly** from the customer's environment — endpoint · network · identity · cloud · web/API · database · email · applications · artefacts — and can also consume evidence from existing SIEM · XDR · EDR platforms.
>
> It performs its own detection, correlation, investigation and evidence-backed verdict — deterministic and AI-optional — then integrates back with the organisation's SIEM · ITSM · SOAR to drive analyst visibility and response.
>
> **Existing SIEM/XDR/EDR are possible sources, not mandatory dependencies.**

### 4.2 What this replaces in the v1.2 wedge language

The v1.2 phrase *"Give NivXRay the evidence from your existing security stack"* implied that NivXRay was a passive layer on top of SIEM/XDR/EDR. **That is wrong.** The corrected framing (v1.3) treats existing security platforms as one class of input, not the only class — and adds downstream integration back to those systems as a first-class product concern.

**Today's verified reality vs the target ingestion / integration architecture:**

| Component | TODAY (🟢 verified in 360° audit) | TARGET (🔵 roadmap) |
|---|---|---|
| Direct-from-source ingestion | 8 adapters: paste · URL · docx · pdf · eml · image · zip + prose recognition | Native adapters: Sysmon EVTX · Windows Event · EDR streams · Cloud audit · Identity (Okta/Entra) · Network (Zeek/NetFlow) · DNS · WAF · DB audit · Email API |
| Consume-from-security-platform | Prose recognition of XDR alert JSON · CSV EDR export | Native connectors: SentinelOne · CrowdStrike · Defender · Sentinel XDR · Splunk saved-search · QRadar offense · Falcon LogScale |
| Detection · Correlation · Investigation · Verdict (independent processing) | ICE Rule R21 · deterministic single-pass · 154 MITRE mappings · 11-field narrative · 9-card brief · 8-tab L4 session · NIST IR export | Cross-session Investigation Knowledge Graph · negative explainability · learned attack-pattern registry |
| Downstream integration (out-bound) | NIST IR PDF/MD export · REST API surface (78 routers) | Native connectors out: SIEM (Splunk · Sentinel · QRadar · Elastic) · ServiceNow / ITSM · SOAR (XSOAR · Torq · Tines) · Slack / Teams / PagerDuty |

**Investor-slide discipline:** the diagram may show the target ingestion + integration architecture, but every slide showing it must include a footer strip listing what is TODAY verified vs ROADMAP. See Slide 07 in the investor deck for the reference implementation.

### 4.3 Wedge diagram — v1.3 corrected (canonical · reuse everywhere)

```
                           SECURITY SOURCES  (🔵 roadmap adapters)
                                    │
   ┌─────────────┬─────────────┬────┼────┬─────────────┬────────────┐
   ▼             ▼             ▼    ▼    ▼             ▼            ▼
Endpoint     Network       Identity Cloud Web/API   Email/Artefact  Apps
Windows      DNS/Proxy     AD/Entra AWS/  WAF/API   PDF/PE/Office   DB/
Sysmon/EDR   NDR/IDS       IAM/MFA  Azure Gateway   Scripts/URLs    HTTP/App
                                    GCP/            App logs
                                    CloudTrail
   │             │             │    │    │             │            │
   └─────────────┴─────────────┴────┼────┴─────────────┴────────────┘
                                    ↓
              ┌─────────────────────────────────────────┐
              │       NivXRay  (🟢 core · TODAY)       │
              │ Universal Ingestion · Input Router      │
              │ Parse · Normalise · Decode · Classify   │
              │ Canonical Evidence                       │
              │ Deterministic Analysis · Detection       │
              │ ATT&CK · Semantic Analysis · Threat Int  │
              │ ICE Rule R21 · Correlation (single-pass) │
              │ Investigation Knowledge Graph            │
              │ Attack Reconstruction                    │
              │ Evidence-backed Verdict                  │
              │ Incident Queue · Analyst Workspace       │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
             SIEM               ServiceNow            SOAR
        Splunk · Sentinel      ITSM · Ticketing   XSOAR · Torq · Tines
        QRadar · Elastic         (🔵 roadmap)         (🔵 roadmap)
             (🔵 roadmap)
                                   │
                                   ▼
                            ANALYST VIEW
```

**Reading rule:** the middle NivXRay box (🟢) is verified today. The top sources row and bottom downstream row are **native adapter/connector roadmap items** — Phase 2-4. **Do not claim they are today.**

### 4.4 Deployment model (customer conversation)

NivXRay can be deployed alongside existing security infrastructure in any of these three modes:

1. **Direct ingestion mode (target · Phase 2+)** — telemetry flows into NivXRay in parallel with existing SIEM/XDR/EDR. Both systems remain independent.
2. **Evidence-consumer mode (today · verified)** — SIEM/XDR/EDR forward alert JSON / saved-search output / vendor blog URLs / CSV exports into NivXRay for deep investigation.
3. **Hybrid (Phase 3+)** — NivXRay ingests some sources directly + some via existing platforms + emits enriched incidents back to SIEM/SNOW/SOAR.

**Investor talking point:** "Existing SIEM/XDR/EDR become possible input sources for NivXRay, not mandatory prerequisites. And NivXRay's incident output flows back into whatever ITSM/SIEM/SOAR the customer already runs — we do not replace their SOC ecosystem, we augment it with an independent investigation engine."



### 4.5 Why this wedge works

1. **Zero rip-and-replace.** Customer keeps every existing tool. Reduces buyer friction to near-zero.
2. **Immediate analyst leverage.** L1/L2 throughput improves on the first paste, no new telemetry pipeline required.
3. **Vendor-neutral by design.** The moment we build the *first* native XDR connector, the story generalises.
4. **Believable at seed stage.** Every capability in the wedge is code-verified TODAY — no vaporware claim.
5. **Defensible against LLM copilots.** Their weakness (hallucination) is our design axiom (Rule R21/R22).

### 4.6 First customers (three concrete personas)

**A · MSSP L1/L2 analyst leverage** (highest priority)
- 500+ MSSPs globally struggling with L1 quality/consistency
- Buyer: SOC Director · MSSP CTO
- Proof: shift-lead pilot on real client tickets
- Pricing hypothesis: per-seat + revenue share (see § 8)

**B · IR / consulting boutiques**
- 200+ IR retainer shops in NA/EU
- Buyer: Partner · IR Lead
- Proof: NIST IR PDF export on a real engagement
- Pricing hypothesis: per-engagement + retainer

**C · Mid-market SOC (200-2000 endpoints)**
- 10,000+ orgs with in-house SOC but under-tooled
- Buyer: CISO · SOC Manager
- Proof: XDR-alert-in / brief-out on their own alert
- Pricing hypothesis: per-analyst seat SaaS

### 4.7 Explicit non-wedges (do NOT chase these first)
- Enterprise SIEM replacement
- Full-stack XDR
- Endpoint agent
- Cloud-security posture
- Detection-rule authoring UI
- SOAR playbook orchestration (Phase 4+ only)

---

## 5 · COMPETITIVE BATTLE — Who We Fight and How

Cross-reference: **[POSTURE § 25, 29, 33, 34]**

### 5.1 Primary battle · LLM-first AI SOC copilots

**Opponents:** Dropzone AI · Prophet Security · Radiant Security · Torq's AI copilot · Microsoft Copilot for Security (partial overlap) · CrowdStrike Charlotte AI · Simbian

**Our defensible frame:** *"Deterministic evidence, LLM optional. Every finding cites a code path or an ATT&CK technique + confidence + provenance. No hallucination liability."*

**Head-to-head demo pattern:**
1. Feed identical Talos blog URL to NivXRay + a leading copilot
2. Compare: (a) evidence citations per claim · (b) provenance trace · (c) hallucination rate on a controlled fabricated-fact test
3. Show NivXRay's ICE `correlate.py` — code-frozen Rule R21 — as architectural proof

**Why they cannot easily copy:**
- Their codebase is LLM-first — retrofitting a full deterministic evidence spine requires re-architecture, not a feature toggle
- Our 56-file equivalence harness enforces zero-drift on any change — governance moat
- Our 154 MITRE mappings + 79 display names are code-frozen — not prompt-programmable

### 5.2 Adjacent-not-direct battles

| Opponent category | Battle stance | Positioning |
|---|---|---|
| SIEM · XDR · EDR giants | 🚫 do not fight | integration partner — "we sit on top" |
| SOAR | 🚫 do not fight yet | Phase 4 SOAR-lite is a co-existence path |
| TIP | 🚫 partial overlap | complement via OSINT + RSS TI |
| Sandbox | 🟡 partial substitution on paste-time | position as *reasoning layer, not detonation* |
| Investigation-write-up | 🟡 partial | NIST IR export is a direct feature parity beat |

### 5.3 Rules of engagement (governance)

1. **Never claim category displacement of a giant.** We are additive, not substitutive.
2. **Always cite a competitor by name only if we can back the comparison with a live demo.** No slide-only competitor attacks.
3. **The demo is the argument.** No slideware claim survives a live deterministic vs LLM head-to-head.
4. **Deterministic ≠ dumb.** Emphasise: the LLM overlay is *available* (Emergent LLM Key) — we choose not to put it in the critical path.

---

## 6 · PRODUCT ROADMAP — The Path from Wedge to Platform

Cross-reference: **[POSTURE § 31, 32]**. This section refines the audit's timing per user's explicit re-prioritisation.

### 6.1 Phase 1 · Investigation Wedge · 0-3 months (seed-round readiness)

**Goal:** prove the wedge on three real design-partner MSSPs / IR shops. Everything below is buildable on the current codebase.

★ **P0 · Fix 6 payload-shape canonical test failures** (`test_investigation_results_payload_shape.py`)
   - Why: engineering-health signal for investor DD
   - Effort: ~1 engineer-week

★ **P0 · Ship L4 top-level deterministic projections (P0h-B/C/D)**
   - `session.timeline` · `session.attack_story` · `session.incident_graph` populated from `investigation_inputs`
   - Why: closes the schema gap the audit surfaced
   - Effort: ~2 engineer-weeks

★ **P0 · Multi-tenant scaffolding + 3-role RBAC (admin · analyst · viewer)**
   - Tenant model in `backend/models/` · middleware · per-tenant investigation isolation
   - Why: unblocks all enterprise pilot conversations
   - Effort: ~4-6 engineer-weeks

★ **P1 · XDR JSON semantic classification hardening (Issue #1 Option B)**
   - Teach IUE to recognise vendor-JSON shapes (`_time`, `mitre_tactics`, `severity`, `console_link`, `use_case: mxdr_incident`)
   - Why: unlocks vendor-neutral investigation layer story
   - Effort: ~1-2 engineer-weeks

**Explicit non-goals for Phase 1:**
- ❌ Do not build a large number of native connectors yet — first prove the value on evidence delivered *by the customer*
- ❌ Do not build landing page yet — wait for this positioning doc to stabilise
- ❌ Do not chase SOC-2 in Phase 1 — start the gap analysis only

**Phase 1 exit criteria:**
- 3 design-partner LOIs (MSSP or IR)
- Multi-tenant + RBAC live
- L4 top-level projections live
- 6 payload-shape tests green
- All P0 items done · zero critical regressions

### 6.2 Phase 2 · Native Connectors + Enterprise Ingestion · 3-6 months (Series-A wedge)

★ **First native XDR connector** — SentinelOne OR Microsoft Defender / Sentinel (customer-signal-driven pick)
★ **Second native XDR connector** — the alternative of the two above
★ **Sysmon EVTX adapter** — unlock the LOCKED path
★ **DNS Event 22 + File-Create Event 11 adapters**
★ **YARA / Sigma execution engine against decoded payloads** (not just extraction)
★ **Basic case-management** — investigation ownership · SLA · handoff · comment thread
★ **SSO via IdP (Okta or Entra)** — enterprise buyer checklist
★ **Audit trail** — who investigated what · when · with what evidence

**Exit criteria:**
- 10 paid pilots · $250k-$1M ARR run-rate
- Two live XDR connectors demonstrated on real customer telemetry
- SOC-2 Type-1 evidence collection started

### 6.3 Phase 3 · Distributed Processing + Scale · 6-12 months (Series-A execution)

★ **Distributed worker pool + queue** (SQS / Redis Streams / NATS)
★ **Horizontal-scale demo** — sustained investigations/sec target
★ **Cross-session Investigation Knowledge Graph MVP** — behaviours learned in one investigation surface in the next (within tenant)
★ **Negative explainability layer** — *why NOT technique X* — killer investor demo
★ **SOC-2 Type-1 complete**
★ **AWS / Azure Marketplace listing**
★ **MSSP wholesale motion** (5 MSSPs on revenue share)

**Exit criteria:** $2M-$5M ARR · path-to-$10M-ARR clear · one flagship enterprise reference customer.

### 6.4 Phase 4 · Cross-Domain Investigation Platform · 12-18 months

- SOAR-lite response (webhook actions gated on verdict + evidence-confidence threshold)
- Detection-rule authoring UI (build YARA/Sigma rules from evidence patterns)
- Cross-tenant threat-intel network effect (opt-in, tenant-anonymised)
- On-prem / air-gapped SKU (federal + regulated)
- GraphQL API for analyst-tooling integrations
- SOC-2 Type-2 · ISO-27001 path

### 6.5 Phase 5 · Evidence-Driven Security Operations Platform · 18-36 months

**Vision-level goal:** NivXRay category-owns Evidence-Driven Security Operations. The initial Investigation wedge has expanded upward into Prevent · Detect · Correlate · Respond · Learn, each still governed by the same deterministic-first + evidence-provenance axioms.

- **Native ingest across the full Collect stage** — SIEM saved-searches · XDR/EDR native · cloud audit (CloudTrail · Azure Activity · GCP Audit) · identity (Okta · Entra · AD-DS) · network (Zeek · NetFlow · DNS) · email · web / API · database audit · malware artefact stream
- **Native Detect stage** — YARA / Sigma / custom-rule execution against ingested telemetry, evidence emitted into the same canonical model
- **SOAR-Lite Response** — verdict-gated automated actions (contain endpoint · disable account · block IOC) via webhook + IdP integrations
- **Learn stage · full cross-tenant threat-intel network effect** — opt-in tenant-anonymised behaviour registry; each investigation strengthens the platform
- **Detection rule authoring UI** — turn observed behaviour into reusable YARA/Sigma rules
- **On-prem / air-gapped SKU** — federal + regulated
- **GraphQL analyst API** — programmatic access for downstream tooling
- **SOC-2 Type-2 · ISO-27001 · HIPAA-ready control set**
- **Category perception target:** analysts search for "evidence-driven security operations" and NivXRay is the default

**Non-goals even at Phase 5:**
- ❌ Never abandon deterministic-first architecture (LLM stays overlay-only)
- ❌ Never emit a claim without evidence citation (governance discipline preserved from Phase 1)
- ❌ Never become an LLM-first copilot even at platform scale

**Exit target:** 50+ enterprise · 30+ MSSPs · $10M-$25M ARR · Series-B set-up.

### 6.6 Roadmap principles (governance)

1. **Do not skip Phase 1.** Multi-tenant + RBAC + L4 projections + XDR classification are non-negotiable before scaling GTM.
2. **Connector count is a business KPI, not an engineering KPI.** Add a connector only when there's a customer waiting for it.
3. **Every capability we add must preserve the deterministic-first architecture.** LLM stays overlay-only.
4. **Every capability we add must preserve evidence provenance.** No feature ships that produces a claim without a citable evidence path.

---

## 7 · MOAT — Why NivXRay Wins Long-Term

Cross-reference: **[POSTURE § 29, 35.3, 35.7]**

### 7.1 The moat statement (v1.2 · refined — the combination IS the moat, not any single pillar)

> **Raw event → Canonical evidence → Entity → Relationship → Behaviour → ATT&CK semantics → Attack progression → Investigation → Verdict.**
>
> **Every conclusion remains traceable to evidence.**
>
> **The moat is the combination — not any single pillar.**
>
> Deterministic-first architecture + evidence-provenance discipline + Investigation Knowledge Graph + curated AST / decode / ATT&CK corpus + accumulated investigation knowledge — reproduced together and preserved as invariants from wedge to platform.

**Refinement discipline (owner-authored · v1.2):**
- The strongest defensibility claim is the *combination*, not any single pillar in isolation
- A competitor *could* eventually build deterministic components — that is a hypothesis, not an impossibility
- The realistic moat argument is: reproducing deterministic architecture **AND** provenance-discipline **AND** the investigation-graph spine **AND** the accumulated AST/decode/ATT&CK corpus **AND** the governance harness — all at once, retroactively, against a codebase originally designed LLM-first — is prohibitively expensive
- Never say "impossible to reproduce" — say "prohibitively expensive to retrofit at scale · foundational design choice, not a feature bolt-on"

### 7.2 What the four pillars actually give us (verified · use in this order)

Each pillar is a **defensibility hypothesis**, not an absolute. The combination is what compounds.

#### Pillar 1 · Deterministic-First Architecture (foundational design choice)
- ICE Rule R21 (single correlation pass · zero LLM) — `services/ice/correlate.py:701`
- Rule R22 (deterministic narrative · zero LLM header in `summary_narrative.py`)
- 56-file equivalence harness enforces zero-drift on every change
- **What it gives us:** reproducibility · evidence traceability · explainability — every conclusion is defensible in front of a customer, an auditor, or a court
- **Defensibility hypothesis:** retrofitting this into an LLM-first codebase is prohibitively expensive because the deterministic guarantees affect data flow, testing philosophy, and the wire boundary — not just a feature toggle

#### Pillar 2 · Evidence-Provenance End-to-End (governance discipline)
- Every field in the 9-card brief traces back through `evidence_confidence` provenance
- `_REPORT_EXTRACTION_KEEP` allow-list at wire boundary
- SHA-256-only IOC policy at wire
- Per-input `investigation_inputs[].source` citations in Evidence Explorer
- **What it gives us:** every claim shipped to the customer or auditor cites its evidence — no hallucination liability
- **Defensibility hypothesis:** provenance is a *codified discipline*, not a feature. Adding it after the fact means auditing every projection, every wire path, every field — enterprise-scale rework

#### Pillar 3 · Canonical Investigation Knowledge Graph (compounding — future)
- Today: in-request graph via `_build_incident_graph()` at `correlate.py:1075`
- Target: cross-session · cross-tenant (opt-in) · learned attack-pattern registry
- **What it gives us (once cross-session lands):** every investigation strengthens future ones — network effect within MSSP consolidation
- **Defensibility hypothesis:** the graph value compounds with each investigation; the earlier we start persisting it, the harder it is for a late entrant to catch up on breadth of learned attack patterns

#### Pillar 4 · Curated AST / Decode / ATT&CK Corpus (accumulated investigation knowledge)
- 6 AST engines · 12-layer recursive decode · 12-codec try-list
- 154 technique→tactic mappings · 79 display names · code-frozen
- Fixture corpus (`memory/rc*_*.json`) accumulates over time
- **What it gives us:** the coverage & accuracy of paste-time analysis grows with every analyst correction and every new fixture
- **Defensibility hypothesis:** takes years of fixture curation and analyst feedback to reproduce breadth; the moat is time × labour, not code

### 7.3 What is NOT a moat (do not pitch as one)

- ❌ "We use AI" (weak · everyone does)
- ❌ "We have a UI" (weak · everyone does)
- ❌ "We produce MITRE mappings" (weak · industry-standard)
- ❌ "We integrate with X" (weak · connector-race)
- ❌ "Deterministic-first is impossible for competitors to copy" (over-claim · say *prohibitively expensive to retrofit* instead)

### 7.4 Compounding moat trajectory

```
Phase 1  →  Deterministic architecture locked · governance discipline set
Phase 2  →  Adapter breadth grows · fixture corpus grows · ATT&CK coverage grows
Phase 3  →  Cross-session graph starts compounding · negative explainability differentiates
Phase 4  →  Cross-tenant graph (opt-in) creates true network effect
Phase 5  →  Category ownership · investor / customer defaults to "this is how you do AI SOC"
```

**Every stage inherits the invariants of the previous stage. That is the compounding argument — not any single-pillar claim.**


---

## 8 · BUSINESS MODEL — How We Monetise

Cross-reference: **[POSTURE § 28]**

### 8.1 Pricing hypotheses (NOT commitments — validate in pilot)

| Model | Segment | Range | When to use |
|---|---|---|---|
| Per-analyst seat SaaS | Mid-market SOC · in-house | $150-$500 / seat / month | Once multi-tenant lands |
| Per-investigation | IR retainers · burst usage | $5-$25 / investigation | Fits variable IR load |
| Per-endpoint | XDR-add-on future SKU | $1-$3 / endpoint / month | Requires connector story |
| Platform license (fixed) | Federal · regulated · air-gapped | $50k-$500k / year | Requires SOC-2 · high-touch sales |
| MSSP wholesale | Channel partners | $20k-$150k / tier + rev-share | Phase 3+ · fastest scaling |

### 8.2 First-round pilot pricing (recommended)

- **MSSP pilot:** flat $2,500/month for 3-month pilot with 5 analyst seats · then per-seat SaaS + revenue share
- **IR consultancy pilot:** flat $1,500/month for unlimited investigations during 3-month pilot · then per-engagement
- **Mid-market SOC pilot:** free 30-day pilot with 3 analyst seats · then per-seat SaaS

### 8.3 Revenue-model principles

1. **Never price against a giant's per-endpoint number.** We are additive, not replacive — anchor on *analyst productivity*, not endpoint coverage.
2. **Include NIST IR export in every tier.** It is a demo-slot-closer.
3. **Meter the LLM overlay separately.** Deterministic-first means the base tier does not require an LLM budget — respect that.
4. **MSSP channel is the fastest scale.** Design commercial terms for wholesale from day 1.

### 8.4 Unit-economics rough target (Phase 2 exit)

- CAC (blended SMB + MSSP): $10k-$20k
- ACV: $30k-$60k per customer
- Gross margin: 80%+ (single-tenant preview → multi-tenant SaaS)
- Payback: 6-9 months
- Net revenue retention: 120%+ (seat expansion + connector uplift)

*All figures illustrative until pilot data.*

---

## 9 · 3-YEAR VISION — What NivXRay Becomes

**Vision statement (dual-layer · both must appear together in comms):**

> **Today (🟢 verified):** NivXRay is the deterministic-first AI SOC Investigation platform — an analyst-side reasoning layer that sits on top of the customer's existing security stack.
>
> **Tomorrow (🔵 vision · label as roadmap):** NivXRay evolves into the Evidence-Driven Security Operations Platform — a unified Prevent · Detect · Correlate · Investigate · Decide · Respond · Learn platform that absorbs the workloads of SIEM · EDR · XDR · SOAR under a single canonical evidence + investigation-graph spine, while preserving deterministic-first architecture and evidence provenance as invariants across every stage.
>
> Deployed across 50+ enterprises and 30+ MSSPs by 2029, winning both the AI SOC Investigation wedge (Year 1-2) and the Evidence-Driven Security Operations Platform category (Year 3+), on the promise:
>
> **"Verdict, cited. Every time."**

### 9.1 Phase-based scoreboard · funding-accelerated (v1.3.3 · owner-directed compression + explicit TODAY anchor)

**Reading rule:** these are **phase milestones**, not calendar years. Column 1 is the verified TODAY state (2026-02-13). Columns 2-4 are funding-accelerated targets. Timing is a function of funding + team velocity. Strong seed round compresses Phase 1 to 6 months. Certain items (SOC-2 audit observation windows, enterprise sales cycles, reference-customer maturity) have irreducible time floors that money cannot fully compress.

| Metric | 🟢 **PHASE 0 · TODAY** (verified 2026-02-13) | Phase 1 · 0–6 mo (Wedge) | Phase 2 · 6–12 mo (Expansion) | Phase 3 · 12–18 mo (Platform trajectory) |
|---|---|---|---|---|
| Paying customers | **0** (preview only) | 3–5 design partners | 15–25 | 30–50 |
| MSSP partners | **0** (no LOIs verified) | 1–2 | 3–5 | 8–12 |
| Enterprise references | **0** | 0–1 (pilot) | 2–3 | 5–8 |
| Native XDR/EDR/SIEM connectors | **0** | 2 (first XDR) | 6+ | 12+ |
| Adapters (structured input) | **8** (paste · URL · docx · pdf · eml · image · zip + base) | Sysmon EVTX + first 3 | 8+ | 15+ |
| OSINT providers | **7** wired (VT · AbuseIPDB · URLhaus · urlscan · ThreatFox · MalwareBazaar · HybridAnalysis) | +OTX + 2 | same + coverage growth | same |
| Product loop stages live | Investigate 🟢 · Decide 🟢 · Correlate 🟡 (per-request) | + Correlate (cross-session MVP) | + Detect (native) · Learn (in-tenant) | + Respond (SOAR-lite) |
| Security domains covered (deep) | **Endpoint · Malware · Email** (adapter + AST) | + Identity | + Network · Cloud | + Web/API · Database |
| ARR | **$0** | $200k–$500k | $1M–$2.5M | $3M–$7M |
| Team | **founder-scale** (exact size confidential) | 8–15 | 20–30 | 35–50 |
| Compliance | **none started** · SOC-2 gap analysis pending | SOC-2 T1 kickoff | SOC-2 T1 complete | SOC-2 T2 in progress |
| Deployment | Preview at REACT_APP_BACKEND_URL · nivxray.nivxforge.com prod idle | Multi-tenant + RBAC live | Marketplace listings | HA · DR · multi-region |
| Codebase | **1448 commits · 78 routers · 33 pages · 88 ADRs · 56 canonical tests · 608 passing** | + P0h-B/C/D + tenant model + first connectors | + distributed workers | + SOAR-lite · detection authoring |
| Category perception | **new entrant · pre-revenue** | "credible wedge" | "credible investigation platform" | "emerging Security Operations Platform" |

### 9.1a Compression floors — what capital **cannot** fully compress (honest disclosure)

Capital accelerates engineering, hiring, sales velocity and pilot volume. But four floors resist compression:

| Floor | Why it can't be bought | Realistic minimum |
|---|---|---|
| **SOC-2 Type-1 audit observation window** | Auditors require operating-controls-observation period | ~3–6 months from kickoff |
| **SOC-2 Type-2** | Continuous evidence collection over time | 6–12 months minimum after T1 |
| **Enterprise sales cycles** | Buyer procurement · security review · budget cycles | 3–9 months first-touch-to-close |
| **Reference-customer maturity** | Customer must actually run the product before being a public reference | 3–6 months post-deployment |

**Investor framing (honest):** *"Today, NivXRay is a pre-revenue technical product with a verified deterministic investigation core, 8 adapters, 7 OSINT providers, 608 passing tests, and a preview deployment. With a strong seed round, Phase 1's engineering deliverables land in 6 months. Compliance and reference-customer maturity extend into Phases 2–3. The engineering-to-outcome compression multiplier is roughly 3× with well-funded execution — but not proportional to capital beyond irreducible business floors."*

### 9.1b Alternative long-term glide-path (if pace holds after Phase 3)

- Phase 4 (18–24 mo): 60–100 customers · 15+ MSSPs · $8M–$15M ARR · SOC-2 T2 complete · ISO-27001 in progress · Marketplace listings live
- Phase 5 (24–36 mo): 100+ customers · 30+ MSSPs · $15M–$30M ARR · Category-owning position in Evidence-Driven SecOps Platform

**These out-year numbers remain aspirational and depend on the compounding of moat pillars (see § 7).** Not for the investor deck; for the internal roadmap only.

### 9.2 Category ownership · definition of done (both categories)

**Wedge category (Year 1-2 · Evidence-Driven AI SOC Investigation):**
- Analysts search "deterministic AI SOC" and find NivXRay first
- Investors classify us in a new sub-category — not lumped with LLM copilots
- MSSPs cite NivXRay as their reference investigation platform
- IR reports produced by NivXRay are quoted by name in customer post-mortems

**Platform category (Year 3+ · Evidence-Driven Security Operations Platform):**
- Gartner / Forrester / IDC coverage lists NivXRay under a new SecOps sub-category
- RFPs from mid-market and enterprise buyers cite NivXRay under "SOC platform" alongside XDR/SIEM incumbents
- MSSPs deploy NivXRay as their primary SecOps platform (not just investigation layer)
- Analysts write and detect rules native to NivXRay, not translated in from Splunk/Sentinel
- The Product Loop (Collect → Detect → Correlate → Investigate → Decide → Respond → Learn) fully runs inside NivXRay for at least one flagship customer

### 9.3 Why the platform vision is credible (not vaporware)

Every element of the platform vision is built on architectural invariants that already exist:

| Platform capability | Invariant it inherits from today | Evidence |
|---|---|---|
| Native ingest (Collect) | 8 adapters + IUE 761 loc + universal-on-paste | **[EVIDENCE Table C]** |
| Deterministic detection (Detect) | YARA/Sigma **extraction** works today; execution engine is additive not architectural | `report_extraction.yara_rules / sigma_rules` verified live |
| Correlation (Correlate) | ICE Rule R21 correlate() 1385 loc — single deterministic pass with 10 output blocks | `services/ice/correlate.py:701` |
| Investigate | 9-card + 8-tab L4 + Evidence Explorer + NIST IR — all shipped | **[EVIDENCE B24-B33]** |
| Decide | Rule R22 verdict + confidence provenance | `services/session/summary_narrative.py` |
| Respond (SOAR-lite) | Webhook + verdict-gating = additive over existing verdict pipeline | Phase 4 · additive |
| Learn (cross-session graph) | `_build_incident_graph()` already produces per-request graph; sidecar persistence is next step | `correlate.py:1075` + `NIVX_EVIDENCE_GRAPH=sidecar` |

**Investable narrative:** every future platform stage is an *addition* to the deterministic-first architecture — not a rebuild. Deterministic-first + evidence-provenance are the invariants that scale from today's wedge to tomorrow's platform.


---

## 10 · Investor Narrative Skeleton (10-slide flow · pitch generates from this)

Every slide has:
- A ONE-LINE hook (green-safe per § 11)
- A short evidence anchor (points to audit trio or a live demo step)
- A "what to say / what NOT to say" annotation

### 10-Slide Structure

**Slide 1 · Problem**
> SOC teams have overwhelming security evidence and still cannot reconstruct what actually happened.
- Anchor: 500-800 alerts/day per L1 analyst benchmark (cite standard source)
- Do NOT say: "SIEM is broken" (fights the wrong battle)

**Slide 2 · Existing stack acknowledgement**
> Every organisation already owns EDR · XDR · SIEM · cloud · identity · network. Investigation still bottlenecks.
- Anchor: [POSTURE § 25 competitive landscape]
- Do NOT say: "we replace them"

**Slide 3 · The Gap**
> Alerts and telemetry exist. Investigation remains fragmented and analyst-intensive. AI copilots hallucinate.
- Anchor: [POSTURE § 25.1 · LLM copilot weakness]
- Do NOT say: "AI is bad"

**Slide 4 · NivXRay = Evidence-Driven AI SOC Investigation**
> A deterministic evidence layer that reconstructs and explains attacks — cited to evidence, ATT&CK-mapped, NIST-report-ready.
- Anchor: § 1 one-liner
- Do NOT say: "AI SOC copilot" (weakens differentiation)

**Slide 5 · Technology architecture**
> Input → Canonical Evidence → Semantic ATT&CK → Correlation → Investigation Graph → Attack Reconstruction → Evidence-Backed Verdict.
- Anchor: § 4.3 wedge diagram + [ARCH § 1]
- Say: "6 AST engines · 12-layer decode · 154 MITRE mappings · Rule R21 single-pass correlation · 608 tests passing"
- Do NOT say: "distributed" or "universal ingestion"

**Slide 6 · Differentiation**
> Deterministic-first. Evidence-cited. LLM-optional. Every finding traces back to a code path or an ATT&CK technique with confidence and provenance.
- Anchor: [POSTURE § 30] + Rule R21 · R22 citations
- Say: "The alternative to hallucinating copilots"
- Do NOT say: "we are better than Copilot for Security" (unbounded claim)

**Slide 7 · Wedge**
> AI-assisted SOC investigation. Analyst leverage for MSSPs and IR shops. Deploy on top of your existing stack — no rip-and-replace.
- Anchor: § 4 wedge
- Say: "3 design-partner MSSPs by end of Phase 1"
- Do NOT say: "$1B TAM tomorrow"

**Slide 8 · Expansion — from Wedge to Platform**
> Investigation → threat hunting → cross-domain correlation → **Evidence-Driven Security Operations Platform** (SIEM + EDR + XDR + SOAR workloads under one canonical evidence + investigation-graph spine).
- Anchor: § 2.3 hierarchy diagram · § 2.4 Product Loop · § 6.1-6.5 roadmap · § 9 dual-lens scoreboard
- Say: "Investigation is our wedge in Year 1-2. Security Operations Platform is our category by Year 3 — every stage inheriting the deterministic-first invariant."
- Do NOT say: "we become the next Splunk" (over-claim; frame as *category expansion*, not vendor displacement)

**Slide 9 · Moat**
> Canonical evidence · investigation knowledge graph · semantic knowledge · deterministic correlation · governance discipline (equivalence harness).
- Anchor: § 7 moat pillars
- Say: "Deterministic-first is a structural moat — LLM-first competitors cannot easily copy"
- Do NOT say: "we have IP" (no patents visible)

**Slide 10 · Vision + Ask**
> Year 1-2: category-own Evidence-Driven AI SOC Investigation.
> Year 3+: expand into the Evidence-Driven Security Operations Platform — unified Prevent · Detect · Correlate · Investigate · Decide · Respond · Learn.
> By 2029, deployed across 50+ enterprises and 30+ MSSPs. Raising [seed amount] to fund Phase 1 + Phase 2 execution.
- Anchor: § 9 dual-lens vision · § 6.1-6.2 near-term roadmap
- Say: verified milestones from § 3.2 metrics + the Product Loop diagram from § 2.4
- Do NOT say: exit multiple or valuation-driven pitch

### 10.1 Deck governance
- The 23-slide auto-generated PPTX at `/api/deck/download` regenerates from THIS document — not the reverse
- Every deck edit that changes a claim must first update this document + point at an audit citation

---

## 11 · Language Discipline — Green · Yellow · Red

Cross-reference: **[POSTURE § 38]**. This is the exhaustive list. Use it in every comms draft.

### 11.1 🟢 Green — say freely (audit-verified · use unconditionally)

- **"Evidence-Driven Security Investigation Platform"** (wedge category · today)
- **"Deterministic-first. AI-optional."** (positioning tagline · always paired)
- "Deterministic-first architecture"
- "AI-optional · never in the critical decision path"
- "Every finding cites its evidence"
- "9-card Analyst Brief with evidence provenance"
- "8-tab L4 Investigation Session workspace"
- "12-layer recursive decode"
- "6 language AST engines"
- "154 MITRE technique mappings, code-frozen"
- "608 tests passing on a 56-file canonical suite"
- "Single-pass deterministic correlation (Rule R21)"
- "NIST IR-ready reports (MD + PDF)"
- "Wire-boundary SHA-256-only IOC policy"
- "56-file equivalence harness enforcing zero-drift"
- "1448 commits · 88 ADRs · 78 backend routers"
- "The evidence-driven alternative to LLM-powered SOC copilots"
- "Sits on top of your existing security stack"
- "Verdict, cited. Every time."

### 11.1b 🟢🔵 Green with roadmap-label (platform vision · say only with an explicit "vision" or "roadmap" or "target" modifier)

Whenever any of these phrases appear in comms, they MUST be preceded or followed by one of: *vision · roadmap · target · Phase 3+ · by 2029 · we are evolving into*.

- "Evidence-Driven Security Operations Platform" (target category · Phase 5)
- "Unified Prevent · Detect · Correlate · Investigate · Decide · Respond · Learn platform" (target)
- "Absorbs SIEM · EDR · XDR · SOAR workloads under one canonical spine" (target)
- "Product Loop: Collect → Detect → Correlate → Investigate → Decide → Respond → Learn" (mixed — cite stage-by-stage · see § 2.4)
- "Cross-session Investigation Knowledge Graph" (target · Phase 3)
- "Native XDR connectors" (target · Phase 2)
- "Full security-domain coverage: identity · network · cloud · web · database · email · endpoint · malware" (target · Phase 2-5)
- "SOAR-lite verdict-gated response" (target · Phase 4)
- "Cross-tenant threat-intel network effect" (target · Phase 4)

### 11.2 🟡 Yellow — qualify carefully

- "MSSP-ready" → say "MSSP wholesale motion planned for Phase 3; multi-tenant scaffolding shipping in Phase 1"
- "Zero-hallucination" → say "zero LLM in the critical path (Rule R21 / R22); LLM overlay is optional and rate-capped"
- "Deployed in production" → say "preview-deployed and technically ready; first paying pilots targeted for Phase 1"
- "Universal input" → say "universal on paste + URL; structured-log adapter roadmap in Phases 2-3"
- "Sits on top of any security stack" → say "sits on top of your existing stack via analyst paste today; native connectors on roadmap"
- "Full Security Operations Platform" → **ALWAYS** qualify as *"target platform / Phase 5 vision"* — never bare
- "Replaces SIEM / EDR / XDR" → say "absorbs Investigation and Correlation workloads from SIEM/XDR under the Evidence-Driven SecOps Platform by 2029 — customers keep existing telemetry pipelines; we own the investigation graph"
- "SIEM / EDR / XDR / SOAR capabilities" → **NEVER** bare · always say *"target platform capabilities · Phase 5 vision"*

### 11.3 🔴 Red — do NOT say

**Permanent naming red-lines (v1.3 · never rewritten):**
- ❌ "AI Investigation"
- ❌ "AI SOC" (as NivXRay's own identity or category — you may reference competitor AI SOC category by name in comparison slides)
- ❌ "AI SOC Investigation"
- ❌ "AI SOC copilot" (competitor category label only — never for NivXRay)
- ❌ "AI NivXRay" / "NivXRay AI"
- ❌ "LLM-powered NivXRay / detection / investigation / anything"
- ❌ Any phrase that puts "AI" or "LLM" in NivXRay's primary product identity
- ❌ Any sentence that implies AI is required, foundational, or in the critical decision path

**Standard red-lines:**
- "Enterprise-ready" (no SOC-2 · no RBAC beyond admin · no encryption at rest)
- "Universal ingestion" (only 8 adapters + paste)
- "Distributed / horizontally scalable" (single FastAPI process)
- "Real-time detection in live telemetry" (no live-telemetry backend)
- "Integrates with any SIEM/XDR/EDR" (0 native connectors)
- "Cross-tenant threat-intelligence network effect" (not built)
- "SOC-2 compliant" (not started)
- "Multi-tenant SaaS" (single-tenant only)
- "Replaces Splunk / CrowdStrike / etc." (never · we complement · absorb workloads over time via SecOps Platform vision)
- "N events per second at p95 latency" (no fresh benchmarks)
- Any specific external-customer name (none verified)
- **Platform-vision guard-rails:**
  - "NivXRay is a SIEM / EDR / XDR / SOAR" (present tense — never)
  - "NivXRay has native SIEM ingest / EDR agent / XDR telemetry" (present tense — never)
  - "NivXRay detects malware / lateral movement / phishing / cloud abuse" (present tense in live telemetry — never · we *analyse* artefacts, we do not *detect* in live telemetry)
  - "NivXRay covers identity / network / cloud / web / database / email domains" (present tense — never; today = endpoint + malware + email deep · other domains 🔵 target)
  - "NivXRay responds automatically to incidents" (present tense — never · SOAR-lite is Phase 4)
  - Any sentence that reads *"NivXRay is a full-fledged SIEM+EDR+XDR+SOAR platform"* in the present tense — **hard red line** · always qualify with vision/target/Phase 5



---

## 12 · Metrics Fact Sheet (canonical numbers for all comms)

**Verified as of 2026-02-13 · reproducible via commands in `NivXRay_360_Product_Market_Posture.md § Living metrics harvest`.**

| # | Metric | Value | Where cited |
|---|---|---|---|
| 1 | Git commits | 1448 | dev velocity |
| 2 | Backend routers | 78 real | API surface breadth |
| 3 | Service modules | 19 top-level | architectural depth |
| 4 | Frontend pages | 33 | UI surface |
| 5 | ADRs | 88 | governance discipline |
| 6 | Canonical test files | 56 | quality bar |
| 7 | Canonical suite passing | 608 | quality signal |
| 8 | Canonical suite failing | 10 (4 LOCKED + 6 P0 fix pending) | honest metric |
| 9 | Canonical suite runtime | 237 s | performance signal |
| 10 | AST engines | 6 | language coverage |
| 11 | Recursive decode depth | 12 layers (`NIVX_ENGINE_BUDGET_DEPTH=12`) | technical depth |
| 12 | Codecs in decoder | 12 | technical depth |
| 13 | MITRE technique→tactic mappings | 154 | ATT&CK coverage |
| 14 | MITRE technique display names | 79 | ATT&CK coverage |
| 15 | Adapters | 8 | input surface |
| 16 | IOC providers | 7 real | OSINT breadth |
| 17 | L4 Session tabs | 8 | UX coverage |
| 18 | Analyst brief cards | 9 | UX coverage |
| 19 | MITRE swim-lane tactics | 12 | visualisation coverage |
| 20 | Summary narrative fields | 11 | narrative depth |

---

## 13 · What This Document Governs

**This document is the single source of truth for:**

1. **Investor pitch deck** — every slide's claim must appear in § 3 · § 10 or be marked 🟡/🔴 in § 11
2. **Landing page (when built)** — hero + differentiator + demo path all sourced here
3. **Customer collateral** — one-pager · sales deck · IR consultancy deck · MSSP deck all derived from § 4 · § 8 · § 10
4. **PR / thought leadership** — every claim traceable to § 3 (verified) or explicitly labelled roadmap
5. **Analyst-relations briefings** (Gartner · Forrester · IDC) — § 2 category positioning · § 3 today · § 6 roadmap
6. **Design-partner LOI language** — § 4.4 personas + § 8.2 pilot pricing
7. **Team communication** — § 6 roadmap · § 11 language discipline

**Update discipline:**

- Any material change to a claim in this document requires (a) an updated citation in the 360° audit trio and (b) a dated changelog entry at the bottom of this section
- The pitch deck at `/api/deck/download` is regenerated from this doc, not the reverse
- If the audit trio changes (fresh audit, new capabilities), this document updates before any external comms

**Cross-reference index:**

| Downstream artefact | Read this section first |
|---|---|
| Investor deck | § 10 · § 3 · § 6 · § 9 |
| Landing page hero | § 1 · § 4.3 · § 4.1 |
| MSSP sales deck | § 4.4A · § 8 · § 5.1 |
| IR consultancy pitch | § 4.4B · § 3.1 pillar 9 (NIST IR) · § 8 |
| Job description / careers page | § 2.3 taglines · § 9 vision · § 7 moat |
| Analyst-relations briefing | § 2 category · § 3 today · § 6 roadmap |
| CISO trust-page | § 3.5 gaps · § 6.1 P0 items · § 11 language discipline |

---

## Changelog

- **2026-02-13 · v1.3.1 · Slide 07 architecture correction + § 4 wedge rewrite (INDEPENDENT PLATFORM)** — per owner directive: NivXRay is an **independent** security analysis and investigation platform, not a passive SIEM plugin.
  1. **§ 4.1 wedge statement rewritten** — "Collect directly. Investigate independently. Integrate everywhere." NivXRay ingests telemetry, logs, artefacts and events **directly** from the environment (endpoint · network · identity · cloud · web/API · database · email · applications · artefacts) and can also consume evidence from existing SIEM/XDR/EDR. Existing security platforms are **possible sources, not mandatory dependencies**.
  2. **§ 4.2 explicit today-vs-target matrix** — direct-from-source ingestion · consume-from-security-platform · independent processing · downstream integration — each row with TODAY (🟢 verified) vs TARGET (🔵 roadmap) columns.
  3. **§ 4.3 corrected wedge diagram** — sources (roadmap) → NivXRay independent core (today) → downstream SIEM/SNOW/SOAR (roadmap). Every row labelled with today/roadmap discipline.
  4. **§ 4.4 deployment model** — three modes: Direct ingestion (Phase 2+ target) · Evidence-consumer (today · verified) · Hybrid (Phase 3+).
  5. **Slide 07 of investor deck rewritten** — headline "Collect directly. Investigate independently. Integrate everywhere." · sources row (Endpoint · Network · Identity · Cloud/IAM · Web/API · Email/Artefacts · Applications) · NivXRay independent-processing box with the deterministic sub-pipeline · downstream integration row (SIEM · ServiceNow · SOAR). Dual badge — "CORE · TODAY" (green) + "INGEST + I/O · ROADMAP" (blue). Footer caveat listing today's 8 verified adapters + noting native telemetry ingestion + downstream connectors as Phase 2-4 roadmap.
  6. Deck regenerated · live at `/api/deck/investor-v1-3.pptx` (55 KB · 12 slides).

- **2026-02-13 · v1.3 · LOCKED · deterministic-first, AI-optional (permanent positioning rule)** — per owner directive, permanent naming rule locked at top of document:
  1. **Core positioning:** "NivXRay — Evidence-Driven Security Investigation Platform · Deterministic-first. AI-optional." (v1.2 label "Evidence-Driven AI SOC Investigation" retired)
  2. **Permanent forbidden names:** AI Investigation · AI SOC · AI NivXRay · NivXRay AI · LLM-powered anything — NivXRay's product identity contains **no AI branding**
  3. **AI-optional principle:** AI/LLMs are augmentation, never foundation, never in the critical security decision path. Removing all AI functionality must leave the deterministic core intact.
  4. Added **top-of-doc permanent positioning rule** section (before ToC)
  5. Added **canonical evidence-flow diagram** (Security Evidence → Parse → Canonical Evidence → Deterministic Analysis → Correlation → Investigation Graph → Attack Reconstruction → Verdict → Incident → Response)
  6. Added **Deterministic-Core-vs-Optional-AI split diagram** showing what lives in each column
  7. Updated § 1.1 / § 1.2 / § 2.0 / § 2.1 to remove "AI SOC" branding; category becomes "Evidence-Driven Security Investigation Platform" (wedge) / "Evidence-Driven Security Operations Platform" (target)
  8. Updated § 11.1 green list (AI-optional tagline added · AI SOC removed) and § 11.3 red-lines (permanent naming forbidden phrases added at top)
  9. Battle-cry unchanged: **"Verdict, cited. Every time."**

- **2026-02-13 · v1.2 · LOCKED · moat refinement + frozen strategic hierarchy** — per owner directive:
  1. Added **§ 2.0 · Frozen Strategic Hierarchy** (TODAY → WEDGE → DIFFERENTIATION → EXPANSION → PLATFORM → VISION) as the load-bearing spine of every NivXRay narrative — do not rewrite / paraphrase away from it
  2. Added **§ 2.6 · Canonical architecture example** — Windows/Sysmon near-term path + multi-domain long-term path — proving the platform vision inherits the same evidence spine (not vaporware)
  3. Refined **§ 7 Moat** from "structural moat / cannot copy" absolutes to **defensibility hypotheses** — the moat is the **combination**, not any single pillar
     - Pillar 1 (Deterministic-first): reframed from "impossible for competitors to retrofit" to "prohibitively expensive to retrofit at scale · foundational design choice, not a feature bolt-on"
     - Added an explicit *"NOT a moat"* row: "Deterministic-first is impossible for competitors to copy" (over-claim) → say *prohibitively expensive to retrofit* instead
     - Every pillar now describes (a) what it gives us + (b) the defensibility hypothesis
  4. Status upgraded to **LOCKED** as the NivXRay posture for investor-pitch work

- **2026-02-13 · v1.1 · platform-vision layer added** — per owner directive, added explicit distinction between:
  - **Wedge (TODAY · 🟢):** Evidence-Driven AI SOC Investigation
  - **Platform (TOMORROW · 🔵):** Evidence-Driven Security Operations Platform
  Added § 1.2 (tomorrow one-liner) · § 2.1 dual-category table · § 2.3 strategic hierarchy diagram (PREVENT · DETECT · RESPOND on top of INVESTIGATE / CORRELATE) · § 2.4 Product Loop (Collect → Detect → Correlate → Investigate → Decide → Respond → Learn with per-stage status) · § 2.5 security-domain coverage matrix (Endpoint · Malware · Identity · Network · Cloud/IAM · Web/API/OWASP · Database · Email) with today / 12-mo / 36-mo columns. Rewrote § 6.5 Phase 5 as the full SecOps Platform target. Rewrote § 9 vision as dual-lens (Year 1-2 wedge / Year 3+ platform). Added § 9.3 credibility table showing every platform capability inherits an existing architectural invariant. Added § 11.1b (roadmap-qualified green) and 6 new absolute red-lines to § 11.3 (no present-tense claims of SIEM/EDR/XDR/SOAR capability). Slide 8 and Slide 10 of the investor narrative updated to the wedge-then-platform expansion.

- **2026-02-13 · v1.0 · initial** — reconciled from 360° audit trio + user's Strategic Refinements message. Category: Evidence-Driven AI SOC Investigation. Wedge codified. Roadmap re-prioritised (multi-tenant + RBAC + L4 projections + XDR classification in Phase 1; native connectors deferred to Phase 2 pending customer signal). Moat re-framed as four pillars. Language discipline codified in § 11.
  1. Added **§ 2.0 · Frozen Strategic Hierarchy** (TODAY → WEDGE → DIFFERENTIATION → EXPANSION → PLATFORM → VISION) as the load-bearing spine of every NivXRay narrative — do not rewrite / paraphrase away from it
  2. Added **§ 2.6 · Canonical architecture example** — Windows/Sysmon near-term path + multi-domain long-term path — proving the platform vision inherits the same evidence spine (not vaporware)
  3. Refined **§ 7 Moat** from "structural moat / cannot copy" absolutes to **defensibility hypotheses** — the moat is the **combination**, not any single pillar
     - Pillar 1 (Deterministic-first): reframed from "impossible for competitors to retrofit" to "prohibitively expensive to retrofit at scale · foundational design choice, not a feature bolt-on"
     - Added an explicit *"NOT a moat"* row: "Deterministic-first is impossible for competitors to copy" (over-claim) → say *prohibitively expensive to retrofit* instead
     - Every pillar now describes (a) what it gives us + (b) the defensibility hypothesis
  4. Status upgraded to **LOCKED** as the NivXRay posture for investor-pitch work

- **2026-02-13 · v1.1 · platform-vision layer added** — per owner directive, added explicit distinction between:
  - **Wedge (TODAY · 🟢):** Evidence-Driven AI SOC Investigation
  - **Platform (TOMORROW · 🔵):** Evidence-Driven Security Operations Platform
  Added § 1.2 (tomorrow one-liner) · § 2.1 dual-category table · § 2.3 strategic hierarchy diagram (PREVENT · DETECT · RESPOND on top of INVESTIGATE / CORRELATE) · § 2.4 Product Loop (Collect → Detect → Correlate → Investigate → Decide → Respond → Learn with per-stage status) · § 2.5 security-domain coverage matrix (Endpoint · Malware · Identity · Network · Cloud/IAM · Web/API/OWASP · Database · Email) with today / 12-mo / 36-mo columns. Rewrote § 6.5 Phase 5 as the full SecOps Platform target. Rewrote § 9 vision as dual-lens (Year 1-2 wedge / Year 3+ platform). Added § 9.3 credibility table showing every platform capability inherits an existing architectural invariant. Added § 11.1b (roadmap-qualified green) and 6 new absolute red-lines to § 11.3 (no present-tense claims of SIEM/EDR/XDR/SOAR capability). Slide 8 and Slide 10 of the investor narrative updated to the wedge-then-platform expansion.

- **2026-02-13 · v1.0 · initial** — reconciled from 360° audit trio + user's Strategic Refinements message. Category: Evidence-Driven AI SOC Investigation. Wedge codified. Roadmap re-prioritised (multi-tenant + RBAC + L4 projections + XDR classification in Phase 1; native connectors deferred to Phase 2 pending customer signal). Moat re-framed as four pillars. Language discipline codified in § 11.

---

*End of NivXRay Strategic Master Positioning Document v1.0.*
*Companion audit artefacts (do not modify without updating this doc):*
- *`/app/memory/NivXRay_360_Product_Market_Posture.md`*
- *`/app/memory/NivXRay_360_Evidence_Matrix.md`*
- *`/app/memory/NivXRay_360_Architecture.md`*
- *`/app/memory/NivXRay_360_Audit_Spec.md`*
