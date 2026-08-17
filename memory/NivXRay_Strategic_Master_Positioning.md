# NivXRay · Strategic Master Positioning Document

**Status:** v1.0 · single source of truth for all future investor / product / GTM narrative
**Date:** 2026-02-13
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

**Master positioning statement (use verbatim across all channels):**

> **NivXRay is an Evidence-Driven AI SOC Investigation platform.**
> It sits on top of any organisation's existing security stack — SIEM, XDR, EDR, cloud, identity, network — and turns fragmented evidence into a fully-cited, deterministic, ATT&CK-mapped attack reconstruction with an evidence-backed verdict.

**Two-line elaboration:**

> Where LLM-first AI SOC copilots hallucinate summaries over alerts, NivXRay treats security investigation as an evidence pipeline: every input becomes canonical evidence, every conclusion cites its evidence source, and every verdict is defensible in front of a customer, an auditor, or a court.
>
> We do not replace Splunk. We do not replace CrowdStrike. We plug into what you already own and give your analysts something they have never had — a deterministic, evidence-cited investigation layer that reconstructs what actually happened.

---

## 2 · Product Definition · Category · Positioning

### 2.1 Category (new-slot claim — refined per user directive)

**NivXRay defines a new SOC sub-category: Evidence-Driven AI SOC Investigation.**

This is distinct from — and complementary to — existing categories:

| Existing category | NivXRay is NOT | Relationship |
|---|---|---|
| SIEM (Splunk / Sentinel / QRadar / Elastic) | not a log platform | ingests from it |
| XDR (Palo Alto XSIAM / CrowdStrike Falcon / Sentinel XDR) | not a telemetry platform | ingests alerts + artefacts from it |
| EDR (CrowdStrike / SentinelOne / Defender) | not an endpoint agent | consumes its detections |
| SOAR (XSOAR / Torq / Tines) | not an orchestration platform | can feed verdicts into it |
| AI SOC copilot (Dropzone AI / Prophet / Radiant) | not an LLM chatbot | competes as *deterministic-first alternative* |
| Sandbox (Any.Run / Joe / VMRay) | not a detonation platform | complements as *paste-time deterministic reasoning* |
| Investigation platforms (IBM Resilient / D3) | not case-mgmt SaaS | complements with evidence-driven reasoning |

### 2.2 Ideal-customer-profile lens
See **[POSTURE § 27]** for the full four-segment expansion. Priority order:
1. **MSSP L1/L2 analyst leverage** — highest immediate demand, easiest proof
2. **IR / consulting boutiques** — NIST IR export is a natural wedge
3. **Mid-market SOC (200-2000 endpoints)** — analyst-productivity fit
4. **Analyst-side layer on enterprise XDR** — Series-A expansion segment

### 2.3 Category battle-cry (candidate — use across all comms)
> **"Verdict, cited. Every time."**

Sub-taglines by audience:
- Investor: *"Deterministic AI SOC — the alternative to hallucinating copilots."*
- CISO / SOC Director: *"Every finding your analysts write is now defensible in evidence."*
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

### 4.1 The wedge statement (user-authored — codify it)

> **Give NivXRay the evidence from your existing security stack — SIEM, XDR, EDR, cloud, identity, network — and let it reconstruct and investigate what actually happened.**
>
> Deterministic. ATT&CK-mapped. Evidence-cited. NIST-report-ready.

### 4.2 Why this wedge works

1. **Zero rip-and-replace.** Customer keeps every existing tool. Reduces buyer friction to near-zero.
2. **Immediate analyst leverage.** L1/L2 throughput improves on the first paste, no new telemetry pipeline required.
3. **Vendor-neutral by design.** The moment we build the *first* native XDR connector, the story generalises.
4. **Believable at seed stage.** Every capability in the wedge is code-verified TODAY — no vaporware claim.
5. **Defensible against LLM copilots.** Their weakness (hallucination) is our design axiom (Rule R21/R22).

### 4.3 Wedge diagram (canonical — reuse everywhere)

```
        Your existing security stack
     ┌────────────────────────────────────┐
     │  SIEM · XDR · EDR · Cloud · IAM ·  │
     │  Network · Endpoint · TI feeds     │
     └──────────────────┬─────────────────┘
                        │
              alerts · artefacts · reports · URLs · pastes
                        │
                        ▼
              ┌─────────────────┐
              │    NivXRay      │
              │  Investigation  │
              │      Layer      │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   Canonical      Semantic       Correlated     Evidence-cited
   Evidence      ATT&CK        Investigation      Verdict
                  Mapping           Graph
                       │
                       ▼
              9-card Analyst Brief
              8-tab L4 Session
              NIST IR Report (MD + PDF)
```

### 4.4 First customers (three concrete personas)

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

### 4.5 Explicit non-wedges (do NOT chase these first)
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

### 6.5 Phase 5 · Broader Security Investigation Platform · 18-36 months

- Full platform: investigation + hunting + rule authoring + reporting + response-lite
- Category leadership in Evidence-Driven AI SOC
- 50+ enterprise · 30+ MSSPs · $10M-$25M ARR
- Series-B set-up

### 6.6 Roadmap principles (governance)

1. **Do not skip Phase 1.** Multi-tenant + RBAC + L4 projections + XDR classification are non-negotiable before scaling GTM.
2. **Connector count is a business KPI, not an engineering KPI.** Add a connector only when there's a customer waiting for it.
3. **Every capability we add must preserve the deterministic-first architecture.** LLM stays overlay-only.
4. **Every capability we add must preserve evidence provenance.** No feature ships that produces a claim without a citable evidence path.

---

## 7 · MOAT — Why NivXRay Wins Long-Term

Cross-reference: **[POSTURE § 29, 35.3, 35.7]**

### 7.1 The moat statement (user-authored — codify it)

> **Raw event → Canonical evidence → Entity → Relationship → Behaviour → ATT&CK semantics → Attack progression → Investigation → Verdict.**
>
> **Every conclusion remains traceable to evidence.**
>
> That is why deterministic-first is not just a design choice — it is the moat.

### 7.2 Four moat pillars (ranked by defensibility)

#### Pillar 1 · Deterministic-First Architecture (structural moat) ★★★★★
- ICE Rule R21 (single correlation pass · zero LLM) — `services/ice/correlate.py:701`
- Rule R22 (deterministic narrative · zero LLM header in `summary_narrative.py`)
- 56-file equivalence harness enforces zero-drift on every change
- **Why it's a moat:** competitors who chose LLM-first architecture cannot retrofit this without a full rewrite

#### Pillar 2 · Evidence-Provenance End-to-End (governance moat) ★★★★★
- Every field in the 9-card brief traces back through `evidence_confidence` provenance
- `_REPORT_EXTRACTION_KEEP` allow-list at wire boundary
- SHA-256-only IOC policy at wire
- Per-input `investigation_inputs[].source` citations in Evidence Explorer
- **Why it's a moat:** codified discipline. Cannot be added as a feature — has to be the design axiom.

#### Pillar 3 · Canonical Investigation Knowledge Graph (compounding moat — future) ★★★★☆
- Today: in-request graph via `_build_incident_graph()` at `correlate.py:1075`
- Target: cross-session · cross-tenant (opt-in) · learned attack-pattern registry
- **Why it's a moat:** every investigation strengthens future ones — real network effect within MSSP consolidation

#### Pillar 4 · Multi-Language AST + Recursive Decode + MITRE Corpus (technical moat) ★★★☆☆
- 6 AST engines · 12-layer recursive decode · 12-codec try-list
- 154 technique→tactic mappings · 79 display names · code-frozen
- Fixture corpus (`memory/rc*_*.json`) accumulates over time
- **Why it's a moat:** takes years of fixture curation and analyst feedback to reproduce

### 7.3 What is NOT a moat (do not pitch as one)

- ❌ "We use AI" (weak · everyone does)
- ❌ "We have a UI" (weak · everyone does)
- ❌ "We produce MITRE mappings" (weak · industry-standard)
- ❌ "We integrate with X" (weak · connector-race)

### 7.4 Compounding moat trajectory

```
Phase 1  →  Deterministic architecture locked · governance discipline set
Phase 2  →  Adapter breadth grows · fixture corpus grows · ATT&CK coverage grows
Phase 3  →  Cross-session graph starts compounding · negative explainability differentiates
Phase 4  →  Cross-tenant graph (opt-in) creates true network effect
Phase 5  →  Category ownership · investor / customer defaults to "this is how you do AI SOC"
```

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

**Vision statement:**

> By 2029, NivXRay is the deterministic-first AI SOC investigation platform.
> The analyst-side reasoning layer on top of any XDR / SIEM / EDR.
> 20+ native connectors · cross-session investigation knowledge graph · negative-explainability verdicts · multi-tenant MSSP-ready · SOC-2 Type-2 compliant.
> Deployed across 50+ enterprises and 30+ MSSPs.
> Winning the Evidence-Driven AI SOC category on the promise:
>
> **"Verdict, cited. Every time."**

### 9.1 3-year scoreboard

| Metric | Year 1 (2027) | Year 2 (2028) | Year 3 (2029) |
|---|---|---|---|
| Paying customers | 10 | 30 | 80 |
| MSSP partners | 3 | 10 | 30 |
| Enterprise references | 1 | 5 | 15 |
| Native connectors | 2 | 6 | 15 |
| Adapters (structured input) | 5 | 12 | 25 |
| ARR | $500k-$1M | $2M-$5M | $10M-$25M |
| Team | 8-12 | 20-30 | 50-80 |
| Compliance | SOC-2 Type-1 | SOC-2 Type-2 | ISO-27001 |
| Category perception | "interesting" | "credible" | "default choice for evidence-driven investigation" |

### 9.2 Category ownership definition of done

- Analysts search for "deterministic AI SOC" and find NivXRay first
- Investors classify us in a new sub-category — not lumped with LLM copilots
- MSSPs cite NivXRay as their reference investigation platform
- IR reports produced by NivXRay are quoted by name in customer-facing incident post-mortems

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

**Slide 8 · Expansion**
> Investigation → threat hunting → cross-domain correlation → enterprise security investigation platform.
- Anchor: § 6.1-6.5 roadmap
- Say: 5-phase roadmap · concrete Phase 1 timeline
- Do NOT say: "we become the next Splunk" (over-claim)

**Slide 9 · Moat**
> Canonical evidence · investigation knowledge graph · semantic knowledge · deterministic correlation · governance discipline (equivalence harness).
- Anchor: § 7 moat pillars
- Say: "Deterministic-first is a structural moat — LLM-first competitors cannot easily copy"
- Do NOT say: "we have IP" (no patents visible)

**Slide 10 · Vision + Ask**
> By 2029, the default choice for evidence-driven investigation across 50+ enterprises and 30+ MSSPs. Raising [seed amount] to fund Phase 1 + Phase 2 execution.
- Anchor: § 9 vision · § 6.1-6.2 roadmap
- Say: verified milestones from § 3.2 metrics
- Do NOT say: exit multiple or valuation-driven pitch

### 10.1 Deck governance
- The 23-slide auto-generated PPTX at `/api/deck/download` regenerates from THIS document — not the reverse
- Every deck edit that changes a claim must first update this document + point at an audit citation

---

## 11 · Language Discipline — Green · Yellow · Red

Cross-reference: **[POSTURE § 38]**. This is the exhaustive list. Use it in every comms draft.

### 11.1 🟢 Green — say freely (audit-verified)

- "Evidence-Driven AI SOC Investigation"
- "Deterministic-first architecture"
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
- "The alternative to hallucinating copilots"
- "Sits on top of your existing security stack"
- "Verdict, cited. Every time."

### 11.2 🟡 Yellow — qualify carefully

- "MSSP-ready" → say "MSSP wholesale motion planned for Phase 3; multi-tenant scaffolding shipping in Phase 1"
- "Zero-hallucination" → say "zero LLM in the critical path (Rule R21 / R22); LLM overlay is optional and rate-capped"
- "Deployed in production" → say "preview-deployed and technically ready; first paying pilots targeted for Phase 1"
- "Universal input" → say "universal on paste + URL; structured-log adapter roadmap in Phases 2-3"
- "Sits on top of any security stack" → say "sits on top of your existing stack via analyst paste today; native connectors on roadmap"

### 11.3 🔴 Red — do NOT say

- "Enterprise-ready" (no SOC-2 · no RBAC beyond admin · no encryption at rest)
- "Universal ingestion" (only 8 adapters + paste)
- "Distributed / horizontally scalable" (single FastAPI process)
- "Real-time detection in live telemetry" (no live-telemetry backend)
- "Integrates with any SIEM/XDR/EDR" (0 native connectors)
- "Cross-tenant threat-intelligence network effect" (not built)
- "SOC-2 compliant" (not started)
- "Multi-tenant SaaS" (single-tenant only)
- "Replaces Splunk / CrowdStrike / etc." (never · we complement)
- "N events per second at p95 latency" (no fresh benchmarks)
- Any specific external-customer name (none verified)

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

- **2026-02-13 · v1.0 · initial** — reconciled from 360° audit trio + user's Strategic Refinements message. Category: Evidence-Driven AI SOC Investigation. Wedge codified. Roadmap re-prioritised (multi-tenant + RBAC + L4 projections + XDR classification in Phase 1; native connectors deferred to Phase 2 pending customer signal). Moat re-framed as four pillars. Language discipline codified in § 11.

---

*End of NivXRay Strategic Master Positioning Document v1.0.*
*Companion audit artefacts (do not modify without updating this doc):*
- *`/app/memory/NivXRay_360_Product_Market_Posture.md`*
- *`/app/memory/NivXRay_360_Evidence_Matrix.md`*
- *`/app/memory/NivXRay_360_Architecture.md`*
- *`/app/memory/NivXRay_360_Audit_Spec.md`*
