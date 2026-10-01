# ADR-0013 — Unified Investigation Pipeline (UI + Output Contract)

- **Status:** **Accepted · slice-1 implemented** (2026-02-28).
- **Deciders:** Operator (product owner) · Emergent (proposer).
- **Threshold met:** Operator directive (2026-02-28) — move Lab
  sidebar sections below the input box, populate on Investigate,
  unify Lab and Workspace on a single output contract; include
  When/What/Why/Where/How narrative + mitigations, all
  deterministic.

## 1 · Problem (evidence)

- Lab sidebar carried 6 SOON-badged sections (Threat Intel, Threat
  Hunting, Knowledge Base, Reports, History, Governance) —
  navigational-only, no output.
- Lab `InvestigatePage.jsx` and Workspace `InvestigationWorkspace.jsx`
  render the same underlying `/api/decode/smart` +
  `/api/v2/auto-investigate` responses through DIFFERENT panels and
  section orders, producing two subtly different analyst experiences.
- The decode/smart response contains all the raw data (verdict, IOCs,
  MITRE, decode chain, `explainability`, `mdr_investigation.recommendations`,
  `executive_card`) but no client-side composer synthesises a
  When/What/Why/Where/How narrative or a mitigation-recommendation
  view.

## 2 · Decision

Introduce one **UI-only synthesiser** — `investigationSynthesizer.js`
— that consumes an unmodified `/api/decode/smart` OR
`/api/v2/auto-investigate` response and produces a canonical
10-section presentation model. One shared React component,
`<InvestigationPipeline>`, renders those sections in a fixed order
as collapsible cards.

### 2.1 · Section order (frozen for slice-1)

1. Executive Summary
2. Technical Analysis
3. Threat Intelligence
4. OSINT Enrichment
5. Indicators of Compromise
6. MITRE ATT&CK
7. Investigation Timeline
8. Investigation Summary (When / What / Why / Where / How)
9. Mitigation
10. Raw Evidence (Decoded Artifacts + Explainability)

### 2.2 · Determinism invariants

- No LLM in the synthesiser. Verdict, severity, confidence, ATT&CK
  mapping, IOC extraction are **read verbatim** from the backend
  response — never re-derived on the client.
- Narrative (When/What/Why/Where/How) is composed from:
  `verdict_card.explainability.contributors` +
  `iocs` + `mitre` + decode chain metadata.
- Mitigation recommendations come from:
  1. `mdr_investigation.recommendations` if present (Workspace path).
  2. Static MITRE-technique → mitigation map for the top techniques
     when 1. is empty (Lab decode/smart path).
- Timeline is derived from decoder layers + evidence order — one
  step per layer, one step per assessment.
- Confidence / severity / verdict are shown verbatim from
  `verdict_card` (or `executive_card` for auto-investigate).

### 2.3 · OSINT policy

- Priority order: existing backend deterministic intel · VirusTotal ·
  AbuseIPDB · URLScan · AlienVault OTX · MalwareBazaar · ThreatFox ·
  Shodan.
- If no API key is configured OR the provider returns empty, the
  section renders **"No enrichment available — configure API key in
  Admin"** — never an error, never a crash.
- Slice-1 renders only the deterministic backend intel from
  `ti_shield`. Real OSINT provider integrations are slice-2
  (require API keys + `integration_playbook_expert_v2`).

### 2.4 · Sidebar reduction

- SOON badges removed from all placeholder sections.
- Sidebar becomes navigation-only. All investigation-output content
  lives inside `<InvestigationPipeline>` below the input box.

### 2.5 · Cross-surface parity

- Lab `InvestigatePage.jsx` and Workspace `InvestigationWorkspace.jsx`
  both render `<InvestigationPipeline result={...} />` — one
  component, one section order, one presentation model.
- Slice-1 wires Lab; Workspace wiring is slice-2 (kept behind a
  parity gate so no analyst regression).

## 3 · Scope

**In scope (slice-1):**
- New shared component `<InvestigationPipeline>` (10 collapsible
  sections, deterministic).
- New helper `investigationSynthesizer.js` (client-side, pure).
- Lab InvestigatePage rewired to use the shared component.
- Sidebar SOON-badge removal.
- Static MITRE-technique → mitigation map (~15 top techniques).

**Out of scope (deferred to slice-2):**
- ❌ Real OSINT provider integrations (VirusTotal, AbuseIPDB, etc.).
- ❌ STIX 2.1 export endpoint.
- ❌ ATT&CK Navigator JSON export endpoint.
- ❌ Workspace InvestigationWorkspace wiring (Lab first, Workspace
  once the shared component is production-verified).
- ❌ Optional LLM Analyst Narrative overlay.

## 4 · Exit criteria

Slice-1 lands green when:

1. Lab InvestigatePage renders all 10 sections in the frozen order.
2. Collapsible cards work (expand/collapse, keyboard-accessible).
3. Sidebar shows no SOON badges.
4. Operator's regsvr32 truncated payload — with ADR-0012 —
   produces a populated Investigation Summary, populated Mitigation,
   and shows `provenance: partial_recovery` labelling.
5. No new pytest failures.
6. Frontend build passes.

## 5 · Non-decisions (deliberately parked)

- ADR-0011 Investigation Engine Unification still pending.
- Workspace wiring deferred; the shared component is designed to
  drop in without changes when we get there.
