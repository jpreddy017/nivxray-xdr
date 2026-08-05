# NivXRay Workspace — Architectural Rules (LOCKED · 2026-02-28)

> These rules are the result of user feedback across the DIE / IUE /
> Trajectory / Analyst Narrative iterations.  Any future agent
> touching the Workspace MUST read and honour them.

## R1 · Do NOT regress or destabilise the current Workspace

The current Workspace is a significant improvement over the previous
"decoder-only" versions and already provides a strong analyst
workflow.  All future work is INCREMENTAL enhancement — never a
redesign or replacement.

    Enhance. Improve. Extend. Do NOT rewrite or remove existing
    capabilities.

Specifically preserve:

- Input Understanding Engine (IUE) — top-of-Workspace card, decode
  plan, engines selected / skipped, live execution trace.
- Attack Story (Inline Attack Story component).
- Workspace Plan checklist with per-step timings.
- Deterministic Report (Executive Summary + Overall Assessment +
  Behavior Summary + Attack Progression + Likely Objective +
  Recommended Actions + Sigma / YARA / MITRE / Threat-actor).
- Evidence Trajectory (swim-lane diagram with draggable nodes,
  Kill-Chain phase colours, `+ / − / RESET` zoom controls,
  always-visible scrollbars).
- Every current Threat Analysis surface: **GRAPH, MITRE, LOLBAS,
  RULES, IOCs, TI-HITS, OSINT, AI, FLOW, CHAIN**.
- Persistence: CLEAR is the ONLY action that wipes state; tab
  navigation preserves Input + Output + IUE + Story + Trajectory +
  Narrative.

## R2 · Every visualisation must be evidence-first, interactive, deterministic

- Every badge opens evidence.
- Every node opens evidence.
- Every MITRE technique opens supporting commands.
- Every phase filters the investigation.
- Every confidence score explains itself.
- Nothing in the Workspace is a dead-end visualisation.

## R3 · Chain endpoint must NOT be called on vendor prose / IR reports

- `/api/decode/chain` caps at 20 items and calls an LLM per step.
- Any vendor-report prose (Talos, Mandiant, CrowdStrike, Microsoft
  Defender, Cisco SecureX, SOC notes) → routes ONLY through the
  preprocessor + IUE + smart-decode path.
- All three chain call sites (`analyze`, `nivxrayDecode`,
  `autoDecode`, `autoInvestigate`) MUST apply the `looksLikeProse`
  guard before touching `/decode/chain`.
- A CHAIN 524 timeout on the Workspace is a release-blocker.

## R4 · Zero LLM in the Analyst Narrative

The Executive Summary, Analyst Summary, Attack Progression, Likely
Objective, Behavior Summary, Overall Assessment, Recommended Actions,
Sigma / YARA ideas, Kill Chain Coverage, and MITRE Matrix are
GENERATED DETERMINISTICALLY from the preprocessor stages
(`services/die/analyst_narrative.py`).  No LLM.  No web calls.
Same paste → same narrative.

## R5 · "Commonly Observed In" is behaviour, not attribution

- Always render with an explicit disclaimer:
  *"Not attribution — historical prevalence only."*
- Never claim "This is LockBit" — always "Commonly observed in LockBit".

## R6 · Every regression test uses the actual user-supplied fixtures

- `/app/backend/tests/fixtures/mixed_investigation_input/` is
  permanent.
- `test_iue_preprocessor_talos_regression.py` must always be green.
- Any new fixture (Mandiant, CrowdStrike, Microsoft, SecureX) is
  added — never replacing an old one.

## R7 · No mouse-wheel / scroll-driven zoom on graphs

- Zoom only via explicit `+ / − / RESET` buttons.
- Users must be able to drag / scroll / touch inside a diagram
  WITHOUT the diagram zooming underneath them.

## R8 · Every major Workspace component must participate in a shared investigation context

Selecting evidence, a stage, a phase, a MITRE technique, or an IOC in
one component should update the rest of the Workspace consistently.
No visualisation exists in isolation.

Concretely, a click on:
  · a Kill-Chain phase pill
  · a MITRE technique badge
  · a Trajectory node
  · an IOC row
  · a DKP family
  · a Confidence chip

… updates the same `investigation.filter` slice and every downstream
component (Attack Story · Trajectory · Evidence · Threat Analysis
(GRAPH · MITRE · LOLBAS · RULES · IOCs · TI-HITS · OSINT · AI · FLOW ·
CHAIN) · Report) applies the filter.

This is what makes the Workspace one integrated investigation
platform rather than a collection of independent panels.

---

## R9 · WORKSPACE STABILITY RULE (Release Gate · 2026-02-28)

The current Workspace architecture is the **baseline**.  Future
development must be **enhancement-first, not replacement-first.**

- Do NOT remove, redesign or replace existing Workspace capabilities
  unless an equivalent or better implementation is fully validated.
- Every new feature MUST integrate with the existing Workspace
  rather than bypass or duplicate it.
- The following investigation components are **PROTECTED SURFACES**
  and must remain fully functional at all times:
  1. Input Understanding Engine (IUE)
  2. Workspace Plan checklist
  3. Attack Story (inline)
  4. Evidence Trajectory + Node Inspector
  5. Analyst Narrative (Executive Summary · Overall Assessment ·
     Attack Progression · Behavior Summary · Likely Objective ·
     Recommended Actions · Sigma · YARA · MITRE Matrix ·
     Threat-actor Context)
  6. Deterministic Report
  7. Threat Analysis right sidebar — **GRAPH · MITRE · LOLBAS ·
     RULES · IOCs · TI-HITS · OSINT · AI · FLOW · CHAIN**
  8. Collapsible RECIPE and CHAIN ANALYSIS cards
  9. Global Investigation Filter Bar
- All enhancements MUST pass regression testing against real-world
  investigation datasets (Talos · Mandiant · CrowdStrike ·
  Microsoft Defender · Huntress · Red Canary · Palo Alto Unit 42 ·
  SentinelOne) before release.
- The objective is to **enhance and improve** the Workspace — not
  damage, simplify, or regress the current analyst experience.

    Enhance.  Improve.  Integrate.  Never regress.

---

## R10 · IUE v2.0 · The Investigation-First Contract (2026-03-01)

Frozen alongside `/app/memory/IUE_ARCHITECTURE_V2.md`.

- **Golden rule**: the *Investigation Results* pane (renamed from
  "OUTPUT") must never duplicate the input.  It always presents the
  deterministic understanding — INPUT UNDERSTANDING · COMMAND
  ANALYSIS · IOC ANALYSIS · LOLBAS · MITRE · SUMMARY — even when no
  decoding is required.
- **No engine consumes raw user input directly.**  Every engine
  (Attack Story · Trajectory · Threat Analysis · Report · MITRE ·
  LOLBAS · OSINT · IDA · IVE · Narrative · Confidence …) MUST
  consume the Canonical Investigation Object emitted by the IUE.
- **The decoder is a capability, not the driver.**  It runs only
  when the IUE Decode Decision layer marks the input as encoded.
  Plain PowerShell / CMD / Bash / Python / JavaScript / Vendor
  Reports / PDFs / DOCX / Screenshots / IOC lists / Sigma / YARA
  bypass the decoder entirely and route straight to the
  Investigation Pipeline.
- **Universal input entry.**  Text pastes, uploaded documents,
  external URLs — all enter through the same IUE and are turned
  into the same Canonical Investigation Object.
- **Never rename back to "Output".**  The pane is *Investigation
  Results*.  "Output" belongs to CyberChef.
- **Every decision is analyst-visible and deterministic.**  Same
  paste → same classification → same plan → same results.

---

## Release Gate — checked before every deployment

Functional
- [ ] IUE correctly classifies every supported input type
- [ ] Decoder runs only when required; plain-text IR reports bypass decoding
- [ ] Attack Story is generated from deterministic stages
- [ ] Trajectory renders correctly with Node Inspector
- [ ] Global Investigation Context synchronises Attack Story, Trajectory,
      Evidence, and Report
- [ ] Threat Analysis sidebar (GRAPH · MITRE · LOLBAS · RULES · IOCs ·
      TI-HITS · OSINT · AI · FLOW · CHAIN) remains fully functional
- [ ] No regressions in Workspace navigation or rendering

Performance
- [ ] Large IR reports (Talos, Mandiant, Microsoft, CrowdStrike) render
      smoothly (no browser freeze)
- [ ] No excessive re-renders when filters are applied
- [ ] No API timeouts (CHAIN 524 must not recur)

Regression
- [ ] `pytest tests/` — 100% green
- [ ] `test_iue_preprocessor_talos_regression.py` — 100% green
- [ ] Manual paste: Talos IR fixture yields ≥ 14 stages · IUE
      classification `vendor_report_text` · Attack Story renders ·
      Node Inspector opens ·  Global filter applies ·  no CHAIN error

---

**These rules are locked.  Any agent that removes a listed
capability is regressing the Workspace.  Enhance, extend, add —
never remove.**
