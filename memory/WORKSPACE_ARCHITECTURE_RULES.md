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

## R11 · Workspace-wide SSOT Consumption Contract (2026-03-01)

Extends R9 (Workspace Stability) and R10 (Investigation-first) to
every visible surface, export, and API contour of the Workspace.

- **Every Workspace surface MUST consume the Canonical Investigation
  Object.**  No UI component, panel, side card, header pill,
  filter, export, or API endpoint is allowed to independently
  parse, decode, or re-interpret the original input once the SSOT
  has been created.
- **All visualizations, reports, filters, exports, and APIs**
  derive exclusively from the SSOT.  If a section is empty, that
  is a data-completeness bug in the SSOT emitter — never a reason
  to duplicate parsing in the consumer.
- **Backwards compatibility**: existing components that already
  read fields from `analyze` / `narrate` are treated as consuming
  a *projection* of the SSOT and remain valid so long as their
  data path terminates in the SSOT.
- **New capabilities plug in below the SSOT**, never beside it.
  IDA, IVE, PCAP, Mach-O, Archive intelligence — all future
  engines emit into the SSOT and read from it.  Their UIs read
  the SSOT too.

Enforcement: `tests/test_investigation_quality_gate.py` locks the
release gate — every supported input type must yield every SSOT
section listed in the Quality Gate (Health · Understanding · Plan ·
Results · Story · Trajectory · Threat Analysis · Evidence · Report).

---

## R12 · One Investigation, One Fetch (2026-03-01)

- **The frontend must retrieve a single Canonical Investigation
  Object per investigation.**  UI components must never orchestrate
  multiple backend investigation calls to assemble state.
- All investigation data is derived from the single SSOT.
- Benefits: lower latency, fewer race conditions, easier caching,
  simpler debugging, deterministic rendering.
- Enforcement: `POST /api/die/investigation` is the SSOT contract.
  Existing endpoints (`/die/understand`, `/die/analyze`,
  `/die/narrate`, `/die/investigation-results`) remain for
  regression tests + backend consumers, but the Workspace SPA must
  route through the single-fetch contract.

---

## R13 · Engine Independence (2026-03-01)

- **Every investigation engine contributes to the Canonical
  Investigation Object but may not directly consume another
  engine's UI output.**  Engine-to-engine communication occurs only
  through the Canonical Investigation Object.
- Correct: `MITRE Engine → SSOT ← Trajectory`.
- Forbidden: `Trajectory reads Attack Story JSON`.
- This eliminates ordering dependencies between engines and makes
  every engine independently unit-testable.

---

## R14 · Engine Responsibility Contract (2026-03-01)

Frozen alongside `/app/memory/IDA_ARCHITECTURE.md`.

> **IUE decides.  IDA acquires.  DIE decodes.  Domain engines
> analyze.  The SSOT unifies.  IVE visualizes.**

- The **IUE** classifies inputs and produces the investigation
  plan.  It NEVER fetches, OCRs, or parses documents.
- **IDA** (Intelligent Document Analyzer) is the ONLY engine
  allowed to *acquire* external content — URLs, PDFs, DOCX,
  images, screenshots, emails, threat-report web pages, archive
  contents, and any other human-readable artifact.  OCR is one
  module inside IDA — never confused with IDA itself.
- **DIE** decodes encoded payloads (base64 · UTF-16LE · hex ·
  XOR · gzip · multi-layer).  It never fetches web content.
- **Domain engines** (CIA · BIA · PIA · IOCE · MITE · LBE · DKP ·
  OSINT · Story · Evidence · Report) each own a single analytical
  responsibility and consume the SSOT.
- **IVE** renders visualisations from the SSOT only.

New investigation artifact types (URLs, PDFs, DOCX, images,
screenshots, archives, mixed pastes) MUST be added by extending
the IUE Input Classifier AND routing to IDA — never by adding
fetch / OCR / parse logic to the IUE or any consumer.

---

## R15 · Objective Taxonomy over Objective Strings (2026-03-01)

The Attack Intent Engine emits both an ``objective`` (specific
rule name) and a ``categories`` array (canonical taxonomy).
Regression tests and downstream consumers MUST validate on
**categories + observed phases + evidence + confidence** — never
on hard-coded objective strings.  The objective taxonomy is a
living surface; new objectives are additive and must not break
existing consumers.

Correct:
```python
assert "Execution" in intent["categories"]
assert intent["observed_phases"]
assert 0.0 <= intent["confidence"] <= 1.0
```

Forbidden:
```python
assert intent["objective"] in ("A", "B", "C")   # brittle
```

Canonical categories: `Initial Access`, `Execution`,
`Deployment`, `Persistence`, `Privilege Escalation`,
`Defense Evasion`, `Credential Access`, `Discovery`,
`Lateral Movement`, `Collection`, `Command and Control`,
`Exfiltration`, `Impact`, `Impair Defenses`.

---

## Schema Versioning (2026-03-01)

The Canonical Investigation Object carries `metadata.version` and
`metadata.schema` so new consumers can validate compatibility and
future engines (IDA, IVE, PCAP, Mach-O, Binary, Archive) can extend
the object without breaking existing readers.

Current: `metadata.version = "1.0"`, `metadata.schema = "investigation-v1"`.

Extensions become `investigation-v2`, `-v3` … only when a breaking
shape change lands; additive fields keep the version stable.

---

## Workspace Freeze v1 (2026-03-01)

The following surfaces are declared **stable and frozen**.  No
redesigns, no relocations, no removal of analyst functionality.

    ✓ Input Health
    ✓ Input Understanding
    ✓ Investigation Plan
    ✓ Investigation Results
    ✓ Attack Story (inline)
    ✓ Evidence Trajectory + Node Inspector
    ✓ Analyst Narrative
    ✓ Threat Analysis sidebar (GRAPH · MITRE · LOLBAS · RULES ·
      IOCs · TI-HITS · OSINT · AI · FLOW · CHAIN)
    ✓ Report
    ✓ Global Investigation Filter
    ✓ IUE-first Architecture

New capabilities plug in *underneath*.  The analyst workflow is
locked; the platform grows below the surface.

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
