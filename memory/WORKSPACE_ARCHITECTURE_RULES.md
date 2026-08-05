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

---

**These rules are locked.  Any agent that removes a listed
capability is regressing the Workspace.  Enhance, extend, add —
never remove.**
