# NivXForge Investigation Report · North Star Reference Artifact

**Source:** User-supplied exemplar, 2026-02-28.
**Status:** REFERENCE ONLY — not an execution trigger.
**Governance routing:** Track B / future ADR-0009+ (Canonical Investigation
View Model + Investigation Narrative Composer). Do NOT act on this artifact
during Track A (ADR-0008 → ADR-0007) execution.

## Why this file exists

The user shared a hand-authored "aspirational output" showing the *shape*
of report NivXForge should synthesize from a real SOC case (MSFT Defender
detection → Cisco XDR incident → PhantomStealer identification). It is
NOT a spec, NOT a test fixture, and NOT a corpus entry. It is a reference
of what "good" looks like from an analyst-consumer perspective.

## Structural features to preserve for future ADRs

The exemplar organizes the investigation into six layers:

1. **Executive Verdict** — verdict, confidence, malware family, category,
   business impact, evidence quality.
2. **Executive Summary** — one-paragraph narrative synthesis with clear
   confirmed/inferred/unknown distinctions.
3. **Investigation Story (stages)** — detection → identification →
   execution context → behaviour → objectives.
4. **Threat Intelligence Correlation** — cross-source consensus with
   named providers and their independent confirmations.
5. **Host Analysis + Risk Assessment** — asset context with plausibility
   framing (not confirmation).
6. **Detection Coverage + Sigma/IDS matches** — with an explicit
   disclaimer that Sigma matches indicate *possibilities*, not confirmed
   events on the endpoint.
7. **Evidence Confidence Matrix** — every finding tagged
   High / Medium-High / Medium / Possible / Unknown with basis.
8. **Investigation Gaps** — explicit list of what the data does NOT
   contain (the "unknown-unknowns → known-unknowns" transformation).
9. **Analyst Recommendations** — Immediate + Threat Hunting.
10. **Overall Assessment** — meta-narrative about *what kind of output*
    NivXForge should aim for.

## Key epistemic contract implied by the exemplar

> "Not just parsing the alert, but synthesizing it into a structured
> investigation. The key improvement over today's tools is not that it
> lists more IOCs, but that it **organizes the information** into:
> what is confirmed, what is strongly inferred, what remains unknown."

This is the North Star epistemic contract. It should inform:

- **ADR-0007** (Verdict-Evidence Gating) — the confidence-vs-evidence
  distinction shown in the Evidence Confidence Matrix directly validates
  the ADR-0007 premise: verdict severity must be backed by *specific*
  evidence, not just structural signals.
- **ADR-0009** (Canonical Investigation View Model) — the exemplar's
  organization is precisely the canonical view model shape.
- A future **ADR-0010** (Investigation Narrative Composer) — synthesis
  layer that composes the exemplar's prose from the canonical model.

## Why we are NOT acting on it now

- Governance is locked. Track A (ADR-0008 → ADR-0007) is the only
  authorized execution track.
- The exemplar is aspirational; it references concrete cases outside
  Corpus v1 (PhantomStealer, glmsa-nsp-gw02) that have not been
  ingested and hashed into the pinned regression benchmark.
- Building narrative-composition capability before the underlying
  evidence gates (ADR-0007, ADR-0008) are validated would violate the
  Operational Loop rule "capability implies benchmark".

## What to do with this artifact after Track A closes

1. Hash the exemplar's PhantomStealer case (SHA256
   `993030fd181cc67dcaa0948f536539aff5ae10bce1aff5265018aa335365e802`)
   into Corpus v2 as a "narrative composition benchmark" — the input
   is the alert data, the expected output is the report shape shown here.
2. Fold the ten structural features into ADR-0009 as the concrete
   Canonical Investigation View Model.
3. Draft ADR-0010 for the narrative composer, with the Evidence
   Confidence Matrix as the mandatory output section.
