# ADR-2026-08-01 · Addendum B · Revised Pipeline + Contract #11

_Locked by operator. Supersedes Addendum A pipeline shape._

## Invariant (enforce mercilessly)

> Every module after the Investigation Graph must consume the
> Investigation Graph — not raw vendor payloads, not decoded strings,
> not intermediate parser outputs.

If any downstream module reads anything other than the Graph, it's a
design violation. Code review must reject it.

## Canonical Pipeline (LOCKED)

```
Input
 → Input Classification
 → Parser
 → Vendor Detection
 → Vendor Normalization
 → Canonical Event Model (CEM)
 → Artifact Discovery
 → Recursive Decoder
 → Evidence Extraction
 → Investigation Graph          ← every stage below this line reads
 → Evidence Validation             ONLY the Graph
 → Entity Resolution
 → Correlation
 → Timeline Builder
 → Attack Chain Builder
 → Threat Intelligence
 → Threat Family Resolution
 → Mechanism Interpretation
 → Hypothesis Engine
 → Root Cause Analysis
 → Visibility Analysis
 → Confidence Engine
 → Recommendation Engine
 → Narrative Engine
 → Customer / Analyst / Threat Hunter / Forensic Views
```

## Changes from Addendum A

- **Input Classification + Parser + Vendor Detection** now precede the
  Vendor Normalizer. Normalizers stop being overloaded with detection
  logic.
- **Artifact Discovery is SEPARATE from Recursive Decoder** and comes
  first. The decoder only processes artifacts flagged as needing decode.
- **Entity Resolution comes BEFORE Correlation**. Identities are
  unified (HOST-01 == host01.company.com == 10.1.1.15) before events
  are grouped.
- **Correlation and Timeline are SEPARATE stages**. Correlation says
  "these events belong together"; Timeline says "this happened before
  that".
- **Attack Chain Builder is a separate stage after Timeline**. Timeline
  is chronological; Attack Chain is tactical (Execution → Persistence →
  Defense Evasion → Discovery → Credential Access → Lateral Movement).
- **Hypothesis Engine comes BEFORE Root Cause Analysis**. Evidence →
  Hypothesis (FOR / AGAINST / Confidence) → Root Cause. Mirrors how
  experienced analysts reason.
- **Recommendation Engine consumes the Graph, never the report**.
- **Narrative Engine is last**. Views (Customer / Analyst / Threat
  Hunter / Forensic) are pure renderers.

## Contract #11 · Investigation Acceptance Contract

Every investigation MUST answer, from the Graph alone, before it can
be considered complete:

1. What happened?
2. How do we know? (Evidence)
3. What artifacts were observed?
4. What was decoded?
5. Who / what was affected?
6. What ATT&CK techniques apply?
7. What attack stage was reached?
8. What threat family or malware is most likely?
9. What evidence supports that conclusion?
10. What evidence contradicts it?
11. What visibility gaps remain?
12. What should the customer do next?

If any answer is unavailable, the engine MUST return
`"Cannot determine from available evidence"` — never guess. Every
answer traces to graph node ids.

## Contracts to freeze — now eleven

Addendum A's contracts 1–10 remain unchanged. **Contract #11
(Investigation Acceptance Contract)** is added and must be signed off
alongside the other ten before Phase 1 code begins.

## Phase 1 CODE sequence (unchanged, still after every contract signed)

1. Implement CEMv1.
2. Cisco Secure Endpoint normalizer → CEMv1.
3. Sysmon normalizer → CEMv1.
4. Investigation Graph builder.
5. Evidence Validation stage.
6. End-to-end demo: raw payload → CEM → Graph → Validation → printable
   investigation state, plus an explicit Contract #11 answer-check on
   the demo output.

## Blocking asks for next session (unchanged)

1. Four gold-standard analyst investigations pasted into
   `/app/memory/P0_MISSION.md`.
2. Sign-off on 11 contracts.
