# Evaluation Rubric (permanent — user directive · 2026-02-04)

Any time a payload is executed in the workspace to evaluate output,
the following FOUR views MUST be inspected — NOT just the top-level
DECODE / AUTO INVESTIGATE output text:

  1. **Attack Story**     — narrative reconstruction of what the
                             adversary did, in analyst prose
  2. **Incident Graph**   — node/edge visualisation of the investigation
                             (RAW INPUT → DECODE OPS → IOCs → MITRE)
  3. **Attack Chain**     — kill-chain / MITRE tactic sequence
  4. **NIST Report**      — the auto-generated IR handoff document
                             (NIST 800-61 shape) with executive summary,
                             indicators, and containment recommendations

These four surfaces are the analyst-visible product.  A payload is only
"fully decoded" when each of the four renders the recovered evidence
(IPs, User-Agents, C2 URLs, MITRE techniques, kill-chain stages) that
came out of the deterministic pipeline.

## Where each surface lives in the Workspace
- Attack Story    → main INVESTIGATION SUMMARY body once
                    AUTO INVESTIGATE completes.  Also under
                    Input → Understanding → Decoder → DIE+DKP →
                    **Attack Story** → Report chip row.
- Incident Graph  → right-hand THREAT ANALYSIS panel · GRAPH tab
                    (or the FLOW / CHAIN tabs for other lenses).
                    Also `OPEN INVESTIGATION WORKSPACE` deep link.
- Attack Chain    → THREAT ANALYSIS panel · CHAIN tab · shows the
                    ordered MITRE technique sequence.  Also under
                    "CHAIN ANALYSIS" collapsible section.
- NIST Report     → "IR HANDOFF EXPORT" row · **SOC BRIEF (.MD)** /
                    **PDF REPORT** / **JSON** / **STIX 2.1** buttons.

## When to check
- Every functional verification on the DECODE / AUTO INVESTIGATE
  button — smoke test AND regression.
- After every fix that touches decoders, IOC extractors, MITRE
  mapping, or verdict scoring.
- Before finishing any task that closes a "user-reported payload"
  regression gate.
