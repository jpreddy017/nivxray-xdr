# NivXRay · Investigation + Incident Response Report Contract

## FROZEN CONTRACT — 2026-03-01 · Rule R19

> The Investigation Report evolves into a **NIST SP 800-61 r2-aligned
> Incident Response Report** — WITHOUT introducing a new reporting
> engine.  The report remains a **pure SSOT projection**.  Every new
> section reads from SSOT.  Missing data → enrich SSOT upstream.

## Audiences (must satisfy all four)
- SOC Analyst → detailed evidence + investigation flow
- IR / DFIR → containment, eradication, recovery, evidence chain
- SOC Manager / IR Lead → scope, confidence, impact, timeline, gaps
- Executive / CISO → decision summary, severity, business impact

## Report Sections (existing kept + NIST additions)
| # | Section | Source | Status |
|---|---------|--------|--------|
| 1 | Report Classification header (Investigation · IR · Threat Intel · Malware · Threat Hunt) | `SSOT.report.classification` | 🚧 new |
| 2 | Incident Overview (Detection · Investigation · Type · Status · Severity · Decision) | `SSOT.incident{}` | 🚧 new |
| 3 | Detection Context (source · alert · rule · sensor · confidence) | `SSOT.detection{}` | 🚧 new |
| 4 | Executive Summary | `SSOT.narrative.executive_summary` | ✅ existing |
| 5 | Overall Assessment | `SSOT.narrative.overall_assessment` | ✅ existing |
| 6 | Incident Scope (hosts · users · accounts · processes · files · registry · services · scheduled tasks · domains · IPs · URLs · hashes) | `SSOT.scope{}` | 🚧 new |
| 7 | Timeline (evidence-backed chronological) — mark **Relative Timeline / Execution Order Only** when timestamps absent | `SSOT.timeline[]` | 🚧 new |
| 8 | Behaviour Summary | `SSOT.narrative.behavior_summary` | ✅ existing |
| 9 | Attack Story | `SSOT.narrative.attack_progression` | ✅ existing |
| 10 | Evidence Matrix (Finding × Supporting Evidence × Source × Confidence) | `SSOT.evidence_matrix[]` | 🚧 new |
| 11 | Evidence Provenance (IDA-7) | `SSOT.explanations[].evidence` + `commands[].source` | 🚧 wire when IDA-7 lands |
| 12 | Business Impact Assessment (per tactic: Observed / Not Observed / Unknown) | `SSOT.impact{}` | 🚧 new |
| 13 | Technical Findings | `SSOT.preprocessor` + `SSOT.behaviour` | ✅ existing |
| 14 | MITRE Coverage | `SSOT.mitre[]` | ✅ existing |
| 15 | Evidence Summary | `SSOT.narrative.evidence_summary` | ✅ existing |
| 16 | Investigation Gaps (missing parent proc · EDR · user context · timestamps · network · memory) | `SSOT.gaps[]` | 🚧 new |
| 17 | Containment Actions (Recommended · Already Performed) | `SSOT.containment[]` | 🚧 new |
| 18 | Eradication Actions | `SSOT.eradication[]` | 🚧 new |
| 19 | Recovery Actions | `SSOT.recovery[]` | 🚧 new |
| 20 | Lessons Learned (Control improvements · Detection opportunities · Playbook updates · Sigma / YARA / SIEM / EDR / Training) | `SSOT.lessons_learned{}` | 🚧 new |
| 21 | Executive Decision Summary (Isolate? · Reset creds? · Notify customers? · Escalate? · Business Impact · Status) | `SSOT.executive_decision{}` | 🚧 new |
| 22 | Confidence Breakdown per investigation domain (Discovery · Execution · Persistence · PrivEsc · Credential Access · Business Impact) | `SSOT.confidence.by_domain{}` | 🚧 new |
| 23 | Recommendations | `SSOT.narrative.recommended_actions` | ✅ existing |
| 24 | Confidence Summary | `SSOT.confidence` | ✅ existing |
| 25 | NIST Lifecycle Mapping Appendix (Preparation / Detection / Containment / Eradication / Recovery / Post-Incident → Completed · Partial · Not Available) | `SSOT.nist_mapping{}` | 🚧 new |
| 26 | **Evidence Completeness** (Commands · MITRE · Timeline · Timestamps · Parent Process · Network Telemetry · EDR Metadata · Memory → Complete / Partial / Missing / Not Available + overall completeness %) | `SSOT.evidence_completeness{}` | 🚧 new · **mandatory** |

## Evidence Completeness Rules (locked · addendum 2026-03-01)

`SSOT.evidence_completeness` is **different from confidence**.  It
tells the analyst *how complete the investigation is*, not how
confident the engine is in what it found.  It exists because NIST
sections like containment recommendations, precise impact, and
recovery are only as good as the evidence available.

Every completeness dimension takes one of four states:

    ✔ Complete    — full evidence present
    ● Relative    — data present but partial (e.g. execution order
                     without wall-clock timestamps)
    ✘ Missing     — dimension expected but not found in the input
    – Not Available  — dimension is not applicable to this input class

The overall percentage is `Complete + 0.5·Relative` over the total
number of applicable dimensions.  Dimensions marked "Not Available"
are excluded from the denominator.

The Report Renderer projects this block directly.  It never
computes completeness — the SSOT emitter is the single owner.

## Evidence Rules (locked)
Every report statement satisfies one of:
1. Supported by deterministic evidence
2. Supported by extracted artifacts
3. Supported by correlated telemetry
4. Explicitly marked as **Analyst Inference**

**Never mix deterministic evidence with assumptions.**

## No Fabrication
- Never invent timestamps.  If absent → label **"Relative Timeline · Execution Order Only"**.
- Never assign severity without deterministic evidence or explicit analyst input.
- Every "Requires Validation" flag must remain visible.

## Report Classification
Auto-select from `SSOT.understanding.input_type` + `SSOT.intent.categories`:
- Command / script / mixed → **Investigation Report**
- Vendor prose / URL / PDF → **Threat Intelligence Report**
- Encoded payload / dropper → **Malware Analysis Report**
- Chain with confirmed impact → **Incident Response Report**
- Hunting query result → **Threat Hunting Report**

## Implementation Constraints (locked)
- No new reporting engine.  Report = pure SSOT projection (Rule R16).
- Missing data → enrich SSOT upstream — never compute inside the report.
- New sections consume SSOT directly.  No duplicate analysis logic.
- Every new SSOT field ships with a Quality-Gate assertion (Rule R11 + R18).
