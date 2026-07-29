# Operational Feedback Loop

**Status:** Standing workflow (2026-02-28 onwards)
**Applies to:** Every real SOC investigation routed through NivXRay/NivXForge.
**Governs:** How real cases move from "run" to "ADR" without shortcuts.

---

## The loop

```
        ┌───────────────────────────────────────────────┐
        │                                               │
        ▼                                               │
1. RUN INVESTIGATION                                    │
   • Paste artifact into NivXForge or Workspace         │
   • Same backend → same analysis                       │
                                                        │
        ▼                                               │
2. REVIEW FINDINGS                                      │
   • Verdict · IOCs · MITRE · TI Shield · Explanation   │
   • Read the reasoning, not just the answer            │
                                                        │
        ▼                                               │
3. RECORD OUTCOME (REAL_WORLD_LOG.md)                   │
   • Correct                                            │
   • Missing Evidence                                   │
   • Incorrect Reasoning                                │
   • Incorrect Verdict                                  │
                                                        │
        ▼                                               │
4. COMPARE WITH ANALYST DECISION                        │
   • What did the human conclude?                       │
   • What was the delta with NivXRay?                   │
                                                        │
        ▼                                               │
5. IDENTIFY RECURRING GAPS                              │
   • Same gap ≥ 3 times → it's a pattern                │
   • Same gap 1-2 times → it's an observation           │
                                                        │
        ▼                                               │
6. DRAFT ADR — ONLY IF JUSTIFIED                        │
   • Recurring pattern documented across ≥ 3 cases      │
   • Otherwise: keep observing                          │
        │                                               │
        └───────────────────────────────────────────────┘
                    (back to step 1)
```

---

## Anti-patterns (things this loop is designed to prevent)

- **Building on a single case.** A one-off gap is an observation, not a mandate.
- **Skipping step 4.** If the analyst's decision isn't captured, we can't tell whether
  NivXRay was wrong or the analyst overrode a correct verdict.
- **ADR without recurrence.** An ADR is a commitment; unfounded ADRs become tech debt.
- **Reasoning-layer speculation.** Hypothesis / Correlation / Recommender engines only
  land after real cases justify them, per `REASONING_ENGINE_VISION.md` §5.

---

## What "quality" means for NivXRay going forward

Not: more tabs, more cards, more dashboards.

Instead:
- **Did the analysis miss an IOC?**  → tracked in REAL_WORLD_LOG.md
- **Was the MITRE mapping appropriate?** → tracked
- **Was the verdict useful?** → tracked
- **Did the explanation help?** → tracked

These four questions are the analyst-quality metrics. They are answered by real cases,
not by UI iteration.

---

## Case-review template (adopted 2026-02-28)

Every case logged in `REAL_WORLD_LOG.md` MUST be evaluated against these eight
categories. Consistency is what makes the log statistically useful over dozens of
cases.

| Category                | Assessment                                                    |
| ----------------------- | ------------------------------------------------------------- |
| Decode Completeness     | Pass / Partial / Fail                                         |
| IOC Completeness        | Pass / Partial / Fail                                         |
| MITRE Mapping           | Appropriate / Missing / Incorrect                             |
| Verdict                 | Useful / Too Weak / Too Strong                                |
| Explanation Quality     | Clear / Partial / Poor                                        |
| Evidence Traceability   | Every finding backed by evidence? Yes / No                    |
| Analyst Notes           | Free-form observations, only lessons that generalise          |
| Action                  | No Action / Monitor / Draft ADR *(only after ≥3 recurrences)* |

Rules:
- **No half-scores.** Use the enumerated buckets exactly. If nothing fits, prefer
  "Partial" over inventing a new bucket.
- **"Action = Draft ADR"** is only permitted when the same gap has been recorded in
  ≥3 cases with matching Missing-Evidence categories.
- **Free-form notes** should capture *generalisable* lessons only — one-off analyst
  context belongs in the ticket, not the log.

### Evidence-vs-hypothesis discipline (mandatory)

The reviewer's independent read is NOT the ground truth. It is an analyst
hypothesis. Every case review MUST explicitly separate three tiers of claim
before scoring the eight categories above:

| Tier                       | Definition                                                                | Example                                                             |
| -------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Observable evidence**    | Decoded strings, IOCs, API imports, network indicators, behaviours directly present in the artifact. | `User-Agent: Mozilla/5.0 ... BOIE9;PTBR` in decoded output; IP `149.28.81.19` extracted. |
| **Evidence-based inference** | A conclusion supported by observed evidence + well-known correspondence. | "The UA string matches Metasploit's default reverse_http stager, therefore this is *likely* Meterpreter." |
| **Analyst hypothesis**      | Attribution, campaign linkage, or family assertion NOT directly evidenced by the artifact. | "This is APT29" · "This is part of Campaign X" · "Threat actor is nation-state." |

**Scoring rule:** if NivXRay disagrees with an *analyst hypothesis* but its
reasoning is well-supported by the *observable evidence*, that is **NOT a defect**
and MUST NOT be recorded as Missing Evidence / Incorrect Reasoning / Incorrect
Verdict. It is a legitimate difference of interpretation and should be logged in
Analyst Notes only.

A defect is recorded only when NivXRay contradicts or misses *observable evidence*
or *evidence-based inference with unambiguous correspondence* — never for a
disagreement about a hypothesis.

---

## Where this document lives in the governance model

- **`PRODUCT_CHARTER.md`** defines the immutable principles (evidence, workspace
  protection, governance).
- **`REASONING_ENGINE_VISION.md`** defines the long-horizon target for analytical
  quality (Analyst Brain).
- **This document** defines the *daily operating loop* that connects the two.
