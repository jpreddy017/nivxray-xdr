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

## Where this document lives in the governance model

- **`PRODUCT_CHARTER.md`** defines the immutable principles (evidence, workspace
  protection, governance).
- **`REASONING_ENGINE_VISION.md`** defines the long-horizon target for analytical
  quality (Analyst Brain).
- **This document** defines the *daily operating loop* that connects the two.
