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

## Case-review template (adopted 2026-02-28 · frozen after §9.2 addition until ≥20 cases evaluated)

Every case logged in `REAL_WORLD_LOG.md` MUST be evaluated against these nine
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
| **Evidence Sufficiency**| **Sufficient / Partially Sufficient / Insufficient** (see §9.2 below) |
| Analyst Notes           | Free-form observations, only lessons that generalise          |
| Action                  | No Action / Monitor / Draft ADR *(only after ≥3 recurrences)* |

Rules:
- **No half-scores.** Use the enumerated buckets exactly. If nothing fits, prefer
  "Partial" over inventing a new bucket.
- **"Action = Draft ADR"** is only permitted when the same gap has been recorded in
  ≥3 cases with matching Missing-Evidence categories.
- **Free-form notes** should capture *generalisable* lessons only — one-off analyst
  context belongs in the ticket, not the log.
- **Template is frozen** until at least 20 real cases have been evaluated with the
  current nine categories. Do not add / remove / reword categories before that
  threshold — consistency across the corpus is more valuable than local
  refinements.

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

### §9.2 Evidence Sufficiency (mandatory ninth category)

For every case, before scoring the other eight categories, answer:

> "Was there enough observable evidence for NivXRay to reasonably reach the
> analyst's conclusion?"

Values:

| Value                    | Meaning                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- |
| **Sufficient**           | The artifact contained enough observable evidence for a well-supported verdict AND the specific inferences the analyst made. |
| **Partially Sufficient** | Enough evidence for a *class* of verdict (e.g., "malicious HTTP stager") but not for the *specific* inference the analyst made (e.g., "Meterpreter reverse_http · APT29"). |
| **Insufficient**         | The artifact was too fragmentary, corrupted, or lacking observable indicators to reach any confident conclusion. |

**Scoring rule:** if Evidence Sufficiency = *Partially Sufficient* or *Insufficient*,
NivXRay CANNOT be scored as "Too Weak" for verdict, "Missing" for MITRE, or "Partial"
for IOC completeness on the basis of leaps beyond what the evidence supported. It
would be unfair to penalise the platform for not making inferences the evidence did
not warrant.

Worked example (Case 0002 pattern):

| Layer                       | Content                                                                                | Fair to score against NivXRay?                     |
| --------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Observable evidence         | IP `149.28.81.19`, IE9 UA `BOIE9;PTBR`, `hnet`/`hwini` shellcode strings               | ✅ Yes — if any of these missing → defect.         |
| Evidence-based inference    | "Likely Meterpreter reverse_http stager"                                               | ⚠️ Partially — score only if UA→family correspondence is unambiguous. |
| Analyst hypothesis          | "APT29 infrastructure" · "part of Campaign X"                                          | ❌ No — never a defect if NivXRay declines this attribution. |

---

## Where this document lives in the governance model

- **`PRODUCT_CHARTER.md`** defines the immutable principles (evidence, workspace
  protection, governance).
- **`REASONING_ENGINE_VISION.md`** defines the long-horizon target for analytical
  quality (Analyst Brain).
- **This document** defines the *daily operating loop* that connects the two.

---

## Implementation-phase rules (adopted 2026-02-28 · applies to every accepted ADR)

Once an ADR is Accepted and moves to implementation:

### Rule 1 · Every ADR MUST carry an Exit Criteria section
No ADR is "implemented" without an explicit success gate. The gate MUST include:
pinned regression cases with expected outcomes; non-regression pins; full
Workspace regression suite requirement; API-contract stability; and — where
applicable — a performance-regression ceiling. Partial success is not success.

### Rule 2 · Sequential implementation when multiple ADRs are queued
If two or more ADRs are simultaneously Accepted:
- Land them **one at a time**, in the order specified by their §7 sequencing.
- Between ADRs, run each ADR's pinned regression suite AND the full Workspace
  suite AND the parity contract test.
- Do **NOT** overlap ADR implementation with Phase-2 evidence-collection
  activities (e.g., sampling new corpora). Sequential attribution makes every
  behavioural change traceable to the ADR that caused it.

### Rule 3 · Parity contract remains a merge gate
Every implementation MUST leave `nivxforge/tests/test_parity_endpoints.py`
green. The invariant is:

```
                    Shared FastAPI backend
                            │
             ┌──────────────┴──────────────┐
             │                             │
        Workspace                      NivXForge
             │                             │
             └────── Same analytical ──────┘
                       results
```

The goal is not identical UI — it is identical analytical results from the
shared backend. If an ADR would break this invariant, it must be re-scoped
before implementation.

### Rule 4 · Post-implementation verification
After both/all ADRs in a batch are landed:
1. Run each ADR's pinned regression.
2. Run the full Workspace regression suite.
3. Run the NivXForge suite.
4. Run the parity contract test.
5. Re-evaluate the cases the ADR was drafted to fix — confirm they now behave
   as the ADR predicted.
6. Only after (1–5) are all green: proceed to the next Phase (e.g. new corpus
   sampling, Analyst Scorecard, etc.).

### Rule 5 · Governance-review-halt (immutable)

If an ADR cannot satisfy **all** Exit Criteria without introducing regressions
or violating the parity contract, implementation **MUST STOP** and return to
governance review.

- Exit Criteria are **not** to be weakened during implementation.
- Regression expectations are **not** to be adjusted to accommodate difficulty.
- Non-regression pins are **not** to be relaxed to admit a change.
- The pinned corpus cases are **not** to be re-scored to make a change pass.

Any of the above would violate the principle that **governance defines
success — not implementation convenience**. The correct response to an
unsatisfiable Exit Criterion is to draft an ADR amendment (with new evidence)
or a superseding ADR, not to weaken the gate.

This rule applies to every ADR now Accepted and every ADR drafted in future.

### Rule 6 · No incidental cleanup during ADR implementation (adopted 2026-02-28)

When implementing an ADR, resist the temptation to "clean up" unrelated code
noticed along the way.

- If another presentation issue, code smell, or minor bug is observed during
  ADR-N implementation, **log it in `REAL_WORLD_LOG.md` under Monitor** and
  move on unless it blocks validation of ADR-N.
- Do NOT bundle unrelated fixes into an ADR's implementation PR. Every
  behavioural change should be attributable to the ADR that caused it —
  incidental refactoring breaks that attribution and makes regressions
  harder to diagnose.
- Exception: a defect that **prevents ADR-N's Exit Criteria from being
  evaluated** (e.g., the AUTO INVESTIGATE rendering regression that
  blocked Track A validation) is treated as a Phase-1 hotfix under the
  originating ADR's scope, not as new work.

The Case 0002 rendering fix (2026-02-28) established the precedent for this
rule: a scoped Phase-1 repair, no adapter introduced, no architectural
redesign, DECODE mode untouched.
