# ADR-0011 · Evidence Pile · Investigation Engine Unification (candidate)

**Status:** Not yet drafted. Highest-signal candidate from Track A close-out.

**Operator directive (2026-02-28):** Do NOT frame the next ADR as
"Verdict Unification". That framing treats a symptom. The parity sweep
proved the real issue is that **two independent investigation engines**
sit on top of one unified decode pipeline and one unified CIM
foundation. The ADR must unify the engine.

## The architectural split the parity sweep exposed

```
                     Unified so far ✅
                     ┌─────────────────────────────┐
                     │      FactSubstrate          │
                     └──────────────┬──────────────┘
                                    │
                        Split (this ADR fixes) ⚠️
                     ┌──────────────┴──────────────┐
                     ▼                              ▼
        build_verdict_card                 LLM executive_card
        (deterministic, ADR-0007          (LLM-driven, narrative-first,
         evidence-gated)                   /api/v2/auto-investigate)
                     │                              │
                     ▼                              ▼
                  same CIM shape                same CIM shape
                  DIFFERENT content             DIFFERENT content
```

## What "unified" must mean

Not just verdict labels matching. Every reasoning layer converges:

| Layer | Today | After ADR-0011 |
|---|---|---|
| Verdict | 2 engines, 0/20 parity | 1 engine, 20/20 parity |
| Evidence classification | 2 taggers, 3/20 parity | 1 tagger, 20/20 |
| AnalysisStage set | 2 pipelines, 1/20 parity | 1 pipeline, 20/20 |
| Assessments | 2 formats | 1 format |
| CIM shape | ✅ already unified | ✅ unchanged |
| Decode | ✅ already unified | ✅ unchanged |

## Target architecture

```
        Raw Input
            │
            ▼
      Normalization
            │
            ▼
       FactSubstrate  (already unified)
            │
            ▼
   Investigation Engine  (ONE engine, this ADR)
            │
            ▼
         CIM  (already unified)
            │
     ┌──────┴────────────────┐
     ▼                        ▼
/api/decode/smart      /api/v2/auto-investigate
    (serializes CIM)         (serializes CIM)
```

## Why NOT do this piecewise

- Verdict-only unification would leave evidence-types and stages
  still forked.
- Evidence-only unification would leave verdicts still forked.
- The 5 measured parity dimensions in CORPUS_V1_PARITY.md are the
  same architectural fork viewed from 5 angles. Fix it once, at the
  engine layer, and all 5 dimensions come green together.

## Refined 4-item backlog (operator ordering 2026-02-28)

1. **⭐⭐⭐⭐⭐ ADR-0011 · Investigation Engine Unification** — one engine consuming FactSubstrate; verdict + evidence + stages converge together.
2. **⭐⭐⭐⭐☆ Narrative Composer** — first user-visible payoff of the CIM foundation; safe to build once the engine is unified because the report doesn't need to disclaim two-source discrepancies.
3. **⭐⭐⭐☆☆ ADR-0010 · Navigation IA** — freeze the 8-tab reorg now that Documents is already relocated.
4. **⭐⭐⭐☆☆ Analyst Corrections Phase 2** — needs more real-world usage under the new architecture.

## Draft trigger

Operator explicit go-ahead. Do NOT auto-draft. The scope will be large;
worth a proper planning pass before execution.
