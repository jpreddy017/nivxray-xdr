# X-Lab Feedback Surface Audit · 2026-02

**Method:** grep every UI element that stores/sends analyst feedback, then trace whether *anything* consumes it at composition time on subsequent investigations. Verified by static analysis on the live codebase.

## Audit matrix

| # | Surface | UI location | Backend endpoint | Storage | Read at composition on future runs? | Actually influences future output? | Status |
|---|---|---|---|---|---|---|---|
| 1 | **Manual Summary** override | `LabV2.jsx` → Executive/Story block | `POST /api/corrections/summary-override` | `analyst_corrections` + `summary_overrides` collections | Same-CIO reload only. **No cross-case retrieval.** | ❌ | **Store-only** |
| 2 | **Verdict marker · Correct** | `LabV2.jsx:967` — `data-testid="verdict-mark-correct"` | *(no handler)* | *(nothing)* | ❌ | ❌ | **COSMETIC — the button is not even wired to onClick** |
| 3 | **Verdict marker · Partial** | `LabV2.jsx:968` | *(no handler)* | *(nothing)* | ❌ | ❌ | **COSMETIC** |
| 4 | **Verdict marker · Wrong** | `LabV2.jsx:969` | *(no handler)* | *(nothing)* | ❌ | ❌ | **COSMETIC** |
| 5 | **IOC / Decoder / MITRE / Threat-model corrections** | Admin console + Correction preview | `POST /api/corrections` → `submit_correction()` in `analyst_corrections.py` with per-surface routing | `analyst_corrections` collection | ✅ Consumed by `routers/threat_model.py` (imports `analyst_corrections as corr` and calls `list_corrections`) at composition time for threat_model / decode / chain / ioc / lolbas / family / risk / detection / mitigation surfaces | ✅ **Wired for the surfaces threat_model.py routes** | **Integrated** (limited to threat-model surfaces) |
| 6 | **`/api/learning/feedback` 👍👎** | Chat / assistant reply thumbs | `POST /api/learning/feedback` → `record_vote()` → `learning_events` collection | `learning_events` collection | Read by `routers/finetune.py` for **offline fine-tune export only** — never consumed at inference | ❌ At runtime | **Store-only** (feeds an offline fine-tune pipeline that isn't currently scheduled) |
| 7 | **`/api/learning/correction`** | Reasoning-chain correction | `POST /api/learning/correction` → `reasoning_learning.record_correction()` | `learning_events` collection | Same as #6 — offline fine-tune only, no runtime lookup | ❌ At runtime | **Store-only** |
| 8 | **Corrections approve/reject/rollback** | Admin console | `POST /api/corrections/{id}/approve\|reject\|rollback` | Updates `analyst_corrections.status` | ✅ `list_corrections` filters `status != superseded` at read time | ✅ Only for surfaces already wired via #5 | **Integrated** |

## Reality summary

- **8 feedback surfaces exist. Only ONE (the shared threat_model/IOC/decoder corrections corpus, #5) actually closes the loop at composition time.**
- **7 out of 8 are cosmetic or store-only.** They collect data. Nothing on the next investigation reads them.
- **The Verdict Correct/Partial/Wrong buttons don't even have an onClick handler.** They render as clickable but do literally nothing when pressed. This is worse than "store-only" — it's a fake button.
- **The Manual Summary block's "trains the learner" tagline is misleading.** It IS filed to the learner corpus (`analyst_corrections` with `surface="summary"`), but no composer ever reads `surface="summary"` records. The learner corpus for summary sits idle.

## What actually works

- Threat-model / decoder / IOC / MITRE corrections DO influence future analysis, because `routers/threat_model.py` explicitly imports `analyst_corrections as corr` and calls `list_corrections()` during composition. Analysts marking these WILL see effects on subsequent similar cases.
- Corrections approval workflow is real — approved corrections propagate; rejected/superseded ones don't.

## What is misleading

- **"Trains the learner"** on the Manual Summary block — the corpus grows but no learner consumes it at inference.
- **Correct / Partial / Wrong** buttons — no handler.
- **`/api/learning/feedback`** and **`/api/learning/correction`** — collected for offline fine-tune, never at runtime, and no scheduled fine-tune job is running.

## Recommended next steps

1. **Immediate honesty fix (5 min)** — either wire onClick handlers to `verdict-mark-*` or hide them.
2. **Correct the Manual Summary tagline** to "Overrides this investigation and stores your correction for future learning" until Phase 2 lands.
3. **Phase 2 · Learning Engine** — single reusable service at `backend/nivxforge/learning/engine.py` that all composers query with a CIO fingerprint. Extract structured knowledge (terminology / structure / ordering) not just free text.
4. **Phase 3 · Wire every surface** to that engine.
5. **Phase 4 · Learning Dashboard** so analysts SEE what influenced each output.
