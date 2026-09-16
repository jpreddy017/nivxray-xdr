# NivXRay XDR · P0-3 · CANONICAL DETECTION / VERDICT REPRESENTATION · DESIGN DECISION

> **Mode:** DESIGN DECISION ONLY. **No implementation performed.** Owner instruction (2026-09-05): *"DO NOT IMPLEMENT THE verdict_stage2/verdict_card fix yet. Produce a short design decision first identifying the canonical detection/verdict representation, writer, reader, and migration/compatibility implications."*
> **Branch:** `feature/rc2-alignment`. **Date:** 2026-09-05.
> **Rule:** NO EVIDENCE → NO CLAIM.

---

## 1 · The problem is larger than the one endpoint I first reported

My P0-1 artifact reported this as *"`/api/edr/detections` is structurally always empty"*. **That understated it.** Live verification of `GET /api/incidents?limit=3`:

```json
{"id":"inc_r382_a7b6e5590445","priority":{"code":"P2"},"severity":"suspicious",
 "verdict":{"stage2_label":null,"stage2_confidence":null,"risk_score":null},
 "evidence_count":0,"techniques_top":["T1059.001","T1218.011"],"confidence":null}
```

**Every incident in the queue returns `evidence_count: 0`, `stage2_label: null`, `stage2_confidence: null`, `risk_score: null`, `confidence: null`** — because all five are derived from `verdict_stage2`, which exists on **0 of 484** documents.

`techniques_top` is populated only because `incidents.py:130-134` unions `verdict_stage2.evidence[].technique_id` **with** `doc.mitre[]` and `doc.techniques[]`. That fallback is why MITRE survives and verdict/evidence do not.

## 2 · The two representations (evidence)

| | `verdict_card` | `verdict_stage2` |
|---|---|---|
| Declared role | *"the sole verdict object"* — `verdict_projection.py:3` | *"ADDITIVE only. **Never mutate the v3.x verdict/verdict_card contract**"* — `services/verdict_stage2/model.py:18`, `engine.py:7` |
| Shape | `{verdict, confidence, reason, engine}` (+ `risk_score`/`risk` in the v3.x lineage, per `verdict_stage2/inputs.py:92-95`) | `{label, confidence, confidence_bucket, risk_score, engine, evidence[]}` where `evidence[]` rows carry `technique_id` |
| Written by | **the canonical XDR pipeline** — `detection_content/xdr_incident.py:92` (comment: *"Additive verdict record (compatible with verdict_stage2 shape)"*) | **only** `routers/verdict_stage2.py:116`, `:183` |
| Live coverage | 198 pipeline incidents + analysis cases | **0 of 484 documents** |
| Engine | `nivxray::xdr::veee` (deterministic, `xdr_veee.py:11-18`) | `services.verdict_stage2.engine` (`engine.py:131`) |

**Both are legitimate. Neither is dead code. They were written by different lineages and never reconciled.**

## 3 · Reader inventory — who breaks today

### 3.1 · Readers WITH a `verdict_card` fallback (correct today)

| Reader | Evidence |
|---|---|
`routers/incidents.py` severity/priority | `:111-113` reads both, then `_derive_priority(stage2, vcard)`; module docstring `:14-15`: *"derived from `verdict_stage2` first, falling back to `verdict_card` when Stage-2 has not run"* |
`routers/incidents.py` MITRE | `:130-134` unions stage2 evidence **+** `doc.mitre[]` **+** `doc.techniques[]` |
`services/attack_graph/service.py` verdict | `:138` `verdict_card.verdict`, `:340`, `:352-353` |

### 3.2 · Readers with NO fallback — pipeline incidents are invisible to these

| Reader | Site | What is lost |
|---|---|---|
`routers/incidents.py` evidence + verdict columns | `:128-129` `evidence = stage2.get("evidence")`; `:317` `"verdict_stage2": stage2 or None` | **`evidence_count` is always 0; verdict columns always null — for every incident in the queue** |
`routers/incidents.py` query filters | `:733` `verdict_stage2.label`, `:736` `.confidence_bucket`, `:740` `.engine`, `:749` `.evidence.technique_id` | **Filtering the queue by verdict, confidence, detection source or technique matches nothing** |
`routers/edr.py` | `:66`, `:90`, `:185`, `:212`, `:221`, `:343-344`, `:431` | `/api/edr/detections`, `/api/edr/endpoints` verdict + risk |
`routers/incident_summary.py` | `:27`, `:48`, `:65`, `:137`, `:149` | incident summary verdict + evidence rows |
`routers/xdr_mss.py` | `:87`, `:125`, `:132`, `:336`, `:355` | MSS detection-overview aggregation (`$verdict_stage2.engine`, `$map` over `$verdict_stage2.evidence`) |
`routers/mitre_catalogue.py` | `:87`, `:112` | stage2-sourced technique coverage (partially mitigated by the `mitre[]` union) |
`routers/xdr_scenarios.py` | `:189`, `:207` | scenario matching over evidence rows |
`routers/narration.py` | `:142`, `:157` | narration evidence |
`services/iue/service.py` | `:142`, `:669`, `:837` | IUE stage2 input + verdict engine attribution |
`services/attack_graph/service.py` | `:139` `verdict_stage2.risk_score` | graph node risk score |

**11 non-test modules read `verdict_stage2`. 3 have a fallback. 8 do not.**

## 4 · Design decision

### 4.1 · The canonical representation is `verdict_stage2`

Rationale, evidence-led:

1. **It is the richer contract.** It carries `evidence[]` with `technique_id`, plus `confidence_bucket` and `risk_score`. `verdict_card` cannot express evidence rows at all, so 8 readers cannot be served by it without inventing data — which the honesty contract forbids.
2. **It is what the platform already reads.** 11 modules read it, including a Mongo aggregation pipeline (`xdr_mss.py:336,355`) that cannot be trivially re-pointed.
3. **The pipeline already declares the intent.** `xdr_incident.py:91` says the verdict record it writes is *"compatible with `verdict_stage2` shape"*. The writer author already anticipated this convergence.
4. **The reverse direction is blocked by an explicit contract.** `verdict_stage2/model.py:18` states *"Never mutate the v3.x verdict/verdict_card contract"*. Promoting `verdict_card` to canonical would require breaking a written invariant; promoting `verdict_stage2` breaks none.

### 4.2 · The canonical WRITER is the canonical pipeline

`detection_content/xdr_incident.py::materialise_incident` must write **both**: keep `verdict_card` (the v3.x contract is protected, and 3 readers rely on it) **and** add a `verdict_stage2` projection derived from the same VEEE output.

**This is a projection, not a second engine.** VEEE remains the sole verdict authority (`xdr_veee.py:11-18`). The mapping is total and deterministic:

| `verdict_stage2` field | Source |
|---|---|
`label` | `veee.label` (`MALICIOUS`/`SUSPICIOUS`/`LIKELY_BENIGN`/`INCONCLUSIVE`) |
`risk_score` | `veee.score` (0-100) |
`confidence` | `veee.score` |
`confidence_bucket` | deterministic band over `veee.score` — must reuse the existing bucket function, not a new one |
`engine` | `veee.engine_id` (`nivxray::xdr::veee`) |
`evidence[]` | one row per real contributor already present in `xdr_pipeline`: the detection rule (`detection.rule_id`), each ICE match (`ice.matches[].match_id`), and IUE-resolved techniques via `xdr_framework_mapping`. **No row without a source.** If there are no contributors, `evidence: []` — never a placeholder |

**Explicitly rejected alternative:** re-pointing `routers/edr.py` (and the other 7 readers) at `verdict_card`. It would require 8 module changes, cannot supply `evidence[]` at all, and would create exactly the second compatibility layer the owner warned against.

### 4.3 · What must NOT change

| Invariant | Why |
|---|---|
`verdict_card` keeps being written, unchanged | `verdict_projection.py:3` calls it the sole verdict object; `verdict_stage2/model.py:18` forbids mutating it; 3 readers depend on it |
`routers/verdict_stage2.py` remains a valid writer | Stage-2 compute-on-demand for analysis cases must keep working |
VEEE stays the only verdict engine | No second scoring path; the projection is arithmetic-free re-shaping |
The incident gate stays as-is | `label ∈ {MALICIOUS,SUSPICIOUS}` **and** `score ≥ 55` (`xdr_incident.py:27`) |
No fabricated `evidence[]` rows | Empty means empty |

## 5 · Migration / compatibility implications

| # | Implication | Assessment |
|---|---|---|
| M-1 | **New incidents only.** The projection applies to incidents created after the change | LOW risk |
| M-2 | **198 existing pipeline incidents stay empty** unless backfilled. Their `xdr_pipeline` envelope retains `veee{}`, `detection_rule_id` and `ice_matches[]`, so a **deterministic backfill is possible from data already on the document** — no re-run of any engine | MEDIUM · needs a separate authorisation and its own before/after evidence, same pattern as the `doc_type` backfill |
| M-3 | **285 analysis cases are out of scope.** They are served by `routers/verdict_stage2.py` on demand. Do not touch | NONE |
| M-4 | **Queue filters start matching.** `?verdict=`, `?confidence=`, `?detection_source=`, `?technique=` currently return nothing and will begin returning results. This is a **visible behaviour change** and must be announced, not shipped silently | MEDIUM |
| M-5 | **MSS aggregation begins producing non-zero detection-overview rows** (`xdr_mss.py:336,355`). Dashboard numbers will move **upward from zero**. Every tile is `count_source: "live"`, so the new numbers are honest — but the movement must be expected | MEDIUM |
| M-6 | **Three test provenance strings must keep passing:** `tests/canonical/incidents/test_incident_summary.py:46,74`, `tests/canonical/edr/test_edr_projections.py:71`. They assert the literal provenance `workspace_cases.verdict_stage2.evidence[]`. Writing the projection **satisfies** them rather than breaking them | LOW — favourable |
| M-7 | **`evidence_count` becomes meaningful**, changing the incident-queue UI from a uniform 0 to real counts | LOW |
| M-8 | **No schema migration, no re-keying, no store move.** One additive sub-document on new writes | LOW |

## 6 · Recommended sequencing (owner decides; nothing authorised)

1. **Decision** (this document) — ratify `verdict_stage2` as canonical, pipeline as writer, `verdict_card` retained. ← *awaiting owner*
2. **Implement the projection** in `xdr_incident.py` for new incidents. Evidence required: golden-corpus ingestion producing a real incident with a populated `verdict_stage2`, plus the 3 provenance tests green.
3. **Decide separately** whether to backfill the 198 existing incidents (M-2). Deterministic and safe, but a distinct authorisation with its own before/after report.
4. **Announce** M-4/M-5 before the numbers move.

**Only then P0-4 (real Suricata telemetry).** Rationale: with the projection in place, the live-source proof will exercise `evidence[]`, queue filters and MSS aggregation on real data — which is a materially stronger production proof than one that leaves five columns null.

## 7 · UNKNOWN

| # | Unknown | Why |
|---|---|---|
| U-1 | Whether `routers/verdict_stage2.py` has ever run successfully in this environment. 0 of 484 docs carry the field | Cannot distinguish "never ran" from "wiped" read-only |
| U-2 | The exact `confidence_bucket` banding used by `services/verdict_stage2/engine.py`. The projection **must reuse it**, not re-derive it — this must be read from source at implementation time, not assumed | Deliberately not guessed here |
| U-3 | Whether any UI surface depends on `evidence_count` being 0 (e.g. an "honest empty" state that would now render differently) | Requires UI inspection, outside this decision's scope |

## 8 · Scope integrity

No code, config, DB or runtime changed by this document. `mal-20` untouched. No UBAE, Sandbox, Stage-4, Gap-B, Stage-11 work. No implementation authorised.

## END · P0-3 Design Decision · awaiting owner ratification of §4
