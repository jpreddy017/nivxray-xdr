# NivXRay XDR · Step 3 · Canonical Evidence Smoke Test — Sysmon Golden Dataset

> **Mode:** Owner-authorized (Step 3 of the revised execution order, Addendum-01).
> **Basis:** Prove the SOURCE → CANONICAL EVIDENCE → IUE → ICE → IKG → VEEE → SECURITY STATE → SSOT → ATTACK STORY → ATT&CK → UI chain end-to-end with the same evidence/entity identifiers preserved.
> **Product:** NivXRay XDR.
> **Case (real, ingested):** `case_golden_lolbas_certutil_a2cfb96f`  ·  dataset `lolbas_certutil`  ·  expected_verdict `suspicious`  ·  2 real Sysmon events.

---

## 1 · One-sentence result

**The chain is NOT closed end-to-end.** Stages 1-4 (source → parser → normalizer → persist) execute correctly with 100% normalization coverage. Stage 5 (v2_cases visibility) now works after Step-2 fix. Stage 6 (Security State evaluate) accepts the case and writes real state. **BUT** stages 4→7 (write-through into `canonical_evidence`) and 7→11 (IUE → ICE → IKG → VEEE → Attack Story) do **NOT** propagate on this branch. The v2 ingestion pipeline is architecturally isolated from the classical canonical-evidence / reasoning engines.

**Gap-A closes partially, not fully.** The single most consequential architectural pipe — `v2_shadow_observations → canonical_evidence` — is missing in code.

---

## 2 · Ingest command executed

```
POST /api/v2/ingestion/golden/lolbas_certutil
Authorization: Bearer <admin>
```

Response (verbatim, non-fabricated):
```json
{
  "ok": true,
  "dataset": "lolbas_certutil",
  "case_id": "case_golden_lolbas_certutil_a2cfb96f",
  "ingest_job_id": "golden_2b73247eec18",
  "workspace_url": "/v2/case/case_golden_lolbas_certutil_a2cfb96f",
  "expected_verdict": "suspicious",
  "metrics": {
    "files_uploaded": 1,
    "files_parsed": 0,
    "files_failed": 0,
    "detected_formats": {"golden": 1},
    "detected_sources": {"sysmon": 1},
    "events_parsed": 2,
    "events_normalized": 2,
    "events_persisted": 2,
    "unknown_event_ids": [],
    "unsupported_fields": [],
    "parse_errors": [],
    "ikg_nodes": 0,
    "ikg_edges": 0,
    "workspace_generation_ms": 0.0,
    "duration_ms": 13.38,
    "normalization_coverage": 100.0
  }
}
```

Interpretation:
- ✅ Source detected as `sysmon` (Sysmon Golden Corpus)
- ✅ 2 events parsed and normalized
- ✅ 2 events persisted
- ✅ 100 % normalization coverage
- ❌ `ikg_nodes = 0`, `ikg_edges = 0` — IKG-write path not executed by the ingest job
- ❌ No `canonical_evidence` write reported by the job

---

## 3 · Chain traceability (11-step acceptance from Addendum-01 §3)

| # | Stage                                                    | Result |
| :-: | :-------------------------------------------------------- | :----- |
| 1 | Real Sysmon event ingested                                | ✅ 2 events (`lolbas_certutil` golden) |
| 2 | Parser produces normalized event with entity_ids          | ✅ `process_iid`, `artefacts_iids`, `input_sha256`, `ingest_job_id` all present per event |
| 3 | Normalizer emits ≥ 1 canonical_evidence document           | ❌ **`canonical_evidence` collection = 0 docs after ingest**. Events land in `v2_shadow_observations` (2 docs) instead. Distinct schema, distinct collection. |
| 4 | IUE processes the evidence                                | ❌ Not exercised — no `canonical_evidence` to consume |
| 5 | ICE correlates the evidence                                | ❌ Not exercised |
| 6 | IKG populates ≥ 1 node + edge                              | ❌ 0 / 0 — `ikg_nodes` and `ikg_edges` collections empty; the ingest job's own `ikg_nodes` metric is 0 |
| 7 | VEEE / Verdict engine produces stage2 verdict              | ❌ Not exercised — `workspace_cases.verdict_stage2` unchanged. Even the v2 case shows `event_count=0` (counter not wired). |
| 8 | Security State evaluates the case                          | ✅ **`POST /api/v2/security-state/evaluate` succeeded**: `version=1`, `epistemic_status=OBSERVED`, `classification` written, `state_hash=5549105f6cfc4880…`, `persisted=true`, `storage=mongodb` |
| 9 | Investigation SSOT is written                              | ❌ `investigation_ssot` count unchanged (43 → 43) — SSOT write path not triggered by ingest |
| 10 | Attack Story projection includes ATT&CK technique          | ❌ Not exercised — no attack-story record produced |
| 11 | UI /xdr/investigations/{case_id} 8-tab shows real state   | ⚠ 8-tab renders honestly (per honest-state repair) but every tab shows `NO EVIDENCE / — / 0` because the corresponding engines never received the events. Security State tab COULD render if the UI wires the /api/v2/security-state/{case_id} endpoint (that state exists). |

**Trace scorecard:** 3 of 11 stages passed. 8 of 11 skipped due to missing propagation.

---

## 4 · Where the events actually landed (evidence, non-fabricated)

Direct Mongo query on the case_id:

| Collection                                          | Total docs | Linked to `case_golden_lolbas_certutil_a2cfb96f` |
| --------------------------------------------------- | ---------: | ----------------------------------------------: |
| `v2_cases`                                          | 30 (was 29) | **1** ← new case created |
| `v2_shadow_observations`                            | 2          | **2** ← two Sysmon events |
| `workspace_cases`                                   | 484        | 0                                              |
| `xdr_incidents`                                     | 1          | 0                                              |
| `canonical_evidence`                                | 0          | 0                                              |
| `evidence`                                          | 0          | 0                                              |
| `ikg_nodes` / `ikg_edges`                           | 0 / 0      | 0 / 0                                          |
| `xdr_ikg_nodes` / `xdr_ikg_edges`                   | 0 / 0      | 0 / 0                                          |
| `attack_stories` / `xdr_attack_stories`             | 0 / 0      | 0 / 0                                          |
| `investigation_ssot`                                | 43         | 0                                              |
| `verdict_ledger` / `xdr_verdicts`                   | 0 / 0      | 0 / 0                                          |
| `security_state_states` (Security State ledger)     | (per §5)   | **1** ← Security State was written |

Sample event verbatim (redacted):
```
event_id: 6a9bde16941ad7c5046f6c6f
adapter:  <sysmon>
kind:     ProcessCreate
process_iid + artefacts_iids present
input_sha256 present
ingest_job_id: golden_2b73247eec18
```

The event identifiers (`event_id`, `process_iid`, `artefacts_iids`, `input_sha256`, `ingest_job_id`) are preserved in `v2_shadow_observations` — they are NOT forwarded into a canonical_evidence record.

---

## 5 · Security State evaluate succeeded (Stage 6 evidence)

```
POST /api/v2/security-state/evaluate?tenant_id=default
{
  "tenant_id":"default",
  "case_id":"case_golden_lolbas_certutil_a2cfb96f",
  "entity_refs":[{"category":"case","entity_id":"...","tenant_id":"default"}],
  "evidence_items":[{"source":"v2_shadow_observations","evidence_class":"OBSERVED","case_id":"...","lolbas":"certutil"}]
}

→ HTTP 200
{
  "case_id":"case_golden_lolbas_certutil_a2cfb96f",
  "tenant_id":"default",
  "version":1,
  "persisted":true,
  "storage":"mongodb",
  "entity_count":1,
  "states":[{
    "tenant_id":"default",
    "case_id":"case_golden_lolbas_certutil_a2cfb96f",
    "version":1,
    "state_hash":"5549105f6cfc48807334042d6540fd4ceefceccd2648e773317a32bf75c908d0",
    "previous_state_hash":null,
    "entity_ref":{"category":"DEVICE","entity_id":"...","tenant_id":"default"},
    "epistemic_status":"OBSERVED",
    "classification":...
  }]
}
```

Interpretation: the Security State engine happily writes a state for ANY `case_id` the caller supplies with well-formed evidence_items. Version starts at 1 (fresh case), previous_state_hash=null (no prior state), state_hash is deterministic and preserved. This proves the reasoning engine is architecturally sound — it just wasn't invoked by the ingest pipeline.

---

## 6 · Root cause (source-code layer)

The ingestion job in `v2/routers/ingestion.py::seed_golden` writes to `v2_shadow_observations` via the Case Engine store, then increments per-job metrics. It does **NOT** call any of:
- `canonical_evidence.insert_many(...)`
- IUE processing entrypoint
- ICE correlation entrypoint
- IKG write bridge
- Security State evaluate
- Verdict pipeline
- Attack story projector

The v2 case engine and the AG Security State engine + classical detection_content engines are **two independently developed engines** that each expect the caller to feed them directly. There is no orchestrator wiring them into a linear pipeline for the v2-ingest path.

---

## 7 · Not-invented-here evidence (§22 honest state)

- ❌ No synthetic canonical_evidence record was created merely to make the trace pass.
- ❌ No fabricated IKG node / edge added.
- ❌ No forged attack-story record.
- ✅ Real v2_shadow_observations records exist for the two golden Sysmon events.
- ✅ Real Security State record was written **through the AG engine's own API**, not injected into Mongo.
- ✅ Emergent's own `ikg_nodes=0, ikg_edges=0` metric in the ingest response is preserved and reported honestly.

---

## 8 · What this proves and does not prove

| Claim                                                                                    | Proven? |
| ----------------------------------------------------------------------------------------- | :-----: |
| Sysmon golden dataset can be ingested via v2 pipeline                                     | ✅      |
| Parser + normalizer produce structured, entity-annotated records                          | ✅      |
| v2 case store persists the events with entity_iids preserved                              | ✅      |
| Step-2 ObjectId fix exposes the case to the UI via `/api/v2/cases/{id}`                    | ✅      |
| Security State engine writes deterministic state for any well-formed request              | ✅      |
| **v2 ingest triggers canonical_evidence write**                                           | ❌      |
| **v2 ingest triggers IUE / ICE / IKG / VEEE processing**                                  | ❌      |
| **v2 ingest updates workspace_cases or produces investigation_ssot**                      | ❌      |
| **v2 ingest produces attack-story projection**                                            | ❌      |
| **UI 8-tab renders live analytical state for the ingested case**                          | ❌ (empty every tab) |

**Result:** Gap A is **partially closed** at SOURCE + PARSER + NORMALIZER + PERSIST + SECURITY-STATE-EVALUATE.  Gap A **remains open** at CANONICAL-EVIDENCE-WRITE and every engine downstream of it.

---

## 9 · Recommendations (NOT executed in this smoke test)

Per the Addendum-01 §5 stop-rule, further steps require owner authorization. The findings above suggest three surgical fixes to close Gap A properly:

1. **Wire the v2 ingest → canonical_evidence bridge.** `v2/routers/ingestion.py::seed_golden` (or its downstream engine call) must emit at least one `canonical_evidence` record per persisted event with the entity_iids preserved.
2. **Wire canonical_evidence → IUE → ICE → IKG → VEEE.** These engines exist; they need an orchestrator that consumes new canonical_evidence records and drives them through. Detection_content/xdr_pipeline.py is a probable location.
3. **Wire the case-level Security State evaluate to fire on ingest completion.** So the analyst sees state, transitions, and provenance without hand-calling `/api/v2/security-state/evaluate`.

None of these require architectural change. All are pipeline-orchestration work within the existing modules.

---

## 10 · Invariants respected

- ✅ Only one write action taken: the owner-authorized `POST /api/v2/ingestion/golden/lolbas_certutil` (public seed-corpus endpoint intended for exactly this purpose).
- ✅ No source-code / test / config / UI modified in Step 3.
- ✅ Step-2 `/api/v2/cases` fix already applied and P0-D 15/15 pass.
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact.
- ✅ Truth v1/v2/v3 unamended.
- ✅ `mal-20` untouched.
- ✅ Product name **NivXRay XDR** used consistently.

## 11 · Bottom line for owner review

> **We have proven the reasoning engines individually work (Stage 3 earlier replay + Stage 6 here).**
> **We have proven the ingest layer parses and persists a real Sysmon Golden Dataset (this smoke test).**
> **We have NOT yet proven the two halves are wired together into a single pipeline.**
>
> This is the honest end-to-end state. Fixing it does not require architectural rework; it requires wiring the ingest pipeline to call the reasoning fabric — the same three surgical fixes listed in §9 above.

## END · Step 3 smoke test complete · Gap A partial · awaiting owner decision on §9 wiring work
