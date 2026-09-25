# GATE 3 · NivXForge DETECTION & PREVENTION FABRIC — ARCHITECTURE & CONTRACTS

Status: **IN_PROGRESS** — contracts frozen in this document, bounded
skeleton implemented under `backend/edr_plane/fabric/`. No ML framework
is introduced for appearance, and no analyzer is given verdict authority.

Owner constraints, restated as invariants:

* **INV-1** An ML finding is **not** automatically malicious. It is a
  finding with a score, the features it was computed from, and evidence
  references.
* **INV-2** **No verdict without evidence.** A verdict cites findings;
  a finding cites canonical evidence; nothing is asserted that cannot be
  traced to a persisted record.
* **INV-3** Observation-time truth and analysis-time truth are separate
  facts and are never merged (this is what makes Gate 6 possible).
* **INV-4** An analyzer that cannot run says so (`NOT_EVALUATED` with a
  reason). Absence of a finding is never reported as "clean".
* **INV-5** Tenant authority is resolved by the server before any
  analyzer sees evidence, and a finding inherits the tenant of the
  evidence — never of the caller.

## 1 · The pipeline

```
Endpoint Event Journal / raw events
        │  (existing: edr_raw_events, v2_shadow_observations)
        ▼
Canonical Evidence            ← the ONE analysable unit (evidence_ref)
        │
        ├─► DETERMINISTIC RULES      (exists today: rule_ids/derivations)
        ├─► IOC / REPUTATION         (intel plane exists; not wired to EDR)
        ├─► STATIC FILE ANALYSIS     (absent — needs file observation)
        ├─► ML · FILE                (absent)
        ├─► ML · PROCESS / COMMAND   (absent)
        ├─► ML · SEQUENCE            (absent)
        ├─► BEHAVIOURAL / ANOMALY    (absent)
        └─► THREAT INTELLIGENCE      (partial, XDR-side)
        │
        ▼   each emits zero or more  FINDINGS  (never a verdict)
   CORRELATION  (groups findings by endpoint · process lineage · time ·
                 artifact identity)
        │
        ▼
   VERDICT  (the single authority; deterministic composition of findings)
        │
        ├─► POLICY  (Gate 8 — what this tenant/group does about it)
        └─► RESPONSE (Gate 14 surface — request → … → VERIFIED)
```

## 2 · The Finding contract (frozen)

Every analyzer, present or future, local or server-side, emits the same
record. This is the extension point: adding an engine must never require
changing the correlation engine, the verdict engine, or the UI.

```
Finding
  finding_id          str   content-addressed: sha256(analyzer_id,
                            model_version, evidence_refs, feature_digest)
  tenant_id           str   inherited from the evidence, server-resolved
  endpoint_ref        str|None
  analyzer_id         str   e.g. "deterministic.rule", "ml.command_line"
  analyzer_class      enum  DETERMINISTIC | REPUTATION | STATIC | ML |
                            BEHAVIORAL | SEQUENCE | ANOMALY | INTEL
  analyzer_version    str   rule pack version OR model semver
  model_id            str|None   ML only
  model_version       str|None   ML only
  score               float|None  0..1 within the analyzer's own scale
  score_scale         str   declared, e.g. "probability" | "rule_weight"
  severity_hint       enum  INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL
  label               str   human sentence, no implementation vocabulary
  features            dict  the values the score was computed FROM
  feature_digest      str   sha256 of the canonical feature serialisation
  evidence_refs       [str] canonical evidence ids — REQUIRED, non-empty
  attck              [str]  technique ids, only when the analyzer declares
  evaluation_time     iso   ANALYSIS time (never shown as activity time)
  observed_at         iso   the evidence's own activity time
  analysis_basis      str   what the analyzer could and could not see
  inference_location  enum  ENDPOINT | BACKEND
  state               enum  EMITTED | SUPERSEDED | SUPPRESSED
  suppressed_by       str|None  exclusion id (Gate 9) — never silent
  retrospection       dict|None  {trigger, of_finding_id, basis} (Gate 6)
```

Rules the contract enforces, mechanically:

* `evidence_refs` must be non-empty → **INV-2** cannot be violated by
  construction.
* `score` without `score_scale` is refused → no dimensionless numbers.
* `features` without `feature_digest` is refused → a score can always be
  re-derived and re-audited.
* an ML `Finding` without `model_id` + `model_version` is refused → no
  unversioned inference can ever enter the evidence chain.

## 3 · The Analyzer interface

```
class Analyzer(Protocol):
    id: str
    analyzer_class: AnalyzerClass
    version: str
    inference_location: InferenceLocation

    def capability(self) -> Capability:
        """What this analyzer can evaluate, and what it CANNOT.
        Reported to the console verbatim — this is how a surface says
        NOT_EVALUATED with a reason instead of implying 'clean'."""

    def evaluate(self, unit: EvidenceUnit) -> AnalyzerResult:
        """Never raises for 'no finding'. Returns findings=[] with an
        explicit outcome: EVALUATED_NO_FINDING | NOT_EVALUATED(reason)
        | EVALUATION_FAILED(reason)."""
```

`EVALUATED_NO_FINDING` ≠ `NOT_EVALUATED` ≠ `EVALUATION_FAILED`. The
console must be able to render all three; today's Command Intelligence
already shows `EVALUATED NO MATCH`, which is this distinction working.

## 4 · Registry and ordering

* Analyzers register declaratively (`fabric/registry.py`) with their
  class, version, inference location and declared capability.
* The registry is the **contract gate**, in the same style as
  `ENDPOINT_KEYED_STORES`: a structural test reads it, so an analyzer
  cannot be wired into the pipeline without declaring itself.
* Execution order is irrelevant to correctness — findings are additive
  and the verdict composes them deterministically. This is what allows
  offline/endpoint analyzers (Gate 4) to produce findings that the
  backend later *joins* rather than *recomputes*.

## 5 · Verdict composition (single authority)

* The verdict engine consumes **findings only** — never raw scores from
  a model, never an analyzer's own opinion of severity.
* Composition is deterministic and explainable: each contributing finding
  is recorded with its weight and its effect on the label, exactly as the
  incident plane already does (`verdict_stage2.contributing_signals`).
* A finding whose analyzer class is ML can **raise confidence** and
  **contribute** to a label, but a *lone* ML finding may not produce a
  MALICIOUS verdict — that rule is data, not code, and is stated in the
  verdict policy so it can be reviewed.
* `ML finding ≠ malicious` is therefore enforced at composition time, not
  by hiding the finding.

## 6 · Model lifecycle (before any model ships)

1. **Identity** `model_id` + semver `model_version`; both persisted on
   every finding.
2. **Provenance** training-data description, feature list, evaluation
   metrics, intended scope, known blind spots — a model card stored with
   the model, referenced by `model_id`.
3. **Distribution** signed artifact; the endpoint verifies origin before
   loading (same requirement as a policy).
4. **Rollback** a model version is a first-class, pinnable value; a bad
   version is rolled back without deleting the findings it produced —
   they become `SUPERSEDED`, and history is preserved (Gate 6 rule).
5. **Shadow mode** a new version runs alongside the current one, emitting
   findings marked as shadow, which cannot reach a verdict. The platform
   already uses shadow flags (`REACT_APP_NIVX_FLAG_*`), so this reuses an
   established pattern.

## 7 · Inference boundary (feeds Gate 4)

| analyzer class | endpoint | backend | why |
|---|---|---|---|
| deterministic rules | yes | yes | must work offline |
| ML · command/process | yes | yes | small models, offline protection |
| ML · file (static) | yes | yes | needs file observation first |
| sequence / behavioural | yes (bounded window) | yes (full history) | endpoint has the journal; backend has the estate |
| reputation / intel | no | yes | requires network + tenant intel |
| retrospection | no | yes | requires historical corpus |

A finding produced on the endpoint carries
`inference_location = ENDPOINT` and is delivered through the SAME
authenticated telemetry path as evidence — it is never trusted as a
verdict, and the backend records who claimed it.

## 8 · What the bounded skeleton implements (this session)

Deliberately small, and truthful about its own scope:

* the `Finding` model with the refusals above;
* `AnalyzerResult` with the three outcomes;
* the registry + a structural contract test;
* ONE real analyzer: `deterministic.rule` — it does **not** invent a new
  detection engine, it projects the detections the platform already
  derives (`edr_raw_events.derivations[]`) into the Finding contract, so
  the fabric has a genuine producer from day one;
* a findings store (`edr_findings`, new collection — nothing existing is
  migrated or mutated) with a content-addressed `finding_id` so
  re-evaluation is idempotent;
* correlation is NOT implemented yet and says so.

## 10 · Evidence for the bounded skeleton (2026-06)

**Contract tests** — `backend/tests/edr/test_gate3_fabric_contracts.py`
→ **15 passed**. They assert the invariants, not the implementation:

* a finding with `evidence_refs=[]` or `[""]` is **refused**
  (`"no verdict without evidence"`) — INV-2 cannot be violated
  downstream because such a record cannot be constructed;
* a `score` without `score_scale` is refused;
* `features` always produce a `feature_digest`;
* an ML-class finding without `model_id`+`model_version` is refused;
* an ML finding carries **no** verdict/disposition field at all — there
  is nothing to set — and its `severity_hint` is named as a hint
  (INV-1);
* `EVALUATED_NO_FINDING` / `NOT_EVALUATED` / `EVALUATION_FAILED` cannot
  be swapped: an outcome that does not match what it carries is refused,
  and `NOT_EVALUATED` without a reason is refused (INV-4);
* identity is content-addressed: the same evaluation twice yields ONE
  `finding_id`, the store reports `inserted 1 / already_present 1`, and
  another tenant reads zero rows (INV-5 + INV-5 tenant partition);
* the registry refuses an analyzer that does not declare itself, and
  **every** analyzer must declare a blind spot — the fabric may not imply
  total coverage;
* structural: no file in `edr_plane/fabric/` may *access* an evidence
  collection (docstrings may name one; code may not open it), which is
  the mechanical guarantee behind INV-3 and Gate 6.

**Real-data proof** — `scripts/gate3_fabric_real_evidence_proof.py`,
**read-only, writes nothing**, output preserved at
`/app/test_reports/gate3_fabric_real_evidence_proof.txt`:

```
read 1545 real raw events (read-only)

outcome distribution (three DIFFERENT facts, never merged):
  NOT_EVALUATED                    745
  FINDINGS                         400
  EVALUATED_NO_FINDING             400

findings produced: 400
distinct content-addressed ids: 400 of 400
NOTHING WAS WRITTEN. 0 findings persisted, 0 evidence rows touched.
```

One finding, verbatim from the platform's own data:

```json
{
  "tenant_id": "default",
  "analyzer_id": "deterministic.rule",
  "analyzer_class": "DETERMINISTIC",
  "analyzer_version": "nivxray::detection_content::nivxray_native_sigma",
  "label": "deterministic detection content matched EDR-LNX-001",
  "evidence_refs": ["cev_3fcaea4cbbf2a1fc505f498c_0"],
  "observed_at":      "2026-09-06T10:16:17.287398+00:00",
  "evaluation_time":  "2026-09-06T10:16:17.711359+00:00",
  "endpoint_ref": "ep_2d57cbe6f80152062109",
  "score": null, "score_scale": null, "model_id": null,
  "severity_hint": "LOW",
  "features": {"rule_ids": ["EDR-LNX-001"],
               "detection_content_version": "nivxray::detection_content::nivxray_native_sigma",
               "ingest_verdict_label": "LIKELY_BENIGN"},
  "feature_digest": "e01306a5…35ebd2",
  "analysis_basis": "projected from the detection derivation recorded at ingest; this analyzer does not re-run detection and does not invent a rule that was not recorded",
  "state": "EMITTED", "retrospection": null,
  "finding_id": "fnd_c274f16259b669f42a88be6b85e5c00b"
}
```

Note the 745 `NOT_EVALUATED`: those raw events carry only a
`CANONICAL_EVIDENCE_CREATED` derivation, so the deterministic plane never
ran on them. The fabric says exactly that, with the sentence *"which is
not a statement that the activity was benign"* — it does not report them
as clean. That is the whole point of the outcome model.

## 11 · Explicitly NOT done (and must not be claimed)


* no ML model exists, is trained, shipped or executed;
* no static file analysis (the sensor does not observe files yet);
* no behavioural/sequence analyzer;
* no endpoint-side inference (Gate 4);
* no correlation engine, no verdict recomposition from findings — the
  incident verdict authority is unchanged;
* nothing in the UI reads findings yet.
