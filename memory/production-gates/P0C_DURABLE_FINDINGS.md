# P0-C · DURABLE EDR FINDINGS — EVIDENCE PACKAGE

Owner directive *OWNER DECISION — P0-A.1 / P0-B ACCEPTED · AUTHORIZE
P0-C*. Closed 2026-09-26. **Backend only. No Findings UI, no triage
workflow, no retrospection/supersession, no invented local engine.**
P0-D was not started. Gate 12 CSS was not touched.

---

## WHAT WAS BUILT

A durable finding lifecycle on the existing evidence architecture, plus
the thing that makes an empty answer honest: a recorded **evaluation
state** per piece of evidence.

Two collections, both new; nothing existing was migrated or mutated:

| Collection | Holds | Written by |
|---|---|---|
| `edr_findings` | the durable finding (write-once analysis + recurrence accounting) | `edr_plane/fabric/store.py` |
| `edr_finding_evaluations` | what actually happened when this evidence was evaluated | `edr_plane/fabric/evaluation_state.py` |

The write path is the **real authenticated telemetry path**. In
`edr_plane/canonical_bridge.py`, immediately after the platform records
what its detection plane did with the event, the outcome is handed to
`edr_plane/findings_intake.py`. It cannot fail the ingest: a fault is
recorded as `EVALUATION_FAILED` for that evidence, which is a different
fact from "no finding".

---

## FILES CHANGED

* `backend/edr_plane/fabric/contracts.py` — `DetectionSource`,
  `IMPLEMENTED_DETECTION_SOURCES`, `DETECTION_SOURCE_DISCLOSURE`,
  mandatory `detection_source` / `detection_source_detail` /
  `severity_basis` / `confidence_basis` / `attck_basis`, plus
  `rule_id · rule_version · rule_name · severity · confidence ·
  confidence_scale · confidence_label`; identity now includes the
  producing source and rule; `EvidenceUnit.detection_citations`.
* `backend/edr_plane/fabric/store.py` — durable persist (write-once
  analysis via `$ifNull`, `created_at` / `first_seen` / `last_seen` /
  `recurrence_count` / `last_recorded_at`), keyset query with filters,
  `get`, `counts`, `ensure_indexes`.
* `backend/edr_plane/fabric/evaluation_state.py` — **new** · the
  evaluation-state ledger.
* `backend/edr_plane/fabric/analyzers/deterministic_rule.py` — one
  finding per producing RULE, carrying the producing rule's own severity,
  confidence and ATT&CK; absent values persisted as absent WITH the
  reason.
* `backend/edr_plane/findings_intake.py` — **new** · the write path
  (citation join, P0-B exclusion gate, findings + ledger).
* `backend/edr_plane/canonical_bridge.py` — two call sites: the detection
  outcome and the `DETECTION_NOT_EVALUATED` outcome.
* `backend/routers/edr_findings.py` — **new** · the read plane (4 routes).
* `backend/routers/edr_tenancy.py` — the 4 routes classified.
* `backend/server.py` — router mounted; indexes ensured in their OWN try
  block (a legacy index conflict elsewhere must not leave this plane
  unindexed).
* Tests: `tests/edr/test_p0c_durable_findings.py` (12),
  `tests/edr/test_p0c_durable_findings_live.py` (11),
  `tests/test_edr_route_tenant_authority.py` (+4 probes),
  `tests/edr/test_gate3_fabric_contracts.py` (fixture carries the new
  mandatory provenance fields; no assertion weakened).

---

## SCHEMA · `edr_findings`

```
finding_id                 fnd_<32 hex>   content-addressed
tenant_id                  partition key + part of identity
endpoint_id                endpoint_ref
analyzer_id/_class/_version
detection_source           enum · MANDATORY
detection_source_detail    the producing engine, named
rule_id · rule_version · rule_name
severity + severity_basis
confidence + confidence_scale + confidence_label + confidence_basis
attck[] + attck_basis
evidence_refs[]            non-empty BY CONSTRUCTION
observed_at                activity time (the endpoint's clock)
evaluation_time            when the analysis happened
first_seen · last_seen · created_at · recurrence_count · last_recorded_at
features + feature_digest  so a score can be re-derived and re-audited
state                      EMITTED (SUPERSEDED/SUPPRESSED reserved, Gate 6/9)
inference_location         BACKEND (ENDPOINT is REFUSED — see provenance)
```

## FINDING IDENTITY ALGORITHM

`fnd_` + first 32 hex of
`sha256(tenant_id ␟ analyzer_id ␟ analyzer_version ␟ detection_source ␟
rule_id ␟ model_id ␟ model_version ␟ sorted(evidence_refs) ␟
feature_digest)`.

Consequences, all asserted:
* the same detection re-evaluated is the **same** finding → idempotent;
* the same evidence in two tenants is **two** findings → no cross-tenant
  collision is even representable;
* a different rule or a different producing source is a **different**
  finding → a later source can never overwrite an earlier one's analysis.

## WRITE PATH

`authenticated telemetry → immutable raw event → canonical bridge →
XDR ingest detection pipeline → detection derivation recorded →
findings_intake`:

1. join the producing source's own per-rule citations
   (`xdr_detection_matches`) on **both** the canonical event id and the
   ingest trace (`raw_id`). The XDR pipeline canonicalises the event
   under its OWN id (`cev_raw_<raw>_pl`) while the EDR plane has its own
   (`cev_<raw>_0`); they are two identities for one event, so the join is
   made on both and never by resemblance — this was found by measurement,
   not assumed (before the fix, `rule_version`, `rule_name` and ATT&CK
   read absent on the live edge);
2. run the registered analyzer through the **P0-B exclusion gate**, so an
   approved exclusion genuinely suppresses the verdict and is recorded as
   its own state;
3. persist findings (idempotent, write-once) and the evaluation state.

## READ PATH

| Route | Class | Answers |
|---|---|---|
| `GET /api/edr/findings` | TENANT_SCOPED | keyset page + counts + `evaluation_state` + disclosure |
| `GET /api/edr/findings/{finding_id}` | TENANT_SCOPED | the finding + **resolved** evidence + its evaluation state; 404 across tenants, disclosing nothing |
| `GET /api/edr/findings/evaluation-state` | TENANT_SCOPED | what was evaluated, per state and per named endpoint |
| `GET /api/edr/findings/taxonomy` | PRODUCT_METADATA | detection sources with `implemented` flags, evaluation states with meanings, analyzer capabilities |

Filters: `endpoint_ref · severity · rule_id · detection_source ·
since · until · limit · cursor`. The cursor is a keyset over
`(first_seen, finding_id)`, so a page boundary cannot drop or repeat a
finding while new ones arrive.

## PROVENANCE CONTRACT (enforced by construction)

* `detection_source` is **mandatory**; `IMPLEMENTED_DETECTION_SOURCES`
  contains exactly one value today —
  `XDR_PLATFORM_DETERMINISTIC_DETECTION`. A finding claiming
  `NIVXFORGE_ENDPOINT_BEHAVIORAL`, `NIVXFORGE_ENDPOINT_PREVENTION`,
  `NIVXFORGE_BACKEND_REPUTATION` or `NIVXFORGE_BACKEND_ML` **cannot be
  constructed** — the contract raises, with the reason that no such
  engine exists.
* `inference_location = ENDPOINT` is likewise **refused**: there is no
  endpoint-side inference engine, so no finding may imply one.
* Every persisted finding names the XDR pipeline as its producer
  (`detection_source_detail`) and states that the EDR plane projected it
  "without re-evaluation".
* The taxonomy discloses the unimplemented sources rather than hiding
  them, with `produced_by: null` and the reason.
* Nothing is fabricated: the producing rule's severity, confidence and
  ATT&CK are read from the source's own records. The rule records a
  **categorical** confidence (`high`), so `confidence_label = "high"` and
  the numeric `confidence` stays `null` with
  `NOT_RECORDED_BY_SOURCE · the rule records a CATEGORICAL label, not a
  numeric score`. No number was invented from a word.

## EVALUATION-STATE SEMANTICS (negative explainability)

Five recorded states, each written only from a real evaluation attempt:

| State | Means |
|---|---|
| `FINDINGS_PRESENT` | evaluated · at least one finding |
| `EVALUATED_NO_FINDING` | this analyzer evaluated it and found nothing — **not** a claim of benign, and silent about engines that do not exist |
| `NOT_EVALUATED` | it was not evaluated · the reason is recorded |
| `EVALUATION_FAILED` | an attempt failed · the evidence is retained and replayable; the outcome is **unknown, not absent** |
| `EVALUATION_SUPPRESSED_BY_EXCLUSION` | P0-B · an approved exclusion suppressed the verdict |

Evidence with **no ledger row** reads `NOT_EVALUATED ·
NO_EVALUATION_RECORDED`. Nothing manufactures `EVALUATED_NO_FINDING`
from the absence of a finding document. Every findings response carries
`truth_semantics`: `NO FINDING != BENIGN · NOT EVALUATED != NO FINDING ·
EVALUATION FAILED != NO FINDING · UNKNOWN != ABSENT`.

## IMMUTABILITY

Every analytic field is written with `$ifNull` inside one aggregation
update, so an existing value is structurally unoverwritable. Only
`last_seen`, `recurrence_count` and `last_recorded_at` move — facts about
the RECORD, not the finding. A different analysis has a different
identity and would be a NEW finding. Historical re-evaluation and
supersession are **Gate 6** and are absent by design; the read plane says
so (`retrospection: "... a finding is never rewritten because detection
logic changed later"`).

No backfill was performed. Detections that predate P0-C have no finding,
and that is reported as `NOT_EVALUATED · NO_EVALUATION_RECORDED` rather
than as a clean result.

---

## PROOF

### Live end-to-end on the preview host (real endpoint, real detection)

A world-writable script was executed on the enrolled Linux endpoint
(`ep_2d57cbe6f80152062109`). The real sensor observed it, the real XDR
detection content matched `EDR-LNX-002`, and the finding plane produced:

```
finding_id      fnd_a85c8e995de270e6101e4b84e07ac49f
rule_id         EDR-LNX-002      rule_version 1
rule_name       Execution from a world-writable directory
severity        MEDIUM   (PRODUCING_RULE_SEVERITY · recorded 'medium')
confidence      null · confidence_label 'high' (CATEGORICAL, not a number)
attck           ["T1059","T1036"]  PRODUCING_RULE_MITRE_MAPPING
detection_source XDR_PLATFORM_DETERMINISTIC_DETECTION
evidence_refs   ["cev_c573f25bdc30948721b759be_0"] → EVIDENCE_RESOLVED
first_seen      2026-09-26T08:46:18.610000+00:00   recurrence_count 1
```

* **Restart durability**: `supervisorctl restart backend`, then the same
  id re-read over HTTP — same `finding_id`, same `rule_id`, same
  `created_at`, evidence still `EVIDENCE_RESOLVED`.
* **Estate state at close**: 6 findings · 340 recorded evaluations
  (`EVALUATED_NO_FINDING` 334 · `FINDINGS_PRESENT` 6) — the 334 are the
  live sensor's ordinary telemetry, evaluated and stated as such rather
  than silently absent.
* **Cross-tenant**: the same id under `X-Tenant-Id: nivx-live` → **404
  FINDING_NOT_FOUND**, and the id does not appear in the refusal.
* **No tenant header** → 403 `TENANT_REQUIRED`; unregistered tenant →
  403 `TENANT_NOT_FOUND`; a scoped analyst naming `default` → 403
  `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, while its own tenant answers
  200.

### `tests/edr/test_p0c_durable_findings.py` — 12, real Mongo, throwaway tenants

1. a detection produces a durable finding with the whole required field
   set (and nothing fabricated);
2. the finding survives the process — read back through a **new** client;
3. three evaluations → **one** finding, `recurrence_count 3`,
   `evaluation_attempts 3`, identical ids;
4. a rewritten analysis under the same identity does **not** change the
   stored label, severity, basis, `created_at` or `first_seen`;
5. identical evidence in two tenants → two ids; neither tenant can be
   answered with the other's finding;
6. cited evidence resolves (`EVIDENCE_RESOLVED`, naming where), an
   unknown reference reads `EVIDENCE_REFERENCE_UNRESOLVED` and states
   that no similar record will be substituted, and the same reference in
   another tenant does not resolve;
7. the producing source is preserved and the detail contains no "local",
   "offline" or "behavioural" claim;
8. a finding claiming a non-existent engine — or ENDPOINT inference —
   **cannot be constructed**;
9. `EVALUATED_NO_FINDING` vs `NOT_EVALUATED`: both are zero findings and
   are reported as two different facts; an unevaluated endpoint reads
   `NO_EVALUATION_RECORDED`; a tenant with nothing evaluated says
   `NOT 'evaluated and clean'`;
10. a forced failure records `EVALUATION_FAILED` with "unknown, not
    absent" and persists no finding;
11. an exclusion-suppressed evaluation is its own state, not "clean";
12. structural: the bridge must hand BOTH outcomes to the finding plane
    (guards against the hook being silently removed).

### `tests/edr/test_p0c_durable_findings_live.py` — 11, live edge, read-only

Taxonomy honesty (only one implemented source ·
`local_behavioral_engine_present false` · absent engines still
disclosed · one analyzer, declaring its own blind spots) · tenant
authority on all three tenant-scoped routes · a principal cannot read a
tenant it does not hold · every response discloses the evaluation state
and the truth semantics · an unevaluated endpoint reads NOT_EVALUATED ·
live findings state their real source, cite evidence and carry the three
bases · a live finding resolves to the evidence responsible for it ·
cross-tenant read refused without disclosure.

### Regression — no test was weakened to obtain green

| Suite | Before | After |
|---|---|---|
| `tests/edr` | 471 passed · 1 skipped | **494 passed · 1 skipped · 0 failed** |
| `tests/test_edr_route_tenant_authority.py` | 292 passed | **308 passed** |
| `scripts/gate3_fabric_real_evidence_proof.py` | 500 findings / 400 ids | **515 findings** over 1 845 real events, three outcomes still separate (845 NOT_EVALUATED · 500 EVALUATED_NO_FINDING · 500 FINDINGS), nothing written |

`tests/test_edr_onboarding_v1.py` (2) and `tests/test_edr_context_p0_f13_3.py`
(5) fail — **PRE-EXISTING**, proven byte-identical on the pre-P0-C tree
by `git stash` (stale live-contract suites already itemised in the master
index). They are not reported as green.

---

## REMAINING RISKS

1. **No backfill.** Only detections that occur from now on become
   findings. Historical detections read `NOT_EVALUATED ·
   NO_EVALUATION_RECORDED` — honest, but the estate will look sparse
   until it fills. A retrospective materialisation is Gate 6 work and
   would need supersession semantics first.
2. **The ledger is current-state per (evidence, analyzer).** Findings are
   immutable; the evaluation STATE of a piece of evidence is updated in
   place (with `first_recorded_at` and `evaluation_attempts` preserved).
   A full evaluation HISTORY is not kept — it belongs with Gate 6.
3. **Confidence is categorical at source.** Every finding's numeric
   confidence is `null` today, deliberately. Any future numeric
   confidence must arrive with the engine that measures it and declare
   its scale.
4. **Storage growth is now real.** `EVALUATED_NO_FINDING` rows are
   written for ordinary telemetry (334 in the first hour on one
   endpoint). There is no retention policy for `edr_finding_evaluations`
   — the same unaddressed retention risk P0-B recorded.
5. **One producer.** `deterministic.rule` is the only analyzer; the
   finding plane is therefore only as good as the XDR detection content.
   No local behavioural, prevention, reputation or ML engine exists, and
   the contract now REFUSES to let one be claimed.
6. **No UI.** The console cannot see findings yet — deliberately, pending
   the Cisco Secure Endpoint / AMP workflow design pass.
