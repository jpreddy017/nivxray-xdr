<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** specification. Counts: `08_VALIDATION/REALITY_MATRIX.md`.

# INCIDENT ARCHITECTURE

Adopts `memory/ANALYST_OPERATIONS_ARCHITECTURE.md`,
`memory/ANALYST_OPERATIONS_MANDATE.md`,
`memory/STEP1_WORKLOG_ADOPTION_CHECK.md`, `memory/IR_REPORT_CONTRACT.md`.

## 1 · SSOT

**`workspace_cases` is the single source of truth for an incident.**
Collection naming is inherited; the vocabulary fix is tracked in
`00_PRODUCT/TERMINOLOGY.md`.

**The worklog is `workspace_cases.incident_state_history[]`,
append-only, and it is the ONLY worklog.** A parallel notes collection is
an architecture violation — this was audited and confirmed
(`STEP1_WORKLOG_ADOPTION_CHECK`).

## 2 · Object model

| Field group | Contents | Authority |
|---|---|---|
| identity | `id`, tenant | platform |
| classification | priority, status, severity inputs | prioritisation engine |
| linkage | detections, endpoint campaign, observables, assets | detection + correlation |
| lifecycle | state, assignee, timestamps | incident plane |
| worklog | `incident_state_history[]` (append-only) | incident plane |
| **provenance** | **MISSING** — see §5 | ingest |

## 3 · Lifecycle

```
detection(s) → correlation → prioritisation → INCIDENT
   → triage → investigation → decision
   → response request → approval → execution → verification
   → recomputed security state → closure (worklog retained)
```

Rules:

1. Every transition appends to `incident_state_history[]`. **No
   transition is silent.**
2. An incident that cannot be prioritised is still **visible** — never
   dropped for lack of a score.
3. Closure never deletes evidence or worklog.
4. **Strict tenant scope on every read.** A cross-tenant IDOR existed
   here and was closed; the proof is
   `scripts/p0_w_incident_tenant_authorization_proof.py` (25 gates).

### Worklog entry types — `EXTEND`, not new store

Typed entries (`state_change`, `priority_change`, `assignment`,
`analyst_note`, `response_requested`, `response_verified`,
`provenance_correction`) must extend the existing array. Tracked for
`CLOSED_BETA`.

## 4 · Prioritisation — honest limits

The reference product combines **detection risk with asset value**
(`SOURCE_REGISTER` A14, `OWNER_ASSERTED`).

**We have no asset-value input at all** — no CMDB, no criticality source,
no business context. Our priority is therefore **detection-risk-only**.

Requirement: any surface displaying priority must disclose its basis.
Showing a priority that implies asset-awareness we do not have is
precisely the class of over-claim this programme exists to prevent.

## 5 · The provenance gap — highest value, lowest cost

Incidents exist in the operational store and **none carry a provenance
label**. Detections and canonical events *are* traceable to real
producer events; the incident set is not.

Consequence: an analyst — or a customer, or an investor — cannot tell a
real incident from one seeded during UI development. There is no
technical answer to *"is that a real incident?"*

**Required at `INTERNAL_ALPHA`:**

1. Add `provenance` to the incident model:
   `REAL_SENSOR_DERIVED` | `SEEDED_FOR_DEVELOPMENT` | `REPLAYED_CORPUS`.
2. Backfill by tracing each incident's linked detections to their raw
   events; anything untraceable is `SEEDED_FOR_DEVELOPMENT` — **never
   guessed into `REAL`**.
3. Enforce at write time; an unlabelled incident cannot be created.
4. Display it on the queue and detail surfaces.
5. Operational default becomes **real-evidence-only**; seeded incidents
   are quarantined to a test scope.

This is small, mechanical, and it is what converts the console from
"looks like a product" to "is demonstrably a product".

## 6 · Reporting

`memory/IR_REPORT_CONTRACT.md` is adopted as the frozen report contract.
A report may only contain evidence-backed statements and must inherit the
incident's provenance label — an exported report that cannot say whether
its incident was real is worse than no report.
