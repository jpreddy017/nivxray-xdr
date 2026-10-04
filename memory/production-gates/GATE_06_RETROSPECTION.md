# GATE 6 · RETROSPECTION — DESIGN (design only · no historical mutation)

Status: **IN_PROGRESS** · design frozen here. Implementation is blocked
on the Gate 3 findings store and is deliberately NOT started. **No
historical evidence is mutated, replayed or re-labelled by this
document.**

Owner constraint, restated: *a verdict discovered today must never
rewrite history as though it existed when the original event occurred.*

## 1 · What retrospection is, precisely

New knowledge arrives **after** evidence was observed:

* reputation change (a hash previously unknown is now malicious);
* new/updated IOC or intel feed;
* new or corrected deterministic rule;
* new model version, or a corrected model;
* analyst decision (this file is authorised in this environment).

Retrospection re-evaluates **retained evidence** under the new knowledge
and produces **new findings**, which may produce a **new verdict** —
without altering the original observation, the original finding, or the
original verdict's history.

## 2 · The two clocks that make this honest

Every retrospective finding carries **both**:

* `observed_at` — the activity time of the evidence (unchanged, ever);
* `evaluation_time` — when THIS analysis happened.

A surface must render a retrospective finding as
*"discovered on <evaluation_time>, about activity on <observed_at>"*.
It may never place the discovery on the timeline at the activity time,
and it may never claim the platform knew it then. The trajectory
timeline already separates activity time from ingest time and refuses to
present one as the other — retrospection extends the same rule to
analysis time.

## 3 · Data model (additive only)

```
RetrospectionRun
  run_id, tenant_id
  trigger      REPUTATION_CHANGE | INTEL_UPDATE | RULE_CHANGE |
               MODEL_VERSION | ANALYST_DECISION
  trigger_ref  the intel/rule/model identity that changed, with version
  corpus       {evidence_window, evidence_count, selector}
  started_at, finished_at, outcome
  findings_emitted, evidence_examined, evidence_skipped + reason
```

A retrospective `Finding` (same frozen contract as Gate 3) additionally
carries:

```
retrospection = {
  run_id, trigger, trigger_ref,
  of_finding_id | None,      # the earlier finding this supersedes
  basis: "the evidence is unchanged; the knowledge applied to it changed"
}
```

**Nothing is updated in place.** The earlier finding transitions to
`SUPERSEDED` and keeps its own `evaluation_time`, score, features and
analyzer version. Superseding is a *link*, not an edit: the original
remains readable and citable forever, which is what preserves
provenance.

The original **raw** and **canonical** evidence rows are never written
to by retrospection. Not one field.

## 4 · Verdict interaction

* A retrospective finding enters the SAME verdict composition as a
  live finding; there is no second verdict authority.
* If the verdict changes, the verdict history records:
  previous label, new label, the run that caused it, and the findings
  that moved it. The previous verdict is not deleted and is not
  described as having been wrong at the time — it was correct under the
  knowledge then available, and the record says so.
* Where the retrospective and the original assessment disagree, both are
  preserved and the difference is disclosed (existing `VERDICT AUTHORITY
  RULE` in the PRD applies unchanged).

## 5 · Corpus selection (bounded, never "the whole estate")

A run declares its corpus and reports what it could not examine:

* time window (retention-bounded);
* selector (the artifact identity / rule scope / model input class the
  trigger applies to);
* tenant partition — one run never crosses tenants.

Evidence that is outside retention is reported as
`EVIDENCE_NOT_RETAINED`, never as "no retrospective finding". A
retrospection result that says *"27,400 records examined, 900 skipped
because they predate retention"* is a truthful result; *"no matches"*
would be a lie.

## 6 · Execution properties

* **Idempotent** — `finding_id` is content-addressed over
  (analyzer, version, evidence_refs, feature_digest), so re-running the
  same trigger over the same corpus emits no duplicates.
* **Resumable** — a run persists its cursor; a killed worker resumes and
  reports the gap rather than silently restarting.
* **Bounded** — off the request path entirely; rate- and
  concurrency-limited so a retrospection storm cannot degrade live
  detection or the analyst console.
* **Auditable** — every run is an audit record: who/what triggered it,
  what it examined, what it emitted.

## 7 · UI contract (for the wave that implements it)

* A detection list must be able to answer *"was this found live or
  retrospectively?"* — a `RETROSPECTIVE` token on the row, with the run
  and the trigger behind it.
* A device trajectory must be able to re-colour a historical event as
  malicious **and** state when that became known.
* A superseded finding stays reachable from the finding that superseded
  it.
* No surface may aggregate retrospective and live findings into one
  number without declaring the split.

## 8 · Explicit prerequisites (so this gate is not started prematurely)

1. Gate 3 findings store, live and populated.
2. A declared retention/tier policy (the Windows gap analysis records
   this as G8 — retrospection over un-retained evidence is impossible).
3. Reputation/intel change events available as *triggers* with versions,
   not as ambient state.
4. Verdict-history persistence (the verdict plane today records the
   current verdict, not its lineage).
