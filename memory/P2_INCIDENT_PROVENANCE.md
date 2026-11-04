# P-2 · INCIDENT PROVENANCE — implementation report

**Date**: 2026-06 · **Scope**: step 1 of the approved sequence, ONLY.
**Status**: `REAL_RUNTIME_VERIFIED` — `scripts/p2_incident_provenance_proof.py`
**27 PASS · 0 FAIL**. **STOPPED before P0-3 as instructed.**

Authoritative documentation:
`docs/nivxray-xdr/02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` §5.

---

## 1 · The question this closes

*"Is that a real incident?"* previously had **no technical answer**.
Every incident now declares where it came from, what rule decided that,
and which artefact was traced.

## 2 · Closed vocabulary (owner-specified, all six)

`REAL_SENSOR_DERIVED` · `SEEDED_FOR_DEVELOPMENT` · `SYNTHETIC_TEST` ·
`REPLAY_DERIVED` · `MIXED_PROVENANCE` · `PROVENANCE_UNKNOWN`

`provenance_is_real` is true for **`REAL_SENSOR_DERIVED` only**. Each
class carries a written meaning published on the API so no consumer
invents its own interpretation.

## 3 · Never guessed — the owner's explicit rule, implemented

Backfill traces a **concrete artefact** per incident:
`xdr_incident.xdr_pipeline.trace_id` → `edr_raw_events` → is it
`source_kind=sensor` with a `sensor_version`?

| Outcome | Count | Basis recorded on every document |
|---|---:|---|
| `REAL_SENSOR_DERIVED` | **16** | traced to a raw event delivered by an authenticated sensor |
| `PROVENANCE_UNKNOWN` | **270** | 268: the raw event it was derived from **no longer exists**; 2: no `trace_id` at all |
| `SEEDED_FOR_DEVELOPMENT` **by inference** | **0** | **never inferred — only accepted when declared at write time** |

**270 incidents are `PROVENANCE_UNKNOWN` and that is the correct
answer.** They are not claimed fake and not claimed real. The label
states that the evidence needed to decide is gone.

Also classified: **285 `analysis_case` documents** — 168 attributed to a
test principal (`*@nivxray.local`) → `SYNTHETIC_TEST`; the remainder
`PROVENANCE_UNKNOWN` because whether a submitted payload came from a real
intrusion is recorded nowhere and is not inferred.

### Count correction the owner should note
I previously reported **572 incidents**. That conflated two different
objects sharing `workspace_cases`: **286 `xdr_incident`** and **285
`analysis_case`** (plus 1 untyped). The real incident count is **286**.
The generated reality matrix now reports them separately so the
conflation cannot recur.

## 4 · Write-time gate

`detection_content/xdr_incident.py::materialise_incident` is the **only**
creation site, so the gate there is the whole gate. An incident cannot be
created without a declared class **and** a recorded basis
(`ProvenanceError`). The label is read from the canonical event's own
recorded provenance — not inferred.

## 5 · Consolidation does not launder provenance

| Merge | Result |
|---|---|
| seeded + real | `MIXED_PROVENANCE` — **not** real |
| real + real | `REAL_SENSOR_DERIVED` |
| unknown + real | `PROVENANCE_UNKNOWN` — pre-existing evidence is still unaccounted for |
| replay + real | `MIXED_PROVENANCE` |

Every change appends a `provenance_change` entry to
`incident_state_history[]` — the existing append-only worklog. **No new
store was created.**

## 6 · Surfaces

- Queue row + detail: `provenance`, `provenance_basis`,
  `provenance_is_real`.
- `GET /api/incidents/provenance/summary` — distribution, published
  vocabulary, tenant-scoped.
- **UI**: new `Provenance` column, `ProvenanceChip`
  (`data-provenance=…`). Verified live: **269 chips rendered · 16 `REAL`
  · 253 `UNKNOWN`**.
- `PROVENANCE_UNKNOWN` is toned **neutral, not as an error**, because it
  is an honest absence rather than a fault.

## 7 · Proof — 27 gates

**A** closed vocabulary; undeclared class rejected; label without a basis
rejected; every class has a written meaning.
**B** write-time gate refuses: no provenance · undeclared class ·
class without basis.
**C** zero unlabelled `xdr_incident`s; zero labels without a basis.
**D** every `REAL` label names the sensor evidence it traced;
**untraceable → `UNKNOWN`, never seeded**; every `UNKNOWN` states why;
**every `REAL` label is falsifiable** — its traced raw event exists and
is sensor-attributed.
**E** the four merge rules.
**F** queue and detail agree; `provenance_is_real` true only for `REAL`.
**G** summary reconciles with the store; states that `UNKNOWN` is not a
claim of fabrication; publishes the vocabulary; another customer sees
only their own scope.

### A gate caught a real risk in my own proof
`D4` initially failed. Investigated before changing anything: **0 false
`REAL` labels** — all 16 trace to genuine sensor events, matched on
`raw_id`, while my gate had only checked `_id`. The **proof** was wrong,
not the data, and the proof was fixed rather than the assertion weakened.

## 8 · Regression

| Gate | Result |
|---|---|
| `p2_incident_provenance_proof` | **27 PASS · 0 FAIL** |
| `x1_x3_xdr_integration_proof` | **22/22** |
| `p0_w_incident_tenant_authorization_proof` | **25/25** |
| `test_p0_2c_alias_invariant` + `test_xdr_incident_queue` | **27 passed** |
| `test_xdr_mss` | **12 passed** |
| `docs_reconcile --gate` | **PASS · 0 violations** |

Note: the 2 previously-baselined queue/MSS failures now pass. They are
**data-dependent count assertions** — this is the data lining up, not a
fix, and it should not be recorded as one.

### The documentation gate caught me twice
1. Adding `/api/incidents/provenance/summary` moved the route count
   865 → 866 and **failed three authored documents** that hand-wrote it.
   Fixed by removing generated counts from authored prose and citing
   `REALITY_MATRIX.md` instead — the durable fix, not a number bump.
2. It surfaced the 572-vs-286 conflation described in §3.

## 9 · Files

`backend/services/incident_provenance.py` (new) ·
`backend/detection_content/xdr_incident.py` (write-time gate + merge) ·
`backend/routers/incidents.py` (projections + summary endpoint) ·
`scripts/backfill_incident_provenance.py` (new, `--dry-run`/`--apply`) ·
`scripts/p2_incident_provenance_proof.py` (new) ·
`apps/nivxray-xdr/src/xdr/components/ProvenanceChip.jsx` (new) ·
`.../xdr/pages/incidents/QueueTable.jsx` · `scripts/docs_reconcile.py`
(incident counts split, provenance surfaced) · 4 authoritative docs
updated.

## 10 · Not done, deliberately

Quarantining non-real data out of the operational scope (GA gate A1
remains `PARTIAL`); typed worklog entry kinds; P0-3 and everything after
it. **Stopped for owner approval.**
