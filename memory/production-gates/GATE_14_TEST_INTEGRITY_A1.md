# GATE 14 (partial) · TEST INTEGRITY · A1 CAMPAIGN STORY REGRESSION — **CLOSED**

Owner instruction: determine whether the failure is a legitimate
regression caused by the trajectory optimisation or an obsolete test
assumption. **Do not merely modify the assertion until green.**

## What was actually failing

The handoff named `test_p0_f7_campaign_story.py::
test_missing_canonical_identity_is_named_not_invented`. Reproduction
showed **two different defects**, and **neither was caused by the
trajectory optimisation**:

### A1-a · `test_p0_f7_campaign_story.py` — 9 tests · TEST INFRASTRUCTURE

In isolation the file passed 9/9. Under the repository's parallel runner
(`pytest-xdist`, `gw0…`) 9/9 **failed** with:

```
pymongo.errors.DuplicateKeyError: E11000 duplicate key error collection:
test_database.workspace_cases index: uniq_incident_number
dup key: { incident_number: "INC000001000" }
```

`_Scope` minted a unique tenant, endpoint and incident id per test but a
**literal** `incident_number` (`INC000000999` / `INC000001000`), and
`workspace_cases` carries a UNIQUE index on that field. Two tests of the
same file running concurrently — or one run against a database that
already held the number — collided on insert, so the story was never
built and every assertion downstream failed. The `_insert_one` trace in
the handoff is this, not the trajectory worker.

**Fix:** `incident_number` is derived per scope
(`f"INC-T-{uuid4().hex[:16].upper()}"`). No assertion was weakened; the
campaign-story semantics are untouched.

### A1-b · `test_p0_f4_endpoint_process_tree.py` — 3 tests · REAL, OBSOLETE PREMISE

```
KeyError: 'proc_root'
AssertionError: assert 'ENDPOINT_NOT_RESOLVED' == 'no_matching_evidence'
```

`_project_endpoint_process_tree(endpoint_id, hours, scope=None)` no
longer queries the evidence store with the raw string the caller
supplied. Since P0-2C it resolves endpoint identity **under the caller's
own scope** through the single authority
(`services.edr.endpoint_query.resolve_endpoint` →
`services.edr.device_identity`), and an identifier that nothing
authorised resolves to returns the `ENDPOINT_NOT_RESOLVED` envelope
instead of an empty tree. The test seeded observations for a fresh tenant
and then called the projection with **no scope**, which correctly means
*"authorised for nothing"*.

So the product is right and the test premise was obsolete. The premise —
not the assertions — was corrected, and the two honest empty states are
now asserted **separately** so the distinction cannot silently rot:

* nothing authorised resolves the reference → `ENDPOINT_NOT_RESOLVED`
  (`test_an_unknown_endpoint_yields_no_fabricated_tree`);
* the endpoint resolved and holds no process evidence →
  `no_matching_evidence` / `evidence_outside_window`
  (`test_a_resolved_endpoint_with_no_process_evidence_says_so`, new);
* **widening identity never widens authorisation** — a real, seeded
  endpoint read under a FOREIGN tenant scope still returns
  `ENDPOINT_NOT_RESOLVED`
  (`test_an_authorised_scope_is_required_even_for_a_real_endpoint`, new).

The ghost-parent invariants, the `counts` assertion
(`observed 3 · ghost_parents 1 · roots 2`) and the pivot-required route
assertion are unchanged.

## Proof

```
$ python -m pytest tests/edr/test_p0_f7_campaign_story.py -q     → 9 passed
$ python -m pytest tests/edr/test_p0_f4_endpoint_process_tree.py -q → 6 passed
$ python -m pytest tests/edr -q
  360 passed, 13 failed, 1 skipped          (was 347 passed / 24 failed)
```

All 13 remaining failures are the pre-existing `TEST_DEFECT_STALE`
live-contract suites itemised in `MASTER_GATE_INDEX.md` (hard-coded
catalog counts, pre-D15 refusal shapes). They are unrelated to this
session's changes: the only backend files touched were the two test
files above.

## Trajectory optimisation verdict

`edr_plane/trajectory_window.py` and its background worker are **not
implicated**. The bounded projection continues to report
`state: BOUNDED_RECENT · observations_projected: 4000 ·
observations_all_time: 207,953 · complete_projection:
WARMING_IN_BACKGROUND`, and its own suites are green. Measurements are
in `GATE_10_SCALE_AND_PERFORMANCE.md`.
