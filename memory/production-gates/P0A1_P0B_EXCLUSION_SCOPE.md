# P0-A.1 + P0-B · EVIDENCE PACKAGE

Owner directive *OWNER REVIEW — P0-A ACCEPTED / NEXT CONTROLLED PHASE*.
Closed 2026-09-26. **P0-C was not started.** The P0-A security contract
was not weakened or bypassed anywhere.

---

# GATE P0-A.1 · SECURITY HARNESS INTEGRITY

## PRECONDITION
`tests/test_edr_route_tenant_authority.py` — **146 failed / 170 passed**.

## CAUSE (triaged, not dismissed)
The harness is table-driven off the LIVE route table. Three kinds of
failure were possible; the measured cause was **exactly one** of them:

* **Stale test inventory — CONFIRMED, 145 of 146.** 28 `TENANT_SCOPED`
  operations added in the Policy / Exclusions / Events / Saved-Views /
  Audit / Connector-deployment wave had no probe in `SAMPLES`, so every
  authority clause raised `KeyError` before reaching the product
  (28 ops × 5 clauses), plus 4 `PRODUCT_METADATA` operations missing from
  `_METADATA_URLS`.
* **Coverage-gap assertion — CONFIRMED, 1 of 146.**
  `test_every_tenant_scoped_operation_has_a_concrete_probe` failed by
  design: it is the clause that refuses to let an unprobed route be
  called "tested". It was doing its job.
* **Tenant-isolation defects — NONE FOUND.** With the probes added, all
  28 routes pass every clause unchanged: no-tenant → 403
  `TENANT_REQUIRED`; unregistered → 403 `TENANT_NOT_FOUND`; archived →
  403 `TENANT_NOT_ACTIVE`; registered ACTIVE → answered; and the
  header-is-never-ignored clause (three distinct outcomes) holds. So the
  product authority was correct and only the harness was blind.

## CHANGE
`tests/test_edr_route_tenant_authority.py` only — 28 parameter-complete
`SAMPLES` probes (mutating ones driven for refusal cases only, so the
suite still creates no policy, exclusion, view or deployment) and 4
`_METADATA_URLS` entries for the connector release catalog and the
exclusion taxonomy (metadata probes additionally assert the response is
byte-identical across tenants, i.e. that it really is product metadata).
**No assertion was weakened, deleted or relaxed.** No product code was
changed for this gate.

## RESULT
**292 passed · 0 failed · 0 unexplained.** (One intermediate run reported
270 errors `ConnectionRefused` — the backend was mid hot-reload; re-run
clean, and the suite reaches the preview edge, not localhost, when
`REACT_APP_BACKEND_URL` is set.)

---

# P0-B · EXCLUSION ENFORCEMENT SCOPE

## PRECONDITION
The only endpoint exclusion engine was `endpoint.collection`: any
approved exclusion dropped the matching event before the durable outbox.
Tuning out a false positive and destroying the evidence were the same
action.

## WHAT WAS BUILT
A new, explicit axis `enforcement_scope`, orthogonal to the existing
`scope` (which says WHERE — tenant / group / endpoint):

| Scope | Suppresses | Evidence | Default |
|---|---|---|---|
| `DETECTION` | the verdict only | **retained** — collected, delivered, in the trajectory, re-evaluable | **yes** |
| `COLLECTION` | collection itself, at the endpoint | destroyed at source, unrecoverable | no — explicit |
| `PREVENTION` | nothing today | n/a | no — **refused** by the connector |

* `ExclusionDraft.enforcement_scope` defaults to `DETECTION`, so ordinary
  analyst tuning no longer costs telemetry.
* The endpoint evaluator (`EVALUATOR_VERSION 1.1.0`, one canonical file,
  byte-identical in both connector releases) drops **only**
  `COLLECTION` matches. A `DETECTION` match is delivered and annotated
  (`endpoint_exclusion_matches[]`: exclusion id, scope, matched
  attribute, value digest) — the endpoint states what it matched and does
  **not** decide the verdict.
* The journal now separates `collection_suppressed_count` from
  `detection_suppression_requested_count` and records
  `evidence_retained`. The report still carries digests only, never the
  excluded content.
* `PREVENTION` scope → `REFUSED_UNSUPPORTED_SCOPE`, reported, never
  silently skipped.
* Server fabric (`enforcement.decide`) is scope-aware: `COLLECTION` and
  `DETECTION` suppress the verdict; an exclusion aimed only at
  `PREVENTION` must never become detection blindness, so it is skipped
  and the engine runs. The decision carries `enforcement_scope`,
  `enforcement_scope_basis` and `evidence_retained`.
* The policy delivered to the connector now carries `enforcement_scope`
  **and** `affected_engines` — a connector that is not told the scope can
  only guess, and a guess here is either lost evidence or an unenforced
  exclusion.
* Two-operator approval, inert-until-approved, revocation, scope
  windows and the enforcement-proof surface are **untouched**.

## MIGRATION — no silent semantic change
Nothing in the database was mutated. An exclusion with no declared scope
resolves at read time to `COLLECTION` with basis
`LEGACY_PRE_P0B_COLLECTION_PRESERVED`, because that is exactly what it
already did. Verified live on the preview host: **all 6 existing
exclusions** read `COLLECTION · LEGACY_PRE_P0B_COLLECTION_PRESERVED ·
evidence_retained=false`. Only newly created exclusions default to
`DETECTION`. Every read (`GET /api/edr/exclusions`) discloses the scope,
the basis and a plain-language impact statement, and
`GET /api/edr/exclusions/taxonomy` publishes the vocabulary plus the
migration rule so the console never hardcodes it.

## FILES CHANGED
`backend/edr_plane/exclusions/contracts.py` (EnforcementScope,
`enforcement_scope_of`, legacy basis, `DETECTION_SUPPRESSING_SCOPES`,
draft field) · `backend/edr_plane/exclusions/store.py` (persist scope +
basis) · `backend/edr_plane/exclusions/enforcement.py` (scope-aware
decision + disclosure fields) · `backend/routers/edr_policies.py`
(delivery projection) · `backend/routers/edr_exclusions.py` (read
disclosure + taxonomy) · `backend/edr_plane/connector/catalog.py`
(release notes now state scope behaviour truthfully) ·
`agents/_shared/nivxforge_exclusions.py` + both shipped copies
(byte-identical) · both sensors (`collection_suppressed_at_endpoint`, an
honest label for a count that now means only "this evidence does not
exist").

## TESTS — `backend/tests/edr/test_p0b_exclusion_scope.py` (11 new)
1. **DETECTION** → `suppressed == 0`, both events delivered, the matching
   event carries the enforcement annotation, journal records
   `detection_suppression_requested_count=1`,
   `collection_suppressed_count=0`, `evidence_retained=true`, and the
   cleartext value is still absent from the report.
2. **DETECTION verdict suppression** proven separately on the server
   engine: `excluded=true`, `SERVER_EXCLUSION_APPLIED`,
   `evidence_retained=true`.
3. **Explicit COLLECTION** → `suppressed == 1`, the matching event is
   never delivered, `evidence_retained=false`.
4. COLLECTION also suppresses the verdict.
5. **Legacy scope-less** exclusion keeps COLLECTION semantics and reports
   the legacy basis.
6. A **new** draft defaults to DETECTION.
7. **PREVENTION** → `REFUSED_UNSUPPORTED_SCOPE`, nothing suppressed.
8. A PREVENTION-only exclusion **never** becomes detection blindness.
9-10. Both shipped evaluators byte-identical to the canonical source.
11. The policy delivery projection carries the scope.

## RESULT
`tests/edr` · **471 passed · 1 skipped · 0 failed** (P0-A baseline
460/1/0, +11). Gate 7's 23 existing endpoint-enforcement tests pass
unchanged, so the exclusion authority and the endpoint enforcement proof
are intact. `tests/test_edr_route_tenant_authority.py` · 292 passed.
Live verification on the preview host as recorded under MIGRATION.

## REMAINING RISKS
1. **No UI control for the scope yet.** The API defaults to `DETECTION`
   and discloses the scope on every read, but the console cannot yet
   choose `COLLECTION` deliberately — an exclusions-UI slice.
2. **A DETECTION-scoped exclusion costs storage**, by design: the evidence
   is retained, so high-volume tuning now grows `edr_raw_events` where it
   previously silenced it. Retention policy is unaddressed.
3. The endpoint's `endpoint_exclusion_matches` annotation is evidence of
   what the endpoint did; the server remains the only verdict authority
   (deliberate — no new trust path was created).
4. `COLLECTION` remains irreversible by nature. It is now explicit and
   disclosed; it is not, and cannot be, recoverable.
5. Running connectors carry evaluator 1.0.0 until they are updated; until
   then they treat every exclusion as COLLECTION (the legacy behaviour
   the platform now states explicitly rather than assuming).
