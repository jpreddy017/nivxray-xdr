<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

# TESTING GUIDE

Adopts `memory/CORPUS_VERSIONING.md`, `memory/evaluation_rubric.md`,
`memory/DEMO_PAYLOAD_BATTERY.md`, `memory/GOLDEN_CASE_SAMPLE1.md`.
Live inventory: `08_VALIDATION/GENERATED_PROOF_INVENTORY.md`.

## 1 · The test ladder

| Level | Proves | Can promote maturity? |
|---|---|---|
| unit | a function behaves | **no** |
| contract | an API honours its contract, including failure states | no |
| structural guard | a whole defect **class** cannot recur | no, but prevents regression |
| integration | components work together | no |
| **runtime proof** | the capability works on the real system | **yes** |
| **real-endpoint proof** | it works with evidence from a real machine | **yes** |
| end-to-end acceptance | the whole chain works on real data | **yes** |

**Passing unit tests cannot promote a capability or a stage.** This rule
exists because "330 tests pass" is not evidence that a product works.

## 2 · Test-only data — the hard boundary

Corpora (`DEMO_PAYLOAD_BATTERY`, `GOLDEN_CASE_SAMPLE1`, replay sets) are
**TEST-ONLY**. They may never be written to the operational
environment.

The current violation is the reason this rule is written down: the
operational store contains development-seeded incidents that are
**indistinguishable from real ones** because no provenance label exists.
Requirement: seeded data must be labelled at write time and confined to a
test scope (`02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` §5).

## 3 · Runtime proof scripts

A proof script must:

1. Run against the real running system, not mocks.
2. Assert **authoritative identifiers**, never counts. "Both returned 6
   rows" is not equivalence; "both returned the same 6 evidence IDs" is.
3. Assert the result is **non-empty**, so a pass cannot be vacuous.
4. Include **negative** gates — forged identifiers, cross-tenant
   principals, missing capability.
5. Assert cross-tenant non-disclosure: a foreign identifier must produce
   the **same observable failure class** as an unknown one.
6. Avoid mutating operational state; where a mutation is unavoidable,
   prove the property by **failure class** instead (e.g. an unobserved
   pid must fail on *target* identity, not on *enrolment* — reaching the
   target check at all proves the alias resolved, and no command is
   created).
7. Print a definitive `N PASS · M FAIL` line and exit non-zero on
   failure.
8. **Never fabricate an ID to satisfy a test.**

## 4 · Structural guards

For a defect class that has recurred, a fix is not enough — add a guard.
Design rules:

- Anchor on what a rename cannot hide (the store, the declared field),
  using **AST analysis, not text search**.
- Pin the enumerated live-site inventory, so a new site cannot bypass
  the invariant silently.
- Include a **negative meta-test**: a guard that matches nothing is
  worse than no guard, so assert the scanner still finds the known sites.
- Allow-list legitimate exceptions **with a written reason**, and assert
  the reason is non-trivial and the file still exists.
- **State the enforcement boundary in the guard's own docstring.** Static
  analysis cannot see runtime-assembled names or opaque filter dicts;
  those need runtime proof. No single layer may be presented as
  sufficient.

## 5 · Baselines

1. **No baseline resets.** A failing test is fixed or classified — never
   re-baselined away.
2. **No silent exclusions.** A skipped test is declared with a reason.
3. Known failures are **separately classified** and carried in the
   report every run, with the count stated (e.g. "340 passed, 3 failed —
   the same 3, cause unchanged").
4. A known failure may not be absorbed into an unrelated change. If new
   work turns out to cause one, **stop and report the dependency**.

## 6 · Regression discipline

Every change re-runs the full gate set and reports each result
individually. A drop in any gate is a regression until proven otherwise
— and *proven* means comparing against `git diff`, not asserting.

Precedent: a proof script dropped from 24/24 to 22/24 during an
unrelated change. The correct response was to verify against the diff
that the relevant code was untouched, identify it as **pre-existing
script drift** (the lane axis had legitimately changed shape in an
earlier phase), and **report it rather than quietly re-run or re-baseline
it**.

## 7 · Frontend testing

`data-testid` on every interactive element and every element showing
user-facing information. Kebab-case, function-named, unique.

State coverage is mandatory: a surface must be tested in **loading,
empty-real, named-absence, partial, stale, unauthorized and error**
states. Testing only the happy path is how a false-empty state reaches
production — the console once rendered "no records in scope" for an
identifier the backend had explicitly declared `ENDPOINT_NOT_RESOLVED`.

## 8 · Definition of tested

- [ ] contract tests cover every declared failure state
- [ ] a runtime proof asserts identifiers, non-emptiness and negatives
- [ ] cross-tenant non-disclosure asserted
- [ ] a recurring class is guarded structurally
- [ ] full gate set re-run; every known failure classified, none absorbed
- [ ] frontend states tested, not just the happy path
