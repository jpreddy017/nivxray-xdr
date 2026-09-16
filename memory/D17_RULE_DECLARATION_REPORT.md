# D17 — RULE DECLARATION CONTRACT + BATCH 1

Date: 2026-09-15 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d17_rule_declaration_contract.py -q
cd /app          && python scripts/p0_d17_rule_declaration_live_proof.py
```

## RESULT: **PASS**

| Proof | Result |
|---|---|
| `tests/test_d17_rule_declaration_contract.py` | **84 passed** |
| `scripts/p0_d17_rule_declaration_live_proof.py` (real HTTP, preview) | **PASS** — declared rule → real incident → complete persisted citation |
| `tests/test_d8_detection_citations.py` | **18 passed** (was 17 passed / 1 failed — see "defect found and fixed") |
| Regression (21 files: D8, D11–D17, ingest, pipeline, EDR, rounds) | **544 passed**, 12 failures — all pre-existing and verified identical on a stashed clean tree |

## THE CONTRACT (now enforceable, not aspirational)

D8 built citations from DECLARED conditions and refused to infer which field
caused a match. It also left declaring **optional in practice**: 30 of 36
runtime rules declared nothing, and nothing stopped a new rule from joining
them. `backend/detection_content/library/declaration_contract.py` closes
that:

| Rule | Enforced by |
|---|---|
| a rule that declares nothing must be on the FROZEN `DECLARATION_DEBT` ledger | `validate_rule()` → gate test fails otherwise |
| a declaration may cite only paths that exist in the canonical evidence model | `canonical_fields()`, **derived from `CanonicalTelemetryEvent` itself**, so the list cannot drift |
| every condition needs a supported operator and a human note | `validate_rule()` |
| a declaration must EXPLAIN the rule's own positive fixtures | `citation_proof()` → `declared_but_unexplained` must be empty |
| declaring must never change what a rule matches | per-fixture predicate assertions |

`report()` gives the operator-facing truth: coverage, the ledger, contract
problems, unexplained declarations, telemetry gaps and known fixture defects.

**A new undeclared rule now fails the gate.** That is the "prevents
undeclared evaluated fields from silently entering production" requirement,
and it is proved by a test that strips a declaration and asserts the refusal.

## BATCH 1 — the Windows/ESXi endpoint command-line family (14 rules)

`DET-EX-002` · `DET-EX-003` · `DET-EX-004` · `DET-EX-005` · `DET-PS-002` ·
`DET-PS-003` · `DET-DE-002` · `DET-CR-001` · `DET-CR-002` · `DET-DS-001` ·
`DET-LM-001` · `DET-CC-001` · `DET-IM-001` · `DET-IM-003`

One coherent family, one reviewable diff: every rule decides on
`process.command_line` and/or `process.executable_path`, which is exactly
what the canonical `process` entity carries.

**Declaration coverage: 6/36 → 20/36.** `rule_version` moved `1 → 2` on every
batch rule, because a declaration change is a rule change and a stored
citation must be tied to the declaration that produced it.

Three new operators exist because the predicates are case-insensitive:
`contains_ci`, `contains_any_ci`, `contains_all_ci`, plus
`basename_in_ci` / `basename_contains_any_ci` for Windows paths. Without them
a declaration would report `NO_MATCH` on the very event that fired the rule —
an approximate declaration is a wrong citation.

Canonical-shaped fixtures were added per batch rule (`positive_canonical` /
`negative_canonical`); the pre-existing Sysmon-shaped fixtures are **kept**,
so both shapes stay proved.

## WHAT WAS NOT DECLARED, AND WHY (named, not disguised)

* **Telemetry gaps** (`TELEMETRY_GAPS`): `DET-PS-001` evaluates
  `registry.path` — there is no registry entity in the canonical model at
  all. Declaring it against `process.command_line` would describe a rule NivX
  cannot actually cite, so it stays on the debt ledger with the gap recorded.
  `DET-CR-001` / `DET-LM-001` have secondary gaps (`process.target`,
  `service_name`) and are declared on the fields that DO exist.
* **16 rules remain on the frozen ledger** — content/behaviour lane (8) and
  cloud/identity event lane (7) families, plus `DET-PS-001`. They produce no
  citation and say so. Next batches: cloud/identity event lane, then
  content/behaviour.

## TWO DEFECTS THE GATE FOUND

1. **`DET-CR-002` fixture defect — reported, deliberately NOT fixed.** Its
   authored positive fixture (`ntdsutil "ac i ntds" "ifm" "create full
   C:\temp"`) does **not** satisfy its own predicate, which requires the
   literal `ntds.dit`. Real-world ntdsutil IFM extraction does not name
   `ntds.dit`, so this is a **predicate coverage gap: the rule under-matches
   the technique it advertises.** Widening the predicate changes detection
   behaviour, which D17 must not do — it is recorded verbatim in
   `KNOWN_FIXTURE_DEFECTS` and asserted by a test, so it cannot be forgotten
   and cannot be silently "fixed" without updating the ledger.
2. **`DET-EX-006` declared-but-unexplained — fixed.** Declared back in D8,
   but its only positive fixture was Sysmon-shaped, so the declared canonical
   field was ABSENT and the citation explained nothing. The declaration was
   right; the proof was missing. A canonical fixture was added. No predicate,
   condition or version change.
3. **Orphaned citations in the preview databases — fixed at the root.**
   `test_d8_detection_citations.py::test_persisted_citations_are_retrievable`
   was failing because earlier suites deleted their canonical evidence but
   kept the citations pointing at it (299 orphan rows across
   `test_database` and `nivxray_ci_local`). Teardown in
   `test_p0_ingest_idempotency`, `test_p0_dedupe_hardening` and
   `tests/edr/test_p0_f_endpoint_detection` now removes citations with the
   evidence they cite, and the stale rows were purged. The D8 suite is green
   and stays green in a combined run.

## LIVE END-TO-END (preview, real HTTP)

A Sysmon process-creation document declaring `microsoft-sysmon` →
`vssadmin delete shadows /all /quiet` → `DET-IM-001` MATCH → verdict
MALICIOUS(80) → incident materialised → persisted citation:

```
declaration_state   DECLARED
completeness        CITED
rule_version        2
matched_conditions  cmd.vssadmin · cmd.delete · cmd.shadow_target
                    all on process.command_line, observed value = the exact
                    command line the source sent
evidence_ref        resolves to canonical evidence that still holds it
```

An undeclared rule in the same database (`DET-EX-001`) still cites nothing
and says why.

**TEST/SYNTHETIC payloads. Nothing deployed, no protected branch touched.**
