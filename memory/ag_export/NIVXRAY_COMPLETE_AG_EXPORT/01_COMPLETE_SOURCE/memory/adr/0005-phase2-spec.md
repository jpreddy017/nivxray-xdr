# ADR-005 · Phase 2 Specification — Canonical SSOT Authoritative Tier

- **Status**: **AUTHORISED for implementation** (owner 2026-08-10)
- **Prerequisites**: Phase 1 CLOSED (`/app/memory/adr/0005-phase1-signoff.md`)
- **Owner decisions carried in**: D2-d (two-tier: authoritative graph + projection tier), D3-z (ReasoningStep + Provenance envelope), D6-r (recursive by reference), D9-both (schema versioning; default back-projectable)
- **Sample1 record**: **NEVER modified** (R-G1..R-G6, IX-1). Any reference to `Sample.docx` below means NEW ingestion.

---

## 1. Scope (owner-authorised, verbatim)

### Allowed in Phase 2
- Canonical SSOT authoritative-tier schema (new module namespace)
- Immutable SSOT store (new collection alongside existing `investigation_ssot`)
- `ssot_ref` type + dereferencing helper
- Provenance-mandatory append semantics (D3-z)
- Fingerprint-addressable canonical JSON serialisation
- Recursive `artifacts[].investigation_ref → ssot_ref` (D6-r)
- Schema versioning (D9-both)
- Structural separation of **authoritative** fields from **projection** fields (projections empty in Phase 2 — Phase 4 populates)
- Unit + integration + contract + determinism + append-only + recursion tests

### NOT allowed in Phase 2
- ❌ Route changes (no router file modified)
- ❌ Workspace UI changes
- ❌ `routers/cases.py` modification
- ❌ Engine A / Verdict changes
- ❌ Wave 1 modification (existing records untouched)
- ❌ **Existing SSOT changes** (`InvestigationModel`, `die-Canonical`, ADR-0014 CIO, North Star CIO, `EvidenceBundle` all stay untouched)
- ❌ Populating the projection fields (`activity.*`, `iocs.*`, `attck`, `attack_chain`, `attack_story`, `analyst_summary`, `executive_summary`, `recommendations`, `reports.*`, `timeline`, `verdict.contributors`) — Phase 4 territory
- ❌ **Copying one existing SSOT wholesale as the canonical SSOT** — build from ADR-005 contract, using existing objects as donors only where structurally appropriate
- ❌ DOCXAdapter changes
- ❌ ADR-004 Step 2 work
- ❌ Sample1 modification of any kind

## 2. Deliverables

```
backend/canonical/ssot/
├── __init__.py                          Public API — AuthoritativeSSOT, SSOTStore, ssot_ref, append()
├── models.py                            Dataclasses per ADR-005 §4.1 (authoritative + projection buckets)
├── authoritative.py                     AuthoritativeSSOT class with append() + freeze semantics
├── store.py                             Immutable content-addressed store (new Mongo collection)
├── ssot_ref.py                          ssot_ref type + validation
└── projections.py                       Empty projection scaffolding (Phase 4 populates)

backend/tests/canonical/ssot/
├── test_ssot_contract.py                T2.1 · schema vs ADR-005 §4.1 minimum
├── test_ssot_provenance.py              T2.2 · Provenance mandatory on every append
├── test_ssot_append_only.py             T2.3 · mutation rejected; only appends succeed
├── test_ssot_determinism.py             T2.4 · canonical JSON + sha256 fingerprint
├── test_ssot_ref_recursion.py           T2.5 · ssot_ref roundtrip; nested SSOT storage
├── test_ssot_projection_boundary.py     T2.6 · projection fields empty; authoritative populated
├── test_ssot_isolation.py               T2.7 · no existing consumer imports the new tier
└── test_ssot_sample_acceptance.py       A2.1 + A2.2 + A2.3
```

## 3. Design constraints

- **Structural donor policy (from ADR-005 §6)**: `evidence_graph` + `reasoning_steps` donated by ADR-0014 CIO shape; per-entry `Provenance{engine, version, at, upstream_evidence_ids[]}` invariant donated by North Star CIO. No existing SSOT is copied wholesale — the authoritative tier is a **new** object built from the ADR-005 §4.1 contract.
- **Authoritative fields (populated in Phase 2)**: `id, created_at, updated_at, schema_version, source, input_raw, input_profile, input_health, iue_decision, plan, execution_trace, artifacts[], evidence_graph{nodes, edges}, reasoning_steps, provenance, context.historical, metadata`.
- **Projection fields (declared but EMPTY in Phase 2)**: `activity{processes, files, network, registry, auth}, iocs{urls, ips, domains, emails, hashes, files, registry, user_agents, bitcoin_addresses}, threat_intel, attck, attack_chain, attack_story, verdict, recommendations, analyst_summary, executive_summary, reports, timeline`.
- **Append-only**: `AuthoritativeSSOT.append(bucket, entry, provenance)` is the ONLY mutation API. Direct field assignment on populated collections raises. Frozen dataclass fields are used where possible.
- **Fingerprint-addressable**: `AuthoritativeSSOT.fingerprint()` returns sha256 of canonical JSON (matches `canonical.iue.determinism` policy).
- **Recursion (D6-r)**: `artifacts[].investigation_ref` holds an `ssot_ref` string; dereferenced via `SSOTStore.dereference(ref) → AuthoritativeSSOT` returns a byte-identical child.
- **Schema versioning (D9-both)**: `schema_version = "2.0.0-phase2"` — a new major indicating the canonical tier. Backwards-compatibility of readers: existing `investigation_ssot` collection is not read from and not written to by Phase 2 code.

## 4. Tests / gates

| Test | File | Gate |
|---|---|---|
| T2.1 contract | `test_ssot_contract.py` | ADR-005 §4.1 25+ buckets declared |
| T2.2 provenance | `test_ssot_provenance.py` | no entry accepted without envelope |
| T2.3 append-only | `test_ssot_append_only.py` | mutation raises; only append succeeds |
| T2.4 determinism | `test_ssot_determinism.py` | canonical JSON stable; sha256 stable |
| T2.5 ssot_ref | `test_ssot_ref_recursion.py` | roundtrip byte-identical; nested SSOTs storable |
| T2.6 projection boundary | `test_ssot_projection_boundary.py` | projections empty; authoritative populated |
| T2.7 isolation | `test_ssot_isolation.py` | no existing consumer imports canonical.ssot |
| A2.1 Sample.docx SSOT | `test_ssot_sample_acceptance.py::test_a2_1_*` | minimal Sample.docx SSOT constructs + validates |
| A2.2 store roundtrip | `test_ssot_sample_acceptance.py::test_a2_2_*` | store + dereference byte-identical |
| A2.3 Sample1 fingerprint | `test_ssot_sample_acceptance.py::test_a2_3_*` | `5b4337d5…08261d` unchanged |

## 5. Explicit exclusions

- No projection function is authored (Phase 4).
- No executor is authored (Phase 3).
- No route is added or modified.
- The `investigation_ssot` legacy collection is not read from and not written to.
- The existing `workspace_cases.ssot` field is not read from and not written to.

## 6. Exit condition

1. T2.1..T2.7 + A2.1..A2.3 green.
2. Phase 2 report at `/app/memory/adr/0005-phase2-report.md` records: files added, test results, Sample.docx canonical SSOT fingerprint, ssot_ref roundtrip proof, Sample1 fingerprint re-verification, and `git diff --name-only` proof of isolation.
3. **STOP.** Owner review before Phase 3.
