<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

# DEVELOPMENT GUIDE

Adopts `memory/DEVELOPING_V2.md`; governance from
`memory/GOVERNANCE_RULES.md`, `memory/GOVERNANCE.md`,
`memory/MASTER_GATE.md`.

## 1 · The order of work — non-negotiable

```
EVIDENCE → CAPABILITY → CONTRACT → API → REAL IMPLEMENTATION
   → TESTS → RUNTIME PROOF → UI → DOCUMENTATION → RELEASE GATE
```

Never:

```
UI → fake data → stub backend → claim complete
```

This is adopted on our own evidence, not by imitation: this repository
has 865 API routes against a small operational core, and the recurring
defect class has been *surfaces asserting more than their API can prove*.

## 2 · Before building anything

```
SEARCH → TRACE → CLASSIFY → ADOPT → WIRE → EXTEND
```

`BUILD` only when repository **and** runtime evidence prove the
capability does not exist. Check first:
`08_VALIDATION/GENERATED_ENGINE_REGISTRY.md`,
`GENERATED_ROUTE_INVENTORY.md`, `GENERATED_CAPABILITY_MATRIX.md`,
`02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md`.

**Never create a second SSOT.** Concrete precedent: a parallel worklog
store was proposed, audited and rejected — `incident_state_history[]`
remains the only worklog. The same rule killed a second identity
resolver.

## 3 · The architecture lock

XDR owns cross-domain correlation, investigation, intelligence,
incidents, prioritisation and orchestration. EDR owns endpoint
acquisition, endpoint detections, trajectory, process tree, live endpoint
evidence and endpoint response execution/verification. **XDR may
orchestrate EDR; it must never duplicate it.**

## 4 · Honesty rules (these are the product)

1. **Never fabricate operational data.** No seeded incidents, alerts,
   counts or metrics in the operational environment. Corpora are
   test-only.
2. **Name the absence.** Every failure resolves to a named state, never
   to an empty success. Unqueried ≠ not seen. Provider down ≠ `clean`.
   Unresolvable identifier ≠ empty result.
3. **No claim without proof.** A capability may not be documented
   `REAL_RUNTIME_VERIFIED` without a reproducing script.
4. **Never simulate a control action.** If the environment cannot
   perform it, the state is `CAPABILITY_UNAVAILABLE` /
   `BLOCKED_ENVIRONMENT`.
5. **No client-side truth.** No component may invent detections, counts,
   incidents, integration status, response status or severity, or make an
   authorisation decision.
6. **Derived ≠ authoritative.** A derived store must be rebuildable from
   its authority; if it is not, it is secretly authoritative.

## 5 · Invariants: guard them, don't review them

The programme's clearest lesson. The endpoint-identity defect was fixed
correctly **three times** and recurred each time, because each fix was
local. It stopped when it became a contract with a guard.

Pattern to follow:

1. **Declare the contract in code** — e.g. `ENDPOINT_KEYED_STORES` names
   every endpoint-keyed store and its identity fields. An undeclared
   store cannot be queried.
2. **Guard structurally, not textually** — anchor on things a rename
   cannot hide (the *store* and its *declared field*), using AST
   analysis, not grep.
3. **Pin the live-site inventory** so a new surface cannot be added
   without resolution.
4. **Prove at runtime** — assert identical evidence **IDs**, never
   counts.
5. **State the enforcement boundary honestly** — static analysis cannot
   see runtime-assembled names; say so in the guard itself rather than
   letting a reader over-trust it.

Next invariant to guard: **tenant scoping on every route.**

## 6 · Adding a backend capability

1. Find the owning component; if none exists, stop and update
   `COMPONENT_ARCHITECTURE.md` first.
2. Name the SSOT. Reuse it.
3. Define the contract, including **every failure state**.
4. Route under `/api`, tenant-scoped, RBAC-gated.
5. Never query an endpoint-keyed store with a raw caller identifier —
   resolve through `services/edr/endpoint_query.py`.
6. Return named absences, never misleading empties.
7. Register the capability with honest status fields.
8. Tests + a runtime proof script.
9. Only then build the surface.

## 7 · Adding a surface

1. Identify authoritative APIs. If a value has no API, **stop**.
2. Implement every state in `03_DESIGN/STATES_AND_ERRORS.md`.
3. Render the backend's declared state; never reinterpret an absence.
   Reference: `EndpointNotResolved.jsx`.
4. `data-testid` on every interactive element and every element showing
   user-facing information.
5. Preserve endpoint, tenant and evidence context on pivots.

## 8 · Documentation obligations

Every change updates the affected authoritative document and re-runs
`python3 scripts/docs_reconcile.py`. Declare the truth layer:
`CURRENT_REALITY` (must match runtime), `TARGET_SPEC` (may run ahead,
must label maturity) or `HISTORICAL_RECORD` (never edited).

## 9 · Definition of done

- [ ] capability registered with honest status
- [ ] SSOT reused, not duplicated
- [ ] tenant-scoped and RBAC-gated
- [ ] every failure state named and rendered
- [ ] tests pass; **no baseline reset, no silent exclusion**
- [ ] runtime proof script exists and passes
- [ ] docs updated; reconciliation gate green
- [ ] nothing claimed that the proof does not show
