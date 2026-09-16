<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> Live per-capability states are **generated**:
> `08_VALIDATION/GENERATED_CAPABILITY_MATRIX.md`. This document defines
> the model, not the values.

# CAPABILITY CATALOG

Adopts `memory/CAPABILITIES_HLD_LLD.md`; supersedes the hand-maintained
`memory/CAPABILITY_REGISTRY.md`, which had drifted from the runtime
registry — exactly the failure the generated matrix plus the
reconciliation gate now prevent.

## 1 · What a capability is

A capability is a **product promise**, not a code path. It must name its
owning product (XDR or EDR), its owning component, its evidence source,
its API, its UI consumer and its proof.

A capability is **not**: a route, an engine package, or a UI page.

## 2 · The state model (implemented in `edr_plane/capability/inventory.py`)

The registry records, per capability: `telemetry_status`,
`backend_status`, `control_driver_status`, `ui_status`,
`contract_status`, `test_status`, `e2e_status`, `declared_state`,
`effective_state`, `gap_class`, `evidence_reference`, `is_operational`
and `claim_is_honest`.

`effective_state` is **derived and can only be downgraded** from
`declared_state`; a downgrade records its reason. This is why the
registry is trustworthy: a component cannot self-promote.

| Effective state | Meaning |
|---|---|
| `NOT_IMPLEMENTED` | nothing exists |
| `CONTRACT_DEFINED` | contract exists, no producer/executor |
| `BACKEND_IMPLEMENTED` | built, not proven end to end |
| `UI_IMPLEMENTED` | surface exists — **not** evidence of a working capability |
| `GOLDEN_CORPUS_VALIDATED` | proven against a fixed corpus |
| `REAL_ENDPOINT_VALIDATED` | proven with evidence from a real machine |
| `END_TO_END_VALIDATED` | proven across the whole chain |
| `OPERATIONAL` | telemetry + backend + control driver + UI all live |

| Gap class | Meaning |
|---|---|
| `TELEMETRY_MISSING` | no producer emits the required evidence |
| `CONTROL_DRIVER_MISSING` | no control plane can execute it |
| `UI_ONLY` | a surface with no authoritative backend |
| `BACKEND_ONLY` | backend with no analyst surface |
| `OWNER_INPUT_PENDING` | blocked on an owner decision |

## 3 · How to read `is_operational` — and how not to

`is_operational` counts capabilities where **every** layer is live. The
current value is in the generated matrix.

**It is a registry fact. It is not a completion percentage and must
never be quoted as one.** A capability whose telemetry does not exist
yet is not "incomplete work" — it is often correctly parked behind a
missing producer.

What the number is legitimately used for:

| Signal | Reading | Decision vocabulary |
|---|---|---|
| many `CONTRACT_DEFINED` | contracts written ahead of producers | `WIRE` when a producer exists |
| many `TELEMETRY_MISSING` | **the platform's real bottleneck is sources** | `BUILD` producers |
| any `UI_ONLY` | a surface may be over-claiming | `WIRE` or remove the surface |
| any `BACKEND_ONLY` | built value is invisible to analysts | `WIRE` a surface |
| `CONTROL_DRIVER_MISSING` | environment or driver blocked | `BLOCKED_ENVIRONMENT`, never simulate |
| route count ≫ operational count | surface built ahead of wiring | `CONSOLIDATE` / `DEPRECATE` |

## 4 · Ownership rule

Every capability has **exactly one** owning product. Zero capabilities
may be owned by both — that is the architecture lock expressed as data
(`00_PRODUCT/PRODUCT_BOUNDARIES.md`).

## 5 · Promotion rules

1. A capability may only be promoted by **evidence**, never by
   assertion.
2. `REAL_ENDPOINT_VALIDATED` requires evidence from a real machine.
3. `OPERATIONAL` requires all four layers live **and** a proof script.
4. **Passing unit tests cannot promote a capability.**
5. `claim_is_honest` must be true for every entry. A capability whose
   declared state exceeds its evidence is a defect, not a status.
6. Documentation asserting a capability is operational while the registry
   disagrees **fails `scripts/docs_reconcile.py`**.

## 6 · Registry obligations not yet met

| Obligation | Status |
|---|---|
| every capability names its owning **component** | `SPEC_PENDING` |
| every capability links to a **proof script** | partial |
| every capability names its **UI consumer** | partial |
| every capability declares required **integration capabilities** | `SPEC_PENDING` |
| integrations declare **against** this registry | `SPEC_PENDING` — the key missing link to `INTEGRATION_ARCHITECTURE.md` |
