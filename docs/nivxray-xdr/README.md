<!-- NIVX-DOC
layer: CURRENT_REALITY
status: AUTHORED
-->

# NivXRay XDR · Authoritative Documentation

**This tree is the single documentation authority.** `/app/memory/` is
retained for provenance and live working state only — every one of its
157 documents is reconciled in
[`01_REFERENCE/DOC_PROVENANCE_LEDGER.md`](01_REFERENCE/DOC_PROVENANCE_LEDGER.md).

## Three truth layers — never mixed

Every document declares its layer in a `NIVX-DOC` front-matter block.

| Layer | Meaning | May it run ahead of the code? |
|---|---|---|
| `CURRENT_REALITY` | generated from, or verified against, the running system | **no** |
| `TARGET_SPEC` | what NivXRay is designed to become | **yes** — must label maturity (`TARGET`, `SPEC_PENDING`, `NOT_IMPLEMENTED`) |
| `HISTORICAL_RECORD` | previous plans and decisions, kept for provenance | never edited |

Statuses: `GENERATED` · `ADOPTED` · `AUTHORED` · `SPEC_PENDING`.

## The gate

```bash
python3 scripts/docs_reconcile.py        # regenerate reality + gate
python3 scripts/docs_reconcile.py --gate # gate only (CI)
```

It **fails** when a document asserts as *current reality* something the
runtime contradicts — a Windows sensor that is operational, an
operational isolation capability, a GA claim. A `TARGET_SPEC` document
may describe all three, provided it says so as intent.

Verified working: a test document claiming an operational Windows sensor,
verified isolation and production-readiness produced **3 gate
violations**, while a `TARGET_SPEC` document describing the same
functionality as future passed.

Supporting generators: `scripts/docs_skeleton.py` (SPEC_PENDING
skeleton), `scripts/docs_provenance.py` (legacy ledger).

## Start here

| Question | Document |
|---|---|
| **What is actually real?** | [`08_VALIDATION/REALITY_MATRIX.md`](08_VALIDATION/REALITY_MATRIX.md) — generated |
| What evidence backs our Cisco claims? | [`01_REFERENCE/SOURCE_REGISTER.md`](01_REFERENCE/SOURCE_REGISTER.md) |
| How is the reference product built? | [`01_REFERENCE/CISCO_XDR_REFERENCE_MODEL.md`](01_REFERENCE/CISCO_XDR_REFERENCE_MODEL.md) |
| Cisco function → our equivalent | [`01_REFERENCE/CISCO_TO_NIVXRAY_MAPPING.md`](01_REFERENCE/CISCO_TO_NIVXRAY_MAPPING.md) |
| How is NivXRay assembled? | [`02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md`](02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md) |
| What are the components? | [`02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md`](02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md) |
| How does a source integrate? | [`02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md`](02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md) |
| What are we allowed to claim? | [`00_PRODUCT/MATURITY_MODEL.md`](00_PRODUCT/MATURITY_MODEL.md) |
| How far from GA? | [`08_VALIDATION/GA_READINESS_MATRIX.md`](08_VALIDATION/GA_READINESS_MATRIX.md) |
| **What do we build next?** | [`09_RELEASE/LAB_VALIDATION_PLAN.md`](09_RELEASE/LAB_VALIDATION_PLAN.md) |
| How do I contribute? | [`04_DEVELOPMENT/DEVELOPMENT_GUIDE.md`](04_DEVELOPMENT/DEVELOPMENT_GUIDE.md) |

## Tree

```
00_PRODUCT/      vision · boundaries · capability catalog · maturity · terminology
01_REFERENCE/    source register · Cisco reference model, components,
                 integration model, workflows, UI catalog · mapping ·
                 doc provenance ledger
02_ARCHITECTURE/ system · component · data · evidence · detection ·
                 correlation · incident · investigation · intelligence ·
                 response · automation · asset · integration ·
                 identity/tenancy · security-state & causal
03_DESIGN/       design system · information architecture · navigation ·
                 page templates · component library · interaction ·
                 states & errors · accessibility · responsive · parity
04_DEVELOPMENT/  development · frontend · backend · API · integration SDK ·
                 sensor · detection content · response adapter · testing ·
                 contribution rules
05_OPERATIONS/   deployment · installation · configuration · integration
                 admin · observability · backup/recovery · upgrade/rollback ·
                 HA/scaling · troubleshooting
06_USER_GUIDES/  SOC analyst · threat hunter · responder · administrator ·
                 MSSP · investigation · automation · response
07_SECURITY/     architecture · RBAC · tenant isolation · authn/authz ·
                 secrets · audit · response safety · threat model
08_VALIDATION/   REALITY_MATRIX + generated inventories · traceability ·
                 Cisco parity · E2E · performance · security · GA readiness
09_RELEASE/      alpha · lab validation · beta · pilot · RC · GA · checklist
```

## Rules

1. **Never mix truth layers.** A user guide describes only what is usable
   today unless a section is explicitly labelled future.
2. **A `SPEC_PENDING` document is a declared gap, not a placeholder.** It
   must carry purpose, owner, dependencies, required source inputs, known
   current reality, unresolved questions, completion criteria and the
   release stage by which it must be complete. No generic filler.
3. **Current-state numbers are generated.** Do not hand-write them —
   that is how `memory/CAPABILITY_REGISTRY.md` came to disagree with the
   runtime.
4. **Cisco claims carry an evidence class.** Inference is never
   presented as Cisco's internal architecture.
5. **A route is not a component. An engine package is not a capability.
   A UI page is not proof of an operational component.**
6. Registry counts are architectural evidence, **never** a maturity
   percentage.
