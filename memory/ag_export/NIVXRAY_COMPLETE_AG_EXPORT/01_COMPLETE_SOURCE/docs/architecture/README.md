# 📜 NivXRay Constitution

> ### 🟢 STATUS · APPROVED — Architecture Complete · Proceed to Implementation
>
> **Constitution v1.0 is architecturally complete and signed off** (2026-02-31).
> No further architectural layers, sections, buses, registries, or pipelines
> may be added without a superseding ADR under `/app/memory/adr/`.
>
> **Every future PR MUST answer YES to these four gates**:
> 1. Does it preserve the CIO contract (§10)?
> 2. Does it improve one or more §13 KPIs?
> 3. Does it avoid introducing a new architectural layer?
> 4. Does it remain deterministic?
>
> If any answer is "no", the change either needs redesign or a superseding ADR.
>
> **Defect classification (locked at sign-off)** — before touching architecture:
> - **Implementation defect** — a bug, parser gap, performance issue, missing
>   mapping, incorrect field, or CI regression. **Fix inside the existing
>   Constitution.** Never triggers an ADR.
> - **Architectural defect** — a demonstrated inability of the Constitution
>   itself to support a required capability. **Requires an ADR** citing the
>   § it supersedes, why the current design cannot express the capability,
>   and what changes. This is the ONLY path to a v1.1.
>
> Ordinary engineering findings MUST NOT be escalated into architectural
> redesigns. Doing so is treated as a code-review hard-fail.
>
> **ADR-required checklist (locked)** — an ADR is required ONLY if ANY of
> these questions is genuinely `no` due to a Constitution limitation:
> 1. Can the capability be implemented within the existing CIO?
> 2. Can it be implemented using the existing Adapter model?
> 3. Can it preserve deterministic behaviour?
> 4. Can it satisfy the four PR gates?
>
> If all four are `yes`, it is an implementation task — not an architectural
> change. This keeps architectural evolution deliberate, not reactive.
>
> **Three-layer PR review (locked)** — every PR is evaluated against three
> layers, in order:
>
> | Layer | Question | Kind |
> |-------|----------|------|
> | **1 · Functional correctness** | Does the feature do what it is supposed to do? | Implementation |
> | **2 · Constitutional compliance** | Does the implementation obey the Constitution (CIO · provenance · determinism · no forks · no new layers)? | Governance |
> | **3 · KPI improvement**     | Does the implementation measurably improve one or more §13 KPIs? | Release-quality |
>
> A PR that passes only Layer 1 does not merge. All three layers must be
> satisfied.
>
> **Merge lifecycle (locked · architecture is NOT part of the loop)**:
> ```
> Backlog Item → Implementation → Golden Corpus Validation → Parity Tests
>              → KPI Measurement → Constitutional Compliance Review → Merge
> ```
>
> **Operating model (the shift that closed the architecture)**:
> ```
> Evidence → Investigation → Knowledge → Decision → Explanation
> ```
> Not `Input → Decode → Output`. This is a different product category.

> **AUTHORITATIVE. Read every constitution file before proposing or implementing anything. If your task conflicts with any of these documents, STOP and report the conflict — do not invent a new architecture.**

## Constitution Documents (load in this order)

| # | File | Scope |
|---|------|-------|
| 00 | [`00_PRODUCT_VISION.md`](./00_PRODUCT_VISION.md) | What NivXRay is and who it is for |
| 01 | [`01_XLAB_CONSTITUTION.md`](./01_XLAB_CONSTITUTION.md) | X-Lab · the one investigation workspace |
| 02 | [`02_UI_CONSTITUTION.md`](./02_UI_CONSTITUTION.md) | Presentation rules (Lab 2.0 face, locked lens list) |
| 03 | [`03_BACKEND_CONSTITUTION.md`](./03_BACKEND_CONSTITUTION.md) | Single-copy engine rule, shared pipeline |
| 04 | [`04_INVESTIGATION_CONSTITUTION.md`](./04_INVESTIGATION_CONSTITUTION.md) | Universal Investigation Engine and CIO contract |
| 05 | [`05_REPORT_CONSTITUTION.md`](./05_REPORT_CONSTITUTION.md) | 14-section Executive Report + Report Composer |
| 06 | [`06_DEFINITION_OF_DONE.md`](./06_DEFINITION_OF_DONE.md) | What "done" means for every task |

## Working Documents

- [`/app/docs/BACKLOG.md`](../BACKLOG.md) — Persistent implementation backlog. Update after every session; do not generate ad-hoc "Next Action Items."
- [`/app/memory/xlab_parity_audit.md`](../../memory/xlab_parity_audit.md) — Legacy Lab ↔ X-Lab parity matrix.
- [`/app/reference/canonical_investigation/sample_incident/`](../../reference/canonical_investigation/sample_incident/) — **Reference Implementation** (golden investigation). Read this before touching any Adapter or engine.

## Update Discipline

- Constitution files change ONLY via an explicit operator directive.
- The BACKLOG is the ONE place to track work status.
- Never re-propose decisions already frozen in a constitution file.
