# STANDING ENGINEERING DIRECTIVE — RESEARCH-FIRST (owner, 2026-09-18)

Applies to W2 and **all** future NivXRay XDR / NivXForge EDR subsystems:
collectors, agents, sensors, parsers/DSMs, APIs, ingestion paths, storage
models, detection pipelines, response, update mechanisms, telemetry contracts.

## The loop (no step may be skipped)
```
INDUSTRY + STANDARDS RESEARCH
  → what is already solved / established patterns / vendor failure modes / standards & APIs
  → compare against the existing NivX repository
  → ADOPT / ADAPT / EXTEND / BUILD / DEFER
  → NivX evidence & provenance requirements
  → architecture decision
  → acceptance gates
  → implementation
  → adversarial + regression testing
  → production evidence
```
**Industry parity first, NivX differentiation second.** Establish parity in
durability, security, deployment, observability and manageability before
differentiating with canonical evidence, provenance, causal correlation,
negative explainability, verification and "Verdict, cited. Every time."

## Mandatory labelling in every research deliverable
`[FACT]` documented vendor/standards statement with source · `[PATTERN]`
industry practice · `[NIVX]` our inference/design choice.
Never copy proprietary implementations. Never infer undocumented internals.

## Required deliverables per subsystem
industry/standards comparison matrix with sources · current NivX capability
matrix · gap analysis · ADOPT/ADAPT/EXTEND/BUILD/DEFER decisions · recommended
architecture + rationale · data/identity/time/durability/security contracts ·
failure-mode analysis · acceptance gates · implementation sequence · explicit
assumptions requiring owner or real-environment verification.

## Four layers, not one
`industry architecture → telemetry/data model → analyst workflow → UI/UX`.

## UI/UX research requirement
Before any UI implementation: collect current public screenshots, product docs
and demos for the capability; compare information architecture, navigation,
tables, filters, timelines, graphs, evidence presentation, pivots,
configuration, health/coverage, response controls, reporting. Return reference
board with sources · vendor/workflow comparison · useful patterns · weaknesses
to avoid · proposed NivX information architecture · wireframes · click/pivot
workflow · **backend field/API behind every visible element** ·
empty/loading/error/degraded states · RBAC and destructive-action behaviour ·
evidence/provenance presentation · responsive/accessibility · acceptance tests
tying UI claims to real backend data.
Do not reproduce another vendor's console. Extract principles, build original.

Every screen must answer: what does the analyst need to know · what decision
are they making · what evidence supports it · what can they pivot to · what
action can they take · how will they know the action worked.

## Absolute rules
* **No decorative mock data may become a production claim.** Every status,
  count, graph, verdict, timestamp and response result must have an
  authoritative backend source.
* No status word — `Healthy`, `Connected`, `Parsed`, `Protected`, `Verified` —
  without an explicit computable contract.
* Do not combine unrelated feature development into a milestone without owner
  approval.
* Research/design phases produce documents only: no production changes, no
  endpoint execution, no modification of frozen milestones.
