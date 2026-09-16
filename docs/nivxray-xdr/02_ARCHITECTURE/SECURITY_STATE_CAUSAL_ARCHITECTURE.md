<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Security State & Causal Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
Document the security-state model, causal FSM and what a counterfactual or intervention claim is permitted to assert.

## Owner
Reasoning

## Dependencies
EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md

## Required source inputs
14 security-state routes; 8 reasoning-fabric capabilities; owner's 34-point technology directive (deferred)

## Known current reality
Security-state and causal surfaces exist and render in the investigation workspace. The owner's technology-adoption audit that would formalise the causal claims is explicitly DEFERRED until the P0s close.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the evidentiary standard for a causal or counterfactual claim? Without one, these surfaces risk asserting more than the evidence supports.

## Completion criteria
Claim taxonomy with required evidence per claim class, and a rule that no causal claim may exceed its evidence, proven by test.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
