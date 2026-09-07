<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# States & Errors

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
The mandatory state vocabulary — loading, empty-real, no-integration, stale, partial, unavailable, unauthorized, not-resolved, error — and the rule that an empty result may never imply absence of evidence.

## Owner
Design + Architecture

## Dependencies
COMPONENT_LIBRARY.md · EVIDENCE_ARCHITECTURE.md

## Required source inputs
P0-2C ENDPOINT_NOT_RESOLVED contract; the WINDOW_HONESTY_GAP finding; existing epistemic_state envelopes

## Known current reality
This is the most mature honesty mechanism in the product: ENDPOINT_NOT_RESOLVED is enforced backend-side and now rendered by three EDR surfaces. Coverage is not universal — the process-tree window gap is a live example of a true-but-misleading empty state.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is there any surface that still renders an empty collection where the backend supplied a named absence?

## Completion criteria
Every state has one component, one API contract and one test; a sweep proves no surface converts a named absence into a bare empty state.

## Release stage by which this must be complete
`LAB_VALIDATED`
