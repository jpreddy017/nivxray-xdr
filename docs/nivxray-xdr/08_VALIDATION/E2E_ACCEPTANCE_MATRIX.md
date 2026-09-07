<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# End-to-End Acceptance Matrix

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
The end-to-end chains that must pass for each maturity stage.

## Owner
QA

## Dependencies
MATURITY_MODEL.md · LAB_VALIDATION_PLAN.md

## Required source inputs
Existing proof scripts; the chain from collection to verified response

## Known current reality
Individual stages are proven in isolation. No single test walks collection to canonical evidence to detection to incident to investigation to response to verification on real data.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the minimum acceptable end-to-end chain for LAB_VALIDATED?

## Completion criteria
One executable end-to-end acceptance chain per stage, passing on real evidence only.

## Release stage by which this must be complete
`LAB_VALIDATED`
