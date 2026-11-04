<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Release Candidate Plan

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Hardening, performance, DR and documentation completeness for RC.

## Owner
Owner

## Dependencies
PILOT_PLAN.md · 08_VALIDATION/*

## Required source inputs
Pilot findings; performance and security matrices

## Known current reality
Not reachable yet. HA, backup, DR and performance are all undone.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the smallest credible RC scope — Linux plus Windows EDR only, deferring broader XDR?

## Completion criteria
All RC gates evidenced with no open P0 or P1.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
