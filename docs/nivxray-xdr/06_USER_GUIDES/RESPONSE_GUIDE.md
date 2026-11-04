<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Response Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Choosing, approving, executing and verifying a response.

## Owner
Product

## Dependencies
RESPONSE_ARCHITECTURE.md

## Required source inputs
Response lifecycle states; approval gating

## Known current reality
The lifecycle is honest about every state, including refusing to call an unverified action successful. Only 2 of 18 catalogued actions are operational.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
How is the action catalogue presented so an analyst is never offered an action that cannot execute?

## Completion criteria
Documented actions are operational, verified and RBAC-gated in the shipped product.

## Release stage by which this must be complete
`CLOSED_BETA`
