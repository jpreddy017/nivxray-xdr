<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Backend Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
How to add a capability: contract, SSOT, tenant scoping, evidence provenance, engine identity and proof obligations.

## Owner
Backend

## Dependencies
DEVELOPMENT_GUIDE.md · API_GUIDE.md

## Required source inputs
865 live routes; the P0-2C alias invariant as the reference pattern

## Known current reality
The P0-2C endpoint-identity invariant is the model to generalise: a declared contract plus an AST guard plus a runtime proof. Nothing else is guarded this way yet.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which other invariants deserve the same treatment — tenant scoping first?

## Completion criteria
A new capability can be added correctly from this document, and its invariants are guarded rather than reviewed.

## Release stage by which this must be complete
`LAB_VALIDATED`
