<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Security Test Matrix

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Every security control paired with the test proving it.

## Owner
Security + QA

## Dependencies
07_SECURITY/*

## Required source inputs
Existing tenant and authorisation proofs; the P0-2C cross-tenant gates

## Known current reality
Tenant isolation and object-level authorisation have real tests, including a proof that a foreign identifier is indistinguishable from an unknown one. Coverage of authn, secrets, audit and response safety is partial.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Do we need an external penetration test before a design-partner pilot?

## Completion criteria
Every control in 07_SECURITY has an automated test; no control is review-only.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
