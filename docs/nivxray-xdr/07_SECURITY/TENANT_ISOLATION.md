<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Tenant Isolation

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
The isolation model and the proof that no surface leaks across customers.

## Owner
Security

## Dependencies
IDENTITY_TENANCY_ARCHITECTURE.md

## Required source inputs
scripts/p0_w_incident_tenant_authorization_proof.py; P0-2C cross-tenant gates; the tenant-constrained alias reverse lookup

## Known current reality
Isolation is proven for incidents and all endpoint evidence surfaces, including the requirement that a foreign identifier is indistinguishable from an unknown one. A resolver-level cross-customer alias bleed was found and closed in P0-2C.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which of the 865 routes have never been isolation-tested?

## Completion criteria
Every tenant-scoped surface has an isolation test; a structural guard prevents adding an unscoped one.

## Release stage by which this must be complete
`LAB_VALIDATED`
