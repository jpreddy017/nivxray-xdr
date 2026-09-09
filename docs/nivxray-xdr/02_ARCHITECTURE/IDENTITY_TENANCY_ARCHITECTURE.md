<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Identity & Tenancy Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Document principals, tenants, scopes and the object-level authorisation rule that every route must satisfy.

## Owner
Security

## Dependencies
07_SECURITY/TENANT_ISOLATION.md · 07_SECURITY/RBAC_MATRIX.md

## Required source inputs
RBAC routes (19); resolve_tenant_scope; scripts/p0_w_incident_tenant_authorization_proof.py

## Known current reality
Tenant scoping is enforced and proven for incidents and endpoint evidence; a cross-tenant IDOR was found and closed. Coverage across all 865 routes is not systematically proven.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is there a route-level guard that fails a new route lacking tenant scoping, comparable to the P0-2C alias guard?

## Completion criteria
Every tenant-scoped route enumerated and covered by an authorisation test; a structural guard prevents adding an unscoped route.

## Release stage by which this must be complete
`CLOSED_BETA`
