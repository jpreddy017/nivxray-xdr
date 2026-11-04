<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# RBAC Matrix

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Every permission, the roles holding it and the routes enforcing it.

## Owner
Security

## Dependencies
IDENTITY_TENANCY_ARCHITECTURE.md

## Required source inputs
require_permission decorators across the route surface; RBAC routes

## Known current reality
Permission enforcement exists via decorators and is proven for response and incident surfaces. There is no complete matrix across 865 routes.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
How many live routes have no permission requirement at all?

## Completion criteria
Every route mapped to a permission, every permission to roles, with an automated check for unprotected routes.

## Release stage by which this must be complete
`CLOSED_BETA`
