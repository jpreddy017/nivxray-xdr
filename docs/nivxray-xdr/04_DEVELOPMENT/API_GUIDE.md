<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# API Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Route naming, versioning, error taxonomy, pagination, idempotency and the named-absence response contract.

## Owner
Backend

## Dependencies
BACKEND_GUIDE.md · GENERATED_ROUTE_INVENTORY.md

## Required source inputs
Generated route inventory; existing error shapes

## Known current reality
865 routes with several competing conventions and no published error taxonomy; ENDPOINT_NOT_RESOLVED is the first properly specified absence contract.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Do we version the API before a design partner, and can the OpenAPI schema be served (it is currently not exposed at /api/openapi.json)?

## Completion criteria
One naming and error convention, published error taxonomy, and route inventory reconciled with zero undocumented live routes.

## Release stage by which this must be complete
`CLOSED_BETA`
