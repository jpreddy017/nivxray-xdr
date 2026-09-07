<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# MSSP / Multi-Tenant Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
Operating many customers from one console without cross-customer leakage.

## Owner
Product

## Dependencies
07_SECURITY/TENANT_ISOLATION.md

## Required source inputs
MSS routes (8); tenant scoping; cross-tenant proofs

## Known current reality
Multi-tenant scoping is real and proven at the incident and endpoint-evidence layers, including a cross-tenant denial that discloses nothing. MSSP operational workflows are not documented.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is MSSP a launch market or a later one? It materially changes isolation and reporting priorities.

## Completion criteria
Multi-customer operation documented and proven with an isolation test per surface.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
