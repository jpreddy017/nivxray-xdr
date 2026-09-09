<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Component Library

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Catalogue every shared UI component with props, states and the data-testid contract.

## Owner
Design + Frontend

## Dependencies
DESIGN_SYSTEM.md · 04_DEVELOPMENT/FRONTEND_GUIDE.md

## Required source inputs
apps/nivxray-xdr/src/**/components; shadcn/ui base set

## Known current reality
Shared components exist (including the new EndpointNotResolved honest empty state) and carry data-testids, but there is no catalogue.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which components are genuinely shared between the XDR and EDR shells versus duplicated per product?

## Completion criteria
Every shared component documented with props, states, testids and its consuming routes; duplicates identified for consolidation.

## Release stage by which this must be complete
`CLOSED_BETA`
