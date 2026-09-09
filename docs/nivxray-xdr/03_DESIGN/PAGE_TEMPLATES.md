<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Page Templates

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
The small set of page archetypes (queue, detail, canvas, matrix, settings) every screen must instantiate.

## Owner
Design

## Dependencies
DESIGN_SYSTEM.md · NAVIGATION_SPEC.md

## Required source inputs
Existing 60 frontend routes; shipped page structures

## Known current reality
Templates are implicit in the code and mostly consistent, but are not written down, so each new page re-derives its layout.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
How many archetypes actually exist across the 60 shipped routes?

## Completion criteria
Each of the 60 routes mapped to exactly one archetype; deviations justified in writing.

## Release stage by which this must be complete
`CLOSED_BETA`
