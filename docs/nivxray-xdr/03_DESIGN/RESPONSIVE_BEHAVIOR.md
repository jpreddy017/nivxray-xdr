<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Responsive Behaviour

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Breakpoints and degradation rules for dense analyst surfaces.

## Owner
Design

## Dependencies
PAGE_TEMPLATES.md

## Required source inputs
Shipped CSS; console is designed for wide displays

## Known current reality
The consoles are built for wide desktop use. Narrow-viewport behaviour is untested and likely broken on the matrix and canvas surfaces.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is tablet or mobile a real requirement for a SOC console, or explicitly out of scope?

## Completion criteria
Per-archetype breakpoint behaviour specified and verified, or out-of-scope recorded as a product decision.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
