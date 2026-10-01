<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Accessibility

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Contrast, focus order, keyboard operability, screen-reader semantics and motion-reduction requirements.

## Owner
Design

## Dependencies
DESIGN_SYSTEM.md · INTERACTION_PATTERNS.md

## Required source inputs
WCAG 2.2 AA; shipped console markup

## Known current reality
No accessibility audit has been performed. The dark, dense console style carries real contrast risk on faint text.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is AA a commitment for GA, and is any customer contractually likely to require it?

## Completion criteria
AA audit passed on every first-class screen with an automated check in CI.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
