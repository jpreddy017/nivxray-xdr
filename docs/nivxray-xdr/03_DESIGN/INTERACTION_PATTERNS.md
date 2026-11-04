<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Interaction Patterns

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Standardise selection, filtering, drawer versus page, bulk action, keyboard navigation and pivot behaviour.

## Owner
Design

## Dependencies
PAGE_TEMPLATES.md · COMPONENT_LIBRARY.md

## Required source inputs
Shipped console behaviour; 14 audited frontend pivots (P0-2C)

## Known current reality
Pivot contracts were audited and one defect fixed. Broader interaction patterns are unwritten.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is there a keyboard model at all today? Cisco-grade consoles are keyboard-driven; ours is largely mouse-driven.

## Completion criteria
Each pattern specified once with acceptance tests, including the full keyboard model.

## Release stage by which this must be complete
`CLOSED_BETA`
