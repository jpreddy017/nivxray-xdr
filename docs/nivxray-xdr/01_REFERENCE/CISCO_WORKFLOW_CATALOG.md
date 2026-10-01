<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Cisco XDR Workflow Catalog

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
Catalogue the analyst workflows Cisco XDR supports end to end, so NivXRay screens are designed around operations rather than pages.

## Owner
Product + Design

## Dependencies
CISCO_COMPONENT_CATALOG.md · SOURCE_REGISTER.md

## Required source inputs
Cisco public product documentation; owner-supplied Cisco training material and XDR.pptx (76 slides, already partly mined in memory/MASTER_CISCO_DELTA.md)

## Known current reality
memory/MASTER_CISCO_DELTA.md and memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md capture a first pass from the owner's deck. Workflow-level detail (step order, decision points, hand-offs) is NOT yet captured.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which Cisco workflows can be evidenced from public docs versus only from owner-held training material? Everything unevidenced must be REFERENCE_CAPTURE_REQUIRED.

## Completion criteria
Every workflow has: trigger, actor, ordered steps, objects touched, decision points, exit states, and a NivXRay equivalent or a declared gap.

## Release stage by which this must be complete
`LAB_VALIDATED`
