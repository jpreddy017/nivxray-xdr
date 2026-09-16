<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Cisco Parity Matrix

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Observable-capability parity against the reference product, per screen and per workflow.

## Owner
Product + Design

## Dependencies
CISCO_TO_NIVXRAY_MAPPING.md · CISCO_UI_REFERENCE_CATALOG.md

## Required source inputs
memory/MASTER_PARITY_MATRIX.md; memory/MASTER_CISCO_DELTA.md; memory/AMP_TRAJECTORY_CONFORMANCE.md

## Known current reality
A parity matrix already exists at the capability level and an AMP trajectory conformance study is complete. Screen-level parity is not evidenced because no Cisco screen captures are held.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which parity items can be judged without Cisco reference captures? Most cannot.

## Completion criteria
Every parity row carries reference evidence or REFERENCE_CAPTURE_REQUIRED, and a state backed by a proof.

## Release stage by which this must be complete
`CLOSED_BETA`
