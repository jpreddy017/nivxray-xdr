<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Navigation Specification

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Define both product rails, their order, grouping, badges, deep-link behaviour and the XDR to EDR pivot contract.

## Owner
Design

## Dependencies
INFORMATION_ARCHITECTURE.md

## Required source inputs
App.jsx route table (generated); memory/Y1_STATUS_REPORT.md rail work; owner mockup (15-item rail) versus shipped 8-primary rail

## Known current reality
The shipped rail is the 8-primary reference structure. The owner has supplied a mockup with a 15-item rail; the conflict is OPEN and was raised but not resolved.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Authoritative rail: the shipped 8-primary structure, or the owner's 15-item mockup, or Cisco IA plus a new Home landing page?

## Completion criteria
One rail specification, per-item route, RBAC visibility rule, badge data source, and reconciliation with the generated UI route inventory.

## Release stage by which this must be complete
`CLOSED_BETA`
