<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Product Boundaries — XDR vs EDR

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **INTERNAL_ALPHA**.

## Purpose
Fix the boundary between NivXRay XDR and NivXForge EDR so neither duplicates the other, and record which side owns each capability.

## Owner
Architecture

## Dependencies
COMPONENT_ARCHITECTURE.md · memory/MASTER_OWNERSHIP_AUDIT.md

## Required source inputs
memory/MASTER_OWNERSHIP_AUDIT.md (1207 lines); memory/XDR_EDR_PARITY_AUDIT.md; memory/XDR_SEPARATION_HANDOFF.md

## Known current reality
The ownership audit is complete and the two consoles are separated with distinct logins, shells and rails. The ARCHITECTURE LOCK is honoured in code today.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Does XDR ever execute an endpoint action directly, or must it always orchestrate through EDR? (Current implementation: always orchestrate.)

## Completion criteria
Every capability in CAPABILITY_CATALOG carries exactly one owning product; zero capabilities owned by both.

## Release stage by which this must be complete
`INTERNAL_ALPHA`
