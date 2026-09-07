<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Response Safety

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
The guarantees preventing a wrong, duplicate or unauthorised action on a production machine.

## Owner
Security + Response

## Dependencies
RESPONSE_ARCHITECTURE.md · AUDIT_ARCHITECTURE.md

## Required source inputs
Response lifecycle invariants; target identity binding; approval separation

## Known current reality
The strongest safety property already holds: a command binds to a process START IDENTITY, so a recycled PID cannot be killed by mistake, and verification refuses to accept a probe without that identity basis.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is there a blast-radius limit — could one request isolate an entire fleet?

## Completion criteria
Idempotency, target binding, approval separation, rate and blast-radius limits all specified and tested.

## Release stage by which this must be complete
`LAB_VALIDATED`
