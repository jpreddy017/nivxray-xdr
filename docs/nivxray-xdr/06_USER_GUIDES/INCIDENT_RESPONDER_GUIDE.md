<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Incident Responder Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Containment and eradication using verified response actions.

## Owner
Product

## Dependencies
RESPONSE_ARCHITECTURE.md

## Required source inputs
Response lifecycle; verification probes

## Known current reality
Only KILL_PROCESS is genuinely verifiable today, and only on Linux. Isolation is BLOCKED_ENVIRONMENT.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What does a responder do when the only verified action is process termination?

## Completion criteria
Every documented action is operational and independently verified in the shipped product.

## Release stage by which this must be complete
`CLOSED_BETA`
