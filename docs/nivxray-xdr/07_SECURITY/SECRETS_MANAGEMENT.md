<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Secrets Management

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
How secrets are stored, rotated, scoped and audited.

## Owner
Security

## Dependencies
CONFIGURATION_GUIDE.md

## Required source inputs
xdr_secrets routes (7); .env files; IOC provider keys

## Known current reality
A secrets surface exists and provider keys are configured. Rotation and audit of secret access are not specified.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Are any secrets currently in .env that belong in the secrets store?

## Completion criteria
Every secret has a store, an owner, a rotation period and an access audit trail.

## Release stage by which this must be complete
`CLOSED_BETA`
