<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Backup & Recovery Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
What must be backed up, how it is restored and what is rebuildable.

## Owner
Operations

## Dependencies
DATA_ARCHITECTURE.md

## Required source inputs
MongoDB collections; response-service SQLite SSOT

## Known current reality
No backup or restore procedure exists or has ever been tested.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which stores are authoritative and must be backed up versus derived projections that can be rebuilt?

## Completion criteria
A restore has been performed successfully in a test environment with a measured RPO and RTO.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
