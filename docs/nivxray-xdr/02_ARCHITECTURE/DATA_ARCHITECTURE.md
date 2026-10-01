<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Data Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Define every store, its SSOT role, retention, tenancy key and the one component allowed to write it.

## Owner
Architecture

## Dependencies
EVIDENCE_ARCHITECTURE.md · GENERATED_ENGINE_REGISTRY.md

## Required source inputs
Live MongoDB collection inventory; the response service SQLite SSOT; backend/services/edr/endpoint_query.py store contract

## Known current reality
Endpoint-keyed stores and their identity fields are declared and guarded (P0-2C). Retention, archival and tenancy keys are NOT documented for most collections.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which collections are authoritative versus derived projections that could be rebuilt? What is the retention obligation per store?

## Completion criteria
Every collection has: owner, SSOT/derived classification, writer, tenancy key, retention, rebuild procedure.

## Release stage by which this must be complete
`CLOSED_BETA`
