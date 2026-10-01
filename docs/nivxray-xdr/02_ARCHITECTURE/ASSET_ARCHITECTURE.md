<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Asset Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Define the asset/device model: identity, deduplication, ownership, criticality and how asset value feeds prioritisation.

## Owner
Architecture

## Dependencies
EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md

## Required source inputs
edr_endpoints registry; services/edr/device_identity.py; P0-2C alias invariant

## Known current reality
Endpoint identity resolution is now a structural invariant with a validated alias set and tenant-constrained reverse lookup. Asset criticality, ownership and business context do NOT exist.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Where does asset value come from with no CMDB integration — manual tagging, or deferred until an integration exists?

## Completion criteria
Asset object model with identity, alias set, dedup rule, criticality source and its effect on incident priority, all evidence-backed.

## Release stage by which this must be complete
`CLOSED_BETA`
