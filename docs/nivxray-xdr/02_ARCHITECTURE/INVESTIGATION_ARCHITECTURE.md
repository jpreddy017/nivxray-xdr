<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Investigation Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Document the investigation plane: observables, pivots, graph, timeline, sightings and the evidence contract behind each.

## Owner
Investigation

## Dependencies
EVIDENCE_ARCHITECTURE.md · INTELLIGENCE_ARCHITECTURE.md

## Required source inputs
IUE/IKG engines; 15 catalogued investigation capabilities; memory/IUE_ARCHITECTURE_V2.md; memory/IUE_INVESTIGATION_SSOT_RECONCILIATION.md

## Known current reality
An investigation workspace, evidence graph and process ancestry exist and render from real evidence. The SSOT reconciliation memo flags unresolved authority questions between IUE and the investigation store.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which store is authoritative for an investigation: the IUE record or workspace_cases? (The SSOT reconciliation memo does not close this.)

## Completion criteria
One declared SSOT per investigation object; every pivot documented with its authoritative API and failure states.

## Release stage by which this must be complete
`CLOSED_BETA`
