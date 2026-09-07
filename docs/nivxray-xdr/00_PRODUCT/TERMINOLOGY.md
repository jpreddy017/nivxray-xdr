<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Terminology

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **INTERNAL_ALPHA**.

## Purpose
One vocabulary for evidence, observation, canonical event, detection, correlation, incident, case, verdict, security state and response, so that documents and APIs stop drifting apart.

## Owner
Architecture

## Dependencies
EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md

## Required source inputs
Existing field names across 865 routes; memory/ARCHITECTURE.md; memory/CAPABILITIES_HLD_LLD.md

## Known current reality
The same concept appears as `case`, `incident` and `workspace_case` in different layers; `observation`, `raw event` and `canonical event` are three genuinely different objects that are often conflated in prose.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Do we rename `workspace_cases` to `incidents` at the storage layer, or keep the collection name and fix only the vocabulary?

## Completion criteria
Every term used in an authoritative doc appears here exactly once with its owning SSOT and its API field name.

## Release stage by which this must be complete
`INTERNAL_ALPHA`
