<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Integration SDK Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
How a new source or control plane implements the NivXRay integration contract without touching platform internals.

## Owner
Integrations

## Dependencies
INTEGRATION_ARCHITECTURE.md

## Required source inputs
Existing collector and vendor-wizard routes; the reference product's capability model

## Known current reality
Collector and vendor-wizard surfaces exist, and a standalone collector runs on :8055, but there is no declared integration contract an external source could implement.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is the first third-party integration written by us or by a partner? That decides how strict the SDK must be.

## Completion criteria
A new integration can be built from this guide alone and declares its capabilities, health and provenance without core changes.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
