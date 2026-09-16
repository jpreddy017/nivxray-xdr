<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Integration Administration Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
How an administrator configures, credentials, tests and monitors an integration.

## Owner
Operations

## Dependencies
INTEGRATION_ARCHITECTURE.md

## Required source inputs
Collector routes (22); vendor wizard (17); data-source routes (10)

## Known current reality
Administration surfaces exist. The collector pipeline has a known split-brain between reported and actual status (P0-4, open).

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Until P0-4 closes, can any integration health status be trusted for administration decisions?

## Completion criteria
Health shown to an administrator is the authoritative health, proven by a reconciliation test.

## Release stage by which this must be complete
`CLOSED_BETA`
