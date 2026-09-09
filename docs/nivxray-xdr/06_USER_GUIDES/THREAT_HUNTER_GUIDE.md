<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Threat Hunter Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
Hypothesis-driven hunting across available evidence.

## Owner
Product

## Dependencies
INVESTIGATION_ARCHITECTURE.md

## Required source inputs
Search and hunting routes; fleet spread index

## Known current reality
Search and spread surfaces exist over one telemetry domain, which sharply limits genuine hunting.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is hunting credible with a single domain, or does this guide wait for a second source?

## Completion criteria
Documented hunts are reproducible on real data and return real results.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
