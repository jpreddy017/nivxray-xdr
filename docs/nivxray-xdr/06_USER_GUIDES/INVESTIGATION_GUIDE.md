<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Investigation Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
How to drive an investigation from observable to conclusion.

## Owner
Product

## Dependencies
INVESTIGATION_ARCHITECTURE.md

## Required source inputs
Investigation workspace; pivots; evidence graph

## Known current reality
The workspace renders real evidence, including process ancestry and the evidence graph, on the one real endpoint.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which pivots return real results with one telemetry domain, and which always return a named absence?

## Completion criteria
Every documented pivot demonstrated on real evidence with its honest limits stated.

## Release stage by which this must be complete
`CLOSED_BETA`
