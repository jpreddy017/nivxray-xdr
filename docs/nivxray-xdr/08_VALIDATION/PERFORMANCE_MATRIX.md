<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Performance Matrix

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Measured throughput, latency and capacity with stated conditions.

## Owner
QA

## Dependencies
HA_SCALING_GUIDE.md

## Required source inputs
memory/V1_6_0_BASELINE_METRICS.md; memory/RC4.6_PIPELINE_PERF_INVESTIGATION.md

## Known current reality
Some historical pipeline performance work exists. Nothing has been measured at fleet scale; the real corpus is roughly 8k events from 2 endpoints.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the target events-per-second per endpoint and per fleet?

## Completion criteria
Measured numbers for ingest, detection, query and UI render at a declared fleet size, reproducible by script.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
