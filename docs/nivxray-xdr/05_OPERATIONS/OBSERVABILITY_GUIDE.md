<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Observability Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
Logs, metrics, traces and the alerts that tell an operator the platform has gone blind.

## Owner
Operations

## Dependencies
DEPLOYMENT_GUIDE.md

## Required source inputs
Structured JSON logging; existing health routes

## Known current reality
Structured logging exists. Critically, the platform went telemetry-blind for over 24 hours and NOTHING alerted — that is the strongest evidence this document is needed.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the staleness threshold at which sensor silence becomes an alert rather than a quiet empty screen?

## Completion criteria
Sensor silence, ingest failure, collector failure and integration failure each raise an operator-visible alert with a proven trigger.

## Release stage by which this must be complete
`LAB_VALIDATED`
