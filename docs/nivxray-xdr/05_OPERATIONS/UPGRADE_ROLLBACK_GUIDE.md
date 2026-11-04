<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Upgrade & Rollback Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
How the platform and the sensor fleet are upgraded and rolled back safely.

## Owner
Operations

## Dependencies
DEPLOYMENT_GUIDE.md · SENSOR_DEVELOPMENT_GUIDE.md

## Required source inputs
memory/RC2.1a_ROLLBACK_PLAN.md; memory/RC2.2_ROLLBACK_PLAN.md

## Known current reality
Point-in-time rollback plans exist for two past releases. There is no general procedure and no sensor upgrade mechanism at all.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Can a sensor self-update, and what happens to in-flight telemetry and pending commands during an upgrade?

## Completion criteria
An upgrade and a rollback both performed in test, including a sensor fleet, with no evidence loss.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
