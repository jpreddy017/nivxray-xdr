<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# HA & Scaling Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Availability targets, scaling limits and measured capacity.

## Owner
Operations

## Dependencies
DEPLOYMENT_GUIDE.md · 08_VALIDATION/PERFORMANCE_MATRIX.md

## Required source inputs
Current single-instance topology

## Known current reality
Single instance of every service; no HA; no load testing. Observed corpus is roughly 8k events from 2 endpoints, so nothing is known about behaviour at fleet scale.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What fleet size must the first pilot support? That number drives every capacity decision.

## Completion criteria
Measured throughput and latency at a stated fleet size, with a documented scaling path and no single point of failure.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
