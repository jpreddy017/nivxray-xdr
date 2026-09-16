<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Deployment Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
How NivXRay is deployed, which services exist, their ports, dependencies and start order.

## Owner
Operations

## Dependencies
SYSTEM_ARCHITECTURE.md

## Required source inputs
Supervisor configuration; backend :8001, frontend :3000, collector ial :8055, response service :8056

## Known current reality
The platform runs as supervisor-managed services in a single environment. There is no documented deployment topology, and the preview environment is not a production topology.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the target production topology — single tenant per install, or multi-tenant SaaS? This changes almost everything downstream.

## Completion criteria
A clean environment can be brought up from this document alone, with verified health on every service.

## Release stage by which this must be complete
`CLOSED_BETA`
