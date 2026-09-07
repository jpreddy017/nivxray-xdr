<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Sensor Development Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
How to build a NivXForge sensor for a new platform: enrolment, transport, event contracts, identity, command execution and verification probes.

## Owner
Endpoint

## Dependencies
INTEGRATION_ARCHITECTURE.md · RESPONSE_ARCHITECTURE.md

## Required source inputs
agents/nivxforge-linux/nivxforge_sensor.py (the only existing producer); edr_plane/enrollment/*; edr_plane/contracts/telemetry.py

## Known current reality
One Linux sensor exists and has delivered real telemetry. The enrolment and ingest APIs are platform-agnostic, but three parts of the platform are Linux-shaped: trajectory lanes cover only PROCESS/FILE/NETWORK, kill verification requires a /proc start_ticks identity basis, and no Windows or macOS producer exists.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Windows process identity basis (PID plus creation time) must be a first-class alternative to start_ticks — does that change the command target contract?

## Completion criteria
A Windows sensor can be built from this guide, its events land in declared lanes, and its kill verification is accepted by the response verifier without weakening the proof standard.

## Release stage by which this must be complete
`LAB_VALIDATED`
