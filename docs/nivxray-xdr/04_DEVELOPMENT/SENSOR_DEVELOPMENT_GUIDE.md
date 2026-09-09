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

**Two lifecycle requirements added by P0-3 (2026-09-08), learned from a
real 24-hour outage.** The Linux sensor did not fail — it was never a
supervised program and its durable state (`identity.json`, outbox,
already-reported set) sat on a path that did not survive container
recreation. Any new sensor MUST therefore:

1. be started by a supervisor with `autorestart`, and survive `SIGKILL`
   by resuming the SAME platform-minted `endpoint_id` from persistent
   state (proven for Linux: `scripts/p0_3_sensor_recovery_proof.py`
   gates F1–F3);
2. emit a **heartbeat at the start of every cycle** — before any
   delivery drain — via `POST /api/edr/agent/heartbeat`, carrying its own
   `report_interval_seconds` and its outbox `queue_depth`. A poll-based
   sensor legitimately has quiet cycles, so without a liveness signal the
   platform cannot tell a healthy quiet sensor from a dead one; and
   sending it after the drain makes liveness depend on delivery
   throughput, which under a backlog reported a busy sensor as
   unconfirmed. The heartbeat must never be treated as telemetry: it
   creates no raw event and does not advance `last_telemetry_at`.

Endpoint identity is minted by the platform from durable machine
attributes (`processor_id > machine_guid > device_iid > hostname`), so a
re-install or credential rotation must resolve to the same endpoint —
and re-enrolment must NOT reset the delivery record (fixed in
`edr_plane/enrollment/store.enroll()`; that record is what blindness
detection is derived from).

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
