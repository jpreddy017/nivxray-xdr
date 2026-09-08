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

**Delivered by P0-3 (2026-09-08), console-visible, not yet alerting.**
Delivery freshness is now a first-class derived state:
`services/edr/endpoint_health.resolve_delivery_freshness()` is the single
authority and produces `DELIVERING` / `STALE` / `BLIND_NO_DELIVERY` with
a `basis` that separates *the link is alive but there is no new evidence*
from *the link is gone*, *never delivered* and *credential revoked*.
`GET /api/edr/telemetry/freshness` exposes it per endpoint and as a fleet
roll-up, and the NivXForge console renders it on Endpoint Overview and
Process Tree. The Process Tree also states what exists OUTSIDE the
requested window, so an empty window can no longer be presented as an
empty endpoint. Report: `memory/P0_3_SENSOR_RECOVERY.md`.

**Still a gap: there is no ALERT.** Blindness is a state an operator can
see on the console; it is not an e-mail, webhook, ticket or paging
signal, and there is no notification channel in the product. Ingest,
collector and integration failure observability are also still absent.
This document therefore remains `SPEC_PENDING`.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
~~What is the staleness threshold at which sensor silence becomes an alert rather than a quiet empty screen?~~ **Answered for the STATE by P0-3**: the threshold is not a fixed number and is not a UI setting. It is derived from the sensor's own declared cadence — `stale_after_s = max(report_interval_s × 3, 60)` and `blind_after_s = max(report_interval_s × 20, 900)` — and the formula is returned with every answer. What remains open is the ALERT: which channel carries it, who is notified, how it de-duplicates across a fleet that is legitimately mostly idle, and whether a `STALE · LINK_ALIVE_NO_NEW_EVIDENCE` endpoint should notify at all.

## Completion criteria
Sensor silence, ingest failure, collector failure and integration failure each raise an operator-visible alert with a proven trigger.

## Release stage by which this must be complete
`LAB_VALIDATED`
