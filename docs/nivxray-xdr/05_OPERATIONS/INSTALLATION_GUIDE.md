<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Installation Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
Operator-facing installation, including sensor deployment at scale.

## Owner
Operations

## Dependencies
DEPLOYMENT_GUIDE.md · SENSOR_DEVELOPMENT_GUIDE.md

## Required source inputs
Linux sensor enrolment flow; agent credential lifecycle

## Known current reality
Sensor enrolment works one machine at a time via a token. There is no packaged installer and no fleet deployment mechanism.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Do we need an MSI/service installer before a design-partner pilot? Almost certainly yes for Windows.

## Completion criteria
An operator can install the platform and enrol a fleet without engineering help.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
