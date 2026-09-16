<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Detection Content Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
How rules are authored, licensed, tested against real telemetry and promoted, including per-platform field requirements.

## Owner
Detection

## Dependencies
DETECTION_ARCHITECTURE.md

## Required source inputs
xdr_detection_rules (98 rules, 5 sources); rule-studio routes; memory/UNIVERSAL_DECODER_LICENSE_MATRIX.md

## Known current reality
98 rules load and a rule studio exists. Licence posture is partly documented; per-rule platform applicability is not.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
How many of the 98 rules assume Windows or Sysmon fields and therefore cannot fire on current Linux telemetry?

## Completion criteria
Every rule declares required fields, platform applicability, licence and a real-telemetry test result.

## Release stage by which this must be complete
`LAB_VALIDATED`
