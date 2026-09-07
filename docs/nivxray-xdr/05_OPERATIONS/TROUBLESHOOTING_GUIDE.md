<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Troubleshooting Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Symptom-to-cause runbooks for the failures that actually occur.

## Owner
Operations

## Dependencies
OBSERVABILITY_GUIDE.md

## Required source inputs
This programme's own incident history: telemetry blindness, collector split-brain, alias resolution failures, empty-state ambiguity

## Known current reality
The real failure modes are known and documented in memory reports; they are not yet expressed as operator runbooks.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which failures can an operator fix versus which require engineering?

## Completion criteria
Every known failure mode has a runbook with a detection signal and a verified remedy.

## Release stage by which this must be complete
`CLOSED_BETA`
