<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Audit Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
What is audited, immutably, and how an auditor reconstructs an action.

## Owner
Security

## Dependencies
RESPONSE_ARCHITECTURE.md

## Required source inputs
xdr_audit_log; incident_state_history append-only worklog

## Known current reality
Response executions and incident state changes are audited, with the worklog held append-only in incident_state_history as the single source of truth.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is the audit log tamper-evident, and what is its retention?

## Completion criteria
Every privileged action audited with actor, time, target and outcome; tamper evidence proven.

## Release stage by which this must be complete
`CLOSED_BETA`
