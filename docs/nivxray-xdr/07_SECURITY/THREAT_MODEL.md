<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Threat Model

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **RELEASE_CANDIDATE**.

## Purpose
Threats against the platform itself, including a compromised sensor and a malicious tenant.

## Owner
Security

## Dependencies
SECURITY_ARCHITECTURE.md

## Required source inputs
STRIDE over the documented trust boundaries

## Known current reality
No formal threat model exists. A security tool that can terminate processes on managed hosts is itself a high-value target.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What happens if an agent credential is stolen — can it read other endpoints' evidence or issue commands?

## Completion criteria
Threat model complete with mitigations mapped to tests for every high and critical threat.

## Release stage by which this must be complete
`RELEASE_CANDIDATE`
