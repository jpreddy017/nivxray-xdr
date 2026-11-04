<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Authentication & Authorization

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Login, sessions, tokens, agent credentials and object-level authorisation.

## Owner
Security

## Dependencies
SECURITY_ARCHITECTURE.md · RBAC_MATRIX.md

## Required source inputs
Auth implementation; agent enrolment credentials; session context routes

## Known current reality
Analyst auth and agent credential issuance both work, including single-use enrolment tokens and revocation.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Password policy, session lifetime, MFA and credential rotation are undefined.

## Completion criteria
Full authn/authz specification with tests for expiry, revocation, reuse and privilege escalation.

## Release stage by which this must be complete
`CLOSED_BETA`
