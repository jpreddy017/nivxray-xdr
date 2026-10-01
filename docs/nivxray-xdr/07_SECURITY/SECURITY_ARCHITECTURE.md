<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Security Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Trust boundaries, service identities and the platform's own attack surface.

## Owner
Security

## Dependencies
IDENTITY_TENANCY_ARCHITECTURE.md · THREAT_MODEL.md

## Required source inputs
Service topology; auth implementation; 865-route surface

## Known current reality
Auth, RBAC and tenant scoping are implemented and partly proven. Service-to-service identity between the platform and the response service on :8056 needs documenting, and a cross-tenant IDOR was found in this programme — evidence that systematic review is required.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Is the response service's trust in the platform authenticated, or network-trusted?

## Completion criteria
Every trust boundary documented with its authentication mechanism and a test proving it cannot be bypassed.

## Release stage by which this must be complete
`CLOSED_BETA`
