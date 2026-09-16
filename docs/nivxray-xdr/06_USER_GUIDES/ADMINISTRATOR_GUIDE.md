<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Administrator Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Tenants, users, roles, integrations, sensors, retention and audit.

## Owner
Product

## Dependencies
IDENTITY_TENANCY_ARCHITECTURE.md · INTEGRATION_ADMIN_GUIDE.md

## Required source inputs
Administration routes; RBAC surfaces

## Known current reality
Administration surfaces exist for RBAC, API keys, secrets and audit. Retention and lifecycle administration do not.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which administrative actions are self-service versus engineering-only today?

## Completion criteria
An administrator can run the platform from this guide without engineering support.

## Release stage by which this must be complete
`CLOSED_BETA`
