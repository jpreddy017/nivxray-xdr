<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Configuration Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Every configuration key, its default, its blast radius and where it lives.

## Owner
Operations

## Dependencies
DEPLOYMENT_GUIDE.md · 07_SECURITY/SECRETS_MANAGEMENT.md

## Required source inputs
backend/.env, frontend/.env, feature flags (including shadow-mode engine flags)

## Known current reality
Feature flags exist including shadow-mode engine toggles. There is no consolidated configuration reference.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Which flags are safe for an operator to change versus engineering-only?

## Completion criteria
Every key documented with type, default, effect and owner; no undocumented key read at runtime.

## Release stage by which this must be complete
`CLOSED_BETA`
