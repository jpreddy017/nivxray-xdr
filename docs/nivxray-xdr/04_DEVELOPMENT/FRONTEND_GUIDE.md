<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Frontend Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
How to add a screen: routing, data access, state vocabulary, testids, and the rule that no component may invent data.

## Owner
Frontend

## Dependencies
DEVELOPMENT_GUIDE.md · COMPONENT_LIBRARY.md

## Required source inputs
Shipped frontend conventions; edrApi/api clients

## Known current reality
Conventions are consistent in practice but unwritten; the no-invented-data rule is enforced by review rather than by tooling.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Can a lint rule detect a hard-coded metric or a client-side severity decision?

## Completion criteria
A new screen can be added correctly by following this document alone, and a lint or test rule catches invented data.

## Release stage by which this must be complete
`LAB_VALIDATED`
