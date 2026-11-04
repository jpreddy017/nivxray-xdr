<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Correlation Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Define cross-source correlation: grouping keys, time semantics, confidence, and the honest limits while only one telemetry domain exists.

## Owner
Detection

## Dependencies
DETECTION_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md

## Required source inputs
xdr_correlation_rules (10 rules); backend correlation engine; memory/ROADMAP.md G-16/FLOW 5 notes

## Known current reality
A correlation engine and 10 rules exist. Genuine CROSS-DOMAIN correlation is not demonstrable: only the endpoint domain has a real producer, so today's correlation is within-domain.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Does any current correlation rule require a second domain, and does it therefore silently never fire?

## Completion criteria
Each rule declares required domains; a runtime proof shows which fire with one domain and which are blocked pending a second.

## Release stage by which this must be complete
`CLOSED_BETA`
