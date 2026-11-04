<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# SOC Analyst Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
The analyst's day: triage, investigate, decide, respond, verify, close.

## Owner
Product

## Dependencies
INFORMATION_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md

## Required source inputs
Shipped console behaviour; owner's workflow description

## Known current reality
The console supports a substantial part of this loop against real evidence. A user guide must describe only what is usable today, so it cannot be written honestly until the incident-provenance question is resolved.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Can an analyst currently tell a real incident from a seeded one? Today, no — 0 of the incidents carry a provenance label.

## Completion criteria
Every documented step performable in the shipped product against real evidence, with screenshots from a real endpoint.

## Release stage by which this must be complete
`CLOSED_BETA`
