<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Intelligence Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
Document reputation/disposition sourcing, caching, provenance and how third-party intelligence is prevented from becoming a verdict.

## Owner
Intelligence

## Dependencies
INVESTIGATION_ARCHITECTURE.md · 07_SECURITY/SECRETS_MANAGEMENT.md

## Required source inputs
7 live IOC providers (abuseipdb, hybrid-analysis, malwarebazaar, threatfox, urlhaus, urlscan, virustotal); threat-intel routes

## Known current reality
Seven providers report live at startup. Provenance and cache-age disclosure on analyst surfaces is not fully specified.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
What is the disclosure contract when a provider is down or a disposition is stale? Must never silently degrade to 'clean'.

## Completion criteria
Per-provider contract: auth, rate limits, cache TTL, staleness disclosure, failure state, and never-infer-clean rule proven by test.

## Release stage by which this must be complete
`CLOSED_BETA`
