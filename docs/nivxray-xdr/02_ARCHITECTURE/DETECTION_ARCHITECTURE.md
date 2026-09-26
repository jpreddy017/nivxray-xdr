<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Detection Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **LAB_VALIDATED**.

## Purpose
Document how a canonical event becomes a detection: rule sources, evaluation, attribution to evidence, and what a detection may claim.

## Owner
Detection

## Dependencies
EVIDENCE_ARCHITECTURE.md · CORRELATION_ARCHITECTURE.md

## Required source inputs
xdr_detection_rules (98 rules, 5 sources); detection_content/ package; scripts/p0_detection_attribution_proof.py

## Known current reality
98 rules are loaded and 64 detections are attributed to REAL sensor events with raw_id + canonical_event_id. Rule provenance, licensing and coverage-by-platform are only partly documented.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
How many of the 98 rules can actually fire against Linux-shaped telemetry versus assuming Windows/Sysmon fields?

## Completion criteria
Rule inventory with per-rule platform applicability, required fields, and a fired/never-fired status backed by runtime evidence.

## Release stage by which this must be complete
`LAB_VALIDATED`
