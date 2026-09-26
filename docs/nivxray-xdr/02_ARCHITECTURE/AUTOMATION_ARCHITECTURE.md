<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Automation Architecture

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **DESIGN_PARTNER_PILOT**.

## Purpose
Define workflows, triggers, approvals and the boundary between automation and response execution.

## Owner
Response

## Dependencies
RESPONSE_ARCHITECTURE.md · 07_SECURITY/RESPONSE_SAFETY.md

## Required source inputs
Existing automation/webhook routes; approval lifecycle in the response service

## Known current reality
Approval gating is real inside the response lifecycle. A general workflow/playbook engine comparable to the reference product is NOT implemented.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
Do we build a workflow engine or expose only fixed, audited playbooks? A general engine is a large security surface.

## Completion criteria
Trigger taxonomy, workflow object model, approval binding, audit contract, and a proof that no workflow can bypass response approval.

## Release stage by which this must be complete
`DESIGN_PARTNER_PILOT`
