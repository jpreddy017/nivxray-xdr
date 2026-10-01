<!-- NIVX-DOC
layer: TARGET_SPEC
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: 2026-09-07T17:57Z
-->

# Response Adapter Guide

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **CLOSED_BETA**.

## Purpose
How a control plane implements a response action with approval, execution and independent verification.

## Owner
Response

## Dependencies
RESPONSE_ARCHITECTURE.md · 07_SECURITY/RESPONSE_SAFETY.md

## Required source inputs
apps/nivxray-xdr-response (:8056); edr_plane/response.py lifecycle

## Known current reality
The lifecycle is real and refuses to claim success: 5 commands reached VERIFIED, 1 VERIFICATION_FAILED, 8 CAPABILITY_UNAVAILABLE. 16 of 18 catalogued actions are NON_OPERATIONAL stubs.

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
For each of the 16 stubs: adopt, wire, or deprecate? Publishing 18 actions where 2 work is a product-honesty problem.

## Completion criteria
Each action either has a real adapter with a verification probe or is removed from the catalogue; no action is listed without a state.

## Release stage by which this must be complete
`CLOSED_BETA`
