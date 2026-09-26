# S3-D · ANCHOR-TO-EVIDENCE — 2026-06-21

**Status: DONE · PROVEN PROGRAMMATICALLY** (no screenshots).
**Frontend only.** No backend change, no new graph/correlation/inference, no
new evidence store, no new authorization mechanism.
Proof: `scripts/p1_s3d_anchor_to_evidence_proof.py` → **24 PASS · 0 FAIL**
(`test_reports/p1_s3d_anchor_to_evidence_proof.txt`) · `yarn build` **PASS**.

## ANCHOR → EVIDENCE AUTHORITY (established from the live records)

Nothing was assumed. What the contract actually holds:

| fact | reality |
|---|---|
| a causal anchor id | an IKG node id — in this dataset `ent_process_a5fb93a39897`, `ent_device_…`. **Not** an evidence id, **not** a label |
| the join | a device-trajectory frame carries those ids in **structured entity slots** (`entity.iid`, `process.iid`, `device.iid`, `user.iid`, `file.iid`, `parent.iid`, `network.iid`, `registry.iid`, `root.iid`, `execution.iid`) |
| the evidence reference | that frame's `frame_iid` + `evidence_ids[]` |
| the chain | `provenance.normalizer → source → origin → ingest_job_id → ingested_at` |
| **entity id ≠ evidence id** | confirmed: the anchor is `ent_process_…`, the frame is `tf_…`, the canonical evidence is `evt_…` |
| **label ≠ lookup key** | never used; the join reads structured slots only |

**CONTRACT GAP — reported, not invented around.** The incident Evidence
table is projected from `incident.evidence_pointers`, and the incident's own
`canonical_evidence_ids` are in a *different namespace*
(`sysmon-1-b10bc713…`) from the engine's `tf_…`/`evt_…` references. The shared
inspector answers `state: MISSING` for engine ids ("process not present in
canonical evidence"), and for this incident every evidence pointer has zero
bullets. **There is therefore no authoritative join from a causal anchor to a
row of the incident Evidence table.** Rather than fabricate one, S3-D
resolves the anchor to the records that genuinely cite it, in a focused
section of the same Evidence tab, and says plainly that the two reference
namespaces are reported separately instead of joined on a guess.

## VISIBLE UI CHANGE

- **Story → Causal anchors** gained a *Supporting evidence* column:
  `Evidence cited · N supporting record(s)` + a `View evidence →` action, or
  a dashed **NO EVENT CITED** chip with **no action at all**.
- **Evidence tab** gained a focused section *"Evidence supporting the selected
  causal anchor"* above the existing coverage strip and evidence table (both
  untouched): a dense table of every citing record
  (`Activity time · Lane · Observed activity · Evidence reference · Source`),
  row expansion showing the provenance chain and the **existing** shared
  `EvidenceInspector`, plus a `Clear anchor` action.

## NAVIGATION BEHAVIOR

Existing query-param routing only (the same contract S3-C uses):
`View evidence` → `?tab=evidence&focus=<anchor id>`. No new route, no second
router, no separate evidence screen (asserted: one `xdr-record-evidence`, one
focused section). A single citing record is auto-expanded;
`Clear anchor` removes the param.

## MULTIPLE-EVIDENCE BEHAVIOR

Every citing record is listed, with the sentence *"Every one of them is listed
— none is chosen as 'the' evidence."* The anchor row states the count before
the analyst navigates. No record is promoted or hidden.

## NO-EVIDENCE BEHAVIOR

- An anchor with no citing frame renders **NO EVENT CITED** and gets no
  action. Asserted: actionable anchors + uncited anchors == all anchors, so an
  action can never appear without a citation.
- An unmapped reference (`?focus=proc_s3d_does_not_exist`) renders
  **REFERENCE NOT MATCHED** + *"NivXRay will not show the nearest similar
  record instead — the same entity label is not provenance"* + *"This is an
  absence of a citation, not a finding that the entity was benign."* No rows,
  no nearest-match fallback.
- An incident with no causal analysis exposes no anchor evidence action at all.

## PROVENANCE

`Causal anchor → citing frame (tf_…) → canonical evidence (evt_…) →
normalizer → source → origin → ingest job`, rendered live as
`event tf_487f2c73b75943aa → canonical evt_c972032f8eb510ad → normalizer
sysmon-normalizer → source Sysmon → origin collector-live → ingest job …`,
with `Ingested` reported separately. Nothing duplicated, nothing synthesised,
no frontend-generated provenance. Where the inspector cannot resolve a
reference it keeps reporting `MISSING` — the gap stays visible.

## ENTITY TYPES

The join is slot-driven and type-agnostic: device · user · process · file ·
hash · IP · domain · URL · command · registry all resolve through the same
`framesForAnchor` slot scan. No per-type special case was added to make the
current fixture pass.

## AUTHORIZATION

No new mechanism. Reads used: the device trajectory (S2-mini incident tenant
authority) and the shared inspector (S1). Cross-tenant: the incident is
refused upstream — asserted that another tenant's incident with a valid
anchor in the URL exposes no citing record and no entity name. A client-
supplied tenant/customer/principal is never authority (already proven in
S2-mini/S3-B and unchanged here).

## FILES CHANGED

New: `src/xdr/incidents/anchorEvidence.js` (the join + chain, with the
contract gap documented in code) · `scripts/p1_s3d_anchor_to_evidence_proof.py`.
Changed: `src/xdr/incidents/IncidentStoryDepth.jsx` (trajectory read,
Supporting-evidence column, hand-off) ·
`src/xdr/pages/incidents/record/tabs/EvidenceTab.jsx` (focused anchor section).

## FOCUSED PROOF

**24 PASS · 0 FAIL**: anchors render · count stated · uncited anchors have no
action · hand-off lands focused · focused section (not a new screen) ·
citing records resolve · multiplicity honest · every record listed ·
provenance chain shown · inspector reachable · existing evidence table intact ·
unmapped reference explicit · no nearest-match · absence ≠ benign ·
NOT_ASSOCIATED offers nothing · cross-tenant exposes nothing · all 7 tabs
render. `yarn build` PASS.

## RESIDUALS

1. **P1 CONTRACT GAP (owner decision needed):** the causal evidence plane
   (`tf_…`/`evt_…`) and the incident evidence plane
   (`evidence_pointers` / `canonical_evidence_ids` = `sysmon-1-<uuid>`) do not
   share a reference namespace, and the shared inspector reports `MISSING` for
   engine ids. Until one side carries the other's reference, a causal anchor
   can be joined to the records that cite it but **not** to a row of the
   incident Evidence table.
2. This incident has 1 frame, so multiplicity is proven by contract and copy
   but not yet observed with N>1 (the dense-timeline check will cover it).
3. Carried P0 security residual, untouched: `response-executions` trusts a
   client-supplied `tenant_id`.
