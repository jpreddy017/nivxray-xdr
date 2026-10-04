/**
 * anchorEvidence · S3-D.
 *
 * The ONE join between a causal anchor and the evidence that supports it.
 *
 * What the data contract actually provides (verified against the live
 * records, not assumed):
 *
 *   · a causal anchor is an IKG node id — `proc_…`, `dev_…`, `user_…`,
 *     `cmd_…` — NOT an evidence id and NOT a label;
 *   · a device-trajectory frame carries those same ids in STRUCTURED entity
 *     slots (`process.iid`, `device.iid`, `user.iid`, `file.iid`,
 *     `parent.iid`, `network.iid`, `registry.iid`, `entity.iid`, `root.iid`);
 *   · each frame carries its own `frame_iid`, its `evidence_ids[]` and its
 *     `provenance` (normalizer · source · origin · ingest job).
 *
 * So the join is: anchor id → the frames whose entity slots CITE that id →
 * those frames' evidence references. This is a recorded citation, never a
 * name match: `same entity label ≠ provenance`, and no label is ever used as
 * a lookup key.
 *
 * KNOWN CONTRACT GAP — CLOSED (P1 Evidence Namespace Bridge, 2026-06): a
 * trajectory frame now carries `canonical_evidence_id`
 * (`xdr_canonical_evidence.event_id`), propagated from the identifier the
 * ingest pipeline already persisted on the observation. A causal anchor
 * therefore joins the incident's own canonical evidence record
 * deterministically, through `GET /api/incidents/{id}/canonical-evidence`.
 * Frames whose observation never carried that identifier stay
 * LEGACY_UNBRIDGED and keep their own namespace — no heuristic match.
 */

/** Every structured entity slot a frame may cite an anchor in. */
const SLOTS = ["process", "device", "user", "file", "parent", "network",
               "registry", "entity", "root", "execution"];

/** The canonical evidence identities the given frames reference. */
export function canonicalIdsFor(frames) {
  const out = new Set();
  (frames || []).forEach((f) => {
    if (f?.canonical_evidence_id) out.add(f.canonical_evidence_id);
  });
  return out;
}

/** Frames that CITE this anchor id in a structured slot. */
export function framesForAnchor(frames, anchorId) {
  if (!anchorId) return [];
  return (frames || []).filter((f) => SLOTS.some((s) => {
    const v = f?.[s];
    if (!v) return false;
    const iid = typeof v === "string" ? v : (v.iid || v.id);
    return iid === anchorId;
  }));
}

/** The authoritative references those frames carry. */
export function evidenceRefsFor(frames) {
  const frameIids = [];
  const evidenceIds = [];
  (frames || []).forEach((f) => {
    if (f.frame_iid) frameIids.push(f.frame_iid);
    (f.evidence_ids || []).forEach((e) => {
      if (!evidenceIds.includes(e)) evidenceIds.push(e);
    });
  });
  return { frameIids, evidenceIds, count: frames?.length || 0 };
}

/** The provenance chain of ONE frame, in reading order. */
export function chainFor(frame) {
  const p = frame?.provenance || {};
  return [
    frame?.frame_iid ? `event ${frame.frame_iid}` : null,
    (frame?.evidence_ids || []).length
      ? `observation ${frame.evidence_ids.join(", ")}` : null,
    frame?.canonical_evidence_id
      ? `canonical ${frame.canonical_evidence_id}` : null,
    p.normalizer ? `normalizer ${p.normalizer}` : null,
    p.source ? `source ${p.source}` : null,
    p.origin ? `origin ${p.origin}` : null,
    p.ingest_job_id ? `ingest job ${p.ingest_job_id}` : null,
  ].filter(Boolean);
}
