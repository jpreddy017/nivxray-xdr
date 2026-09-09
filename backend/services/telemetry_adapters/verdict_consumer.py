"""
Verdict Engine consumer adapter — Phase 2 Final Integration Gate.

Owner rule: the existing Verdict Engine is the sole verdict
authority.  This adapter is a THIN, governed intake — it accepts
`VerdictInput` records + `EvidenceGraphEdge` records from the
cross-lane correlation bridge and persists them alongside the
incident so the existing engine can consume them at its next
scoring pass.

Guarantees:
  · Never scores, never promotes ATT&CK to OBSERVED, never
    inflates confidence.
  · Strips any field that looks like verdict authority before
    write, so a future refactor of the bridge cannot leak
    scoring authority through this path.
  · Every persisted edge carries `attck_promotion=False` in its
    provenance — a cross-lane hint is NEVER an ATT&CK promotion.
  · Idempotent-safe: uses `correlation_key` as the natural key
    for inputs; edges use (correlation_key, src, dst) so
    reruns of the same correlation window do not fabricate
    additional edges.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any


_FORBIDDEN_VERDICT_FIELDS = (
    "verdict", "severity", "maliciousness",
    "verdict_confidence", "attck_promote",
)

_VERDICT_INPUTS_COLL = "xdr_verdict_inputs"
_EVIDENCE_EDGES_COLL = "xdr_evidence_graph_edges"


def _strip_verdict_authority(d: dict[str, Any]) -> dict[str, Any]:
    for forbidden in _FORBIDDEN_VERDICT_FIELDS:
        d.pop(forbidden, None)
    return d


def _to_dict(rec: Any) -> dict[str, Any]:
    if hasattr(rec, "__dataclass_fields__"):
        d = asdict(rec)
    elif isinstance(rec, dict):
        d = dict(rec)
    else:
        d = dict(rec.__dict__)
    # Convert tuples → lists so Mongo stores JSON-friendly shapes.
    for k, v in list(d.items()):
        if isinstance(v, tuple):
            d[k] = list(v)
    return d


async def record_verdict_inputs_for_incident(
    db,
    incident_id: str,
    verdict_inputs: list[Any],
    evidence_graph_edges: list[Any] | None = None,
) -> dict[str, Any]:
    """Persist governed inputs + evidence-graph edges for an
    incident.  Returns a summary that never leaks values."""
    if not incident_id:
        raise ValueError("incident_id is required")

    now = datetime.now(timezone.utc).isoformat()
    stored_inputs = 0
    stored_edges  = 0

    # -- Persist VerdictInput records ---------------------------------
    for vi in verdict_inputs or []:
        d = _strip_verdict_authority(_to_dict(vi))
        d["incident_id"]     = incident_id
        d["recorded_at"]     = now
        d["authority_note"]  = (
            "governed input only — existing Verdict Engine remains "
            "authoritative")
        key = {
            "incident_id":     incident_id,
            "correlation_key": d.get("correlation_key"),
        }
        await db[_VERDICT_INPUTS_COLL].update_one(
            key, {"$set": d}, upsert=True,
        )
        stored_inputs += 1

    # -- Persist EvidenceGraphEdge records ----------------------------
    for edge in evidence_graph_edges or []:
        d = _to_dict(edge)
        prov = d.get("provenance") or {}
        # Hard invariant — a cross-lane hint NEVER promotes ATT&CK.
        prov["attck_promotion"] = False
        d["provenance"]  = prov
        d["incident_id"] = incident_id
        d["recorded_at"] = now
        key = {
            "incident_id":      incident_id,
            "correlation_key":  d.get("correlation_key"),
            "src_canonical_id": d.get("src_canonical_id"),
            "dst_canonical_id": d.get("dst_canonical_id"),
        }
        await db[_EVIDENCE_EDGES_COLL].update_one(
            key, {"$set": d}, upsert=True,
        )
        stored_edges += 1

    return {
        "incident_id":     incident_id,
        "stored_inputs":   stored_inputs,
        "stored_edges":    stored_edges,
        "authority":       "existing-verdict-engine",
        "attck_promotion": False,
    }
