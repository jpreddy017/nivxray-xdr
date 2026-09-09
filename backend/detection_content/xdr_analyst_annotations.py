"""
Round 18.6 · Analyst Annotations Fabric
────────────────────────────────────────

**Overlay, not replacement.**  The deterministic Executive Summary
composer + the evidence-derived recommendation synthesizer remain
authoritative ground truth. Analyst findings are RECORDED here as an
overlay so:

    * The audit trail proves what the analyst added AND what the
      deterministic engines said — separately.
    * A future re-compute never erases analyst work.
    * A superseded annotation is NEVER hard-deleted; only marked
      `superseded_by` so the history stays intact.

Storage: `xdr_analyst_annotations` collection.

Sections (locked):
    executive           — narrative prose additions
    technical           — key/value overrides or notes
    supporting_evidence — new claim rows the analyst can add
    recommendations     — notes attached to a specific reco_id OR
                          analyst-authored custom recommendations

Contract:
    * Analyst annotations are ALWAYS labelled `origin = ANALYST`
      by the API; the frontend must render an obvious badge so the
      analyst never confuses their own text with composer output.
    * `create`, `update` and `retire` (soft-delete) return the full
      annotation record + a fresh audit entry.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any


COLLECTION = "xdr_analyst_annotations"


SECTION_VALUES = {"executive", "technical",
                            "supporting_evidence", "recommendations"}
KIND_VALUES    = {"note", "finding", "override", "custom_reco"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return "ann-" + uuid.uuid4().hex[:16]


def _validate(section: str, kind: str) -> None:
    if section not in SECTION_VALUES:
        raise ValueError(f"section must be one of {SECTION_VALUES}, "
                                f"got {section!r}")
    if kind not in KIND_VALUES:
        raise ValueError(f"kind must be one of {KIND_VALUES}, "
                                f"got {kind!r}")


async def create(db, incident_id: str, section: str, kind: str,
                    payload: dict, author: str,
                    target_id: str | None = None) -> dict:
    """Create a new analyst annotation.  `target_id` links the record
    to a specific reco_id / technical-field / supporting-evidence row
    when applicable."""
    _validate(section, kind)
    now = _now()
    doc = {
        "id":            _new_id(),
        "origin":        "ANALYST",
        "incident_id":   incident_id,
        "section":       section,
        "kind":          kind,
        "target_id":     target_id,
        "payload":       payload or {},
        "author":        author,
        "created_at":    now,
        "updated_at":    now,
        "superseded_by": None,
        "retired_at":    None,
        "history":       [],
    }
    await db[COLLECTION].insert_one(dict(doc))
    return doc


async def update(db, incident_id: str, ann_id: str,
                    payload: dict, author: str) -> dict | None:
    """
    Update an existing annotation.  The previous payload is appended
    to `history` — nothing is silently overwritten.  Returns the
    fresh doc, or None if the annotation is not found / retired.
    """
    doc = await db[COLLECTION].find_one({"id": ann_id,
                                                            "incident_id": incident_id},
                                                          {"_id": 0})
    if not doc or doc.get("retired_at") or doc.get("superseded_by"):
        return None
    now = _now()
    prior = {
        "payload":    doc.get("payload") or {},
        "author":     doc.get("author"),
        "updated_at": doc.get("updated_at"),
    }
    await db[COLLECTION].update_one(
        {"id": ann_id, "incident_id": incident_id},
        {"$set":  {"payload":    payload or {},
                       "author":     author,
                       "updated_at": now},
          "$push": {"history":    prior}},
    )
    doc = await db[COLLECTION].find_one({"id": ann_id,
                                                            "incident_id": incident_id},
                                                          {"_id": 0})
    return doc


async def retire(db, incident_id: str, ann_id: str,
                    author: str, reason: str | None = None) -> dict | None:
    """Soft-delete: mark `retired_at` and record the reason.  The
    document is retained so the audit trail stays intact."""
    doc = await db[COLLECTION].find_one({"id": ann_id,
                                                            "incident_id": incident_id},
                                                          {"_id": 0})
    if not doc or doc.get("retired_at"):
        return None
    now = _now()
    await db[COLLECTION].update_one(
        {"id": ann_id, "incident_id": incident_id},
        {"$set": {"retired_at":    now,
                      "retired_by":    author,
                      "retired_reason": reason,
                      "updated_at":    now}},
    )
    return await db[COLLECTION].find_one({"id": ann_id,
                                                              "incident_id": incident_id},
                                                            {"_id": 0})


async def list_for_incident(db, incident_id: str,
                                        include_retired: bool = False) -> list[dict]:
    q: dict[str, Any] = {"incident_id": incident_id}
    if not include_retired:
        q["retired_at"] = None
    out: list[dict] = []
    async for d in db[COLLECTION].find(q, {"_id": 0}) \
                                       .sort("created_at", 1):
        out.append(d)
    return out


async def group_by_section(db, incident_id: str) -> dict[str, list[dict]]:
    """Return active annotations grouped by section, ready for the
    composer overlay."""
    grouped: dict[str, list[dict]] = {k: [] for k in SECTION_VALUES}
    for d in await list_for_incident(db, incident_id,
                                                  include_retired=False):
        grouped.setdefault(d["section"], []).append(d)
    return grouped
