"""
Round 26.5 · Cortex Incident Promotion Policy.
==============================================

Consumes canonical evidence rows produced by Round 26 and
DECIDES whether they represent a new NivXRay incident, an update
to an existing one, or should be suppressed by an exclusion rule.

Owner-locked invariants (Round 26.5):
  1. Evidence dedup ≠ Incident dedup.  Round 26's `event_id` upsert
     is the ONLY dedup at the evidence plane.  Promotion never
     re-dedups evidence — it dedups incidents.
  2. `xdr_incident_id` (the vendor's incident ID) is the primary
     idempotency key on the incident plane.  Same Cortex incident
     seen twice → SAME NivXRay incident (fields refreshed, no
     duplicate).
  3. Host + time-window clustering only kicks in for canonical rows
     that carry NO `xdr_incident_id` — an unusual case reserved for
     future ingest sources.
  4. Exclusion respect — a promotion may be denied and the incident
     never created.  This decision is recorded honestly on the
     canonical row itself (``promotion_state=SUPPRESSED``).
  5. A promotion decision NEVER fabricates evidence.  The incident
     record references canonical `event_id`s; it does not copy
     evidence fields.

Storage:
  * ``xdr_incidents``               — one row per promoted incident.
  * ``xdr_incident_promotion_audit`` — append-only decision trail.
"""
from __future__ import annotations

import datetime as _dt
import logging
from typing import Any, Optional

log = logging.getLogger("nivxray.xdr.cortex_promotion")

CANONICAL       = "xdr_canonical_evidence"
INCIDENTS       = "xdr_incidents"
PROMOTION_AUDIT = "xdr_incident_promotion_audit"
EXCLUSIONS      = "xdr_exclusions"


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


async def _is_excluded(db, host: Optional[str], integration_id: str) -> Optional[dict]:
    """Return the exclusion rule matching this host, or None."""
    if not host:
        return None
    rec = await db[EXCLUSIONS].find_one(
        {"integration_id": integration_id, "host": host, "active": True},
        {"_id": 0, "rule_id": 1, "host": 1, "reason": 1},
    )
    return rec


async def promote_from_ingest(db, *, integration_id: str,
                                    canonical_rows: list[dict],
                                    principal: str) -> dict:
    """Group canonical rows by `xdr_incident_id`; for each group
    promote (or refresh) exactly one NivXRay incident.  Returns a
    summary envelope."""
    grouped: dict[str, list[dict]] = {}
    for row in canonical_rows:
        key = row.get("xdr_incident_id") or ""
        if not key:
            continue
        grouped.setdefault(key, []).append(row)

    promoted:   list[str] = []
    refreshed:  list[str] = []
    suppressed: list[str] = []

    for xdr_id, rows in grouped.items():
        decision = await _promote_one(
            db, integration_id=integration_id,
            xdr_incident_id=xdr_id, rows=rows,
            principal=principal,
        )
        if decision["outcome"] == "PROMOTED":
            promoted.append(decision["nivx_incident_id"])
        elif decision["outcome"] == "REFRESHED":
            refreshed.append(decision["nivx_incident_id"])
        elif decision["outcome"] == "SUPPRESSED":
            suppressed.append(decision["xdr_incident_id"])

    envelope = {
        "integration_id":   integration_id,
        "principal":        principal,
        "at":               _iso_now(),
        "groups":           len(grouped),
        "promoted":         promoted,
        "refreshed":        refreshed,
        "suppressed":       suppressed,
    }
    await db[PROMOTION_AUDIT].insert_one(dict(envelope))
    return envelope


async def _promote_one(db, *, integration_id: str,
                              xdr_incident_id: str, rows: list[dict],
                              principal: str) -> dict:
    incident_row = next(
        (r for r in rows if r.get("source_object_type") == "incident"), None)
    if incident_row is None:
        # Should not happen with Round 26 parser, but stay honest.
        return {"outcome": "IGNORED",
                    "xdr_incident_id": xdr_incident_id,
                    "reason": "no_incident_row_in_batch"}

    fields = incident_row.get("fields") or {}
    hosts  = fields.get("hosts") or []
    users  = fields.get("users") or []
    primary_host = hosts[0] if hosts else None

    excl = await _is_excluded(db, primary_host, integration_id)
    if excl is not None:
        # Mark evidence honestly suppressed, do not create an incident.
        await db[CANONICAL].update_many(
            {"xdr_incident_id": xdr_incident_id,
              "source_integration_id": integration_id},
            {"$set": {"promotion_state": "SUPPRESSED",
                          "promotion_reason": f"host_excluded:{excl.get('rule_id')}",
                          "promoted_at": _iso_now()}},
        )
        return {"outcome": "SUPPRESSED",
                    "xdr_incident_id": xdr_incident_id,
                    "reason": f"host_excluded:{excl.get('rule_id')}"}

    # Idempotency key = vendor incident id + integration.
    lookup = {"source_integration_id": integration_id,
                 "xdr_incident_id": xdr_incident_id}
    existing = await db[INCIDENTS].find_one(lookup, {"_id": 0, "nivx_incident_id": 1})
    now = _iso_now()

    if existing is None:
        # Deterministic NivXRay incident id (short, stable).
        import hashlib
        material = f"{integration_id}|{xdr_incident_id}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
        nivx_id = f"INC-CORTEX-{digest}"

        doc = {
            "nivx_incident_id":      nivx_id,
            "source_integration_id": integration_id,
            "xdr_incident_id":       xdr_incident_id,
            "vendor":                incident_row.get("vendor"),
            "severity":              fields.get("severity"),
            "status":                fields.get("status") or "new",
            "description":           fields.get("description"),
            "hosts":                 hosts,
            "users":                 users,
            "mitre_tactics":         fields.get("mitre_tactics") or [],
            "mitre_techniques":      fields.get("mitre_techniques") or [],
            "evidence_event_ids":    [r["event_id"] for r in rows if r.get("event_id")],
            "observed_at":           incident_row.get("observed_at"),
            "created_at":            now,
            "updated_at":            now,
            "promotion_principal":   principal,
        }
        await db[INCIDENTS].insert_one(doc)
        await db[CANONICAL].update_many(
            {"xdr_incident_id": xdr_incident_id,
              "source_integration_id": integration_id},
            {"$set": {"nivx_incident_id":  nivx_id,
                          "promotion_state":   "PROMOTED",
                          "promoted_at":       now}},
        )
        return {"outcome": "PROMOTED",
                    "nivx_incident_id": nivx_id,
                    "xdr_incident_id": xdr_incident_id}

    # Refresh existing incident with the newest projection.
    nivx_id = existing["nivx_incident_id"]
    await db[INCIDENTS].update_one(
        lookup,
        {"$set": {
            "severity":            fields.get("severity"),
            "status":              fields.get("status") or "new",
            "description":         fields.get("description"),
            "hosts":               hosts,
            "users":               users,
            "mitre_tactics":       fields.get("mitre_tactics") or [],
            "mitre_techniques":    fields.get("mitre_techniques") or [],
            "updated_at":          now,
          },
          "$addToSet": {
            "evidence_event_ids": {"$each": [
                r["event_id"] for r in rows if r.get("event_id")]},
          }},
    )
    await db[CANONICAL].update_many(
        {"xdr_incident_id": xdr_incident_id,
          "source_integration_id": integration_id,
          "promotion_state": {"$ne": "SUPPRESSED"}},
        {"$set": {"nivx_incident_id": nivx_id,
                      "promotion_state":  "PROMOTED",
                      "promoted_at":      now}},
    )
    return {"outcome": "REFRESHED",
                "nivx_incident_id": nivx_id,
                "xdr_incident_id": xdr_incident_id}
