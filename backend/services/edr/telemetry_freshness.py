"""P0-3 · fleet telemetry freshness — a PROJECTION, not a second authority.

Every state token in here is produced by
`services/edr/endpoint_health.resolve_delivery_freshness()`. This module
only decides WHICH endpoints to ask about and how to summarise the
answers, so there is exactly one place where "are we blind?" is decided.

Why this exists at all: for months the console could not tell the
difference between *"this endpoint did nothing"* and *"we stopped
receiving from this endpoint"*. Both rendered as an empty screen. The
whole point of P0-3 is that the second case is now a first-class,
observable fact.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from deps import sync_collection
from services.edr import endpoint_query as eq
from services.edr.endpoint_health import (BLINDNESS_NOTE, DELIVERY_STATES,
                                          resolve_delivery_freshness)

_ENDPOINTS = "edr_endpoints"

#: Enrolled endpoints that have never delivered anything are counted, but
#: they are NOT the fleet's blindness signal — an endpoint that was
#: enrolled for a test and never started is not a pipeline failure. They
#: are reported separately so neither fact hides the other.
_NEVER = "NEVER_DELIVERED"


def _rows(scope: Any, endpoint: Optional[str] = None
          ) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Enrolment records the caller is authorised to see.

    Resolution order matters. `resolve_endpoint()` resolves through
    OBSERVED evidence, so it cannot address an endpoint that is enrolled
    and has never reported — which is exactly the endpoint blindness
    detection is most about. So when the resolver finds nothing, the
    ENROLMENT REGISTRY is asked directly, tenant-constrained: it is the
    authority on enrolment (the same doctrine as
    `routers/edr_response.py::_canonical_endpoint_id`, which asks whether
    a literal string is already an enrolment key before resolving).
    """
    q: Dict[str, Any] = {}
    tenants = (list((scope or {}).get("tenant_ids") or [])
               if isinstance(scope, dict) and not scope.get("all_tenants")
               else None)
    addressed: Optional[Dict[str, Any]] = None
    if endpoint:
        resolution = eq.resolve_endpoint(endpoint, scope)
        if resolution:
            q.update(resolution.predicate(_ENDPOINTS))
            addressed = resolution.descriptor()
        else:
            key = str(endpoint).strip()
            reg = {"$or": [{"endpoint_id": key}, {"hostname": key},
                           {"device_iid": key}]}
            if tenants is not None:
                reg["tenant_id"] = {"$in": tenants}
            hit = sync_collection(_ENDPOINTS).find_one(
                reg, {"_id": 0, "endpoint_id": 1, "tenant_id": 1})
            if not hit:
                return [], None
            q["endpoint_id"] = hit["endpoint_id"]
            addressed = {"resolved": True,
                         "resolved_via": "ENROLMENT_REGISTRY_DIRECT",
                         "endpoint_id": hit["endpoint_id"],
                         "tenant_id": hit.get("tenant_id"),
                         "addressed_by": [key],
                         "note": ("resolved through the enrolment registry "
                                  "because this endpoint has produced no "
                                  "observation to resolve through")}
    if tenants is not None:
        q["tenant_id"] = {"$in": tenants}
    docs = list(sync_collection(_ENDPOINTS).find(
        q, {"_id": 0, "endpoint_id": 1, "tenant_id": 1, "hostname": 1,
            "platform": 1, "device_iid": 1, "sensor_version": 1,
            "sensor_state": 1, "credential_state": 1, "enrolled_at": 1,
            "revoked_at": 1, "last_seen": 1, "last_telemetry_at": 1,
            "last_heartbeat_at": 1, "report_interval_seconds": 1,
            "cadence_basis": 1, "event_count": 1,
            "outbox_queue_depth": 1}))
    return docs, addressed


def endpoint_freshness(doc: Dict[str, Any],
                       now: Optional[datetime] = None) -> Dict[str, Any]:
    fresh = resolve_delivery_freshness(
        last_telemetry_at=doc.get("last_telemetry_at"),
        report_interval_seconds=doc.get("report_interval_seconds"),
        last_heartbeat_at=doc.get("last_heartbeat_at"),
        event_count=int(doc.get("event_count") or 0),
        queue_depth=doc.get("outbox_queue_depth"),
        revoked_at=doc.get("revoked_at"), now=now)
    return {
        "endpoint_id": doc.get("endpoint_id"),
        "tenant_id": doc.get("tenant_id"),
        "hostname": doc.get("hostname"),
        "platform": doc.get("platform"),
        "sensor_version": doc.get("sensor_version"),
        "sensor_state": doc.get("sensor_state"),
        "enrolled_at": doc.get("enrolled_at"),
        "delivery": fresh,
    }


def fleet_freshness(scope: Any, *, endpoint: Optional[str] = None,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """Per-endpoint delivery freshness plus the fleet blindness summary."""
    now = now or datetime.now(timezone.utc)
    docs, addressed = _rows(scope, endpoint)
    unresolved = bool(endpoint) and addressed is None
    if unresolved:
        # P0-2C invariant: a supplied-but-unresolvable identifier is
        # ENDPOINT_NOT_RESOLVED, never an empty answer about that
        # endpoint. The FLEET answer is a different scope and does not
        # depend on the identifier, so it is still returned — labelled.
        docs, _ = _rows(scope, None)

    rows = [endpoint_freshness(d, now) for d in docs]
    if addressed and len(rows) == 1:
        # The row IS the endpoint that was addressed, so it carries how it
        # was addressed. Consumers should not have to correlate the row
        # with a response-level field to learn that.
        rows[0]["addressed_by"] = addressed
    rows.sort(key=lambda r: str(r["delivery"].get("last_delivery_at") or ""),
              reverse=True)

    by_state = {s: 0 for s in DELIVERY_STATES}
    never = 0
    for r in rows:
        by_state[r["delivery"]["state"]] += 1
        if r["delivery"]["basis"] == _NEVER:
            never += 1
    delivering = by_state["DELIVERING"]
    ever = [r for r in rows if r["delivery"]["last_delivery_at"]]
    latest = max((r["delivery"]["last_delivery_at"] for r in ever),
                 default=None)

    if not rows:
        state = "NO_ENROLLED_ENDPOINTS"
        statement = ("No endpoint is enrolled in your scope, so there is no "
                     "telemetry pipeline to be blind or healthy.")
    elif delivering > 0:
        state = "PARTIALLY_DELIVERING" if delivering < len(ever) or not ever \
            else "DELIVERING"
        statement = (f"{delivering} of {len(rows)} enrolled endpoint(s) are "
                     f"delivering within their declared cadence.")
    elif ever:
        state = "FLEET_BLIND"
        statement = ("NOT ONE enrolled endpoint that has ever delivered is "
                     "delivering now. The platform is blind to this fleet; "
                     "every endpoint surface is reporting history, not the "
                     "present.")
    else:
        state = "NEVER_DELIVERED"
        statement = ("Endpoints are enrolled but not one has ever delivered "
                     "telemetry. Enrolment is not evidence of visibility.")

    return {
        "engine_id": "nivxray::edr_plane::telemetry_freshness",
        **(eq.unresolved_envelope(endpoint) if unresolved else {}),
        "endpoints": [] if unresolved else rows,
        "count": 0 if unresolved else len(rows),
        "addressed_by": addressed,
        "fleet": {
            "state": state,
            "statement": statement,
            "scope": "FLEET_WIDE_NOT_THE_SUPPLIED_IDENTIFIER" if unresolved
                     else "CALLER_AUTHORISED_FLEET",
            "enrolled": len(rows),
            "ever_delivered": len(ever),
            "never_delivered": never,
            "by_delivery_state": by_state,
            "latest_delivery_at": latest,
            "evaluated_at": now.isoformat(),
        },
        "source": f"{_ENDPOINTS} · derived by "
                  f"services/edr/endpoint_health.resolve_delivery_freshness",
        "note": BLINDNESS_NOTE,
    }
