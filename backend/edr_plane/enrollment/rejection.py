"""Rejected telemetry as a SECURITY SIGNAL — owner decision 4C.

The rule, stated so it cannot be softened later:

    Reject at the trust boundary (401/403) **AND** record a visible
    security signal. Never silently drop it. The rejected payload is a
    security signal but is **NOT trusted endpoint evidence** and must
    never enter the authoritative EDR evidence, detection or response
    pipelines.

Both halves matter and they pull in opposite directions, which is why
they live in a separate collection with its own name. `edr_rejected_
telemetry` is not queried by any evidence, trajectory, detection or
verdict path — the isolation is structural, not a convention. An
investigator can read it; the reasoning engines cannot reach it.

What is recorded is metadata sufficient to investigate the attempt, and
never the secret that was presented: a credential FINGERPRINT lets an
analyst correlate repeated attempts by the same bad credential without the
platform ever storing the credential.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pymongo import ASCENDING, DESCENDING

from .security import fingerprint

COLLECTION = "edr_rejected_telemetry"

#: Codes that mean "an agent that once had standing is now refused". These
#: are more interesting than a plain unauthenticated attempt: something
#: that HAD a credential is using it after revocation.
POST_TRUST_CODES = frozenset({
    "AGENT_CREDENTIAL_REVOKED", "ENDPOINT_REVOKED", "SESSION_REVOKED",
    "SESSION_SUPERSEDED", "AGENT_UNENROLLED",
})


async def ensure_indexes(db: Any) -> None:
    await db[COLLECTION].create_index([("observed_at", DESCENDING)])
    await db[COLLECTION].create_index(
        [("credential_fingerprint", ASCENDING), ("observed_at", DESCENDING)])
    await db[COLLECTION].create_index([("source_ip", ASCENDING)])
    await db[COLLECTION].create_index([("code", ASCENDING)])


async def record_rejection(db: Any, *, tenant_id: Optional[str],
                           presented_secret: Optional[str],
                           source_ip: Optional[str], code: str, reason: str,
                           request_id: Optional[str] = None,
                           path: Optional[str] = None,
                           endpoint_id: Optional[str] = None) -> dict:
    """Record the attempt. Never raises — a failure to record must not
    become a way to make a rejection quieter."""
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "rejection_id": f"rej_{uuid4().hex[:16]}",
        "observed_at": now,
        # Unauthenticated by definition: the tenant is usually UNRESOLVED,
        # and pretending otherwise would attribute an attack to a tenant on
        # the attacker's word.
        "tenant_id": tenant_id,
        "tenant_resolution": "RESOLVED" if tenant_id else "UNRESOLVED",
        "endpoint_id": endpoint_id,
        "endpoint_resolution": "RESOLVED" if endpoint_id else "UNRESOLVED",
        "credential_fingerprint": (fingerprint(presented_secret)
                                   if presented_secret else None),
        "credential_kind": (presented_secret.split("_", 1)[0]
                            if presented_secret and "_" in presented_secret
                            else None),
        "source_ip": source_ip,
        "request_id": request_id,
        "path": path,
        "code": code,
        "reason": reason,
        "severity": "HIGH" if code in POST_TRUST_CODES else "MEDIUM",
        "signal_class": ("REVOKED_AGENT_STILL_TRANSMITTING"
                         if code in POST_TRUST_CODES
                         else "UNAUTHORISED_SENSOR_INGEST_ATTEMPT"),
        "payload_retained": False,
        "trust_state": "REJECTED",
        "evidence_eligibility": "NEVER_EVIDENCE",
        "honesty_note": (
            "An unauthorised sensor attempting ingest IS a security signal. "
            "The rejected payload is NOT trusted endpoint evidence and is "
            "excluded from the evidence, detection and response pipelines."),
    }
    try:
        await db[COLLECTION].insert_one(dict(doc))
    except Exception:  # noqa: BLE001
        pass
    doc.pop("_id", None)
    return doc


async def list_rejections(db: Any, *, limit: int = 100,
                          code: str | None = None) -> list[dict]:
    q = {"code": code} if code else {}
    return await db[COLLECTION].find(q, {"_id": 0}) \
        .sort("observed_at", DESCENDING).limit(limit).to_list(length=limit)


async def rejection_summary(db: Any) -> dict:
    coll = db[COLLECTION]
    total = await coll.count_documents({})
    post_trust = await coll.count_documents(
        {"code": {"$in": list(POST_TRUST_CODES)}})
    distinct_ips = len(await coll.distinct("source_ip"))
    distinct_creds = len(await coll.distinct("credential_fingerprint"))
    return {
        "total_rejections": total,
        "revoked_agent_still_transmitting": post_trust,
        "distinct_source_ips": distinct_ips,
        "distinct_credential_fingerprints": distinct_creds,
        "isolation": (
            f"Stored in {COLLECTION}, which no evidence, trajectory, "
            f"detection or verdict path queries. The isolation is "
            f"structural, not a convention."),
    }
