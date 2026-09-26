"""N2.1 · endpoint-owned address EVIDENCE — deliberately not an identity.

An address is a lease, not a device. DHCP hands `10.8.0.31` to a laptop this
morning and to a phone this afternoon; NAT and proxies collapse thousands of
endpoints onto one address; container and pod addresses are recycled within
seconds; a VPN gives one endpoint several addresses at once, and a shared
host gives one address to many processes.

So this module records what was genuinely OBSERVED — "the authenticated
endpoint E was using address A between T1 and T2, and here is the evidence
that says so" — and refuses, structurally, to answer "which endpoint is
address A?". `lookup()` never returns an attribution: it returns candidates
with the reason they cannot be treated as identity. Correlation content
(CORR-EP-001) does not consult this module at all; it uses the endpoint
identity that arrived WITH the evidence.

The observations come from authenticated sensor NETWORK evidence, where the
endpoint is bound by its enrolment credential — not from a self-declared
enrolment field an agent could simply assert.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

COLLECTION = "edr_endpoint_address_observations"

#: Stated on every stored row so nothing downstream can quietly reinterpret
#: these rows as identity.
BINDING_POLICY = "TIME_BOUNDED_OBSERVATION_NOT_IDENTITY"

NO_OBSERVATION = "NO_OBSERVATION"
SINGLE_CANDIDATE = "SINGLE_CANDIDATE_TIME_BOUNDED"
MULTIPLE_CANDIDATES = "MULTIPLE_CANDIDATES_AMBIGUOUS"
OUTSIDE_WINDOW = "OUTSIDE_OBSERVED_WINDOW"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes(db: Any) -> None:
    await db[COLLECTION].create_index(
        [("tenant_id", 1), ("endpoint_id", 1), ("address", 1)], unique=True)
    await db[COLLECTION].create_index([("tenant_id", 1), ("address", 1)])


async def record_from_canonical(db: Any, *, tenant_id: str, endpoint_id: str,
                                canonical: Dict[str, Any]) -> Optional[dict]:
    """Record the endpoint's OWN address as observed on its own evidence.

    Only the local side is recorded. A remote address belongs to a peer and
    is never an endpoint's address — the fabrication this plane has already
    had to fix once.
    """
    net = canonical.get("network") or {}
    address = net.get("src_ip")
    if not (endpoint_id and address):
        return None
    at = canonical.get("event_time") or _now()
    await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "address": address},
        {"$setOnInsert": {"first_observed_at": at,
                          "binding_policy": BINDING_POLICY},
         "$set": {"last_observed_at": at,
                  "last_evidence_event_id": canonical.get("event_id"),
                  "provenance": {
                      "source": (canonical.get("source_product")
                                 or "nivxforge-linux-sensor"),
                      "basis": "AUTHENTICATED_ENDPOINT_OWN_TELEMETRY",
                      "evidence_ref": (
                          f"xdr_canonical_evidence/{canonical.get('event_id')}"
                          if canonical.get("event_id") else None),
                      "observed_field": "network.src_ip",
                  }},
         "$inc": {"observation_count": 1}},
        upsert=True)
    return {"endpoint_id": endpoint_id, "address": address,
            "observed_at": at}


async def lookup(db: Any, *, tenant_id: str, address: str,
                 at: Optional[str] = None) -> Dict[str, Any]:
    """Candidates for an address — never an attribution.

    `usable_for_attribution` is False in every branch, on purpose. Even one
    candidate inside its observed window is only a lead: NAT, VPN, proxies,
    container reuse and DHCP all produce exactly that shape while being
    wrong.
    """
    rows: List[dict] = [
        r async for r in db[COLLECTION].find(
            {"tenant_id": tenant_id, "address": address}, {"_id": 0})]
    if not rows:
        return {"address": address, "state": NO_OBSERVATION,
                "candidates": [], "usable_for_attribution": False,
                "reason": ("no authenticated endpoint has been observed "
                           "using this address")}
    if at:
        in_window = [r for r in rows
                     if r.get("first_observed_at", "") <= at
                     <= r.get("last_observed_at", "")]
        if not in_window:
            return {"address": address, "state": OUTSIDE_WINDOW,
                    "candidates": rows, "usable_for_attribution": False,
                    "reason": ("the address was observed for this tenant, "
                               "but not at the instant asked about; an "
                               "address observed at another time says "
                               "nothing about this one")}
        rows = in_window
    state = SINGLE_CANDIDATE if len(rows) == 1 else MULTIPLE_CANDIDATES
    return {
        "address": address, "state": state, "candidates": rows,
        "usable_for_attribution": False,
        "reason": ("address observations are evidence, not identity: DHCP "
                   "reassignment, NAT/PAT, VPN, proxy egress, container and "
                   "pod address reuse and shared hosts all produce this "
                   "same shape. Use it to find evidence, never to attribute "
                   "activity to an endpoint"),
    }
