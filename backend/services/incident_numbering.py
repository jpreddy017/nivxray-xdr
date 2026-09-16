"""
NivXRay XDR · incident numbering (owner-authorised 2026-09-05).

POLICY — decided and documented here so it cannot drift:

  * ``incident_number`` is a HUMAN-FACING identifier: ``INC000000137``.
  * The authoritative backend identity remains the immutable ``id``
    (``inc_<hex>``) / ``_id``.  The number is NEVER used to derive,
    replace or regenerate it, and an incident is NEVER renumbered.
  * **Uniqueness is GLOBAL, not per tenant.**  NivXRay is operated as an
    MSS/MSSP console: a number is quoted in tickets, e-mail, bridges and
    customer reports that cross tenant boundaries, so ``INC000000137``
    must identify exactly one incident on the platform.  A per-tenant
    sequence would make "INC000000137" ambiguous the moment two
    customers are onboarded.  A compound ``(tenant_id, incident_number)``
    index is created as well so tenant-scoped lookups stay covered.
  * Allocation is ATOMIC via a single ``counters`` document updated with
    ``find_one_and_update($inc)``.  Two concurrent pipeline runs cannot
    receive the same number.
  * Only ``doc_type == "xdr_incident"`` documents get a number.  Analysis
    cases in the same ratified store never do.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

COUNTERS_COLLECTION = "counters"
COUNTER_ID          = "incident_number"
INCIDENT_COLLECTION = "workspace_cases"
INCIDENT_DOC_TYPE   = "xdr_incident"

# INC + 9 digits → head-room to 999,999,999 incidents.
_WIDTH  = 9
_PREFIX = "INC"


def format_incident_number(seq: int) -> str:
    """``137`` → ``INC000000137``."""
    return f"{_PREFIX}{int(seq):0{_WIDTH}d}"


def parse_incident_number(value: str) -> Optional[int]:
    """``INC000000137`` → ``137``; anything else → ``None``."""
    if not value:
        return None
    v = str(value).strip().upper().replace("-", "")
    if not v.startswith(_PREFIX):
        return None
    tail = v[len(_PREFIX):]
    return int(tail) if tail.isdigit() else None


async def allocate_incident_number(db) -> str:
    """Atomically reserve the next global incident number."""
    doc = await db[COUNTERS_COLLECTION].find_one_and_update(
        {"_id": COUNTER_ID},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    # Motor returns the post-update document because of return_document=True.
    seq = (doc or {}).get("seq")
    if not seq:
        # Extremely defensive: a driver that ignored return_document.
        doc = await db[COUNTERS_COLLECTION].find_one({"_id": COUNTER_ID})
        seq = (doc or {}).get("seq") or 1
    return format_incident_number(seq)


async def ensure_incident_number_indexes(db) -> Dict[str, Any]:
    """Unique index on the number (global) + tenant-scoped companion.

    ``partialFilterExpression`` keeps the unique constraint limited to
    documents that actually carry a number, so analysis cases (which
    never get one) do not collide on ``null``.
    """
    created = []
    await db[INCIDENT_COLLECTION].create_index(
        [("incident_number", 1)],
        name="uniq_incident_number",
        unique=True,
        partialFilterExpression={"incident_number": {"$type": "string"}},
    )
    created.append("uniq_incident_number")
    await db[INCIDENT_COLLECTION].create_index(
        [("tenant_id", 1), ("incident_number", 1)],
        name="tenant_incident_number",
    )
    created.append("tenant_incident_number")
    return {"indexes": created, "uniqueness": "global"}
