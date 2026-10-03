"""G-26 · the AUTHORITATIVE endpoint identity on canonical evidence.

DECLARATION AND PURE CLASSIFIER ONLY. Nothing here is wired into a read path, a
writer, an index or a migration. It exists so the target identity contract is
stated in one place, measured, and guarded by tests before anything changes.

WHY: the §d canonical read currently addresses three DERIVED representations —
`provenance.collector_id`, `host.host_id`, `host.hostname` — and merges the
results. Measurement (Step 34E, preview corpus of 299,771 canonical rows) shows:

* 294,107 rows (98.1%) carry `additional_fields.endpoint_id`, and in EVERY one
  of them `host.host_id` is byte-identical to it (0 rows disagree). So
  `host.host_id` is not an independent identity when the authoritative field
  exists — it is a copy.
* 3,557 rows have NO authoritative field and a `host.host_id` that is NOT
  platform-minted (a hostname written by a third-party DSM). 3,558 of the
  authoritative-less rows carry a hostname.
* 2,049 rows have no host object at all (collector-sourced, e.g. a network
  sensor). These are not endpoint-scoped evidence and must never be associated
  with an endpoint.
* 1,236 authoritative-less rows carry `provenance.collector_id` that IS
  platform-minted — the authenticated endpoint ingest boundary supplied it while
  a non-sensor DSM normalized the event, so that value is authenticated rather
  than observation-derived.

THE RULE: an endpoint identity is authoritative only when it is PLATFORM-MINTED
and arrived from the AUTHENTICATED boundary. A hostname, a vendor host id, a
device_iid or a third-party collector id is NEVER promoted to a platform
endpoint identity. Evidence whose authoritative identity cannot be established
stays explicitly UNRESOLVED.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

#: The one field that carries the platform-minted endpoint identity.
AUTHORITATIVE_FIELD = "additional_fields.endpoint_id"

#: The ONLY other field that may carry an authenticated platform endpoint id:
#: supplied by the authenticated ingest boundary, not derived from the event.
AUTHENTICATED_BOUNDARY_FIELD = "provenance.collector_id"

#: The legacy compatibility field for evidence written before the contract.
#: A NAME, deliberately kept separate from identity.
LEGACY_NAME_FIELD = "host.hostname"

#: Never an identity source for canonical endpoint addressing.
NEVER_IDENTITY = ("host.host_id", "host.hostname", "device_iid",
                  "event.computer", "host.ip")

PLATFORM_ID_PREFIX = "ep_"

RESOLVED_AUTHORITATIVE = "ENDPOINT_IDENTITY_AUTHORITATIVE"
RESOLVED_AUTHENTICATED_BOUNDARY = "ENDPOINT_IDENTITY_AUTHENTICATED_BOUNDARY"
UNRESOLVED_NAME_ONLY = "ENDPOINT_IDENTITY_UNRESOLVED_NAME_ONLY"
UNRESOLVED_NOT_ENDPOINT_SCOPED = "EVIDENCE_NOT_ENDPOINT_SCOPED"
UNRESOLVED_NO_IDENTITY = "ENDPOINT_IDENTITY_UNRESOLVED"


def _get(row: Mapping[str, Any], path: str) -> Optional[str]:
    node: Any = row
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    if node is None:
        return None
    s = str(node).strip()
    return s or None


def is_platform_minted(value: Optional[str]) -> bool:
    """Platform-minted means `ep_` + a minted suffix. Shape only: membership in
    the endpoint registry is an authorisation question answered elsewhere."""
    return bool(value) and value.startswith(PLATFORM_ID_PREFIX) and \
        len(value) > len(PLATFORM_ID_PREFIX)


def classify(row: Mapping[str, Any]) -> Tuple[Optional[str], str]:
    """`(authoritative endpoint_id or None, reason)`. Pure; never infers.

    Order is the trust order: the stamped authoritative field, then the
    authenticated ingest boundary, then nothing. A name is never promoted.
    """
    value = _get(row, AUTHORITATIVE_FIELD)
    if is_platform_minted(value):
        return value, RESOLVED_AUTHORITATIVE
    if value:
        # present but not platform-minted: a fallback leaked into the field.
        return None, UNRESOLVED_NO_IDENTITY
    boundary = _get(row, AUTHENTICATED_BOUNDARY_FIELD)
    if is_platform_minted(boundary):
        return boundary, RESOLVED_AUTHENTICATED_BOUNDARY
    if _get(row, LEGACY_NAME_FIELD):
        return None, UNRESOLVED_NAME_ONLY
    if not isinstance(row.get("host"), Mapping) or not row.get("host"):
        return None, UNRESOLVED_NOT_ENDPOINT_SCOPED
    return None, UNRESOLVED_NO_IDENTITY


def backfill_candidate(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """The ONLY deterministic backfill this contract permits: copy the
    AUTHENTICATED boundary value into the authoritative field when the
    authoritative field is absent and the boundary value is platform-minted.
    Returns None for every other row — including every name-only row.
    """
    if _get(row, AUTHORITATIVE_FIELD):
        return None
    boundary = _get(row, AUTHENTICATED_BOUNDARY_FIELD)
    if not is_platform_minted(boundary):
        return None
    return {"set": {AUTHORITATIVE_FIELD: boundary},
            "source": AUTHENTICATED_BOUNDARY_FIELD,
            "basis": "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID"}
