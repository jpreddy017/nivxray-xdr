"""
P0 · Round 24 · Capability Service
──────────────────────────────────

**Bridges the EDR adapter contract to the response synthesizer.**

The synthesizer's `_capability_of(action_id)` used to be a static
"None wired" answer.  With Round 24 the answer becomes deterministic
based on **live-probed capabilities persisted in `xdr_integrations`**:

    No integration doc            → CAPABILITY_UNAVAILABLE
    Integration present, probe    → CAPABILITY_UNAVAILABLE / FAILED
    FAILED / NOT_SUPPORTED
    Integration + probe = AVAILABLE → APPLICABLE

## Invariants

* NivXRay MUST NEVER return AVAILABLE unless a persisted
  `capability_matrix` entry says so — no inference from credentials.
* The service is read-only.  Writes happen exclusively through the
  integration lifecycle (Round 25).
* Deterministic: same DB state → same answer.
"""
from __future__ import annotations
from typing import Any

from .xdr_edr_adapter import (
    AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED,
)


COLLECTION = "xdr_integrations"


# Canonical map: action_id → capability_id used by the integration
# probe record. Kept here so a new vendor adapter only has to publish
# its own probe result matrix; no synthesizer edit required.
_ACTION_TO_CAPABILITY: dict[str, str] = {
    "ENDPOINT_ISOLATE":            "edr.isolate_endpoint",
    "TERMINATE_PROCESS":           "edr.terminate_process",
    "PROCESS_EXCLUSION_ADD":       "edr.exclusion.process",
    "PATH_EXCLUSION_ADD":          "edr.exclusion.path",
    "THREAT_EXCLUSION_ADD":        "edr.exclusion.threat_name",
    "APPLICATION_ALLOW_LIST_ADD":  "edr.exclusion.allowlist_hash",
    "BLOCK_OBSERVED_HASH":         "edr.blocklist.hash",
}


async def resolve_capability(db, action_id: str) -> dict:
    """Return the deterministic capability answer for one action_id.

    Shape:
        {
          "action_id":       str,
          "capability_id":   str | None,
          "state":           AVAILABLE / UNAVAILABLE / FAILED / NOT_SUPPORTED,
          "provider":        integration_id or None,
          "detail":          honest description,
        }
    """
    cap_id = _ACTION_TO_CAPABILITY.get(action_id)
    if cap_id is None:
        return {"action_id": action_id, "capability_id": None,
                    "state":     UNAVAILABLE,
                    "provider":  None,
                    "detail":    "action is not adapter-served "
                                    "(handled by NivXRay internals)"}

    async for integ in db[COLLECTION].find(
        {"active": True, "connected": True}, {"_id": 0}
    ):
        matrix = integ.get("capability_matrix") or []
        for entry in matrix:
            if entry.get("capability_id") != cap_id \
                and entry.get("action_id") != action_id:
                continue
            state = entry.get("state") or UNAVAILABLE
            return {"action_id":     action_id,
                        "capability_id": cap_id,
                        "state":         state,
                        "provider":      integ.get("integration_id"),
                        "detail":        entry.get("detail")
                                                or "resolved from integration probe"}

    return {"action_id":     action_id,
                "capability_id": cap_id,
                "state":         UNAVAILABLE,
                "provider":      None,
                "detail":        "no active integration provides "
                                        f"capability {cap_id}"}


async def is_available(db, action_id: str) -> tuple[bool, str]:
    """Convenience for the synthesizer: returns (ok, reason)."""
    res = await resolve_capability(db, action_id)
    ok = res["state"] == AVAILABLE
    return ok, res["detail"] or res["state"]
