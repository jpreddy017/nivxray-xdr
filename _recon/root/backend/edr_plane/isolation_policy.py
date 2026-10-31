"""P0-F.10 · endpoint isolation POLICY — explicit, operator-controlled.

The allow-list is deliberately NOT in the driver. A hardcoded allow-list is
unauditable, cannot differ per tenant, and cannot be reviewed before a
containment cuts a business system off. So the policy lives here, is
tenant-scoped, is versioned, and every command carries the exact policy
version it was executed under.

Two invariants that are NOT settings, because making them settings is how
an operator locks himself out of his own fleet:

  * **The sensor's own control channel is ALWAYS allowed.** There is no
    field to disable it. The sensor resolves its own API endpoint at apply
    time and allows it; a policy cannot remove it, and a sensor that
    cannot resolve it refuses to isolate at all rather than strand itself.
  * **A verification target must exist.** Without an independently chosen
    external target there is no behavioural proof, and "the rule is
    installed" alone is not containment.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

COLLECTION = "edr_isolation_policy"

#: Shipped starting point, clearly labelled as such. It is a DEFAULT, not
#: an operator decision, and every command records which of the two it was.
PLATFORM_DEFAULT: Dict[str, Any] = {
    "allow_dns": True,
    "allow_list": [],
    "verification_target": {"host": "1.1.1.1", "port": 443},
    "auto_release_seconds": None,
    "control_channel_mode": "SENSOR_API_ENDPOINT",
    "extra_control_hosts": [],
}

INVARIANTS = [
    "The sensor's own control channel is always allowed and cannot be "
    "disabled by policy; a sensor that cannot resolve it refuses to "
    "isolate rather than strand itself.",
    "Everything not explicitly allowed is DENIED — inbound, outbound and "
    "forwarded.",
    "Isolation is never marked VERIFIED from the rule being installed. "
    "Kernel policy state AND independent connectivity behaviour must both "
    "prove containment.",
    "There is no automatic release. A configured timeout raises a NEW, "
    "authorised release command that is independently verified; it never "
    "flips the state on a timer.",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def get_policy(db, *, tenant_id: str) -> Dict[str, Any]:
    doc = await db[COLLECTION].find_one({"tenant_id": tenant_id}, {"_id": 0})
    if not doc:
        return {**PLATFORM_DEFAULT, "tenant_id": tenant_id, "version": 0,
                "policy_source": "PLATFORM_DEFAULT_NOT_YET_REVIEWED",
                "updated_by": None, "updated_at": None,
                "invariants": INVARIANTS}
    return {**doc, "policy_source": "OPERATOR_CONFIGURED",
            "invariants": INVARIANTS}


async def put_policy(db, *, tenant_id: str, updated_by: str,
                     allow_list: Optional[List[str]] = None,
                     allow_dns: Optional[bool] = None,
                     verification_target: Optional[Dict[str, Any]] = None,
                     auto_release_seconds: Optional[int] = None,
                     extra_control_hosts: Optional[List[str]] = None
                     ) -> Dict[str, Any]:
    current = await get_policy(db, tenant_id=tenant_id)
    target = verification_target or current["verification_target"]
    if not (isinstance(target, dict) and target.get("host")
            and isinstance(target.get("port"), int)):
        raise ValueError("a verification target (host + port) is required: "
                         "without one, containment cannot be proven by "
                         "behaviour and only the rule could be claimed")
    doc = {
        "tenant_id": tenant_id,
        "allow_dns": current["allow_dns"] if allow_dns is None else allow_dns,
        "allow_list": [s.strip() for s in
                       (current["allow_list"] if allow_list is None
                        else allow_list) if str(s).strip()],
        "extra_control_hosts": [s.strip() for s in
                                (current["extra_control_hosts"]
                                 if extra_control_hosts is None
                                 else extra_control_hosts) if str(s).strip()],
        "verification_target": {"host": str(target["host"]),
                                "port": int(target["port"])},
        "auto_release_seconds": (current["auto_release_seconds"]
                                 if auto_release_seconds is None
                                 else auto_release_seconds),
        "control_channel_mode": "SENSOR_API_ENDPOINT",
        "version": int(current.get("version") or 0) + 1,
        "updated_by": updated_by, "updated_at": _now(),
    }
    await db[COLLECTION].replace_one({"tenant_id": tenant_id}, doc,
                                     upsert=True)
    return {**doc, "policy_source": "OPERATOR_CONFIGURED",
            "invariants": INVARIANTS}


def bind(policy: Dict[str, Any]) -> Dict[str, Any]:
    """What travels with the command, so the sensor executes a POLICY and
    the record states exactly which version it ran under."""
    return {"policy_version": policy.get("version", 0),
            "policy_source": policy.get("policy_source"),
            "allow_dns": policy["allow_dns"],
            "allow_list": list(policy["allow_list"]),
            "extra_control_hosts": list(policy.get("extra_control_hosts")
                                        or []),
            "verification_target": dict(policy["verification_target"]),
            "control_channel_mode": "SENSOR_API_ENDPOINT",
            "auto_release_seconds": policy.get("auto_release_seconds")}
