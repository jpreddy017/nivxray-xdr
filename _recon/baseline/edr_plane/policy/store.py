"""GATE 5 · the policy authority's storage and state transitions.

Collections (all new, none migrated):

    edr_policies                 the policy object (name, os, current version)
    edr_policy_versions          IMMUTABLE versions; a change is a new version
    edr_policy_endpoint_state    per-endpoint delivery / ack / apply record
    edr_policy_audit             append-only record of every authority action

`edr_groups` and `edr_endpoints` already exist and are reused: a group
carries `policy_id`, an endpoint carries `policy_id` plus
`policy_source`. No second placement model is introduced.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from edr_plane.policy.contracts import (PolicyConfig, ScopeType,
                                        derive_endpoint_state)

POLICIES = "edr_policies"
VERSIONS = "edr_policy_versions"
STATE = "edr_policy_endpoint_state"
AUDIT = "edr_policy_audit"
GROUPS = "edr_groups"
ENDPOINTS = "edr_endpoints"


class PolicyError(Exception):
    def __init__(self, code: str, status: int, reason: str):
        self.code, self.status, self.reason = code, status, reason
        super().__init__(reason)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pid() -> str:
    return "pol_" + secrets.token_hex(8)


async def ensure_indexes(db: Any) -> None:
    await db[POLICIES].create_index([("tenant_id", 1), ("id", 1)],
                                    unique=True, name="uniq_tenant_policy")
    await db[VERSIONS].create_index(
        [("tenant_id", 1), ("policy_id", 1), ("version", 1)],
        unique=True, name="uniq_tenant_policy_version")
    await db[STATE].create_index([("tenant_id", 1), ("endpoint_id", 1)],
                                 unique=True, name="uniq_tenant_endpoint")
    await db[AUDIT].create_index([("tenant_id", 1), ("at", -1)],
                                 name="audit_tenant_at")
    await db[GROUPS].create_index([("tenant_id", 1), ("id", 1)],
                                  unique=True, name="uniq_tenant_group")


async def _audit(db: Any, tenant_id: str, action: str, by: str,
                 detail: Dict[str, Any]) -> None:
    await db[AUDIT].insert_one({"tenant_id": tenant_id, "action": action,
                                "by": by, "at": _now(), "detail": detail})


# ── policies + versions ──────────────────────────────────────────────
async def create_policy(db: Any, *, tenant_id: str, name: str,
                        os_family: str, description: Optional[str],
                        config: PolicyConfig, by: str) -> Dict[str, Any]:
    if await db[POLICIES].find_one({"tenant_id": tenant_id, "name": name}):
        raise PolicyError("POLICY_NAME_IN_USE", 409,
                          "a policy with this name already exists in the "
                          "tenant; a change is a new VERSION of that policy")
    policy_id = _pid()
    doc = {"id": policy_id, "tenant_id": tenant_id, "name": name,
           "os": os_family, "description": description or None,
           "current_version": 1, "is_default": False,
           "created_at": _now(), "created_by": by,
           "lifecycle_state": "CREATED"}
    await db[POLICIES].insert_one(dict(doc))
    version = await _write_version(db, tenant_id=tenant_id,
                                   policy_id=policy_id, version=1,
                                   config=config, by=by,
                                   notes="initial version")
    await _audit(db, tenant_id, "POLICY_CREATED", by,
                 {"policy_id": policy_id, "name": name, "version": 1})
    doc.pop("_id", None)
    return {"policy": doc, "version": version}


async def _write_version(db: Any, *, tenant_id: str, policy_id: str,
                         version: int, config: PolicyConfig, by: str,
                         notes: Optional[str]) -> Dict[str, Any]:
    doc = {"tenant_id": tenant_id, "policy_id": policy_id,
           "version": version, "config": config.model_dump(),
           "config_digest": config.digest(), "created_at": _now(),
           "created_by": by, "notes": notes or None, "immutable": True}
    await db[VERSIONS].insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


async def create_version(db: Any, *, tenant_id: str, policy_id: str,
                         config: PolicyConfig, by: str,
                         notes: Optional[str]) -> Dict[str, Any]:
    policy = await db[POLICIES].find_one({"tenant_id": tenant_id,
                                          "id": policy_id}, {"_id": 0})
    if not policy:
        raise PolicyError("POLICY_NOT_FOUND", 404,
                          "no such policy in the tenant you are authorised "
                          "for")
    version = int(policy.get("current_version") or 0) + 1
    doc = await _write_version(db, tenant_id=tenant_id, policy_id=policy_id,
                               version=version, config=config, by=by,
                               notes=notes)
    await db[POLICIES].update_one(
        {"tenant_id": tenant_id, "id": policy_id},
        {"$set": {"current_version": version, "updated_at": _now(),
                  "updated_by": by}})
    await _audit(db, tenant_id, "POLICY_VERSION_CREATED", by,
                 {"policy_id": policy_id, "version": version,
                  "config_digest": doc["config_digest"]})
    return doc


async def list_policies(db: Any, *, tenant_id: str) -> List[Dict[str, Any]]:
    policies = [p async for p in db[POLICIES].find({"tenant_id": tenant_id},
                                                   {"_id": 0})]
    groups = [g async for g in db[GROUPS].find({"tenant_id": tenant_id},
                                               {"_id": 0})]
    out: List[Dict[str, Any]] = []
    for p in policies:
        vcount = await db[VERSIONS].count_documents(
            {"tenant_id": tenant_id, "policy_id": p["id"]})
        bound_groups = [g["name"] for g in groups
                        if g.get("policy_id") == p["id"]]
        endpoints = await db[ENDPOINTS].count_documents(
            {"tenant_id": tenant_id, "policy_id": p["id"]})
        out.append({**p, "version_count": vcount,
                    "bound_groups": bound_groups,
                    "endpoints_assigned": endpoints})
    return sorted(out, key=lambda r: str(r.get("created_at") or ""))


async def get_policy(db: Any, *, tenant_id: str,
                     policy_id: str) -> Dict[str, Any]:
    policy = await db[POLICIES].find_one({"tenant_id": tenant_id,
                                          "id": policy_id}, {"_id": 0})
    if not policy:
        raise PolicyError("POLICY_NOT_FOUND", 404, "no such policy")
    versions = [v async for v in db[VERSIONS].find(
        {"tenant_id": tenant_id, "policy_id": policy_id},
        {"_id": 0}).sort("version", -1)]
    return {"policy": policy, "versions": versions}


# ── groups ───────────────────────────────────────────────────────────
async def list_groups(db: Any, *, tenant_id: str) -> List[Dict[str, Any]]:
    groups = [g async for g in db[GROUPS].find({"tenant_id": tenant_id},
                                               {"_id": 0})]
    for g in groups:
        g["endpoint_count"] = await db[ENDPOINTS].count_documents(
            {"tenant_id": tenant_id, "group_id": g["id"]})
    return sorted(groups, key=lambda r: str(r.get("name") or ""))


async def create_group(db: Any, *, tenant_id: str, name: str,
                       description: Optional[str], policy_id: Optional[str],
                       by: str) -> Dict[str, Any]:
    if await db[GROUPS].find_one({"tenant_id": tenant_id, "name": name}):
        raise PolicyError("GROUP_NAME_IN_USE", 409,
                          "a group with this name already exists")
    if policy_id and not await db[POLICIES].find_one(
            {"tenant_id": tenant_id, "id": policy_id}):
        raise PolicyError("POLICY_NOT_FOUND", 404,
                          "the named policy does not exist in this tenant")
    doc = {"id": "grp_" + secrets.token_hex(8), "tenant_id": tenant_id,
           "name": name, "description": description or None,
           "policy_id": policy_id, "is_default": False,
           "created_at": _now(), "created_by": by}
    await db[GROUPS].insert_one(dict(doc))
    await _audit(db, tenant_id, "GROUP_CREATED", by,
                 {"group_id": doc["id"], "name": name,
                  "policy_id": policy_id})
    doc.pop("_id", None)
    return doc


# ── assignment ───────────────────────────────────────────────────────
async def assign(db: Any, *, tenant_id: str, policy_id: str,
                 scope_type: str, scope_id: str, by: str) -> Dict[str, Any]:
    """Bind a policy to a GROUP or a single ENDPOINT.

    Assignment writes the ASSIGNED fact and nothing else. It does not
    deliver, it does not mark the endpoint protected, and it never
    touches an applied state — that is the whole point of the gate.
    """
    policy = await db[POLICIES].find_one({"tenant_id": tenant_id,
                                          "id": policy_id}, {"_id": 0})
    if not policy:
        raise PolicyError("POLICY_NOT_FOUND", 404, "no such policy")
    at = _now()
    if scope_type == ScopeType.GROUP.value:
        res = await db[GROUPS].update_one(
            {"tenant_id": tenant_id, "id": scope_id},
            {"$set": {"policy_id": policy_id, "policy_assigned_at": at,
                      "policy_assigned_by": by}})
        if not res.matched_count:
            raise PolicyError("GROUP_NOT_FOUND", 404, "no such group")
        endpoints = [e async for e in db[ENDPOINTS].find(
            {"tenant_id": tenant_id, "group_id": scope_id},
            {"_id": 0, "endpoint_id": 1})]
    elif scope_type == ScopeType.ENDPOINT.value:
        res = await db[ENDPOINTS].update_one(
            {"tenant_id": tenant_id, "endpoint_id": scope_id},
            {"$set": {"policy_id": policy_id,
                      "policy_source": "ENDPOINT_OVERRIDE",
                      "policy_assigned_at": at, "policy_assigned_by": by}})
        if not res.matched_count:
            raise PolicyError("ENDPOINT_NOT_FOUND", 404,
                              "no such endpoint in this tenant")
        endpoints = [{"endpoint_id": scope_id}]
    else:
        raise PolicyError("SCOPE_NOT_SUPPORTED", 422,
                          "scope_type must be GROUP or ENDPOINT")

    for e in endpoints:
        await db[STATE].update_one(
            {"tenant_id": tenant_id, "endpoint_id": e["endpoint_id"]},
            {"$set": {"assigned_at": at, "assigned_policy_id": policy_id,
                      "assigned_by": by},
             "$setOnInsert": {"created_at": at}}, upsert=True)
    await _audit(db, tenant_id, "POLICY_ASSIGNED", by,
                 {"policy_id": policy_id, "scope_type": scope_type,
                  "scope_id": scope_id,
                  "endpoints_touched": len(endpoints)})
    return {"policy_id": policy_id, "scope_type": scope_type,
            "scope_id": scope_id, "assigned_at": at,
            "endpoints_assigned": len(endpoints),
            "state": "ASSIGNED",
            "note": ("ASSIGNED only. Nothing has been delivered to any "
                     "endpoint and no endpoint is reported as applying "
                     "this policy until it acknowledges it.")}


async def resolve_assignment(db: Any, *, tenant_id: str,
                             endpoint: Dict[str, Any]
                             ) -> Optional[Dict[str, Any]]:
    """Which policy version does this endpoint resolve to, and why.

    Precedence, documented and single-sourced:
        1. an explicit ENDPOINT override
        2. the endpoint's GROUP policy
        3. the placement written at enrolment
        4. nothing -> POLICY_UNASSIGNED
    """
    policy_id = source = None
    if endpoint.get("policy_source") == "ENDPOINT_OVERRIDE" \
            and endpoint.get("policy_id"):
        policy_id, source = endpoint["policy_id"], "ENDPOINT_OVERRIDE"
    if policy_id is None and endpoint.get("group_id"):
        group = await db[GROUPS].find_one(
            {"tenant_id": tenant_id, "id": endpoint["group_id"]}, {"_id": 0})
        if group and group.get("policy_id"):
            policy_id, source = group["policy_id"], "GROUP"
    if policy_id is None and endpoint.get("policy_id"):
        policy_id, source = endpoint["policy_id"], "ENROLMENT_PLACEMENT"
    if policy_id is None:
        return None
    policy = await db[POLICIES].find_one({"tenant_id": tenant_id,
                                          "id": policy_id}, {"_id": 0})
    if not policy:
        return None
    version = await db[VERSIONS].find_one(
        {"tenant_id": tenant_id, "policy_id": policy_id,
         "version": policy.get("current_version")}, {"_id": 0})
    if not version:
        return None
    return {"policy_id": policy_id, "policy_name": policy.get("name"),
            "source": source, "version": version["version"],
            "config": version["config"],
            "config_digest": version["config_digest"],
            "policy": policy, "version_doc": version}


# ── delivery + acknowledgement ───────────────────────────────────────
async def record_delivery(db: Any, *, tenant_id: str, endpoint_id: str,
                          assigned: Dict[str, Any],
                          connector_version: Optional[str]) -> str:
    at = _now()
    await db[STATE].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": {"delivered_at": at,
                  "delivered_policy_id": assigned["policy_id"],
                  "delivered_version": assigned["version"],
                  "delivered_config_digest": assigned["config_digest"],
                  "connector_version": connector_version},
         "$inc": {"delivery_count": 1},
         "$setOnInsert": {"created_at": at}}, upsert=True)
    return at


async def record_ack(db: Any, *, tenant_id: str, endpoint_id: str,
                     assigned: Optional[Dict[str, Any]], policy_id: str,
                     version: int, config_digest: str, applied: bool,
                     running_config_digest: Optional[str],
                     failure_reason: Optional[str],
                     connector_version: Optional[str]) -> Dict[str, Any]:
    """The ONLY route to APPLIED.

    The acknowledgement must name the exact policy id, version and config
    digest that is currently assigned. An ACK for anything else is
    RECORDED — it is real endpoint truth — but it is recorded as
    OUT_OF_SYNC and can never produce APPLIED.
    """
    at = _now()
    matches = bool(assigned) and (
        assigned["policy_id"] == policy_id
        and int(assigned["version"]) == int(version)
        and assigned["config_digest"] == config_digest)

    existing = await db[STATE].find_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id}, {"_id": 0}) or {}

    set_: Dict[str, Any] = {
        "last_ack_at": at, "connector_version": connector_version,
        "last_ack": {"policy_id": policy_id, "version": version,
                     "config_digest": config_digest, "applied": applied,
                     "running_config_digest": running_config_digest,
                     "failure_reason": failure_reason, "at": at,
                     "accepted": matches}}
    outcome = "RECORDED_OUT_OF_SYNC"
    if not matches:
        set_["out_of_sync_at"] = at
    elif failure_reason and not applied:
        set_.update({"failure_reason": failure_reason, "failed_version": version,
                     "failed_at": at})
        outcome = "RECORDED_FAILED"
    else:
        set_.update({"acknowledged_at": at,
                     "acknowledged_policy_id": policy_id,
                     "acknowledged_version": version,
                     "acknowledged_config_digest": config_digest})
        set_["failure_reason"] = None
        set_["failed_version"] = None
        outcome = "RECORDED_ACKNOWLEDGED"
        if applied and running_config_digest == config_digest:
            already = (existing.get("applied_config_digest") == config_digest
                       and existing.get("applied_at"))
            if already:
                # A LATER, independent check-in re-reporting the same
                # running digest is what VERIFIED means. The apply ACK
                # itself can never verify itself.
                set_["verified_at"] = at
                outcome = "RECORDED_VERIFIED"
            else:
                set_.update({"applied_at": at, "applied_version": version,
                             "applied_config_digest": config_digest})
                set_["verified_at"] = None
                outcome = "RECORDED_APPLIED"
    await db[STATE].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": set_, "$inc": {"ack_count": 1},
         "$setOnInsert": {"created_at": at}}, upsert=True)
    await _audit(db, tenant_id, "POLICY_ACK", endpoint_id,
                 {"policy_id": policy_id, "version": version,
                  "config_digest": config_digest, "applied": applied,
                  "accepted": matches, "outcome": outcome})
    return {"outcome": outcome, "accepted": matches, "at": at,
            "reason": (None if matches else
                       "the acknowledgement does not name the policy "
                       "version currently assigned to this endpoint; it is "
                       "retained as endpoint truth and reported as "
                       "OUT_OF_SYNC")}


# ── read models ──────────────────────────────────────────────────────
async def endpoint_policy_state(db: Any, *, tenant_id: str,
                                endpoint: Dict[str, Any]) -> Dict[str, Any]:
    assigned = await resolve_assignment(db, tenant_id=tenant_id,
                                        endpoint=endpoint)
    state_doc = await db[STATE].find_one(
        {"tenant_id": tenant_id,
         "endpoint_id": endpoint.get("endpoint_id")}, {"_id": 0})
    return derive_endpoint_state(assigned=assigned, state_doc=state_doc,
                                 endpoint=endpoint)


async def deployment_matrix(db: Any, *, tenant_id: str,
                            policy_id: Optional[str] = None
                            ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Per-endpoint delivery truth for the Policies console."""
    endpoints = [e async for e in db[ENDPOINTS].find({"tenant_id": tenant_id},
                                                     {"_id": 0})]
    groups = {g["id"]: g async for g in db[GROUPS].find(
        {"tenant_id": tenant_id}, {"_id": 0})}
    rows: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for e in endpoints:
        st = await endpoint_policy_state(db, tenant_id=tenant_id, endpoint=e)
        if policy_id and st.get("assigned_policy_id") != policy_id:
            continue
        counts[st["state"]] = counts.get(st["state"], 0) + 1
        rows.append({
            "endpoint_id": e.get("endpoint_id"),
            "hostname": e.get("hostname"),
            "os": e.get("platform"),
            "group": (groups.get(e.get("group_id")) or {}).get("name"),
            "group_id": e.get("group_id"),
            "connector_version": (st.get("connector_version")
                                  or e.get("sensor_version")),
            **st})
    rows.sort(key=lambda r: str(r.get("hostname") or r.get("endpoint_id")))
    return rows, counts
