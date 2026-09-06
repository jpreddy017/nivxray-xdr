"""P0-F.5/F.6 · endpoint response — request, dispatch, execute, VERIFY.

The rule this module exists to enforce: **REQUESTED ≠ SUCCEEDED.** A
response is not a POST that answers `{"success": true}`. It is a command
carried to a real endpoint, executed by the real sensor, and then proven
by INDEPENDENT evidence gathered after the fact. Until that evidence
exists the action is `EXECUTED`, never `VERIFIED`.

No second response *decision* engine is created: the existing
`detection_content/xdr_response_decision.py` still recommends. This is
the execution channel and its evidence.

State machine (forward only, every transition stamped):
    REQUESTED → DISPATCHED → EXECUTED → VERIFIED
                                     ↘ VERIFICATION_FAILED
                          ↘ FAILED / CAPABILITY_UNAVAILABLE
    REQUESTED → REFUSED  (authorisation or identity could not be proven)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

COLLECTION = "edr_response_commands"
ENGINE_ID = "nivxray::edr_plane::response"
ACTIONS = ("KILL_PROCESS", "ISOLATE_ENDPOINT", "RELEASE_ISOLATION")
TERMINAL = ("VERIFIED", "VERIFICATION_FAILED", "FAILED",
            "CAPABILITY_UNAVAILABLE", "REFUSED")


class ResponseError(Exception):
    def __init__(self, code: str, reason: str, http: int = 400):
        self.code, self.reason, self.http = code, reason, http
        super().__init__(reason)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes(db) -> None:
    await db[COLLECTION].create_index([("tenant_id", 1), ("endpoint_id", 1),
                                       ("state", 1)], name="cmd_lookup")
    await db[COLLECTION].create_index("command_id", unique=True,
                                      name="cmd_id_unique")


async def request_action(db, *, tenant_id: str, endpoint_id: str, action: str,
                         target: Dict[str, Any], requested_by: str,
                         reason: str) -> Dict[str, Any]:
    """Authorise, then record the REQUEST. Nothing is executed here."""
    if action not in ACTIONS:
        raise ResponseError("UNKNOWN_ACTION", f"{action} is not a response "
                            f"action this platform performs")
    ep = await db["edr_endpoints"].find_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id})
    if not ep:
        raise ResponseError("ENDPOINT_NOT_ENROLLED",
                            "a response cannot be sent to an endpoint that "
                            "has never enrolled", 404)
    if str(ep.get("enrollment_state")) == "REVOKED":
        raise ResponseError("ENDPOINT_REVOKED",
                            "this endpoint's enrolment is revoked; it holds "
                            "no valid credential to act on a command")

    if action == "KILL_PROCESS":
        # Identity, not a bare pid. Killing by pid alone is how a response
        # plane terminates the wrong process after a pid is reused.
        pid = target.get("pid")
        if not isinstance(pid, int) or pid <= 1:
            raise ResponseError("TARGET_IDENTITY_UNPROVEN",
                                "a kill requires a real observed pid (>1)")
        # The observation plane keys on device_iid / hostname; the response
        # plane speaks endpoint_id. Resolve across all three so a real
        # observation is never missed and a kill never proceeds without one.
        needles = [v for v in (endpoint_id, ep.get("hostname"),
                               ep.get("device_iid")) if v]
        obs = await db["v2_shadow_observations"].find_one(
            {"$or": [{"collector_id": endpoint_id},
                     {"device_iid": {"$in": needles}},
                     {"event.computer": {"$in": needles}}],
             # CES stringifies identifiers, so accept both forms rather
             # than silently failing to find real evidence.
             "event.raw.pid": {"$in": [pid, str(pid)]}},
            sort=[("_id", -1)])
        if not obs:
            raise ResponseError(
                "TARGET_NOT_OBSERVED",
                f"pid {pid} has not been observed on {endpoint_id}; the "
                f"platform refuses to act on a process it never saw")
        raw = ((obs.get("event") or {}).get("raw") or {})
        target = {**target,
                  "observed_command_line": raw.get("command_line"),
                  "observed_image_path": raw.get("image_path"),
                  "observed_start_time": raw.get("start_time"),
                  "process_iid": ((obs.get("event") or {}).get("process")
                                  or {}).get("iid")}

    doc = {
        "command_id": f"cmd_{uuid.uuid4().hex[:20]}",
        "tenant_id": tenant_id, "endpoint_id": endpoint_id,
        "action": action, "target": target,
        "state": "REQUESTED", "requested_at": _now(),
        "requested_by": requested_by, "reason": reason,
        "engine_id": ENGINE_ID,
        "dispatched_at": None, "executed_at": None, "verified_at": None,
        "sensor_result": None, "verification": None,
        "history": [{"state": "REQUESTED", "at": _now(),
                     "actor": requested_by}],
    }
    await db[COLLECTION].insert_one(dict(doc))
    doc.pop("_id", None)
    return {**doc,
            "honesty_note": ("REQUESTED only. This command has not reached "
                             "the endpoint and nothing has happened yet.")}


async def claim_pending(db, *, tenant_id: str,
                        endpoint_id: str) -> List[Dict[str, Any]]:
    """The sensor claims its own commands. Dispatch is recorded so a
    command that never came back is visibly stuck at DISPATCHED rather
    than silently lost."""
    out: List[Dict[str, Any]] = []
    while True:
        doc = await db[COLLECTION].find_one_and_update(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "state": "REQUESTED"},
            {"$set": {"state": "DISPATCHED", "dispatched_at": _now()},
             "$push": {"history": {"state": "DISPATCHED", "at": _now(),
                                   "actor": endpoint_id}}},
            projection={"_id": 0, "command_id": 1, "action": 1, "target": 1},
            sort=[("requested_at", 1)])
        if not doc:
            return out
        out.append(doc)


async def record_result(db, *, tenant_id: str, endpoint_id: str,
                        command_id: str, outcome: str, detail: str,
                        evidence: Optional[Dict[str, Any]] = None) -> Dict:
    """The sensor reports what it did. This is a CLAIM, not proof."""
    state = {"EXECUTED": "EXECUTED", "FAILED": "FAILED",
             "CAPABILITY_UNAVAILABLE": "CAPABILITY_UNAVAILABLE"}.get(outcome)
    if not state:
        raise ResponseError("UNKNOWN_OUTCOME", f"outcome {outcome!r}")
    doc = await db[COLLECTION].find_one_and_update(
        {"command_id": command_id, "tenant_id": tenant_id,
         "endpoint_id": endpoint_id, "state": "DISPATCHED"},
        {"$set": {"state": state, "executed_at": _now(),
                  "sensor_result": {"outcome": outcome, "detail": detail,
                                    "evidence": evidence or {},
                                    "at": _now()}},
         "$push": {"history": {"state": state, "at": _now(),
                               "actor": endpoint_id, "reason": detail}}},
        projection={"_id": 0}, return_document=True)
    if not doc:
        raise ResponseError("COMMAND_NOT_DISPATCHED",
                            "no dispatched command matches", 404)
    return {**doc,
            "honesty_note": ("The sensor's own report. The action is NOT "
                             "verified until independent evidence proves "
                             "the effect.")}


async def verify(db, *, tenant_id: str, endpoint_id: str, command_id: str,
                 probe: Dict[str, Any]) -> Dict[str, Any]:
    """Independent verification, from evidence gathered AFTER the action.

    For a kill: the sensor re-reads /proc for the exact pid and reports
    whether it is still present. Absence verifies the kill; presence is a
    VERIFICATION_FAILED, which is the honest outcome — the analyst must
    know the process is still running.
    """
    doc = await db[COLLECTION].find_one({"command_id": command_id,
                                         "tenant_id": tenant_id,
                                         "endpoint_id": endpoint_id})
    if not doc:
        raise ResponseError("COMMAND_NOT_FOUND", "no such command", 404)
    if doc["state"] != "EXECUTED":
        raise ResponseError(
            "NOT_EXECUTED",
            f"a command in state {doc['state']} cannot be verified; "
            f"verification only follows a claimed execution")

    if doc["action"] == "KILL_PROCESS":
        still = bool(probe.get("process_present"))
        ok = not still
        finding = ("the target pid is no longer present in /proc"
                   if ok else
                   "THE TARGET PROCESS IS STILL RUNNING — the kill did not "
                   "take effect")
    else:
        ok = bool(probe.get("effect_confirmed"))
        finding = str(probe.get("detail") or
                      ("effect confirmed" if ok else "effect NOT confirmed"))

    state = "VERIFIED" if ok else "VERIFICATION_FAILED"
    await db[COLLECTION].update_one(
        {"command_id": command_id},
        {"$set": {"state": state, "verified_at": _now(),
                  "verification": {"method": probe.get("method")
                                   or "post_action_endpoint_probe",
                                   "probe": probe, "finding": finding,
                                   "at": _now()}},
         "$push": {"history": {"state": state, "at": _now(),
                               "actor": endpoint_id, "reason": finding}}})
    return {"command_id": command_id, "state": state, "finding": finding,
            "honesty_note": ("VERIFIED means evidence gathered after the "
                             "action proves the effect. It is never "
                             "inferred from the command succeeding.")}


async def list_commands(db, *, tenant_id: str,
                        endpoint_id: Optional[str] = None) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_id:
        q["endpoint_id"] = endpoint_id
    rows = [d async for d in db[COLLECTION].find(q, {"_id": 0}).sort(
        "requested_at", -1).limit(100)]
    by_state: Dict[str, int] = {}
    for r in rows:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    return {"commands": rows, "count": len(rows), "by_state": by_state,
            "note": ("REQUESTED/DISPATCHED means nothing is proven yet. "
                     "Only VERIFIED is backed by post-action evidence.")}
