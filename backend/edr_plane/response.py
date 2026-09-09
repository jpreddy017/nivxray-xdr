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

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from edr_plane.isolation_policy import bind as bind_policy
from edr_plane.isolation_policy import get_policy
from services.edr.endpoint_query import endpoint_predicate

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


async def _resolve_kill_target(db, *, tenant_id: str, endpoint_id: str,
                               pid: int, target: Dict[str, Any]
                               ) -> Dict[str, Any]:
    """Bind the command to ONE exact observed process, from the immutable
    raw sensor evidence.

    Endpoint + pid + process START IDENTITY is what names a process. A
    bare pid does not: Linux reuses pids within minutes, so a stale pid
    can refer to a completely different process by the time a command
    reaches the endpoint. This function therefore REFUSES rather than
    degrade to pid-only targeting.
    """
    found = None
    # P0-2C · the identifier reaching this function is already the
    # canonical enrolment key (the HTTP boundary resolves aliases), and
    # `endpoint_ref` is stamped by the AUTHENTICATED sensor session, so
    # the canonical key is the only alias this store can hold for a
    # command target. The predicate is still built from the declared
    # identity field of the declared store, so the invariant holds here
    # too.
    cur = db["edr_raw_events"].find(
        {"tenant_id": tenant_id,
         **endpoint_predicate([endpoint_id], "edr_raw_events"),
         "payload": {"$regex": f'"pid": ?{pid}[,}}]'}},
        {"payload": 1, "raw_id": 1, "derivations": 1}).sort("_id", -1).limit(
            400)
    async for doc in cur:
        try:
            ev = json.loads(doc.get("payload") or "")
        except (ValueError, TypeError):
            continue
        if ev.get("activity") != "PROCESS" or ev.get("pid") != pid:
            continue
        found = (doc, ev)
        break
    if not found:
        raise ResponseError(
            "TARGET_NOT_OBSERVED",
            f"pid {pid} has not been observed on {endpoint_id}; the "
            f"platform refuses to act on a process it never saw")

    doc, ev = found
    ticks = ev.get("start_ticks")
    if not isinstance(ticks, int):
        raise ResponseError(
            "TARGET_IDENTITY_UNVERIFIED",
            f"pid {pid} was observed on {endpoint_id} but its process START "
            f"IDENTITY was never captured, so this pid cannot be bound to "
            f"one exact process. Linux reuses pids, so acting on the pid "
            f"alone could terminate a different process than the one "
            f"observed. The platform refuses rather than fall back to "
            f"pid-only targeting.")

    cev = next((d.get("event_id") for d in reversed(doc.get("derivations")
                                                    or []) if d.get("event_id")
                ), None)
    obs = (await db["v2_shadow_observations"].find_one(
        {"tenant_id": tenant_id, "canonical_event_id": cev},
        {"event.process.iid": 1}) if cev else None) or {}
    return {**target,
            "observed_start_ticks": ticks,
            "observed_start_time": ev.get("start_time"),
            "observed_command_line": ev.get("command_line"),
            "observed_image_path": ev.get("image_path"),
            "observed_user": ev.get("user"),
            "identity_basis": "endpoint_id + pid + start_ticks",
            "evidence_raw_id": doc.get("raw_id"),
            "evidence_canonical_event_id": cev,
            "process_iid": (((obs.get("event") or {}).get("process") or {})
                            .get("iid"))}


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
        target = await _resolve_kill_target(
            db, tenant_id=tenant_id, endpoint_id=endpoint_id, pid=pid,
            target=target)

    authorisation: Optional[Dict[str, Any]] = None
    if action in ("ISOLATE_ENDPOINT", "RELEASE_ISOLATION"):
        # Containment is a POLICY decision, so it carries an explicit
        # AUTHORIZED step of its own. A kill is authorised by binding it to
        # one observed process (above); an isolation is authorised by
        # binding it to a reviewed policy that provably keeps the control
        # channel reachable.
        pol = await get_policy(db, tenant_id=tenant_id)
        bound = bind_policy(pol)
        if not (bound["verification_target"].get("host")
                and bound["verification_target"].get("port")):
            raise ResponseError(
                "VERIFICATION_TARGET_NOT_CONFIGURED",
                "containment cannot be proven without an independently "
                "chosen external target; configure one before isolating")
        target = {**target, "policy": bound}
        authorisation = {
            "authorised_by": requested_by,
            "at": _now(),
            "policy_version": bound["policy_version"],
            "policy_source": bound["policy_source"],
            "control_channel_protected": True,
            "basis": ("the sensor's own control channel is allowed by an "
                      "invariant the policy cannot switch off; the sensor "
                      "refuses to isolate if it cannot resolve it"),
        }

    doc = {
        "command_id": f"cmd_{uuid.uuid4().hex[:20]}",
        "tenant_id": tenant_id, "endpoint_id": endpoint_id,
        "action": action, "target": target,
        "state": "REQUESTED", "requested_at": _now(),
        "requested_by": requested_by, "reason": reason,
        "engine_id": ENGINE_ID,
        "dispatched_at": None, "executed_at": None, "verified_at": None,
        "authorisation": authorisation,
        "sensor_result": None, "verification": None,
        "history": [{"state": "REQUESTED", "at": _now(),
                     "actor": requested_by}],
    }
    if authorisation:
        doc["state"] = "AUTHORIZED"
        doc["authorised_at"] = authorisation["at"]
        doc["history"].append(
            {"state": "AUTHORIZED", "at": authorisation["at"],
             "actor": requested_by,
             "reason": (f"policy v{authorisation['policy_version']} "
                        f"({authorisation['policy_source']}) bound; control "
                        f"channel protected")})
    await db[COLLECTION].insert_one(dict(doc))
    doc.pop("_id", None)
    return {**doc,
            "honesty_note": ("Recorded only. This command has not reached "
                             "the endpoint and nothing has happened yet.")}


async def expire_isolations(db, *, tenant_id: str, endpoint_id: str) -> int:
    """A configured timeout raises a NEW authorised release command. It
    never flips a state on a timer: an endpoint whose release has not been
    verified is still isolated, and must read that way."""
    pol = await get_policy(db, tenant_id=tenant_id)
    secs = pol.get("auto_release_seconds")
    if not isinstance(secs, int) or secs <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc)
              - timedelta(seconds=secs)).isoformat()
    raised = 0
    async for doc in db[COLLECTION].find(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "action": "ISOLATE_ENDPOINT", "state": "VERIFIED",
             "verified_at": {"$lt": cutoff},
             "auto_release_raised": {"$ne": True}}, {"command_id": 1}):
        await request_action(
            db, tenant_id=tenant_id, endpoint_id=endpoint_id,
            action="RELEASE_ISOLATION", target={},
            requested_by="policy:auto_release",
            reason=(f"configured auto-release after {secs}s of verified "
                    f"containment (isolation {doc['command_id']}); this is "
                    f"a request, not a release — it is verified like any "
                    f"other action"))
        await db[COLLECTION].update_one(
            {"command_id": doc["command_id"]},
            {"$set": {"auto_release_raised": True}})
        raised += 1
    return raised


async def claim_pending(db, *, tenant_id: str,
                        endpoint_id: str) -> List[Dict[str, Any]]:
    """The sensor claims its own commands. Dispatch is recorded so a
    command that never came back is visibly stuck at DISPATCHED rather
    than silently lost."""
    await expire_isolations(db, tenant_id=tenant_id, endpoint_id=endpoint_id)
    out: List[Dict[str, Any]] = []
    while True:
        doc = await db[COLLECTION].find_one_and_update(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "state": {"$in": ["REQUESTED", "AUTHORIZED"]}},
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
        # The probe must prove the OBSERVED process is gone, not merely
        # that the pid is unoccupied. A pid can be free because the
        # process died on its own, and it can be occupied by an unrelated
        # new process — neither is evidence about the target.
        expected = (doc.get("target") or {}).get("observed_start_ticks")
        if (probe.get("identity_basis") != "start_ticks"
                or probe.get("observed_start_ticks") != expected):
            ok = False
            finding = ("VERIFICATION_IDENTITY_UNPROVEN — the probe did not "
                       "carry the process start identity this command was "
                       "bound to, so it proves only something about the "
                       "pid, not about the target process")
        else:
            still = bool(probe.get("process_present"))
            ok = not still
            if still:
                finding = ("THE TARGET PROCESS IS STILL RUNNING — the kill "
                           "did not take effect")
            elif probe.get("pid_reoccupied"):
                finding = ("the target process is gone (its start identity "
                           "is no longer at that pid); the pid is now held "
                           "by a DIFFERENT, later process")
            else:
                finding = ("the target process is no longer present in "
                           "/proc under its observed start identity")
    elif doc["action"] in ("ISOLATE_ENDPOINT", "RELEASE_ISOLATION"):
        ok, finding = _verify_containment(doc["action"], probe)
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
    if doc["action"] in ("ISOLATE_ENDPOINT", "RELEASE_ISOLATION"):
        await _record_isolation_state(db, tenant_id=tenant_id,
                                      endpoint_id=endpoint_id,
                                      action=doc["action"], verified=ok,
                                      command_id=command_id, finding=finding)
    return {"command_id": command_id, "state": state, "finding": finding,
            "honesty_note": ("VERIFIED means evidence gathered after the "
                             "action proves the effect. It is never "
                             "inferred from the command succeeding.")}


def _verify_containment(action: str, probe: Dict[str, Any]):
    """Two INDEPENDENT proofs, both required.

    A firewall rule that exists is not containment: the rule may not match
    the traffic, may sit below an earlier ACCEPT, or may cover the wrong
    address family. So the kernel policy state must confirm the rules ARE
    installed, and the endpoint's own behaviour must confirm an
    independently chosen external target is unreachable WHILE the control
    channel still is. Losing the control channel is a failure too — a host
    we cannot talk to is not contained, it is lost.
    """
    cp = probe.get("control_plane") or {}
    bh = probe.get("behavioural") or {}
    if not cp or not bh:
        return False, ("VERIFICATION_INCOMPLETE — containment requires BOTH "
                       "kernel policy state and independent connectivity "
                       "behaviour; this probe carried "
                       + ("no behavioural proof" if cp else
                          "no control-plane proof"))
    if action == "ISOLATE_ENDPOINT":
        installed = cp.get("rules_installed") is True
        blocked = bh.get("external_blocked") is True
        control = bh.get("control_channel_reachable") is True
        if installed and blocked and control:
            return True, (
                f"containment proven twice: {cp.get('backend')} policy is "
                f"installed (default-deny on "
                f"{', '.join(cp.get('deny_chains') or [])}) AND the endpoint "
                f"cannot reach {bh.get('external_target')} while the "
                f"NivXForge control channel "
                f"{bh.get('control_channel')} remains reachable")
        if installed and blocked and not control:
            return False, ("CONTROL_CHANNEL_LOST — external traffic is "
                           "blocked but the endpoint can no longer reach "
                           "NivXForge. That is not containment, it is an "
                           "unmanageable host.")
        if installed and not blocked:
            return False, ("RULES_INSTALLED_BUT_NOT_EFFECTIVE — the policy "
                           f"is present yet the endpoint still reached "
                           f"{bh.get('external_target')}. Containment is "
                           f"NOT in force.")
        return False, ("POLICY_NOT_INSTALLED — the kernel does not hold the "
                       "containment rules; nothing is contained")
    absent = cp.get("rules_absent") is True
    restored = bh.get("external_restored") is True
    if absent and restored:
        return True, ("release proven twice: the containment policy is gone "
                      f"from the kernel AND {bh.get('external_target')} is "
                      f"reachable again")
    if absent and not restored:
        return False, ("RULES_REMOVED_BUT_TRAFFIC_STILL_BLOCKED — the "
                       "endpoint remains cut off; treat it as isolated and "
                       "investigate before telling anyone it is back")
    return False, ("CONTAINMENT_POLICY_STILL_PRESENT — the kernel still "
                   "holds isolation rules; the endpoint is NOT released")


async def _record_isolation_state(db, *, tenant_id: str, endpoint_id: str,
                                  action: str, verified: bool,
                                  command_id: str, finding: str) -> None:
    """The endpoint's isolation state changes ONLY on verified evidence.
    An unproven isolation is recorded as unproven, never as isolated and
    never as released — both would be a claim the evidence does not
    support."""
    if verified:
        state = ("ISOLATED" if action == "ISOLATE_ENDPOINT" else "RELEASED")
    else:
        state = ("ISOLATION_UNPROVEN" if action == "ISOLATE_ENDPOINT"
                 else "RELEASE_UNPROVEN")
    await db["edr_endpoints"].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": {"isolation": {"state": state, "at": _now(),
                                "evidence_command_id": command_id,
                                "finding": finding,
                                "proven_by": ("kernel policy state + "
                                              "independent connectivity "
                                              "behaviour")}}})


#: What a record PROVES — computed from the record, never from intent.
#: The console renders THIS, so an EXECUTED command cannot be painted as a
#: completed one anywhere in the product.
PROOF_STATES = {
    "REQUESTED": ("NOTHING_HAS_HAPPENED_YET", False,
                  "Recorded only. The command has not reached the endpoint."),
    "AUTHORIZED": ("AUTHORISED_NOT_YET_SENT", False,
                   "Policy and authority are bound, but the command has not "
                   "reached the endpoint. Nothing has happened yet."),
    "DISPATCHED": ("CLAIMED_BY_ENDPOINT_NO_RESULT", False,
                   "The endpoint has claimed the command. No result has "
                   "come back, so nothing is proven — and a command stuck "
                   "here is visibly stuck, not silently lost."),
    "EXECUTED": ("SENSOR_CLAIM_ONLY_NOT_VERIFIED", False,
                 "The sensor's own report that it acted. This is a CLAIM. "
                 "It is not success and must never be displayed as one."),
    "VERIFIED": ("VERIFIED_BY_POST_ACTION_EVIDENCE", True,
                 "Evidence gathered from the endpoint AFTER the action "
                 "proves the effect."),
    "VERIFICATION_FAILED": ("EFFECT_NOT_PROVEN", False,
                            "Post-action evidence did NOT prove the effect. "
                            "Treat the target as still live."),
    "FAILED": ("NO_EFFECT_CLAIMED", False,
               "The action did not take place. Nothing was changed on the "
               "endpoint."),
    "CAPABILITY_UNAVAILABLE": ("CAPABILITY_NOT_PRESENT", False,
                               "This endpoint cannot perform the action. It "
                               "is reported as unavailable rather than "
                               "faked."),
    "REFUSED": ("REFUSED_BEFORE_DISPATCH", False,
                "Authorisation or target identity could not be proven, so "
                "the command was never sent."),
}


def proof_of(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The single authoritative answer to "what does this record prove?".

    The one case that must never be smoothed over: a row marked VERIFIED
    that carries no verification probe. That is an integrity fault in the
    record itself, and it is surfaced as an alarm rather than rendered as
    a success.
    """
    state = str(doc.get("state"))
    if state == "VERIFIED" and not ((doc.get("verification") or {})
                                    .get("probe")):
        return {"proof": "CLAIMED_VERIFIED_WITHOUT_EVIDENCE",
                "success_claimed": False, "integrity_alarm": True,
                "meaning": ("This record claims VERIFIED but carries no "
                            "post-action evidence. It is shown as an "
                            "integrity fault, never as a success.")}
    label, ok, meaning = PROOF_STATES.get(
        state, ("UNKNOWN_STATE", False,
                "This state is not part of the response lifecycle."))
    return {"proof": label, "success_claimed": ok,
            "integrity_alarm": False, "meaning": meaning}


async def get_command(db, *, tenant_id: str,
                      command_id: str) -> Dict[str, Any]:
    doc = await db[COLLECTION].find_one(
        {"tenant_id": tenant_id, "command_id": command_id}, {"_id": 0})
    if not doc:
        raise ResponseError("COMMAND_NOT_FOUND", "no such command", 404)
    return {**doc, "proof": proof_of(doc)}


async def list_commands(db, *, tenant_id: str,
                        endpoint_id: Optional[str] = None,
                        endpoint_refs: Optional[list] = None) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_refs:
        # P0-W.F-1 / P0-2C · address the endpoint by every identifier its
        # resolved identity owns, over the store's declared identity
        # field, not by the string the caller happened to supply.
        q.update(endpoint_predicate(list(endpoint_refs), COLLECTION))
    elif endpoint_id:
        q.update(endpoint_predicate([endpoint_id], COLLECTION))
    rows = [d async for d in db[COLLECTION].find(q, {"_id": 0}).sort(
        "requested_at", -1).limit(100)]
    total = await db[COLLECTION].count_documents(q)
    by_state: Dict[str, int] = {}
    for r in rows:
        r["proof"] = proof_of(r)
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    return {"commands": rows, "count": len(rows), "total_count": total,
            "truncated": total > len(rows), "by_state": by_state,
            "verified_count": sum(1 for r in rows
                                  if r["proof"]["success_claimed"]),
            "integrity_alarms": sum(1 for r in rows
                                    if r["proof"]["integrity_alarm"]),
            "note": ("REQUESTED/DISPATCHED means nothing is proven yet. "
                     "Only VERIFIED is backed by post-action evidence.")}
