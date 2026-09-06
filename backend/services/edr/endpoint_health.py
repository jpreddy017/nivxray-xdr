"""
P0-A.1 · Endpoint Health — two INDEPENDENT dimensions, never collapsed.

Frozen rule this exists to enforce:

    NO TELEMETRY  !=  NO ATTACK

A single "status" field cannot express the difference between an agent that
is offline, an agent that is connected but silent, telemetry that arrived
and failed to parse, and an endpoint that was never enrolled. Collapsing
them would let a visibility gap read as an all-clear. So two dimensions are
computed and reported separately:

  A · AGENT LIFECYCLE  — Cisco-compatible connector lifecycle. Operational.
      What the agent link is doing.

  B · TELEMETRY HEALTH — NivXRay epistemic state. What we actually KNOW
      about this endpoint's evidence.

Both are derived deterministically from timestamps and recorded facts. No
clock-dependent guessing beyond the explicit staleness thresholds below,
and no dimension is ever inferred from the other.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

# ── A · Agent lifecycle (Cisco-compatible) ────────────────────────
LIFECYCLE = (
    "INITIALIZING",
    "PROVISIONING",
    "PROVISIONING_FAILED_RETRYING",
    "REGISTERING",
    "REGISTRATION_FAILED_RETRYING",
    "CONNECTING",
    "CONNECTION_FAILED_RETRYING",
    "CONNECTED",
    "DISABLED",
    "DISCONNECTED_RETRYING",
    "OFFLINE",
    # NivXRay addition: there is no agent at all. Cisco has no equivalent
    # because Cisco only lists endpoints that HAVE a connector.
    "NO_AGENT",
)

# ── B · Telemetry health (NivXRay epistemic) ──────────────────────
TELEMETRY_HEALTH = (
    "ONLINE",
    "DEGRADED",
    "STALE",
    "NO_TELEMETRY",
    "AGENT_ERROR",
    "PARSER_ERROR",
    "ISOLATED",
    "UNENROLLED",
    "NEVER_ENROLLED",
)

# Staleness thresholds, in seconds. Stated as data so an operator can read
# the policy instead of inferring it from behaviour.
HEARTBEAT_GRACE_S = 300        # agent link considered lost past this
OFFLINE_S = 1800               # link presumed offline past this
TELEMETRY_DEGRADED_S = 900     # telemetry gap that reduces confidence
TELEMETRY_STALE_S = 3600       # telemetry gap we will not vouch for

_EVIDENCE_BY_HEALTH = {
    "ONLINE":         "SUFFICIENT",
    "DEGRADED":       "PARTIAL",
    "STALE":          "PARTIAL",
    "NO_TELEMETRY":   "INSUFFICIENT",
    "AGENT_ERROR":    "INSUFFICIENT",
    "PARSER_ERROR":   "PARTIAL",
    "ISOLATED":       "PARTIAL",
    "UNENROLLED":     "INSUFFICIENT",
    "NEVER_ENROLLED": "INSUFFICIENT",
}

# The one thing this module must never do.
NEVER_MEANS_BENIGN = (
    "Absence of telemetry is a visibility gap, not evidence that nothing "
    "happened. This endpoint's evidence completeness is reduced; its "
    "security verdict is unchanged."
)


def _age_s(ts: Optional[str], now: datetime) -> Optional[float]:
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (now - parsed).total_seconds()


def resolve_agent_lifecycle(agent: Optional[dict[str, Any]],
                            now: Optional[datetime] = None) -> dict[str, Any]:
    """Dimension A. Derived from the agent record only.

    An endpoint with no agent record is NO_AGENT — not OFFLINE. "Offline"
    would imply an agent exists and is unreachable, which is a stronger
    claim than the evidence supports.
    """
    now = now or datetime.now(timezone.utc)
    if not agent:
        return {"state": "NO_AGENT",
                "reason": "no agent record is bound to this endpoint",
                "heartbeat_age_s": None}

    reported = str(agent.get("lifecycle_reported") or "").upper()
    age = _age_s(agent.get("last_heartbeat_at"), now)

    # A terminal state the agent itself declared wins: the agent knows it
    # was disabled or is still registering better than we can infer it.
    if reported in ("DISABLED", "INITIALIZING", "PROVISIONING",
                    "PROVISIONING_FAILED_RETRYING", "REGISTERING",
                    "REGISTRATION_FAILED_RETRYING", "CONNECTING",
                    "CONNECTION_FAILED_RETRYING"):
        return {"state": reported,
                "reason": f"agent self-reported {reported}",
                "heartbeat_age_s": age}

    if age is None:
        return {"state": "REGISTERING",
                "reason": "agent enrolled but has never sent a heartbeat",
                "heartbeat_age_s": None}
    if age <= HEARTBEAT_GRACE_S:
        return {"state": "CONNECTED",
                "reason": f"heartbeat {int(age)}s ago",
                "heartbeat_age_s": age}
    if age <= OFFLINE_S:
        return {"state": "DISCONNECTED_RETRYING",
                "reason": f"no heartbeat for {int(age)}s "
                          f"(grace {HEARTBEAT_GRACE_S}s)",
                "heartbeat_age_s": age}
    return {"state": "OFFLINE",
            "reason": f"no heartbeat for {int(age)}s (threshold {OFFLINE_S}s)",
            "heartbeat_age_s": age}


def resolve_telemetry_health(*, agent: Optional[dict[str, Any]],
                             last_telemetry_at: Optional[str],
                             observation_count: int = 0,
                             parser_failures: int = 0,
                             dropped_events: int = 0,
                             isolated: bool = False,
                             now: Optional[datetime] = None) -> dict[str, Any]:
    """Dimension B. Derived from evidence, NOT from the agent link.

    Evaluated in strict precedence so the most consequential unknown wins.
    Deliberately independent of Dimension A: a CONNECTED agent that sends
    nothing is `NO_TELEMETRY`, and that is exactly the case a single
    collapsed status field would hide.
    """
    now = now or datetime.now(timezone.utc)
    age = _age_s(last_telemetry_at, now)

    def out(state: str, reason: str) -> dict[str, Any]:
        return {"state": state, "reason": reason,
                "telemetry_age_s": age,
                "evidence_sufficiency": _EVIDENCE_BY_HEALTH[state],
                "parser_failures": parser_failures,
                "dropped_events": dropped_events,
                "observation_count": observation_count,
                "note": NEVER_MEANS_BENIGN if state != "ONLINE" else None}

    if agent is None and observation_count == 0:
        return out("NEVER_ENROLLED",
                   "no agent has ever enrolled and no observation exists")
    if agent is not None and agent.get("revoked_at"):
        return out("UNENROLLED",
                   f"agent credential revoked at {agent['revoked_at']}")
    if isolated:
        return out("ISOLATED",
                   "endpoint is intentionally isolated; telemetry reduction "
                   "is expected and is not a fault")
    if agent is not None and agent.get("agent_error"):
        return out("AGENT_ERROR", str(agent["agent_error"]))
    if parser_failures > 0 and observation_count == 0:
        return out("PARSER_ERROR",
                   f"{parser_failures} payload(s) arrived and failed to "
                   f"parse; raw evidence is retained and replayable")
    if age is None:
        return out("NO_TELEMETRY",
                   "no telemetry has ever been received for this endpoint"
                   if observation_count == 0 else
                   "observations exist but carry no usable timestamp")
    if parser_failures > 0:
        return out("PARSER_ERROR",
                   f"{parser_failures} payload(s) failed to parse; parsed "
                   f"telemetry is present but incomplete")
    if age > TELEMETRY_STALE_S:
        return out("STALE",
                   f"last telemetry {int(age)}s ago "
                   f"(threshold {TELEMETRY_STALE_S}s)")
    if age > TELEMETRY_DEGRADED_S or dropped_events > 0:
        return out("DEGRADED",
                   f"last telemetry {int(age)}s ago"
                   + (f", {dropped_events} event(s) dropped"
                      if dropped_events else ""))
    return out("ONLINE", f"telemetry {int(age)}s ago")


def resolve_endpoint_health(*, agent: Optional[dict[str, Any]] = None,
                            last_telemetry_at: Optional[str] = None,
                            observation_count: int = 0,
                            parser_failures: int = 0,
                            dropped_events: int = 0,
                            isolated: bool = False,
                            now: Optional[datetime] = None) -> dict[str, Any]:
    """Both dimensions, side by side, plus the visibility statement an
    analyst should read before trusting an empty trajectory."""
    lifecycle = resolve_agent_lifecycle(agent, now=now)
    telemetry = resolve_telemetry_health(
        agent=agent, last_telemetry_at=last_telemetry_at,
        observation_count=observation_count, parser_failures=parser_failures,
        dropped_events=dropped_events, isolated=isolated, now=now)
    return {
        "agent_lifecycle": lifecycle,
        "telemetry_health": telemetry,
        "visibility": _visibility(lifecycle["state"], telemetry["state"]),
        "dimensions_note": (
            "agent_lifecycle and telemetry_health are independent and are "
            "never collapsed into one status. A CONNECTED agent can be "
            "NO_TELEMETRY, and an OFFLINE agent can still have SUFFICIENT "
            "historic evidence."),
        "thresholds": {"heartbeat_grace_s": HEARTBEAT_GRACE_S,
                        "offline_s": OFFLINE_S,
                        "telemetry_degraded_s": TELEMETRY_DEGRADED_S,
                        "telemetry_stale_s": TELEMETRY_STALE_S},
        "resolved_at": (now or datetime.now(timezone.utc)).isoformat(),
    }


_FULL = {"ONLINE"}
_NONE = {"NEVER_ENROLLED", "UNENROLLED", "NO_TELEMETRY"}


def _visibility(lifecycle: str, telemetry: str) -> dict[str, Any]:
    if telemetry in _FULL and lifecycle == "CONNECTED":
        return {"state": "FULL",
                "statement": "Live telemetry is arriving from an enrolled, "
                             "connected agent."}
    if telemetry in _NONE:
        return {"state": "NONE",
                "statement": "There is NO endpoint telemetry for this host. "
                             "Any empty trajectory, process tree or file "
                             "view reflects a visibility gap, NOT an absence "
                             "of activity.",
                "affects": ["process telemetry", "process ancestry",
                             "file activity", "file hashes",
                             "endpoint network attribution",
                             "endpoint-scoped detections"]}
    return {"state": "DEGRADED",
            "statement": "Endpoint visibility is reduced. Findings remain "
                         "valid; their evidence completeness is lower and "
                         "absence of a finding is not reassurance.",
            "affects": ["evidence completeness", "detection coverage"]}
