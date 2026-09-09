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



# ── C · Delivery freshness · P0-3 blindness detection ─────────────
#
# This is the SAME authority as the two dimensions above, extended — not a
# second health model. Dimensions A/B grade an endpoint against a FIXED
# platform policy. Dimension C answers the narrower operational question
# the console has to be able to ask about itself:
#
#     "Is this endpoint's telemetry pipeline delivering RIGHT NOW, and if
#      not, for how long have we been blind to it?"
#
# and it does so against **the cadence the sensor itself declared**, so a
# 15-second sensor and a 5-minute sensor are not judged by one arbitrary
# UI number. The owner's constraint, honoured literally: no threshold in
# this file is a UI opinion; every threshold is derived from the sensor's
# own configured heartbeat/flush interval by the formula below, and the
# formula travels with the answer.

DELIVERY_STATES = ("DELIVERING", "STALE", "BLIND_NO_DELIVERY")

#: Cycles of the sensor's OWN interval, not seconds. One missed cycle is
#: jitter; three consecutive misses cannot be explained by scheduling or a
#: single retry, so that is where "late" becomes STALE.
MISSED_CYCLES_STALE = 3
#: Twenty consecutive missed cycles is not lateness — the pipeline is not
#: delivering. Past this the platform stops claiming visibility.
MISSED_CYCLES_BLIND = 20
#: Floors, so a very fast sensor cannot make the console flap.
MIN_STALE_S = 60
MIN_BLIND_S = 900
#: Used ONLY when the sensor has never declared its cadence (every
#: endpoint enrolled before P0-3). It is reported as
#: `CADENCE_NOT_DECLARED_BY_SENSOR` so the answer never pretends the
#: interval was measured.
POLICY_FALLBACK_INTERVAL_S = 15

CADENCE_DECLARED = "DECLARED_BY_SENSOR"
CADENCE_NOT_DECLARED = "CADENCE_NOT_DECLARED_BY_SENSOR"

_FORMULA = ("stale_after_s = max(report_interval_s × {ms}, {mins}) · "
            "blind_after_s = max(report_interval_s × {mb}, {minb})").format(
    ms=MISSED_CYCLES_STALE, mins=MIN_STALE_S,
    mb=MISSED_CYCLES_BLIND, minb=MIN_BLIND_S)

BLINDNESS_NOTE = (
    "Blind means the platform is receiving nothing from this endpoint. It "
    "is NOT a statement that nothing is happening on it, and an empty "
    "trajectory, process tree or detection list while blind is a "
    "visibility gap, never an all-clear.")


def delivery_thresholds(report_interval_seconds: Optional[float]
                        ) -> dict[str, Any]:
    """The cadence-derived policy, with its own derivation attached."""
    declared = (report_interval_seconds
                if report_interval_seconds and report_interval_seconds > 0
                else None)
    interval = float(declared or POLICY_FALLBACK_INTERVAL_S)
    return {
        "report_interval_s": interval,
        "cadence_basis": CADENCE_DECLARED if declared else CADENCE_NOT_DECLARED,
        "missed_cycles_stale": MISSED_CYCLES_STALE,
        "missed_cycles_blind": MISSED_CYCLES_BLIND,
        "stale_after_s": max(interval * MISSED_CYCLES_STALE, MIN_STALE_S),
        "blind_after_s": max(interval * MISSED_CYCLES_BLIND, MIN_BLIND_S),
        "formula": _FORMULA,
    }


def resolve_delivery_freshness(*, last_telemetry_at: Optional[str],
                               report_interval_seconds: Optional[float] = None,
                               last_heartbeat_at: Optional[str] = None,
                               event_count: int = 0,
                               queue_depth: Optional[int] = None,
                               revoked_at: Optional[str] = None,
                               now: Optional[datetime] = None
                               ) -> dict[str, Any]:
    """Dimension C. `DELIVERING` / `STALE` / `BLIND_NO_DELIVERY`.

    `basis` is what makes the three tokens usable: a sensor that is alive
    and has simply observed nothing new is a very different operational
    fact from a sensor whose link is gone, and both can legitimately read
    STALE. The state says how much we know; the basis says why.
    """
    now = now or datetime.now(timezone.utc)
    th = delivery_thresholds(report_interval_seconds)
    age = _age_s(last_telemetry_at, now)
    link_age = _age_s(last_heartbeat_at, now)
    link_alive = link_age is not None and link_age <= th["stale_after_s"]
    backlogged = bool(link_alive and (queue_depth or 0) > 0)
    #: A sensor that is alive and behind has NOT stopped, and saying "no
    #: new evidence" about it would be a false statement.
    live_basis = ("DELIVERY_BACKLOGGED_AT_SENSOR" if backlogged
                  else "LINK_ALIVE_NO_NEW_EVIDENCE")

    def out(state: str, basis: str, statement: str) -> dict[str, Any]:
        return {
            "state": state,
            "basis": basis,
            "statement": statement,
            "last_delivery_at": last_telemetry_at,
            "delivery_age_s": None if age is None else int(age),
            "last_heartbeat_at": last_heartbeat_at,
            "heartbeat_age_s": None if link_age is None else int(link_age),
            "link_confirmed": link_alive,
            "queue_depth": queue_depth,
            "delivered_events": int(event_count or 0),
            "thresholds": th,
            "note": None if state == "DELIVERING" else BLINDNESS_NOTE,
        }

    if revoked_at:
        return out("BLIND_NO_DELIVERY", "CREDENTIAL_REVOKED",
                   f"the endpoint's credential was revoked at {revoked_at}; "
                   f"it cannot deliver and is not expected to")
    if age is None:
        return out("BLIND_NO_DELIVERY", "NEVER_DELIVERED",
                   "this endpoint has never delivered telemetry — enrolment "
                   "is not evidence of visibility")
    if age <= th["stale_after_s"]:
        return out("DELIVERING", "DELIVERY_WITHIN_DECLARED_CADENCE",
                   f"last delivery {int(age)}s ago, inside "
                   f"{int(th['stale_after_s'])}s "
                   f"({MISSED_CYCLES_STALE} × {int(th['report_interval_s'])}s "
                   f"cadence)")
    if age <= th["blind_after_s"]:
        return out("STALE",
                   live_basis if link_alive
                   else "DELIVERY_LATE_LINK_UNCONFIRMED",
                   f"last delivery {int(age)}s ago, past "
                   f"{int(th['stale_after_s'])}s"
                   + ((f" — the sensor link is confirmed alive and it is "
                       f"still sending a backlog of {queue_depth} queued "
                       f"event(s), so evidence is DELAYED, not absent"
                       if backlogged else
                       " — the sensor link is confirmed alive, so it is "
                       "reporting no NEW evidence rather than being gone")
                      if link_alive else
                      " and no sensor heartbeat confirms the link"))
    return out("BLIND_NO_DELIVERY",
               live_basis if link_alive else "DELIVERY_CEASED",
               f"no delivery for {int(age)}s, past "
               f"{int(th['blind_after_s'])}s"
               + ((f" — the link is alive with {queue_depth} event(s) still "
                   f"queued at the sensor"
                   if backlogged else
                   " — the link is alive but nothing has been delivered for "
                   "longer than the blindness threshold")
                  if link_alive else
                  " and no sensor heartbeat confirms the link"))
