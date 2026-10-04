"""GATE 5 · policy contracts and the effective-state derivation.

The states are the owner-locked lifecycle. They are NOT interchangeable
labels: each one names a different fact about who has done what.

    CREATED           a policy version exists in the authority
    ASSIGNED          an endpoint resolves to this policy version
    PENDING_DELIVERY  the endpoint is eligible to receive it and has not
                      yet fetched it
    DELIVERED         the platform handed the exact version to the
                      endpoint's authenticated session
    ACKNOWLEDGED      the endpoint confirmed RECEIPT of that exact
                      version and config digest
    APPLIED           the endpoint confirmed it APPLIED that exact
                      config digest
    VERIFIED          a LATER, independent check-in re-reported the same
                      running config digest
    FAILED            the endpoint reported it could not apply it
    STALE             the endpoint stopped checking in before the state
                      could be confirmed
    OUT_OF_SYNC       the endpoint holds a different version than the
                      one currently assigned

`POLICY_UNASSIGNED` is not part of the lifecycle: it is the honest
answer for an endpoint that no policy resolves to at all.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PolicyState(str, Enum):
    CREATED = "CREATED"
    ASSIGNED = "ASSIGNED"
    PENDING_DELIVERY = "PENDING_DELIVERY"
    DELIVERED = "DELIVERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    STALE = "STALE"
    OUT_OF_SYNC = "OUT_OF_SYNC"


POLICY_UNASSIGNED = "POLICY_UNASSIGNED"

#: The states in which the platform has NOT been told what the endpoint
#: is actually running. A console may never draw these as protection.
UNCONFIRMED_STATES = (PolicyState.ASSIGNED.value,
                      PolicyState.PENDING_DELIVERY.value,
                      PolicyState.DELIVERED.value,
                      PolicyState.STALE.value,
                      PolicyState.OUT_OF_SYNC.value,
                      PolicyState.FAILED.value,
                      POLICY_UNASSIGNED)


class PolicyMode(str, Enum):
    DETECT_ONLY = "DETECT_ONLY"
    PREVENT = "PREVENT"


class ScopeType(str, Enum):
    GROUP = "GROUP"
    ENDPOINT = "ENDPOINT"


class PolicyConfig(BaseModel):
    """The configuration a connector is asked to run.

    `extra="forbid"` is the point: a setting that no connector honours
    cannot be smuggled into a policy and then rendered as protection.
    """
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    mode: PolicyMode = PolicyMode.DETECT_ONLY
    prevention_enabled: bool = False
    report_interval_seconds: int = Field(default=60, ge=10, le=3600)
    heartbeat_interval_seconds: int = Field(default=60, ge=10, le=3600)
    collect_process_events: bool = True
    collect_file_events: bool = False
    collect_network_events: bool = False
    collect_registry_events: bool = False
    exclusion_set_ids: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

    def digest(self) -> str:
        """Content digest of the config the endpoint must acknowledge.

        The ACK carries this value, which is what makes "the endpoint
        applied THIS configuration" checkable rather than asserted.
        """
        blob = json.dumps(self.model_dump(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "cfg_" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


#: What the shipped Windows connector actually honours. Sourced from the
#: connector release catalog's declared capabilities, so a policy never
#: claims enforcement the released artifact cannot perform.
def unsupported_settings(config: PolicyConfig,
                         connector_capabilities: Dict[str, bool] | None = None
                         ) -> List[Dict[str, str]]:
    caps = connector_capabilities or {}
    checks = (
        ("prevention_enabled", config.prevention_enabled,
         "endpoint_prevention",
         "the released connector collects and reports; it executes no "
         "prevention, so this setting is delivered but not enforced"),
        ("collect_file_events", config.collect_file_events,
         "file_event_collection",
         "the released connector does not observe the file system"),
        ("collect_network_events", config.collect_network_events,
         "network_event_collection",
         "the released connector does not observe network connections"),
        ("collect_registry_events", config.collect_registry_events,
         "registry_event_collection",
         "the released connector does not observe the registry"),
        ("exclusion_set_ids", bool(config.exclusion_set_ids),
         "endpoint_exclusions",
         "the released connector does not evaluate exclusions locally; "
         "these exclusions are enforced server-side in the detection "
         "fabric only"),
    )
    out: List[Dict[str, str]] = []
    for setting, requested, capability, reason in checks:
        if requested and not caps.get(capability, False):
            out.append({"setting": setting, "capability": capability,
                        "state": "NOT_SUPPORTED_BY_CONNECTOR",
                        "reason": reason})
    if config.mode == PolicyMode.PREVENT.value and not caps.get(
            "endpoint_prevention", False):
        out.append({"setting": "mode", "capability": "endpoint_prevention",
                    "state": "NOT_SUPPORTED_BY_CONNECTOR",
                    "reason": "PREVENT cannot be honoured by the released "
                              "connector; it is recorded as requested and "
                              "reported as not enforced"})
    return out


def _age_seconds(iso: Optional[str], now: datetime) -> Optional[float]:
    if not iso:
        return None
    try:
        return (now - datetime.fromisoformat(
            str(iso).replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return None


def derive_endpoint_state(*, assigned: Optional[Dict[str, Any]],
                          state_doc: Optional[Dict[str, Any]],
                          endpoint: Dict[str, Any],
                          now: Optional[datetime] = None) -> Dict[str, Any]:
    """The one derivation of an endpoint's policy truth.

    Nothing here is stored as a headline state: the state is COMPUTED
    from what the platform recorded and what the endpoint reported, so a
    state can never drift away from its own evidence.
    """
    now = now or datetime.now(timezone.utc)
    if not assigned:
        return {"state": POLICY_UNASSIGNED,
                "underlying_state": None,
                "confirmed_by_endpoint": False,
                "basis": ("no policy resolves to this endpoint through an "
                          "endpoint override, its group, or an enrolment "
                          "placement"),
                "assigned_policy_id": None, "assigned_version": None,
                "assigned_config_digest": None}

    s = state_doc or {}
    av = assigned.get("version")
    ad = assigned.get("config_digest")

    applied_d = s.get("applied_config_digest")
    acked_v, acked_d = (s.get("acknowledged_version"),
                        s.get("acknowledged_config_digest"))
    delivered_v, delivered_d = (s.get("delivered_version"),
                                s.get("delivered_config_digest"))

    if s.get("failure_reason") and s.get("failed_version") == av:
        base, basis = PolicyState.FAILED.value, (
            "the endpoint reported it could not apply this version: "
            + str(s.get("failure_reason")))
    elif applied_d == ad and s.get("verified_at"):
        base, basis = PolicyState.VERIFIED.value, (
            "a later, independent check-in re-reported the same running "
            "config digest, so the applied state was confirmed twice")
    elif applied_d == ad:
        base, basis = PolicyState.APPLIED.value, (
            "the endpoint acknowledged that it applied this exact config "
            "digest over its authenticated session")
    elif acked_v == av and acked_d == ad:
        base, basis = PolicyState.ACKNOWLEDGED.value, (
            "the endpoint confirmed receipt of this exact version, and has "
            "not yet confirmed that it applied it")
    elif delivered_v == av and delivered_d == ad:
        base, basis = PolicyState.DELIVERED.value, (
            "the platform handed this exact version to the endpoint's "
            "authenticated session; the endpoint has not acknowledged it")
    elif applied_d or acked_d or delivered_d:
        base, basis = PolicyState.OUT_OF_SYNC.value, (
            "the endpoint last reported a different version than the one "
            f"now assigned (endpoint holds "
            f"{s.get('applied_version') or acked_v or delivered_v}, "
            f"assigned is {av})")
    elif (endpoint.get("enrollment_state") == "ENROLLED"
            and endpoint.get("credential_state") == "ACTIVE"):
        base, basis = PolicyState.PENDING_DELIVERY.value, (
            "the endpoint is enrolled with an active credential and is "
            "eligible to receive this version at its next check-in; "
            "nothing has been delivered yet")
    else:
        base, basis = PolicyState.ASSIGNED.value, (
            "the policy is assigned in the authority, but this endpoint is "
            "not currently eligible to receive it (no active credential)")

    interval = endpoint.get("report_interval_seconds")
    limit = float(interval) * 3 if interval else 900.0
    last = (endpoint.get("last_heartbeat_at")
            or endpoint.get("last_telemetry_at"))
    age = _age_seconds(last, now)
    state = base
    if base in (PolicyState.ASSIGNED.value,
                PolicyState.PENDING_DELIVERY.value,
                PolicyState.DELIVERED.value,
                PolicyState.ACKNOWLEDGED.value) and age is not None \
            and age > limit:
        state = PolicyState.STALE.value
        basis = (f"{base}, but the endpoint has not checked in for "
                 f"{int(age)}s (beyond {int(limit)}s), so the platform "
                 "cannot confirm what it is running")

    return {
        "state": state,
        "underlying_state": base if state != base else None,
        "confirmed_by_endpoint": state in (PolicyState.APPLIED.value,
                                           PolicyState.VERIFIED.value),
        "basis": basis,
        "assigned_policy_id": assigned.get("policy_id"),
        "assigned_policy_name": assigned.get("policy_name"),
        "assigned_version": av,
        "assigned_config_digest": ad,
        "assignment_source": assigned.get("source"),
        "assigned_at": s.get("assigned_at"),
        "delivered_at": s.get("delivered_at"),
        "delivered_version": delivered_v,
        "acknowledged_at": s.get("acknowledged_at"),
        "applied_at": s.get("applied_at"),
        "applied_version": s.get("applied_version"),
        "verified_at": s.get("verified_at"),
        "last_ack_at": s.get("last_ack_at"),
        "connector_version": s.get("connector_version"),
    }


LIFECYCLE_CONTRACT = (
    "ASSIGNED, DELIVERED, ACKNOWLEDGED, APPLIED and VERIFIED are five "
    "different facts and are never collapsed. Delivery alone NEVER "
    "produces APPLIED: only an authenticated connector acknowledgement "
    "naming the exact policy id, version and config digest can.")
