"""The atomic identity boundary.

`AuthenticatedEndpoint` is the ONLY object the ingestion contract accepts.
It is produced by an authenticator in `transport.py` and it is deliberately
frozen: nothing downstream may adjust who it thinks it is talking to.

Note what it does NOT contain: no token, no secret, no header, no scheme
beyond a label, no socket. That absence is the pluggable boundary — an
mTLS authenticator produces the same object from a client certificate, and
ingestion cannot tell the difference.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentState(str, Enum):
    """The endpoint's RELATIONSHIP to the platform."""
    NEVER_ENROLLED = "NEVER_ENROLLED"
    ENROLLMENT_PENDING = "ENROLLMENT_PENDING"
    ENROLLED = "ENROLLED"
    REVOKED = "REVOKED"
    RETIRED = "RETIRED"


class CredentialState(str, Enum):
    """The state of the durable per-agent secret."""
    NONE = "NONE"
    ACTIVE = "ACTIVE"
    ROTATION_PENDING = "ROTATION_PENDING"
    REVOKED = "REVOKED"


class SensorState(str, Enum):
    """What the sensor has actually DONE, which is a different question
    from whether it is allowed to (enrollment) or able to (credential).

    `ENROLLED_NEVER_REPORTED` is the state that matters most: an endpoint
    that authenticated successfully and then sent nothing is a visibility
    gap, and it must never be summarised as healthy.
    """
    NO_SENSOR = "NO_SENSOR"
    ENROLLED_NEVER_REPORTED = "ENROLLED_NEVER_REPORTED"
    REPORTING = "REPORTING"
    SILENT = "SILENT"
    REVOKED = "REVOKED"


class AuthenticatedEndpoint(BaseModel):
    """Proof of WHO produced a piece of evidence.

    Frozen on purpose. Every field is derived from the SERVER-SIDE record,
    never from anything the caller asserted about itself — a request body
    claiming `tenant_id` or `endpoint_id` is ignored.
    """
    model_config = ConfigDict(extra="forbid", frozen=True,
                              use_enum_values=True)

    tenant_id: str
    endpoint_id: str
    credential_id: str
    session_id: str
    auth_method: str = Field(
        description="bearer_session | mtls | signed_request. A LABEL for "
                    "provenance, not a mechanism the caller chooses.")
    device_iid: Optional[str] = Field(
        default=None,
        description="The authoritative NivXRay device identity, once bound. "
                    "Hostname remains observation-derived and is never "
                    "promoted to identity.")
    authenticated_at: str

    def provenance(self) -> dict:
        """Stamped onto every raw event so the question
        'which authenticated endpoint produced this exact evidence?' has a
        recorded answer rather than an inference."""
        return {
            "authenticated_endpoint_id": self.endpoint_id,
            "credential_id": self.credential_id,
            "session_id": self.session_id,
            "auth_method": self.auth_method,
            "device_iid": self.device_iid,
        }


class EndpointRecord(BaseModel):
    """The durable endpoint row. Exactly the fields the owner specified,
    with the three lifecycles kept SEPARATE.

    Collapsing enrollment_state, credential_state and sensor_state into
    one 'status' is the mistake this model exists to prevent: an ENROLLED
    endpoint with an ACTIVE credential that has never reported is a very
    different situation from a REVOKED one, and a single field cannot say
    both.
    """
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    tenant_id: str
    endpoint_id: str
    device_iid: Optional[str] = None
    credential_id: Optional[str] = None

    enrollment_state: EnrollmentState = EnrollmentState.NEVER_ENROLLED
    credential_state: CredentialState = CredentialState.NONE
    sensor_state: SensorState = SensorState.NO_SENSOR

    hostname: Optional[str] = None
    platform: Optional[str] = None
    sensor_version: Optional[str] = None

    enrolled_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_seen: Optional[str] = None
    last_telemetry_at: Optional[str] = None
    event_count: int = 0

    def trust_summary(self) -> dict:
        """Directive §10 acceptance criterion: **no ambiguity about trust
        state.** Returns the three dimensions plus a single explicit
        `telemetry_trusted` boolean, so no caller has to infer it."""
        enr = EnrollmentState(self.enrollment_state)
        cred = CredentialState(self.credential_state)
        trusted = (enr == EnrollmentState.ENROLLED
                   and cred in (CredentialState.ACTIVE,
                                CredentialState.ROTATION_PENDING))
        if trusted:
            reason = "endpoint is enrolled with an active credential"
        elif enr == EnrollmentState.NEVER_ENROLLED:
            reason = ("endpoint has never enrolled; nothing it sends is "
                      "endpoint evidence")
        elif enr == EnrollmentState.REVOKED:
            reason = ("enrollment was revoked; telemetry is refused and "
                      "recorded as a security signal")
        elif cred == CredentialState.REVOKED:
            reason = "credential was revoked; the agent must re-enrol"
        else:
            reason = f"enrollment={enr.value} credential={cred.value}"
        return {
            "enrollment_state": enr.value,
            "credential_state": cred.value,
            "sensor_state": SensorState(self.sensor_state).value,
            "telemetry_trusted": trusted,
            "reason": reason,
        }
