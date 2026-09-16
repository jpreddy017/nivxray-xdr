"""P0-A.2 · Enrolment + Sensor Identity + Telemetry Authentication.

Owner instruction, and the reason this is ONE package rather than three
features: *"make Enrollment + Sensor Identity + Telemetry Authentication
one atomic architectural boundary."*

Every telemetry event must be able to answer:

    Which AUTHENTICATED endpoint produced this EXACT evidence?

That question is what makes Device Trajectory, Fleet File Trajectory,
Attack Story, response authorisation and forensic integrity trustworthy
later. If the answer is ever "we think it was probably that host", none of
those five downstream capabilities can be relied on.

The boundary that must survive every future change (directive §3):

    Endpoint Identity ≠ Authentication Mechanism ≠ Transport
                      ≠ Telemetry Envelope

`transport.py` is the only file that knows a bearer token exists. Swapping
it for mTLS must not touch identity, the envelope, ingestion, or any
investigation/response contract.
"""
from .identity import (AuthenticatedEndpoint, CredentialState, EndpointRecord,
                       EnrollmentState, SensorState)

__all__ = ["AuthenticatedEndpoint", "EndpointRecord", "EnrollmentState",
           "CredentialState", "SensorState"]
