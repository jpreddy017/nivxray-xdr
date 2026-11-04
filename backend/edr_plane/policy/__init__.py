"""GATE 5 · the ONE policy authority of NivXForge EDR.

Every consumer — the Policies console, Exclusion sets (Gate 7), the
Connector deployment workflow and the sensor itself — goes through this
package. There is deliberately no second policy model, no second
delivery mechanism and no second acknowledgement path.

The binding invariant:

    ASSIGNED  !=  DELIVERED  !=  ACKNOWLEDGED  !=  APPLIED  !=  VERIFIED

A policy that the platform handed to an endpoint is NOT a policy the
endpoint applied. Only the endpoint can make it APPLIED, by
acknowledging the exact policy id, version and config digest over its
authenticated connector session.
"""
from edr_plane.policy import contracts, store  # noqa: F401

__all__ = ["contracts", "store"]
