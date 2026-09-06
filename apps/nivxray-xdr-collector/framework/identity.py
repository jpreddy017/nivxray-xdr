"""Collector deployment identity.

`collector_id` must match a collector ENROLLED in the NivXRay core —
the core rejects telemetry from an unknown collector rather than
creating one implicitly. It is supplied by deployment configuration.
"""
import os


def collector_id() -> str:
    return os.environ.get("NIVX_COLLECTOR_ID") or "collector-local"


def tenant_id() -> str:
    """Deployment tenant. The core rejects telemetry whose tenant does
    not match the enrolled collector's tenant, so this must be set to
    the tenant the collector was enrolled under."""
    return os.environ.get("NIVX_TENANT_ID") or "default"
