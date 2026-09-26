"""Collector deployment identity.

`collector_id` must match a collector ENROLLED in the NivXRay core —
the core rejects telemetry from an unknown collector rather than
creating one implicitly. It is supplied by deployment configuration.
"""
import os


def collector_id() -> str:
    return os.environ.get("NIVX_COLLECTOR_ID") or "collector-local"


def tenant_id() -> str:
    """Deployment tenant, from ``NIVX_TENANT_ID``.

    B7 Option A · this returned ``"default"`` when unset, so a mis-deployed
    collector labelled its telemetry with a tenant that does not exist in the
    NivXRay registry. There is no default tenant: an unset value returns the
    empty string and the core refuses the batch with ``TENANT_REQUIRED``,
    which is the honest outcome. Telemetry never establishes tenancy.
    """
    return os.environ.get("NIVX_TENANT_ID") or ""
