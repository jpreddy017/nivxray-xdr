"""GATE 7 · exclusions and declared protection blind spots.

An exclusion record in MongoDB is NOT an exclusion. An exclusion exists
only when it demonstrably changes what an engine does, and the record
preserves WHICH engine, at WHICH enforcement point, and WHAT actually
happened.

Six truth states, deliberately not collapsed into one:

    EXCLUDED                          a finding existed and was suppressed
    NOT_EVALUATED_DUE_TO_EXCLUSION    the engine was bypassed before it ran
    SERVER_EXCLUSION_APPLIED          enforced in the backend fabric
    ENDPOINT_EXCLUSION_APPLIED        enforced on the endpoint itself
    EXCLUSION_PENDING_POLICY          approved, but the carrying policy
                                      version is not APPLIED on the endpoint
    EXCLUSION_NOT_SUPPORTED_BY_ENGINE the target engine cannot honour it
"""
from edr_plane.exclusions import contracts, enforcement, store  # noqa: F401

__all__ = ["contracts", "enforcement", "store"]
