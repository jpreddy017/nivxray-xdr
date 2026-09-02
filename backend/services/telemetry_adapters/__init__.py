from .framework import (
    CanonicalEvent, EvidenceCapability, Provenance, SourceKind,
    TelemetryAdapter, TelemetryAdapterRegistry, get_registry,
)
from .adapters.okta_system_log import OktaSystemLogAdapter
from .adapters.entra_signin_log import EntraSignInLogAdapter
from .adapters.aws_cloudtrail import AwsCloudTrailAdapter
from .runner import (
    IngestionJob, IngestionHealth, IngestionRunner,
    CheckpointStore, DedupStore, SourcePoller,
    InMemoryCheckpoint, InMemoryDedup,
)
from .correlation import CrossLaneCorrelation, correlate


def _register_default_adapters() -> None:
    reg = get_registry()
    for a in (OktaSystemLogAdapter(),
                       EntraSignInLogAdapter(),
                       AwsCloudTrailAdapter()):
        try:
            reg.register(a)
        except ValueError:
            pass                          # already registered — idempotent


_register_default_adapters()


__all__ = [
    "CanonicalEvent", "EvidenceCapability", "Provenance",
    "SourceKind", "TelemetryAdapter", "TelemetryAdapterRegistry",
    "get_registry",
    "OktaSystemLogAdapter", "EntraSignInLogAdapter",
    "AwsCloudTrailAdapter",
    "IngestionJob", "IngestionHealth", "IngestionRunner",
    "CheckpointStore", "DedupStore", "SourcePoller",
    "InMemoryCheckpoint", "InMemoryDedup",
    "CrossLaneCorrelation", "correlate",
]
