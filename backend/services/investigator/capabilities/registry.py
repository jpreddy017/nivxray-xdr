"""Round 32 · Capability registry seeder.

Registers every built-in capability the Autonomous Investigator can
select from.  Idempotent — safe to import multiple times.
"""
from __future__ import annotations

from services.investigator.capabilities.base import (
    register_capability, all_capabilities,
)
from services.investigator.capabilities.historical import (
    HistoricalCorrelationCapability,
    CorrelationCapability,
    MitreExpansionCapability,
    DetectionIntelCapability,
)
from services.investigator.capabilities.endpoint import (
    ProcessAncestryCapability,
    CommandLineDecodeCapability,
    LolbasLookupCapability,
)
from services.investigator.capabilities.network_identity_file import (
    NetworkPivotCapability,
    DnsPivotCapability,
    IocPivotCapability,
    FileReputationCapability,
    IdentityPivotCapability,
)


def seed() -> None:
    if all_capabilities():
        return
    for cls in (
        # History / correlation / MITRE / detection
        HistoricalCorrelationCapability,
        CorrelationCapability,
        MitreExpansionCapability,
        DetectionIntelCapability,
        # Endpoint
        ProcessAncestryCapability,
        CommandLineDecodeCapability,
        LolbasLookupCapability,
        # Network / DNS / IOC / File / Identity
        NetworkPivotCapability,
        DnsPivotCapability,
        IocPivotCapability,
        FileReputationCapability,
        IdentityPivotCapability,
    ):
        register_capability(cls())
