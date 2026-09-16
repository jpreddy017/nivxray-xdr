"""
NivXRay XDR — Quality Validation & Lifecycle Framework Package.
"""
from .gates import GateResult, ValidationGates, LicensePolicy, LicenseStatus
from .tiers import ValidationTier, TierValidationReport, QualityValidationFramework
from .lifecycle import LifecycleState, TransitionAuditRecord, ContentLifecycleManager, LIFECYCLE_MANAGER
from .binding_bridge import BindingStatus, EngineBindingReport, EngineBindingBridge, SecurityStateBridgeIntegration

__all__ = [
    "GateResult",
    "ValidationGates",
    "LicensePolicy",
    "LicenseStatus",
    "ValidationTier",
    "TierValidationReport",
    "QualityValidationFramework",
    "LifecycleState",
    "TransitionAuditRecord",
    "ContentLifecycleManager",
    "LIFECYCLE_MANAGER",
    "BindingStatus",
    "EngineBindingReport",
    "EngineBindingBridge",
    "SecurityStateBridgeIntegration",
]
