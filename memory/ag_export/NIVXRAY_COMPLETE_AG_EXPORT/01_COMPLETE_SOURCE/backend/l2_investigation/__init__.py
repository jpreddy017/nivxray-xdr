"""L2 Investigation Services · Analyst Workspace Blueprint v1.1.

Layered architecture (Blueprint §7):

    L4 Analyst Workspace (React)
        ▲
    L3 Presentation Services (per-lens formatting)
        ▲
    L2 Investigation Services   ←── THIS PACKAGE
        ▲
    L1 Evidence Services (read APIs · `/api/investigation/*`)
        ▲
    L0 Deterministic Platform (FROZEN — `workspace.convergence.*`)

L2 services consume an ``EvidenceBundle`` (built from L1 evidence,
including the L0 ``ConvergenceCertificate``) and produce deterministic
structured outputs. Every service is a pure function: same bundle ⇒
byte-identical output (hash-stable, verified in tests).

PR-1 delivers **scaffolding only**: schemas, state models, service
skeletons, and the deterministic contract. No L1 APIs are wired yet
(PR-2), no UI (PR-3+).

Damage-prevention contract (per ARB PR-0 sign-off):
    * No imports from ``workspace.convergence`` internals other than
      the read-only ``ConvergenceCertificate`` dataclass.
    * No modifications to any file outside this package.
    * Determinism proven by hash-stability tests.
"""
from __future__ import annotations

from .state import (
    InvestigationState,
    InvestigationStateMachine,
    InvalidStateTransition,
    STATE_ORDER,
)
from .workspace_state import (
    WorkspaceMode,
    WorkspaceLens,
    WorkspaceState,
)
from .schemas import (
    EvidenceBundle,
    IocEvidence,
    CapabilityEvidence,
    MitreEvidence,
    TransformationEvidence,
    SampleMetadata,
    ServiceOutput,
)

__all__ = [
    "InvestigationState",
    "InvestigationStateMachine",
    "InvalidStateTransition",
    "STATE_ORDER",
    "WorkspaceMode",
    "WorkspaceLens",
    "WorkspaceState",
    "EvidenceBundle",
    "IocEvidence",
    "CapabilityEvidence",
    "MitreEvidence",
    "TransformationEvidence",
    "SampleMetadata",
    "ServiceOutput",
]

L2_VERSION = "L2-0.1.0-scaffold"
