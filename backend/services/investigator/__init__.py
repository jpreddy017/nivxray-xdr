"""Round 31 · NivXRay XDR · Autonomous Investigator.

Public surface:
  * ``InvestigatorService`` — the orchestrator.
  * ``models`` — Pydantic contracts.
  * ``capabilities`` — built-in capability registry (Round 32 will extend).
"""
from services.investigator.orchestrator import InvestigatorService  # noqa: F401
from services.investigator.models import (  # noqa: F401
    InvestigationState,
    PivotAction,
    EngineExecution,
    Finding,
    LifecycleState,
    ActivityEntry,
)
