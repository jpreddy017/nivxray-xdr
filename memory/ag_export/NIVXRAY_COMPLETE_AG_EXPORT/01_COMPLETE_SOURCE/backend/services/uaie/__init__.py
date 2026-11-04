"""UAIE · Universal Artifact Intelligence Engine (Rule R25)

Public contracts:
    Artifact         — immutable, URI-addressed unit of analysis
    Recognizer       — classifier: "what is this?"
    Capability       — analyser:   "given this type, what can I do?"
    Evidence         — normalised finding, family-agnostic
    Ledger           — immutable, append-only investigation log
    Orchestrator     — work-queue engine wiring all five together

Phase 1 · Scaffolding only.  No plugins.  No behaviour changes to
existing pipelines.  Pure additive under `services/uaie/`.
"""
from .artifact    import Artifact, ArtifactURI, compute_uri, make_artifact
from .capability  import (Capability, CapabilityResult,
                            all_registered, clear, for_type, register)
from .evidence    import Evidence, make_evidence
from .ledger      import (ACTION_COMPLETE, ACTION_EMIT_EVIDENCE, ACTION_ENQUEUE,
                            ACTION_EXECUTE, ACTION_RECOGNIZE, ACTION_SCHEDULE_SKIP,
                            Ledger, LedgerEntry)
from .orchestrator import Orchestrator, OrchestratorResult
from .recognizer  import (CERTAIN, HIGH, LIKELY, POSSIBLE, UNKNOWN,
                            Reason, Recognition, Recognizer)

__all__ = [
    "Artifact", "ArtifactURI", "compute_uri", "make_artifact",
    "Recognizer", "Recognition", "Reason",
    "UNKNOWN", "POSSIBLE", "LIKELY", "HIGH", "CERTAIN",
    "Capability", "CapabilityResult",
    "register", "for_type", "all_registered", "clear",
    "Evidence", "make_evidence",
    "Ledger", "LedgerEntry",
    "ACTION_RECOGNIZE", "ACTION_EXECUTE", "ACTION_ENQUEUE",
    "ACTION_EMIT_EVIDENCE", "ACTION_SCHEDULE_SKIP", "ACTION_COMPLETE",
    "Orchestrator", "OrchestratorResult",
]
