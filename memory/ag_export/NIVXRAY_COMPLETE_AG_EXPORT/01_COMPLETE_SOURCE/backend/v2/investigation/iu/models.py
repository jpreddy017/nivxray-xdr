"""Input Understanding · canonical models.

The classifier answers ONLY four questions:
    1. What artefact(s) am I looking at?
    2. How confident am I?
    3. What evidence supports that conclusion?
    4. Which analysis capabilities should run next?

It does NOT perform semantic analysis or threat assessment.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Evidence


class ArtefactType(str, Enum):
    """Every artefact type the Workspace can currently classify."""
    COMMAND_LINE       = "command_line"
    POWERSHELL_SCRIPT  = "powershell_script"
    BASH               = "bash"
    PYTHON             = "python"
    JAVASCRIPT         = "javascript"
    VBSCRIPT           = "vbscript"
    OFFICE_MACRO       = "office_macro"
    SCHEDULED_TASK_XML = "scheduled_task_xml"
    SERVICE_DEFINITION = "service_definition"
    REGISTRY_BLOB      = "registry_blob"
    MSI                = "msi"
    NETWORK_ARTEFACT   = "network_artefact"
    BASE64             = "base64"
    HEX                = "hex"
    UNKNOWN_BINARY     = "unknown_binary"
    UNKNOWN            = "unknown"


class Capability(str, Enum):
    """Downstream analysis capabilities the classifier can request.
    Capability-based dispatch — an investigation may need multiple
    engines to cooperate (e.g. CRE + DECODER + SEMANTIC + IOC)."""
    CRE                = "cre"                 # Command Reconstruction Engine
    DECODER            = "decoder"             # Recursive decoder chain
    SEMANTIC           = "semantic"            # PS / cmd / bash / py semantic
    JAVASCRIPT_ENGINE  = "javascript_engine"   # JS-specific analyzer (future)
    VBSCRIPT_ENGINE    = "vbscript_engine"     # VBS-specific analyzer (future)
    OFFICE_ENGINE      = "office_engine"       # VBA / XLM analyzer (future)
    REGISTRY_ENGINE    = "registry_engine"     # .reg / hive analyzer (future)
    IOC                = "ioc"                 # IOC extractor
    MITRE              = "mitre"               # ATT&CK mapper
    VERDICT            = "verdict"             # verdict engine
    BEHAVIOR           = "behavior"            # behavior extractor


@dataclass
class ArtefactClassification:
    """The complete IU output for a single input.

    Fields:
        primary_type    — the OUTERMOST artefact type (e.g. COMMAND_LINE
                           for a wmic-shaped input).
        embedded        — ordered list of nested artefact types the
                           classifier suspects inside `primary_type`.
                           E.g. wmic → cmd → ps → base64 → js.
                           This is a FIRST-CLASS finding, not a hint;
                           downstream engines walk it in order.
        confidence      — 0-100 aggregate confidence for the primary type.
        evidence        — list of canonical Evidence objects supporting
                           the classification.
        dispatch        — ordered list of Capabilities to invoke on this
                           input. Multi-capability by design — a wmic
                           command might need CRE + DECODER + SEMANTIC + IOC.
        determinism_hash— SHA-256 over the canonical serialization for
                           regression proofs of deterministic behavior.
    """
    primary_type: ArtefactType
    embedded: list[ArtefactType] = field(default_factory=list)
    confidence: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    dispatch: list[Capability] = field(default_factory=list)
    determinism_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_type":     self.primary_type.value,
            "embedded":         [t.value for t in self.embedded],
            "confidence":       self.confidence,
            "evidence":         [e.to_dict() for e in self.evidence],
            "dispatch":         [c.value for c in self.dispatch],
            "determinism_hash": self.determinism_hash,
        }
