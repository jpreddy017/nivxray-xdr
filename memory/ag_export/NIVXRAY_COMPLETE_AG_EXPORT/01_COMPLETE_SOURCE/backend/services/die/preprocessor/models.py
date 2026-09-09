"""
DIE · Preprocessor · Data model
───────────────────────────────
Strict schemas for artifacts, stages and inferred process edges.
Every downstream consumer (DIE, DKP, Attack Story, Narrative, IDA,
IVE) reads these exact shapes.

Determinism rules:
    • Every ``id`` is content-derived (hash of type + normalized text +
      first offset).  Same input → same ids across runs.
    • Every artifact carries provenance: raw_text · normalized_text ·
      line_number · start_offset · end_offset.
    • ``confidence`` is 0.0 – 1.0.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from hashlib import sha1
from typing import Any, Dict, List, Optional


# ── Artifact taxonomy ─────────────────────────────────────────────
# Top-level types the extractor emits.  ``subtype`` refines within a
# type (e.g. registry.hive="HKLM", url.scheme="https").
ARTIFACT_TYPES = (
    "command",
    "executable",
    "registry",
    "process",
    "service",
    "file_path",
    "unc_path",
    "url",
    "ip",
    "hash",
    "env_var",
    "lolbin",
    "network_endpoint",
    "scheduled_task",
    "dll",
    "unknown",
)


def _stable_id(prefix: str, *parts: Any) -> str:
    h = sha1("::".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{h}"


@dataclass
class Artifact:
    """One structured extraction with full provenance."""
    id:              str
    type:            str
    subtype:         Optional[str]
    raw_text:        str
    normalized_text: str
    line_number:     int
    start_offset:    int
    end_offset:      int
    confidence:      float = 1.0
    source:          str = "preprocessor"
    # Free-form annotations added by later stages (family, tactic …).
    attributes:      Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, type_: str, subtype: Optional[str], raw: str, normalized: str,
              line_number: int, start: int, end: int,
              confidence: float = 1.0, attributes: Optional[Dict[str, Any]] = None) -> "Artifact":
        aid = _stable_id("art", type_, normalized, start)
        return cls(
            id=aid, type=type_, subtype=subtype,
            raw_text=raw, normalized_text=normalized,
            line_number=line_number, start_offset=start, end_offset=end,
            confidence=round(confidence, 3),
            attributes=dict(attributes or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Stage:
    """A grouped unit of analyst-observed activity.

    A stage is NOT limited to commands — it can hold registry writes,
    scheduled-task drops, service creations, file drops, network
    endpoints … whatever the analyst pasted.
    """
    id:                 str
    index:              int
    kind:               str                          # "command" | "registry" | "network" | ...
    title:              str                          # short human title
    # Analyst-grade enrichment (2026-02-28 P0 polish):
    objective:          str = ""                     # one-sentence "what this stage accomplishes"
    tactic:             Optional[str] = None         # MITRE ATT&CK tactic bucket
    mitre:              List[str] = field(default_factory=list)   # ["T1490", "T1059.001"]
    evidence:           List[str] = field(default_factory=list)   # short human evidence bullets
    commonly_observed_in: List[str] = field(default_factory=list) # ["LockBit","Medusa","Chaos"]
    child_stage_ids:    List[str] = field(default_factory=list)   # deterministic child stage refs
    command_family:     Optional[str] = None         # populated when the family recognizer fires
    artifact_ids:       List[str] = field(default_factory=list)
    normalized_command: Optional[str] = None
    raw_excerpt:        str = ""
    line_number:        int = 0
    confidence:         float = 1.0

    @classmethod
    def build(cls, index: int, kind: str, title: str,
              artifact_ids: List[str], normalized_command: Optional[str] = None,
              raw_excerpt: str = "", line_number: int = 0,
              command_family: Optional[str] = None, confidence: float = 1.0,
              objective: str = "", tactic: Optional[str] = None,
              mitre: Optional[List[str]] = None,
              evidence: Optional[List[str]] = None,
              commonly_observed_in: Optional[List[str]] = None,
              child_stage_ids: Optional[List[str]] = None) -> "Stage":
        sid = _stable_id("stage", index, kind, normalized_command or title)
        return cls(
            id=sid, index=index, kind=kind, title=title,
            artifact_ids=list(artifact_ids),
            normalized_command=normalized_command,
            raw_excerpt=raw_excerpt, line_number=line_number,
            command_family=command_family,
            confidence=round(confidence, 3),
            objective=objective,
            tactic=tactic,
            mitre=list(mitre or []),
            evidence=list(evidence or []),
            commonly_observed_in=list(commonly_observed_in or []),
            child_stage_ids=list(child_stage_ids or []),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessEdge:
    """Deterministically inferred parent → child relationship.

    Never emit an edge without ``why`` and ``confidence`` — the rule
    that produced it must be visible to analysts.
    """
    id:            str
    parent:        str          # normalized executable / stage title
    child:         str
    inferred:      bool = True
    why:           str = ""
    confidence:    float = 0.6
    supporting_artifact_ids: List[str] = field(default_factory=list)

    @classmethod
    def build(cls, parent: str, child: str, why: str,
              confidence: float, supporting: List[str]) -> "ProcessEdge":
        eid = _stable_id("edge", parent.lower(), child.lower())
        return cls(
            id=eid, parent=parent, child=child, inferred=True,
            why=why, confidence=round(confidence, 3),
            supporting_artifact_ids=list(supporting),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
