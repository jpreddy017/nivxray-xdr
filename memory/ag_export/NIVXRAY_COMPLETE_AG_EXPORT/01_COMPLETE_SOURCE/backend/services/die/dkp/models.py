"""
DKP · Data Model
────────────────
Plain dataclasses so patterns can be authored in Python literals or
loaded from a JSON overlay without any framework dependency.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Signature:
    """A single matcher rule for a DKP pattern.

    ``kind`` selects which side of the DIE envelope the rule inspects:

        regex   — regex over ``against`` ("raw" | "decoded")
        flag    — DIE AST flag must be truthy   (``flag=...``)
        mitre   — MITRE technique id must be present (``id=...``)
        lolbin  — LOLBAS binary must be present    (``binary=...``)
        family  — arbitrary language flag         (``language=...``)
        all     — every child signature must match (``of=[...]``)
        any     — at least one child must match   (``of=[...]``)
    """
    kind:      str
    weight:    float = 1.0
    pattern:   Optional[str] = None
    against:   Optional[str] = None
    flag:      Optional[str] = None
    id:        Optional[str] = None
    binary:    Optional[str] = None
    language:  Optional[str] = None
    of:        Optional[List["Signature"]] = None


@dataclass
class Pattern:
    id:                str
    name:              str
    intent:            str
    signatures:        List[Signature]
    mitre:             List[str]              = field(default_factory=list)
    enterprise_uses:   List[str]              = field(default_factory=list)
    malware_uses:      List[str]              = field(default_factory=list)
    families:          List[str]              = field(default_factory=list)
    typical_parent:    Optional[str]          = None
    typical_child:     Optional[str]          = None
    common_followon:   Optional[str]          = None
    confidence:        int                    = 80   # base 0-100
    narrative_template: str                   = ""
    investigation:     List[str]              = field(default_factory=list)
    detection_logic:   Optional[str]          = None
    references:        List[str]              = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MatchedPattern:
    pattern:            Pattern
    matched_signatures: List[Signature]
    confidence:         float           # 0.0 – 1.0, blended with pattern.confidence
    evidence:           List[str]        # human-readable snippets

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":                 self.pattern.id,
            "name":               self.pattern.name,
            "intent":             self.pattern.intent,
            "mitre":              self.pattern.mitre,
            "enterprise_uses":    self.pattern.enterprise_uses,
            "malware_uses":       self.pattern.malware_uses,
            "families":           self.pattern.families,
            "typical_parent":     self.pattern.typical_parent,
            "typical_child":      self.pattern.typical_child,
            "common_followon":    self.pattern.common_followon,
            "narrative_template": self.pattern.narrative_template,
            "investigation":      self.pattern.investigation,
            "detection_logic":    self.pattern.detection_logic,
            "references":         self.pattern.references,
            "confidence":         round(self.confidence, 3),
            "matched_signatures": [asdict(s) for s in self.matched_signatures],
            "evidence":           self.evidence,
        }
