"""
NivXRay XDR — Semantic Deduplication Engine.
Compares candidate CanonicalIR rules against an active library to classify semantic relationships:
- DUPLICATE: 100% equivalent behavioral logic and field requirements
- COMPLEMENTARY: Same technique/platform, different arguments or coverage scopes
- RELATED: Same tactic or overlapping telemetry field sets
- CONFLICTING: Opposing boolean conditions or mutually exclusive predicates
- UNIQUE: Novel detection logic
Preserves complete provenance from all sources; never automatically deletes rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from ..canonical_ir.models import CanonicalIR, ProvenanceInfo
from ..canonical_ir.nodes import FieldCompareNode, Operator, IRNode, BooleanLogicNode
from .fingerprint import BehavioralFingerprinter, _FIELD_ALIAS_MAP


class SemanticRelationship(str, Enum):
    DUPLICATE     = "DUPLICATE"
    COMPLEMENTARY = "COMPLEMENTARY"
    RELATED       = "RELATED"
    CONFLICTING   = "CONFLICTING"
    UNIQUE        = "UNIQUE"


@dataclass
class DeduplicationVerdict:
    relationship: SemanticRelationship
    candidate_id: str
    matched_rule_id: Optional[str] = None
    similarity_score: float = 0.0
    shared_sources: List[ProvenanceInfo] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship": self.relationship.value,
            "candidate_id": self.candidate_id,
            "matched_rule_id": self.matched_rule_id,
            "similarity_score": self.similarity_score,
            "shared_sources": [asdict(s) for s in self.shared_sources],
            "reasons": self.reasons,
        }


from dataclasses import asdict


class SemanticDeduplicationEngine:
    def __init__(self, existing_rules: Optional[List[CanonicalIR]] = None):
        self._rules: Dict[str, CanonicalIR] = {}
        self._fingerprints: Dict[str, Dict[str, Any]] = {}
        if existing_rules:
            for r in existing_rules:
                self.index_rule(r)

    def index_rule(self, ir: CanonicalIR):
        self._rules[ir.content_id] = ir
        self._fingerprints[ir.content_id] = BehavioralFingerprinter.compute_fingerprint(ir)

    @staticmethod
    def _has_contradiction(n1: IRNode, n2: IRNode) -> bool:
        """Detect mutually exclusive / contradictory predicates on identical field."""
        if isinstance(n1, FieldCompareNode) and isinstance(n2, FieldCompareNode):
            f1 = _FIELD_ALIAS_MAP.get(n1.field_name.lower().strip(), n1.field_name.lower().strip())
            f2 = _FIELD_ALIAS_MAP.get(n2.field_name.lower().strip(), n2.field_name.lower().strip())
            if f1 == f2 and str(n1.value).lower() == str(n2.value).lower():
                if (n1.operator == Operator.EQUALS and n2.operator == Operator.NOT_EQUALS) or \
                   (n1.operator == Operator.NOT_EQUALS and n2.operator == Operator.EQUALS):
                    return True
        return False

    def evaluate_candidate(self, candidate: CanonicalIR) -> DeduplicationVerdict:
        candidate_fp = BehavioralFingerprinter.compute_fingerprint(candidate)

        # 1. Check exact semantic hash match (DUPLICATE)
        for rule_id, fp in self._fingerprints.items():
            if fp["semantic_hash"] == candidate_fp["semantic_hash"]:
                matched_rule = self._rules[rule_id]
                # Merge provenance into shared sources
                shared_prov = [matched_rule.provenance, candidate.provenance]
                return DeduplicationVerdict(
                    relationship=SemanticRelationship.DUPLICATE,
                    candidate_id=candidate.content_id,
                    matched_rule_id=rule_id,
                    similarity_score=1.0,
                    shared_sources=shared_prov,
                    reasons=[
                        f"Exact semantic AST and field requirement match with existing rule '{rule_id}'",
                        f"Preserved source attribution: '{candidate.provenance.source}:{candidate.provenance.source_id}'",
                    ],
                )

        # 2. Check for Conflicting predicates
        for rule_id, matched_rule in self._rules.items():
            if self._has_contradiction(candidate.root_node, matched_rule.root_node):
                return DeduplicationVerdict(
                    relationship=SemanticRelationship.CONFLICTING,
                    candidate_id=candidate.content_id,
                    matched_rule_id=rule_id,
                    similarity_score=1.0,
                    shared_sources=[matched_rule.provenance, candidate.provenance],
                    reasons=[
                        f"Contradictory/opposing predicates on identical field against rule '{rule_id}'",
                        "One rule asserts condition, other asserts negation",
                    ],
                )

        # 3. Check Complementary
        for rule_id, fp in self._fingerprints.items():
            # Same technique and platform
            if fp["platform"] == candidate_fp["platform"] and fp["technique"] == candidate_fp["technique"]:
                # Check field overlap
                set_a = set(candidate_fp["required_fields"])
                set_b = set(fp["required_fields"])
                overlap = len(set_a.intersection(set_b)) / max(len(set_a.union(set_b)), 1)

                if overlap > 0.5:
                    return DeduplicationVerdict(
                        relationship=SemanticRelationship.COMPLEMENTARY,
                        candidate_id=candidate.content_id,
                        matched_rule_id=rule_id,
                        similarity_score=overlap,
                        shared_sources=[self._rules[rule_id].provenance, candidate.provenance],
                        reasons=[
                            f"Shares platform '{fp['platform']}' and technique '{fp['technique']}' with '{rule_id}'",
                            f"Field set overlap: {overlap:.2f}",
                            "Provides complementary coverage for alternate arguments or OS versions",
                        ],
                    )

        # 4. Check Related
        for rule_id, fp in self._fingerprints.items():
            if fp["tactic"] == candidate_fp["tactic"]:
                return DeduplicationVerdict(
                    relationship=SemanticRelationship.RELATED,
                    candidate_id=candidate.content_id,
                    matched_rule_id=rule_id,
                    similarity_score=0.4,
                    shared_sources=[self._rules[rule_id].provenance, candidate.provenance],
                    reasons=[f"Shares ATT&CK tactic '{fp['tactic']}' with rule '{rule_id}'"],
                )

        # 4. Otherwise UNIQUE
        return DeduplicationVerdict(
            relationship=SemanticRelationship.UNIQUE,
            candidate_id=candidate.content_id,
            matched_rule_id=None,
            similarity_score=0.0,
            shared_sources=[candidate.provenance],
            reasons=["Novel detection logic with no existing semantic fingerprint collisions"],
        )
