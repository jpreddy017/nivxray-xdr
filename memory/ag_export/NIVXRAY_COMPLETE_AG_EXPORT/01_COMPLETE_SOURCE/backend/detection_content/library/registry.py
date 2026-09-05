"""
NivXRay XDR — Enterprise Detection Library Registry.
Maintains the indexed catalogue of enterprise rules and provides deterministic evaluation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from .models import DetectionRuleContent, Platform, Severity, Tactic
from .rules_enterprise import ENTERPRISE_DETECTION_RULES


class DetectionLibraryRegistry:
    def __init__(self, rules: Optional[List[DetectionRuleContent]] = None):
        self._rules: Dict[str, DetectionRuleContent] = {}
        for r in (rules or ENTERPRISE_DETECTION_RULES):
            self._rules[r.rule_id] = r

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleContent]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._rules.values()]

    def count(self) -> int:
        return len(self._rules)

    def filter(
        self,
        tactic: Optional[Tactic] = None,
        platform: Optional[Platform] = None,
        severity: Optional[Severity] = None,
        technique_id: Optional[str] = None,
    ) -> List[DetectionRuleContent]:
        results = list(self._rules.values())
        if tactic:
            results = [r for r in results if r.tactic == tactic]
        if platform:
            results = [r for r in results if r.platform == platform]
        if severity:
            results = [r for r in results if r.severity == severity]
        if technique_id:
            results = [r for r in results if r.technique_id == technique_id]
        return results

    def evaluate_event(self, canonical_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate all rules against one canonical event.
        Returns a list of match records (never verdicts).
        """
        matches: List[Dict[str, Any]] = []
        for r in self._rules.values():
            if r.evaluate(canonical_event):
                matches.append({
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "tactic": r.tactic.value,
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "severity": r.severity.value,
                    "confidence": r.confidence,
                    "lane": r.lane,
                    "mitre_attack": r.mitre_attack,
                })
        return matches

    def summary(self) -> Dict[str, Any]:
        tactics: Dict[str, int] = {}
        platforms: Dict[str, int] = {}
        severities: Dict[str, int] = {}
        for r in self._rules.values():
            tactics[r.tactic.value] = tactics.get(r.tactic.value, 0) + 1
            platforms[r.platform.value] = platforms.get(r.platform.value, 0) + 1
            severities[r.severity.value] = severities.get(r.severity.value, 0) + 1

        return {
            "total_rules": len(self._rules),
            "tactics_coverage": tactics,
            "platforms_coverage": platforms,
            "severities_coverage": severities,
            "engine": "nivxray::detection_content::enterprise_library",
        }


# Authoritative singleton registry instance
REGISTRY = DetectionLibraryRegistry()
