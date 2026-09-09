"""
NivXRay XDR — Enterprise Detection Content Models.
Provides strongly-typed models for high-fidelity enterprise detections.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Tactic(str, Enum):
    INITIAL_ACCESS      = "Initial Access"
    EXECUTION           = "Execution"
    PERSISTENCE         = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION     = "Defense Evasion"
    CREDENTIAL_ACCESS   = "Credential Access"
    DISCOVERY           = "Discovery"
    LATERAL_MOVEMENT    = "Lateral Movement"
    COLLECTION          = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION        = "Exfiltration"
    IMPACT              = "Impact"


class Platform(str, Enum):
    WINDOWS    = "windows"
    LINUX      = "linux"
    MACOS      = "macos"
    CLOUD      = "cloud"
    IDENTITY   = "identity"
    HYPERVISOR = "hypervisor"
    CONTAINER  = "container"


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class DetectionFixture:
    """A positive or negative verification fixture for a rule."""
    name: str
    event: Dict[str, Any]
    should_match: bool
    rationale: str = ""


@dataclass
class DetectionRuleContent:
    """Authoritative representation of an enterprise detection rule."""
    rule_id: str
    name: str
    description: str
    tactic: Tactic
    technique_id: str
    technique_name: str
    platform: Platform
    severity: Severity
    confidence: str  # low | medium | high | confirmed
    lane: str  # event | endpoint | ioc | network | behavior | content
    predicate: Callable[[Dict[str, Any]], bool]
    telemetry_requirements: List[str]
    false_positive_notes: str = ""
    mitre_attack: List[str] = field(default_factory=list)
    fixtures: List[DetectionFixture] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def evaluate(self, canonical_event: Dict[str, Any]) -> bool:
        """Evaluate rule predicate against canonical event safely."""
        try:
            return bool(self.predicate(canonical_event))
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "platform": self.platform.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "lane": self.lane,
            "telemetry_requirements": self.telemetry_requirements,
            "false_positive_notes": self.false_positive_notes,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
        }
