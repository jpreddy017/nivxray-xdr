"""Projection · Behavior → Impact tags.

Impact-family tag set used by the v2 Evidence-Driven Recommendation
Engine on ``InvestigationOutcome.impacts``.  Vocabulary matches
``IMPACT_TAGS`` in ``services.mitigation.evidence_driven.case_context``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple


BEHAVIOR_TO_IMPACTS: Dict[str, Tuple[str, ...]] = {
    "shadow_copy_deletion":            ("recovery_inhibited",),
    "inhibit_recovery_wmic":           ("recovery_inhibited",),
    "inhibit_recovery_bcdedit":        ("recovery_inhibited",),
    "data_encryption_for_impact":      ("data_encrypted",),
    "credential_dumping_lsass":        ("credential_exposed",),
    "credential_dumping_mimikatz":     ("credential_exposed",),
    "data_staging_exfil_rclone":       ("data_theft",),
    "powershell_in_memory":            ("in_memory_execution",),
    "self_deletion":                   ("data_destroyed",),
}


def project_to_impacts(behaviors: Sequence[Any]) -> List[str]:
    """Return the sorted, deduplicated impact tag set."""
    tags: set = set()
    for b in behaviors:
        tags.update(BEHAVIOR_TO_IMPACTS.get(b.behavior_type, ()))
    return sorted(tags)


def impacts_for(behavior_type: str) -> List[str]:
    """Return the impact tag list mapped to a single ``behavior_type``."""
    return list(BEHAVIOR_TO_IMPACTS.get(behavior_type, ()))


__all__ = ["BEHAVIOR_TO_IMPACTS", "project_to_impacts", "impacts_for"]
