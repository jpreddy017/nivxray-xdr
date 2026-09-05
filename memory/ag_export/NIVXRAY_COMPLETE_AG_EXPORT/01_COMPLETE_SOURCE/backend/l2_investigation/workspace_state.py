"""Workspace State model · Blueprint §8.3.

Persistence contract: two returns to the same case must produce a
byte-identical restored Workspace State. Server-side canonical JSON is
used to enforce this.

The state persisted here is *presentation state* — not evidence. It is
disposable from a determinism standpoint (throwing it away doesn't
lose evidence), but it drives analyst continuity.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .state import InvestigationState


class WorkspaceMode(str, Enum):
    """Blueprint §8.2 · three modes on the same Workspace."""

    QUICK_TRIAGE = "quick_triage"
    INVESTIGATION = "investigation"
    DEEP_ANALYSIS = "deep_analysis"


class WorkspaceLens(str, Enum):
    """Blueprint §8 · six top-level lenses."""

    SUMMARY = "summary"
    STORY = "story"
    TIMELINE = "timeline"
    EVIDENCE = "evidence"
    ANALYSIS = "analysis"
    EXPORTS = "exports"


# Default lens per mode (Blueprint §8.2 table).
_DEFAULT_LENS_BY_MODE: dict[WorkspaceMode, WorkspaceLens] = {
    WorkspaceMode.QUICK_TRIAGE: WorkspaceLens.SUMMARY,
    WorkspaceMode.INVESTIGATION: WorkspaceLens.SUMMARY,
    WorkspaceMode.DEEP_ANALYSIS: WorkspaceLens.EVIDENCE,
}


def default_lens_for(mode: WorkspaceMode) -> WorkspaceLens:
    return _DEFAULT_LENS_BY_MODE[mode]


@dataclass(frozen=True)
class WorkspaceState:
    """Persistence contract from Blueprint §8.3.

    Every field listed in §8.3 is captured here. The dataclass is frozen
    to prevent accidental mutation — updates create a new instance via
    ``dataclasses.replace``.
    """

    case_id: str
    mode: WorkspaceMode = WorkspaceMode.INVESTIGATION
    active_lens: WorkspaceLens = WorkspaceLens.SUMMARY
    scroll_positions: dict[str, int] = field(default_factory=dict)  # lens.value → pixels
    selected_evidence_id: str | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    timeline_position: int = 0  # index into timeline events; 0 = start
    investigation_state: InvestigationState = InvestigationState.NEW

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "mode": self.mode.value,
            "active_lens": self.active_lens.value,
            "scroll_positions": dict(sorted(self.scroll_positions.items())),
            "selected_evidence_id": self.selected_evidence_id,
            "filters": _canonicalize(self.filters),
            "timeline_position": self.timeline_position,
            "investigation_state": self.investigation_state.value,
        }

    def to_json(self) -> str:
        """Canonical, sort-key JSON. Byte-identical restoration proof."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @classmethod
    def initial(cls, case_id: str, mode: WorkspaceMode = WorkspaceMode.INVESTIGATION) -> "WorkspaceState":
        """Blueprint-defined initial state at case entry."""
        return cls(
            case_id=case_id,
            mode=mode,
            active_lens=default_lens_for(mode),
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WorkspaceState":
        return cls(
            case_id=payload["case_id"],
            mode=WorkspaceMode(payload.get("mode", WorkspaceMode.INVESTIGATION.value)),
            active_lens=WorkspaceLens(payload.get("active_lens", WorkspaceLens.SUMMARY.value)),
            scroll_positions=dict(payload.get("scroll_positions") or {}),
            selected_evidence_id=payload.get("selected_evidence_id"),
            filters=dict(payload.get("filters") or {}),
            timeline_position=int(payload.get("timeline_position", 0)),
            investigation_state=InvestigationState(
                payload.get("investigation_state", InvestigationState.NEW.value)
            ),
        )


def _canonicalize(value: Any) -> Any:
    """Recursively sort dict keys so JSON is byte-identical across returns."""
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonicalize(v) for v in value]
    return value


__all__ = [
    "WorkspaceMode",
    "WorkspaceLens",
    "WorkspaceState",
    "default_lens_for",
]
