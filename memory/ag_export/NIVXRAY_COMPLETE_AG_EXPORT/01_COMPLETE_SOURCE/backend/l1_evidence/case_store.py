"""Persistence for Investigation Cases (Blueprint §8.1 · §8.3).

Storage layout (MongoDB collection ``investigation_cases``)::

    {
      "case_id":        str,   # unique
      "created_at":     ISO8601,
      "updated_at":     ISO8601,
      "owner_email":    str,   # analyst / operator identity
      "bundle":         { ... EvidenceBundle.to_dict() ... },
      "workspace":      { ... WorkspaceState.to_dict() ... },
      "state_history":  [ { ... StateTransition.to_dict() ... } ],
    }

All fields are canonical-JSON serializable. The store performs pure
CRUD; no derived content lives here. L2 services derive content from
``bundle`` on demand.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from l2_investigation.state import (
    InvalidStateTransition,
    InvestigationState,
    InvestigationStateMachine,
    StateTransition,
)
from l2_investigation.workspace_state import WorkspaceState


class CaseNotFound(LookupError):
    """Raised when a case lookup returns nothing."""


@dataclass(frozen=True)
class CaseRecord:
    """A fully hydrated case record."""

    case_id: str
    owner_email: str
    created_at: str
    updated_at: str
    bundle: dict
    workspace: dict
    state_history: list[dict]

    @property
    def current_state(self) -> InvestigationState:
        if not self.state_history:
            return InvestigationState.NEW
        return InvestigationState(self.state_history[-1]["to_state"])

    def to_workspace_state(self) -> WorkspaceState:
        return WorkspaceState.from_dict(self.workspace)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseStore:
    """CRUD facade over the ``investigation_cases`` collection.

    Uses the synchronous pymongo proxy exposed by ``deps.sync_collection``
    to match the pattern of the existing routers. All methods are pure
    (no HTTP concerns).
    """

    def __init__(self, collection):
        self._col = collection

    # ------------------------------------------------------------------
    # Create / Read
    # ------------------------------------------------------------------

    def create(
        self,
        case_id: str,
        owner_email: str,
        bundle: dict,
        workspace: dict,
    ) -> CaseRecord:
        now = _now_iso()
        # First transition: New → new, recorded implicitly. The state
        # machine starts at NEW; explicit transitions are appended to
        # `state_history` via ``transition_state``.
        record = {
            "case_id": case_id,
            "owner_email": owner_email,
            "created_at": now,
            "updated_at": now,
            "bundle": bundle,
            "workspace": workspace,
            "state_history": [],
        }
        self._col.insert_one(record)
        return self._to_record(record)

    def get(self, case_id: str) -> CaseRecord:
        doc = self._col.find_one({"case_id": case_id}, {"_id": 0})
        if not doc:
            raise CaseNotFound(case_id)
        return self._to_record(doc)

    def exists(self, case_id: str) -> bool:
        return bool(self._col.find_one({"case_id": case_id}, {"_id": 1}))

    def list(self, owner_email: Optional[str] = None, limit: int = 100) -> list[CaseRecord]:
        q: dict = {}
        if owner_email:
            q["owner_email"] = owner_email
        docs = list(
            self._col.find(q, {"_id": 0}).sort("created_at", -1).limit(limit)
        )
        return [self._to_record(d) for d in docs]

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_workspace(self, case_id: str, workspace: dict) -> CaseRecord:
        now = _now_iso()
        res = self._col.find_one_and_update(
            {"case_id": case_id},
            {"$set": {"workspace": workspace, "updated_at": now}},
            projection={"_id": 0},
            return_document=True,
        )
        if not res:
            raise CaseNotFound(case_id)
        return self._to_record(res)

    def transition_state(
        self,
        case_id: str,
        target: InvestigationState,
        actor: str,
        reason: str = "",
    ) -> tuple[CaseRecord, StateTransition]:
        rec = self.get(case_id)
        machine = InvestigationStateMachine(
            case_id=case_id,
            current=rec.current_state,
            history=[],
        )
        entry = machine.transition(target, actor=actor, reason=reason)
        # Append; also mirror the resulting state into the workspace so
        # the Workspace pill (Blueprint §8.1) reads consistently.
        new_workspace = dict(rec.workspace)
        new_workspace["investigation_state"] = target.value
        now = _now_iso()
        res = self._col.find_one_and_update(
            {"case_id": case_id},
            {
                "$push": {"state_history": entry.to_dict()},
                "$set": {"workspace": new_workspace, "updated_at": now},
            },
            projection={"_id": 0},
            return_document=True,
        )
        if not res:
            raise CaseNotFound(case_id)
        return self._to_record(res), entry

    # ------------------------------------------------------------------
    # Delete (dev / cleanup only)
    # ------------------------------------------------------------------

    def delete(self, case_id: str) -> bool:
        res = self._col.delete_one({"case_id": case_id})
        return res.deleted_count == 1

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _to_record(doc: dict[str, Any]) -> CaseRecord:
        return CaseRecord(
            case_id=doc["case_id"],
            owner_email=doc["owner_email"],
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            bundle=doc["bundle"],
            workspace=doc["workspace"],
            state_history=list(doc.get("state_history", [])),
        )


__all__ = ["CaseStore", "CaseRecord", "CaseNotFound", "InvalidStateTransition"]
