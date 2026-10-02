"""Append-only retrospective status/detection events and approval-only response requests."""
from __future__ import annotations

import builtins
import hashlib
import json
from typing import Any

from .contracts import require_tenant

RETRO_KINDS = ("RETRO_DETECTION", "STATUS_CHANGE")


class AppendOnlyViolation(RuntimeError):
    pass


class StatusLog:
    """Append-only. Each record references the ORIGINAL event; originals are never rewritten."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []

    def append(self, *, tenant_id: str, subject: str, kind: str, state: str, recorded_at: str,
               references_event_id: str | None, provenance: dict[str, Any]) -> dict[str, Any]:
        t = require_tenant(tenant_id)
        if kind not in RETRO_KINDS:
            raise ValueError(f"kind must be one of {RETRO_KINDS}")
        if not provenance.get("source") or not recorded_at:
            raise ValueError("every status carries provenance.source and a timestamp")
        prior = self.current(t, subject)
        row = {"status_event_id": f"se_{len(self._rows) + 1:06d}", "tenant_id": t, "subject": subject,
               "kind": kind, "state": state, "recorded_at": recorded_at, "references_event_id": references_event_id,
               "supersedes": prior["status_event_id"] if prior else None, "provenance": dict(provenance)}
        self._rows.append(row)
        return dict(row)

    def update(self, *_a: Any, **_k: Any) -> None:
        raise AppendOnlyViolation("status events are append-only")

    delete = update

    def history(self, tenant_id: str, subject: str | None = None) -> list[dict[str, Any]]:
        t = require_tenant(tenant_id)
        return [dict(r) for r in self._rows if r["tenant_id"] == t and (subject is None or r["subject"] == subject)]

    def current(self, tenant_id: str, subject: str) -> dict[str, Any] | None:
        h = self.history(tenant_id, subject)
        return h[-1] if h else None


APPROVAL_ACTIONS = ("BLOCK_APPLICATION", "ADD_HASH_TO_BLOCKLIST", "QUARANTINE_FILE", "ISOLATE_DEVICE",
                    "STOP_ISOLATION", "RUN_SCAN", "FORENSIC_SNAPSHOT", "DIAGNOSE_SENSOR", "MOVE_TO_GROUP")
PIVOTS = ("COPY_HASH", "SEARCH_HASH", "SEARCH_FILENAME", "OPEN_FILE_TRAJECTORY")
#: E3 can only ever create the first state. The rest are owned by E1's hardened response boundary.
RESPONSE_STATES = ("APPROVAL_REQUESTED", "ACCEPTED", "EXECUTED", "CONTAINED", "VERIFIED")


class ApprovalStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], dict[str, Any]] = {}
        self.audit: list[dict[str, Any]] = []

    def request(self, *, tenant_id: str, action: str, target: dict[str, Any], requested_by: str,
                idempotency_key: str, reason: str, at: str) -> tuple[dict[str, Any], bool]:
        t = require_tenant(tenant_id)
        if action not in APPROVAL_ACTIONS:
            raise ValueError(f"action must be one of {APPROVAL_ACTIONS}")
        if not requested_by or not idempotency_key:
            raise ValueError("requested_by and idempotency_key are required")
        k = (t, hashlib.sha256(json.dumps([action, target, idempotency_key], sort_keys=True).encode()).hexdigest())
        if k in self._rows:
            self.audit.append({"at": at, "tenant_id": t, "event": "IDEMPOTENT_REPLAY", "request_id": self._rows[k]["request_id"]})
            return dict(self._rows[k]), False
        row = {"request_id": f"apr_{k[1][:20]}", "tenant_id": t, "action": action, "target": dict(target),
               "state": "APPROVAL_REQUESTED", "state_history": [{"state": "APPROVAL_REQUESTED", "at": at,
                                                                  "by": requested_by, "source": "e3"}],
               "requested_by": requested_by, "reason": reason, "requested_at": at, "executed": False,
               "statement": "Approval requested only. Nothing was sent to the endpoint; "
                            "ACCEPTED/EXECUTED/CONTAINED/VERIFIED are owned by E1."}
        self._rows[k] = row
        self.audit.append({"at": at, "tenant_id": t, "event": "APPROVAL_REQUESTED", "request_id": row["request_id"],
                           "by": requested_by, "action": action})
        return dict(row), True

    def list(self, tenant_id: str) -> builtins.list[dict[str, Any]]:
        t = require_tenant(tenant_id)
        return [dict(r) for r in self._rows.values() if r["tenant_id"] == t]


def pivot(kind: str, value: str) -> dict[str, Any]:
    if kind not in PIVOTS:
        raise ValueError(f"pivot must be one of {PIVOTS}")
    targets = {"COPY_HASH": {"clipboard": value}, "SEARCH_HASH": {"route": f"/edr/search?sha256={value}"},
               "SEARCH_FILENAME": {"route": f"/edr/search?filename={value}"},
               "OPEN_FILE_TRAJECTORY": {"route": f"/edr/file-trajectory?sha256={value}"}}
    return {"pivot": kind, "value": value, "read_only": True, "approval_required": False, **targets[kind]}
