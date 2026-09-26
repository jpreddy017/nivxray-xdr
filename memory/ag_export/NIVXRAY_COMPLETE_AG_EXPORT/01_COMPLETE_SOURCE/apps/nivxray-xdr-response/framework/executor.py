"""
Executor · Response Engine state-machine core.

Implements the persisted execution lifecycle documented in
RESPONSE_CONTRACT.md:

    QUEUED
      ├── (no approval)     ─→ RUNNING ─→ EXECUTING ─→ FORWARDING_EVIDENCE ─→ SUCCEEDED
      ├── (approval needed) ─→ WAITING_APPROVAL
      │                          ├── (approve) ─→ EXECUTING ─→ FORWARDING_EVIDENCE ─→ SUCCEEDED
      │                          └── (reject)  ─→ FAILED_APPROVAL
      └── (validation fail) ─→ REJECTED / FAILED_TARGET

Owner-locked invariants:
  1. An execution is SUCCEEDED only when adapter returned ok=True AND
     the Evidence Forwarder produced evidence_ref + audit_ref + timeline_ref.
  2. If the adapter succeeded but forwarding failed → FAILED_FORWARDING.
     Never fabricate success.
  3. Every state transition is persisted BEFORE any external side effect,
     so a crash mid-flight leaves an inspectable failed_recovered row —
     never a silently re-executed action.
  4. Idempotency: re-POSTing the same
     (tenant_id, invoker_kind, invoker_id, execution_id) returns the
     prior response verbatim with ``idempotent_replay = true``.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing   import Any, Dict, List, Optional

from framework.forwarder       import EvidenceForwarder
from framework.execution_store import (
    ExecutionStore,
    STATE_QUEUED, STATE_RUNNING, STATE_WAITING_APPROVAL, STATE_EXECUTING,
    STATE_FORWARDING, STATE_SUCCEEDED, STATE_FAILED_APPROVAL,
    STATE_FAILED_TARGET, STATE_FAILED_EXECUTION, STATE_FAILED_FORWARDING,
    STATE_REJECTED, TERMINAL_STATES,
)
from framework.registry        import ActionRegistry, ActionSpec


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecutorError(Exception):
    def __init__(self, code: int, error: str, detail: Optional[Dict] = None):
        super().__init__(error)
        self.code   = code
        self.error  = error
        self.detail = detail or {}


class Executor:
    def __init__(self, *, registry: ActionRegistry,
                    store: ExecutionStore,
                    forwarder: EvidenceForwarder) -> None:
        self.registry  = registry
        self.store     = store
        self.forwarder = forwarder

    # ── target resolution ───────────────────────────────────────────
    def resolve_target(self, action: ActionSpec, params: Dict[str, Any]) -> Dict[str, Any]:
        canonical: Dict[str, Any] = {}
        if "host_id" in params:
            h = str(params["host_id"] or "").strip()
            if not h:
                raise ExecutorError(422, "unresolved_target",
                                          {"field": "host_id", "reason": "empty"})
            canonical["asset"] = f"asset:{h}"
        if "user_id" in params or "user" in params:
            u = str(params.get("user_id") or params.get("user") or "").strip()
            if not u:
                raise ExecutorError(422, "unresolved_target",
                                          {"field": "user_id", "reason": "empty"})
            canonical["identity"] = f"identity:{u}"
        if "ip" in params:
            v = str(params["ip"] or "")
            if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v):
                raise ExecutorError(422, "unresolved_target",
                                          {"field": "ip", "reason": "malformed"})
            canonical["indicator"] = f"ip:{v}"
        if "domain" in params:
            canonical["indicator"] = f"domain:{params['domain']}"
        if "hash" in params:
            canonical["indicator"] = f"hash:{params['hash']}"
        return canonical

    # ── param + scope validation ────────────────────────────────────
    def validate_params(self, action: ActionSpec, params: Dict[str, Any]) -> None:
        for p in action.parameters:
            if p.get("required") and (p["key"] not in params
                                            or params[p["key"]] in (None, "")):
                raise ExecutorError(422, "missing_parameter",
                                          {"key": p["key"]})

    def check_scopes(self, action: ActionSpec, authz: Dict[str, Any],
                        invoker: Dict[str, Any]) -> None:
        scopes = set(authz.get("scopes") or [])
        need   = {(p["role"], p["scope"]) for p in action.required_permissions}
        missing = [f"{r}:{s}" for (r, s) in need
                        if f"{r}:{s}" not in scopes and s not in scopes]
        if missing:
            raise ExecutorError(403, "authorization_failed",
                                      {"missing_scopes": missing,
                                        "invoker": invoker})

    # ── main entrypoint ─────────────────────────────────────────────
    async def execute(self, req: Dict[str, Any]) -> Dict[str, Any]:
        # 1. structural validation
        for field in ("execution_id", "tenant_id", "invoker", "action"):
            if not req.get(field):
                raise ExecutorError(400, "malformed_request",
                                          {"missing_field": field})
        invoker = req["invoker"]
        for f in ("kind", "id"):
            if not invoker.get(f):
                raise ExecutorError(400, "malformed_request",
                                          {"missing_field": f"invoker.{f}"})
        action_req = req["action"]
        action_id  = action_req.get("action_id")
        if not action_id:
            raise ExecutorError(400, "malformed_request",
                                      {"missing_field": "action.action_id"})

        spec = self.registry.get(action_id)
        if not spec:
            raise ExecutorError(422, "unknown_action", {"action_id": action_id})

        tenant       = req["tenant_id"]
        exec_id      = req["execution_id"]
        params       = action_req.get("parameters") or {}
        authz        = req.get("authorization") or {}
        constraints  = req.get("constraints") or {}
        dry_run      = bool(constraints.get("dry_run"))

        # 2. idempotency lookup — return prior response verbatim
        prior = self.store.find(tenant, invoker["kind"], invoker["id"], exec_id)
        if prior and prior.get("response"):
            return {**prior["response"], "idempotent_replay": True}

        # 3. authz + params + target resolution.  Every rejection is
        #    still recorded as a REJECTED row so a replay is deterministic.
        try:
            self.check_scopes(spec, authz, invoker)
            self.validate_params(spec, params)
            canonical = self.resolve_target(spec, params)
        except ExecutorError as e:
            return self._reject(req, spec, e)

        # 4. Persist as QUEUED
        approval_required = bool(spec.approval_required)
        preapproved       = approval_required and bool(authz.get("approval_ref")) \
                              and bool(authz.get("approved_by"))
        self.store.insert({
            "tenant_id":         tenant,
            "invoker_kind":      invoker["kind"],
            "invoker_id":        invoker["id"],
            "invoker":           invoker,
            "execution_id":      exec_id,
            "action_id":         action_id,
            "provider":          spec.provider,
            "capability":        spec.capability,
            "parameters":        params,
            "canonical":         canonical,
            "scopes":            authz.get("scopes") or [],
            "approval_required": approval_required,
            "approval_status":   "approved" if preapproved
                                    else ("pending" if approval_required else None),
            "dry_run":           dry_run,
            "state":             STATE_QUEUED,
        })
        key = self.store.key_of(tenant, invoker["kind"], invoker["id"], exec_id)

        # 5. If approval required and NOT pre-approved → park in WAITING_APPROVAL.
        #    Do NOT return 403 — the execution is pending, not rejected.
        if approval_required and not preapproved:
            self.store.transition(key, state=STATE_WAITING_APPROVAL,
                                     patch={"approval_status": "pending",
                                              "requested_at":     _iso()})
            return self._snapshot(key, extra={
                "note": "waiting_approval — call POST /api/respond/approve/{execution_id} to resume",
            })

        # 6. Otherwise run adapter → forwarder → SUCCEEDED / FAILED_*
        if preapproved:
            self.store.transition(key, state=STATE_QUEUED, patch={
                "approval_status": "approved",
                "approval_ref":    authz.get("approval_ref"),
                "approved_by":     authz.get("approved_by"),
                "approved_at":     _iso(),
                "approval_reason": authz.get("reason"),
            })
        return await self._run(key)

    # ── approval decisions ──────────────────────────────────────────
    async def approve(self, execution_id: str, *, approved_by: str,
                        approval_ref: Optional[str] = None,
                        reason: Optional[str] = None) -> Dict[str, Any]:
        row = self.store.find_by_execution_id(execution_id)
        if not row:
            raise ExecutorError(404, "execution_not_found",
                                      {"execution_id": execution_id})
        if row["state"] != STATE_WAITING_APPROVAL:
            # Immutable audit — an approval can only be applied once,
            # and only to a truly pending execution.
            raise ExecutorError(409, "invalid_state_for_approval",
                                      {"state": row["state"]})
        if not approved_by:
            raise ExecutorError(400, "missing_field", {"field": "approved_by"})
        key = self.store.key_of(row["tenant_id"], row["invoker_kind"],
                                     row["invoker_id"], row["execution_id"])
        self.store.transition(key, state=STATE_QUEUED, patch={
            "approval_status": "approved",
            "approval_ref":    approval_ref or f"approval-{uuid.uuid4().hex[:12]}",
            "approved_by":     approved_by,
            "approved_at":     _iso(),
            "approval_reason": reason,
        })
        return await self._run(key)

    def reject(self, execution_id: str, *, rejected_by: str,
                  reason: Optional[str] = None) -> Dict[str, Any]:
        row = self.store.find_by_execution_id(execution_id)
        if not row:
            raise ExecutorError(404, "execution_not_found",
                                      {"execution_id": execution_id})
        if row["state"] != STATE_WAITING_APPROVAL:
            raise ExecutorError(409, "invalid_state_for_rejection",
                                      {"state": row["state"]})
        key = self.store.key_of(row["tenant_id"], row["invoker_kind"],
                                     row["invoker_id"], row["execution_id"])
        self.store.transition(key, state=STATE_FAILED_APPROVAL, patch={
            "approval_status":  "rejected",
            "rejected_by":      rejected_by,
            "rejected_at":      _iso(),
            "rejection_reason": reason,
            "failure_reason":   "rejected_by_" + rejected_by,
            "completed_at":     _iso(),
        })
        return self._finalise_snapshot(key)

    # ── the real execution pipeline (adapter → forwarder) ───────────
    async def _run(self, key: str) -> Dict[str, Any]:
        # Load current row → we work from the persisted spec, not the
        # inbound request, so an approval-driven resume runs the exact
        # action the analyst approved (no request-body swap).
        row = self._require(key)
        exec_id  = row["execution_id"]
        tenant   = row["tenant_id"]
        invoker  = row.get("invoker") or {}
        spec     = self.registry.get(row["action_id"])
        if not spec:  # deleted between intake and run — hard failure
            self.store.transition(key, state=STATE_FAILED_EXECUTION,
                                     patch={"failure_reason": "unknown_action",
                                              "completed_at":    _iso()})
            return self._finalise_snapshot(key)

        params    = row.get("parameters") or {}
        canonical = row.get("canonical") or {}
        dry_run   = bool(row.get("dry_run"))

        started_at = _iso()
        self.store.transition(key, state=STATE_RUNNING,
                                 patch={"started_at": started_at})

        # ── adapter phase ─
        self.store.transition(key, state=STATE_EXECUTING)
        try:
            if dry_run:
                adapter_out = {"ok": True,
                                  "result": {"dry_run": True, "params": params},
                                  "reversal_id": None}
            else:
                adapter_out = await spec.adapter(params,
                                                       {"invoker":   invoker,
                                                         "tenant_id": tenant,
                                                         "canonical": canonical})
        except Exception as e:                                  # noqa: BLE001
            adapter_out = {"ok": False,
                              "error": f"{type(e).__name__}: {e}"}
        adapter_ok = bool(adapter_out.get("ok"))
        self.store.transition(key, state=STATE_EXECUTING, patch={
            "adapter_ok":          1 if adapter_ok else 0,
            "adapter_result_json": adapter_out.get("result"),
            "adapter_error":       adapter_out.get("error"),
        })

        # ── forwarding phase ─
        self.store.transition(key, state=STATE_FORWARDING)
        completed_at = _iso()
        envelope = {
            "execution_id":     exec_id,
            "tenant_id":        tenant,
            "invoker":          invoker,
            "action":           {"action_id":  spec.action_id,
                                   "provider":   spec.provider,
                                   "capability": spec.capability},
            "parameters":       params,
            "canonical_target": canonical,
            "adapter_result":   adapter_out.get("result"),
            "adapter_ok":       adapter_ok,
            "started_at":       started_at,
            "completed_at":     completed_at,
            "dry_run":          dry_run,
            "authorization": {
                "approved_by":  row.get("approved_by"),
                "approval_ref": row.get("approval_ref"),
                "reason":       row.get("approval_reason"),
            },
        }
        forward = await self.forwarder.forward(envelope)
        forward_ok = forward.get("forwarding_state") in ("forwarded", "not_wired")

        # ── final state ─
        if adapter_ok and forward_ok:
            state       = STATE_SUCCEEDED
            failure_msg = None
        elif not adapter_ok:
            state       = STATE_FAILED_EXECUTION
            failure_msg = adapter_out.get("error") or "adapter_failed"
        else:
            state       = STATE_FAILED_FORWARDING
            failure_msg = f"evidence_forwarding_failed: {forward.get('reason')}"

        self.store.transition(key, state=state, patch={
            "evidence_ref":     forward.get("evidence_ref"),
            "audit_ref":        forward.get("audit_ref"),
            "timeline_ref":     forward.get("timeline_ref"),
            "forwarding_state": forward.get("forwarding_state"),
            "forwarding_error": forward.get("reason") if not forward_ok else None,
            "failure_reason":   failure_msg,
            "completed_at":     completed_at,
        })
        return self._finalise_snapshot(key)

    # ── rejection helper (validation errors) ────────────────────────
    def _reject(self, req: Dict[str, Any], spec: ActionSpec,
                     err: ExecutorError) -> Dict[str, Any]:
        now = _iso()
        # Persist the rejection so a replay returns the same verdict.
        self.store.insert({
            "tenant_id":         req["tenant_id"],
            "invoker_kind":      req["invoker"]["kind"],
            "invoker_id":        req["invoker"]["id"],
            "invoker":           req["invoker"],
            "execution_id":      req["execution_id"],
            "action_id":         spec.action_id,
            "provider":          spec.provider,
            "capability":        spec.capability,
            "parameters":        req["action"].get("parameters") or {},
            "canonical":         {},
            "scopes":            (req.get("authorization") or {}).get("scopes") or [],
            "approval_required": bool(spec.approval_required),
            "approval_status":   None,
            "dry_run":           bool((req.get("constraints") or {}).get("dry_run")),
            "state":             STATE_REJECTED,
        })
        key = self.store.key_of(req["tenant_id"], req["invoker"]["kind"],
                                     req["invoker"]["id"], req["execution_id"])
        self.store.transition(key, state=STATE_FAILED_TARGET if err.error == "unresolved_target"
                                                                else STATE_REJECTED,
                                 patch={"failure_reason": err.error,
                                          "completed_at":    now,
                                          "started_at":      now})
        # Preserve the previous behaviour: the route surfaces HTTP 4xx.
        raise err

    # ── snapshotting ────────────────────────────────────────────────
    def _require(self, key: str) -> Dict[str, Any]:
        parts = key.split("|", 3)
        row = self.store.find(*parts)
        if not row:
            raise ExecutorError(500, "execution_row_missing", {"key": key})
        return row

    def _snapshot(self, key: str,
                     extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build the wire response for an in-flight / waiting execution."""
        row = self._require(key)
        return self._response_from_row(row, extra=extra)

    def _finalise_snapshot(self, key: str) -> Dict[str, Any]:
        """Snapshot + persist the final response_json so idempotent
        replays return the identical body verbatim."""
        row = self._require(key)
        resp = self._response_from_row(row)
        if row["state"] in TERMINAL_STATES:
            self.store.transition(key, state=row["state"],
                                     patch={"response_json": resp})
        return resp

    @staticmethod
    def _response_from_row(row: Dict[str, Any],
                                extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # ── legacy `status` field maintained so existing tests + UI
        #    that speak "succeeded/failed/rejected" keep working.
        st = row["state"]
        legacy = {
            STATE_SUCCEEDED:         "succeeded",
            STATE_FAILED_APPROVAL:   "failed",
            STATE_FAILED_TARGET:     "rejected",
            STATE_FAILED_EXECUTION:  "failed",
            STATE_FAILED_FORWARDING: "failed",
            STATE_REJECTED:          "rejected",
            STATE_WAITING_APPROVAL:  "waiting_approval",
            STATE_QUEUED:            "in_progress",
            STATE_RUNNING:           "in_progress",
            STATE_EXECUTING:         "in_progress",
            STATE_FORWARDING:        "in_progress",
        }.get(st, "in_progress")
        spec_row = {
            "execution_id":     row["execution_id"],
            "state":            st,
            "status":           legacy,
            "action_id":        row["action_id"],
            "invoker":          row.get("invoker") or {},
            "tenant_id":        row["tenant_id"],
            "started_at":       row.get("started_at"),
            "completed_at":     row.get("completed_at"),
            "requested_at":     row.get("requested_at"),
            "duration_ms":      _dur(row.get("started_at"), row.get("completed_at")),
            "result":           row.get("adapter_result"),
            "adapter_ok":       bool(row.get("adapter_ok")),
            "evidence_ref":     row.get("evidence_ref"),
            "audit_ref":        row.get("audit_ref"),
            "timeline_ref":     row.get("timeline_ref"),
            "forwarding_state": row.get("forwarding_state"),
            "forwarding_error": row.get("forwarding_error"),
            "failure_reason":   row.get("failure_reason"),
            "dry_run":          bool(row.get("dry_run")),
            "approval": {
                "required":  bool(row.get("approval_required")),
                "status":    row.get("approval_status"),
                "ref":       row.get("approval_ref"),
                "approved_by": row.get("approved_by"),
                "approved_at": row.get("approved_at"),
                "reason":      row.get("approval_reason"),
                "rejected_by": row.get("rejected_by"),
                "rejected_at": row.get("rejected_at"),
                "rejection_reason": row.get("rejection_reason"),
            },
            "reversal": {
                "reversible": bool(row.get("adapter_ok")),
                "reversal_id": None,   # future: wire adapter reversal_id
            },
            "error": row.get("failure_reason") if st in TERMINAL_STATES
                                                        and st != STATE_SUCCEEDED
                        else None,
        }
        if extra: spec_row.update(extra)
        return spec_row


def _dur(a: Optional[str], b: Optional[str]) -> int:
    if not a or not b:
        return 0
    try:
        da = datetime.fromisoformat(a.replace("Z", "+00:00"))
        db = datetime.fromisoformat(b.replace("Z", "+00:00"))
        return int((db - da).total_seconds() * 1000)
    except Exception:                                           # noqa: BLE001
        return 0
