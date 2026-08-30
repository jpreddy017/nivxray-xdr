"""
Executor · Phase 1.

Single execution pipeline:

    validate → authorize → approval-check → target-resolve →
    idempotency-lookup → run adapter → forward evidence →
    finalise → return response

The invariant: an execution MUST NOT be reported `succeeded` unless:
  1. the adapter returned ok=True
  2. the forwarder produced evidence/audit/timeline refs

If forwarding failed, status is `failed` — even if the adapter
succeeded — because the evidence chain is broken.  Operators can
investigate via /executions/{id} and re-run.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing   import Any, Dict, Optional

from framework.forwarder   import EvidenceForwarder
from framework.idempotency import (
    IdempotencyStore,
    STATUS_SUCCEEDED, STATUS_FAILED, STATUS_IN_PROGRESS, STATUS_REJECTED,
)
from framework.registry    import ActionRegistry, ActionSpec


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
                    idempotency: IdempotencyStore,
                    forwarder: EvidenceForwarder) -> None:
        self.registry    = registry
        self.idempotency = idempotency
        self.forwarder   = forwarder

    # ── target resolution ────────────────────────────────────
    def resolve_target(self, action: ActionSpec, params: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 1: shape validation only.  Phase 2 will call the base
        Asset/Identity graph over the same evidence contract."""
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

    # ── authorization ────────────────────────────────────────
    def authorize(self, action: ActionSpec, authz: Dict[str, Any],
                     invoker: Dict[str, Any]) -> None:
        # Phase 1: check `authz.scopes` (list) covers every required scope.
        # Real deployments will validate the bearer token upstream and
        # inject the resolved scopes here.
        scopes = set(authz.get("scopes") or [])
        need   = {(p["role"], p["scope"]) for p in action.required_permissions}
        missing = [f"{r}:{s}" for (r, s) in need
                        if f"{r}:{s}" not in scopes and s not in scopes]
        if missing:
            raise ExecutorError(403, "authorization_failed",
                                      {"missing_scopes": missing,
                                        "invoker": invoker})
        # Approval gate
        if action.approval_required:
            approval_ref = authz.get("approval_ref")
            approved_by  = authz.get("approved_by")
            if not approval_ref or not approved_by:
                raise ExecutorError(403, "approval_required",
                                          {"action_id": action.action_id,
                                            "detail":    "authorization.approval_ref + approved_by required"})

    # ── param validation ─────────────────────────────────────
    def validate_params(self, action: ActionSpec, params: Dict[str, Any]) -> None:
        for p in action.parameters:
            if p.get("required") and (p["key"] not in params
                                            or params[p["key"]] in (None, "")):
                raise ExecutorError(422, "missing_parameter",
                                          {"key": p["key"]})

    # ── main entrypoint ──────────────────────────────────────
    async def execute(self, req: Dict[str, Any]) -> Dict[str, Any]:
        # 1. structural validation
        for field in ("execution_id", "tenant_id", "invoker", "action"):
            if not req.get(field):
                raise ExecutorError(400, "malformed_request",
                                          {"missing_field": field})
        invoker = req["invoker"]
        action_req = req["action"]
        for f in ("kind", "id"):
            if not invoker.get(f):
                raise ExecutorError(400, "malformed_request",
                                          {"missing_field": f"invoker.{f}"})
        action_id = action_req.get("action_id")
        if not action_id:
            raise ExecutorError(400, "malformed_request",
                                      {"missing_field": "action.action_id"})

        spec = self.registry.get(action_id)
        if not spec:
            raise ExecutorError(422, "unknown_action",
                                      {"action_id": action_id})

        tenant       = req["tenant_id"]
        exec_id      = req["execution_id"]
        params       = action_req.get("parameters") or {}
        authz        = req.get("authorization") or {}
        constraints  = req.get("constraints") or {}
        dry_run      = bool(constraints.get("dry_run"))

        # 2. idempotency lookup — return prior result verbatim
        prior = self.idempotency.find(tenant, invoker["kind"],
                                            invoker["id"], exec_id)
        if prior:
            return {**prior["response"], "idempotent_replay": True}

        # 3. authorize + validate params + resolve target
        try:
            self.authorize(spec, authz, invoker)
            self.validate_params(spec, params)
            canonical = self.resolve_target(spec, params)
        except ExecutorError as e:
            return await self._finalise_error(req, spec, e)

        # 4. record in-progress
        started_at = _iso()
        stub_response = {"execution_id": exec_id, "status": STATUS_IN_PROGRESS,
                            "started_at": started_at}
        self.idempotency.record_in_progress(tenant, invoker["kind"],
                                                  invoker["id"], exec_id,
                                                  action_id, stub_response)

        # 5. run adapter (or short-circuit for dry-run)
        try:
            if dry_run:
                adapter_out = {"ok": True,
                                  "result": {"dry_run": True, "params": params},
                                  "reversal_id": None}
            else:
                adapter_out = await spec.adapter(params,
                                                       {"invoker": invoker,
                                                         "tenant_id": tenant,
                                                         "canonical": canonical})
        except Exception as e:                                  # noqa: BLE001
            adapter_out = {"ok": False,
                              "error": f"{type(e).__name__}: {e}"}

        # 6. forward evidence — MANDATORY
        completed_at = _iso()
        envelope = {
            "execution_id":     exec_id,
            "tenant_id":        tenant,
            "invoker":          invoker,
            "action":           {"action_id": action_id,
                                   "provider":  spec.provider,
                                   "capability": spec.capability},
            "parameters":       params,
            "canonical_target": canonical,
            "adapter_result":   adapter_out.get("result"),
            "adapter_ok":       adapter_out.get("ok", False),
            "started_at":       started_at,
            "completed_at":     completed_at,
            "dry_run":          dry_run,
            "authorization":    {"approved_by":  authz.get("approved_by"),
                                   "approval_ref": authz.get("approval_ref"),
                                   "reason":       authz.get("reason")},
        }
        forward = await self.forwarder.forward(envelope)

        # 7. final status
        adapter_ok = adapter_out.get("ok", False)
        forward_ok = forward.get("forwarding_state") in ("forwarded", "not_wired")
        if adapter_ok and forward_ok:
            status = STATUS_SUCCEEDED
            err    = None
        else:
            status = STATUS_FAILED
            if not adapter_ok:
                err = adapter_out.get("error") or "adapter_failed"
            else:
                err = f"evidence_forwarding_failed: {forward.get('reason')}"

        response = {
            "execution_id":  exec_id,
            "status":        status,
            "started_at":    started_at,
            "completed_at":  completed_at,
            "duration_ms":   _duration_ms(started_at, completed_at),
            "result":        adapter_out.get("result"),
            "evidence_ref":  forward.get("evidence_ref"),
            "audit_ref":     forward.get("audit_ref"),
            "timeline_ref":  forward.get("timeline_ref"),
            "forwarding_state": forward.get("forwarding_state"),
            "reversal": {
                "reversible":  bool(spec.reversible) and adapter_ok,
                "reversal_id": adapter_out.get("reversal_id"),
                "expires_at":  None,
            },
            "error":         err,
            "invoker":       invoker,
            "action_id":     action_id,
            "dry_run":       dry_run,
        }
        self.idempotency.finalise(tenant, invoker["kind"], invoker["id"],
                                        exec_id, status, response)
        return response

    async def _finalise_error(self, req: Dict[str, Any],
                                    spec: ActionSpec,
                                    err: ExecutorError) -> Dict[str, Any]:
        # Persist the rejection so a re-POST returns the same verdict.
        now = _iso()
        response = {
            "execution_id":  req["execution_id"],
            "status":        STATUS_REJECTED,
            "started_at":    now, "completed_at": now, "duration_ms": 0,
            "result":        None,
            "evidence_ref":  None, "audit_ref": None, "timeline_ref": None,
            "forwarding_state": "not_attempted",
            "reversal":      {"reversible": False, "reversal_id": None},
            "error":         err.error,
            "detail":        err.detail,
            "invoker":       req["invoker"],
            "action_id":     req["action"].get("action_id"),
            "dry_run":       bool((req.get("constraints") or {}).get("dry_run")),
        }
        try:
            self.idempotency.record_in_progress(
                req["tenant_id"], req["invoker"]["kind"], req["invoker"]["id"],
                req["execution_id"], spec.action_id, response)
            self.idempotency.finalise(
                req["tenant_id"], req["invoker"]["kind"], req["invoker"]["id"],
                req["execution_id"], STATUS_REJECTED, response)
        except Exception:                                       # noqa: BLE001
            pass
        # Re-raise so the route returns the right HTTP code.
        raise err


def _duration_ms(a: str, b: str) -> int:
    try:
        da = datetime.fromisoformat(a.replace("Z", "+00:00"))
        db = datetime.fromisoformat(b.replace("Z", "+00:00"))
        return int((db - da).total_seconds() * 1000)
    except Exception:                                           # noqa: BLE001
        return 0
