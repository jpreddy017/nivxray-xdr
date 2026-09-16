"""Execute route + simulate-playbook trace route."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi  import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from framework.executor import Executor, ExecutorError


router = APIRouter(tags=["execute"])


class ExecuteRequest(BaseModel):
    execution_id:  str
    tenant_id:     str
    invoker:       Dict[str, Any]
    action:        Dict[str, Any]
    authorization: Dict[str, Any] = Field(default_factory=dict)
    constraints:   Dict[str, Any] = Field(default_factory=dict)


@router.post("/execute")
async def execute(req: ExecuteRequest, request: Request):
    ex: Executor = request.app.state.executor
    try:
        return await ex.execute(req.model_dump())
    except ExecutorError as e:
        detail = {"error": e.error, **e.detail}
        raise HTTPException(status_code=e.code, detail=detail)


# ── Playbook end-to-end simulator ──────────────────────────────
class PlaybookNode(BaseModel):
    id:        str
    kind:      str
    action_id: Optional[str] = None
    config:    Dict[str, Any] = Field(default_factory=dict)
    next:      Optional[str] = None
    yes_next:  Optional[str] = None
    no_next:   Optional[str] = None


class SimulatePlaybookRequest(BaseModel):
    playbook_id: str
    tenant_id:   str = "simulate"
    entry:       str
    nodes:       List[PlaybookNode]
    event:       Dict[str, Any] = Field(default_factory=dict)
    invoker:     Dict[str, Any] = Field(default_factory=lambda: {
        "kind": "simulator", "id": "playbook-simulator", "context": {}})


@router.post("/simulate-playbook")
async def simulate_playbook(req: SimulatePlaybookRequest, request: Request):
    """Executes a whole playbook end-to-end through the same executor,
    with `constraints.dry_run = True` on every action.  Returns a
    trace [{ node_id, kind, status, elapsed_ms, result?, branch? }]
    the frontend renders as an animated walkthrough.  Never calls a
    real vendor SDK — dry_run short-circuits every adapter."""
    ex: Executor = request.app.state.executor
    by_id = {n.id: n for n in req.nodes}
    trace: List[Dict[str, Any]] = []
    cur = by_id.get(req.entry)
    seen: set[str] = set()
    step = 0

    while cur and cur.id not in seen and step < 200:
        seen.add(cur.id)
        step += 1
        entry: Dict[str, Any] = {"step": step, "node_id": cur.id, "kind": cur.kind}
        if cur.kind == "start":
            entry.update({"status": "ok"})
            trace.append(entry); cur = by_id.get(cur.next or ""); continue
        if cur.kind == "end":
            entry.update({"status": "ok", "terminal": True})
            trace.append(entry); break
        if cur.kind == "condition":
            branch = _evaluate_condition(cur.config or {}, req.event)
            nxt_id = cur.yes_next if branch else cur.no_next
            entry.update({"status": "evaluated", "branch": "yes" if branch else "no",
                            "config": cur.config})
            trace.append(entry); cur = by_id.get(nxt_id or ""); continue
        if cur.kind == "action":
            # Build an ExecuteRequest dry-run and pipe through the executor.
            action_req = {
                "execution_id": f"sim-{req.playbook_id}-{cur.id}-{step}",
                "tenant_id":    req.tenant_id,
                "invoker": {**req.invoker,
                              "context": {**(req.invoker.get("context") or {}),
                                          "playbook_id":     req.playbook_id,
                                          "playbook_node_id": cur.id}},
                "action": {"action_id":  cur.action_id or "",
                             "parameters": (cur.config or {}).get("parameters") or {}},
                "authorization": {
                    "scopes": _all_scopes_from_registry(request),
                    "approval_ref": "sim-approval",
                    "approved_by":  "user:simulator",
                    "reason":       "Simulator auto-approval — no side effects",
                },
                "constraints":   {"dry_run": True},
            }
            try:
                result = await ex.execute(action_req)
                entry.update({"status":     result.get("status"),
                                "action_id":  cur.action_id,
                                "duration_ms": result.get("duration_ms"),
                                "result":     result.get("result"),
                                "forwarding_state": result.get("forwarding_state")})
            except ExecutorError as e:
                entry.update({"status": "rejected", "error": e.error, "detail": e.detail,
                                "action_id": cur.action_id})
            trace.append(entry)
            cur = by_id.get(cur.next or "")
            continue
        # unknown kind
        entry.update({"status": "skipped", "reason": "unknown_kind"})
        trace.append(entry)
        cur = by_id.get(cur.next or "")

    return {
        "mode":       "simulation",
        "note":       "All adapters run in dry_run · no side effects.  "
                        "Live execution requires POST /api/respond/execute.",
        "playbook_id": req.playbook_id,
        "steps":       len(trace),
        "trace":       trace,
    }


def _evaluate_condition(cfg: Dict[str, Any], event: Dict[str, Any]) -> bool:
    field, op, value = cfg.get("field"), cfg.get("op", "eq"), cfg.get("value")
    v = event.get(field) if field else None
    try:
        if op == "eq":       return str(v) == str(value)
        if op == "neq":      return str(v) != str(value)
        if op == "gt":       return float(v) >  float(value)
        if op == "gte":      return float(v) >= float(value)
        if op == "lt":       return float(v) <  float(value)
        if op == "lte":      return float(v) <= float(value)
        if op == "contains": return str(value).lower() in str(v or "").lower()
    except Exception:                                           # noqa: BLE001
        return False
    return False


def _all_scopes_from_registry(request: Request) -> List[str]:
    """Simulator grants every scope declared by any action in the
    registry.  Live executions still enforce real scopes."""
    scopes: set[str] = set()
    for spec in request.app.state.registry.list():
        for p in spec.required_permissions:
            scopes.add(f"{p['role']}:{p['scope']}")
            scopes.add(p["scope"])
    return sorted(scopes)
