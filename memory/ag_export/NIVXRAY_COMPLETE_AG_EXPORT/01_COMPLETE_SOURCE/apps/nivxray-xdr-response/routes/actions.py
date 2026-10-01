"""Action-registry catalogue route.

Exposes every canonical action with its ``adapter_status`` so the
frontend can distinguish AVAILABLE / NOT_CONNECTED / NOT_IMPLEMENTED /
NOT_AUTHORIZED before the analyst tries to run it.  Phase 1 ships
every action wired to a deterministic stub adapter, so status is
``AVAILABLE`` (with a ``simulation_only`` flag) — this prevents the UI
from claiming a vendor is connected when only the engine boundary is.
"""
from fastapi import APIRouter, Request

router = APIRouter(tags=["actions"])


@router.get("/actions")
def list_actions(request: Request):
    rows = []
    for spec in request.app.state.registry.list():
        rows.append({
            "action_id":            spec.action_id,
            "provider":             spec.provider,
            "capability":           spec.capability,
            "label":                spec.label,
            "parameters":           spec.parameters,
            "required_permissions": spec.required_permissions,
            "approval_required":    spec.approval_required,
            "reversible":           spec.reversible,
            "destructive":          spec.destructive,
            # ── adapter status honesty ─
            # Phase 1: every action is wired to a deterministic STUB adapter.
            # The engine + evidence forwarder + state machine + approval
            # workflow are all real; only the vendor call is stubbed.
            # Phase C wires real CrowdStrike / Defender / SentinelOne
            # adapters and flips these to AVAILABLE without renaming.
            "adapter_status":       "AVAILABLE",
            "simulation_only":      True,
            "note":                 "adapter is a deterministic Phase-1 stub; "
                                        "real vendor calls land in Phase C",
        })
    return {"actions": rows, "count": len(rows),
             "phase":  "integration",
             "engine_version": "0.2.0-integration"}
