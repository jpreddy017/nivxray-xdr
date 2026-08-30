"""Action-registry catalogue route."""
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
            "execution_status":     "wired_stub",     # engine ready · stub adapter
        })
    return {"actions": rows, "count": len(rows), "phase": "1"}
