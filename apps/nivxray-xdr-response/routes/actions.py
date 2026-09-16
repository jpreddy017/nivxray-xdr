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
            # ── dispatch honesty ─
            # REAL_PRODUCT_API    → handed to the authoritative source
            #   product, which owns execution AND verification. Nothing
            #   here claims either.
            # STUB_NO_SIDE_EFFECT → the engine lifecycle runs but NO
            #   control action leaves this service, so it can never read
            #   as executed or verified.
            "dispatch_mode":        spec.dispatch_mode,
            "adapter_status":       ("AVAILABLE"
                                     if spec.dispatch_mode == "REAL_PRODUCT_API"
                                     else "NOT_CONNECTED"),
            "simulation_only":      spec.dispatch_mode != "REAL_PRODUCT_API",
            "authoritative_for_execution": ("nivxforge-edr"
                                            if spec.dispatch_mode == "REAL_PRODUCT_API"
                                            else None),
            "note":                 ("dispatched to NivXForge EDR, which owns "
                                     "endpoint execution and verification"
                                     if spec.dispatch_mode == "REAL_PRODUCT_API"
                                     else "no product adapter — engine "
                                          "lifecycle only; nothing is executed"),
        })
    real = sum(1 for r in rows if r["dispatch_mode"] == "REAL_PRODUCT_API")
    return {"actions": rows, "count": len(rows),
             "real_product_api":     real,
             "stub_no_side_effect":  len(rows) - real,
             "phase":  "integration",
             "engine_version": "0.2.0-integration"}
