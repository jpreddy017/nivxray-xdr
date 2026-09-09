"""NivXForge EDR dispatch adapter — the REAL endpoint control path.

Ownership boundary, per the locked product architecture:

    NivXRay XDR            requests · approves · orchestrates · audits
    Response Engine        this service — dispatch decision + evidence
    NivXForge EDR          OWNS endpoint execution AND verification
    Endpoint               performs the action

So this adapter must NOT execute anything itself. It hands the approved
action to the authoritative EDR response API
(`POST /api/edr/response/actions`) and then reads the record back
(`GET /api/edr/response/actions/{command_id}`) to carry the EDR's own
state and `proof` verbatim.

Two rules it exists to enforce:

1. **Tenant identity is never asserted by this service.** The EDR API
   derives `tenant_id` from the authenticated principal's token, never
   from a request body, so the caller's bearer is passed through and the
   authoritative product performs the scoping. This service
   re-implements no authorization.

2. **`accepted` is not `executed`, and `executed` is not `verified`.**
   The adapter returns `ok` only for a real EDR acceptance, and reports
   the EDR's `state` (`REQUESTED` / `DISPATCHED` / `EXECUTED` /
   `VERIFIED` / `VERIFICATION_FAILED` / `FAILED`) plus its `proof` block
   untouched. It never upgrades a state and never synthesises one.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

# Response-Engine action_id → the authoritative EDR action verb.
EDR_ACTION_VERBS: Dict[str, str] = {
    "endpoint.isolate":       "ISOLATE_ENDPOINT",
    "endpoint.release":       "RELEASE_ISOLATION",
    "endpoint.kill_process":  "KILL_PROCESS",
}


def base_url() -> Optional[str]:
    return (os.environ.get("NIVX_BASE_URL") or "").rstrip("/") or None


def timeout() -> float:
    return float(os.environ.get("NIVX_EDR_DISPATCH_TIMEOUT", "30"))


def _bearer(ctx: Dict[str, Any]) -> Optional[str]:
    """The acting analyst's bearer, forwarded by the base backend.

    Absent it, the adapter refuses. It will not fall back to a service
    identity, because that would let the response plane act outside a
    real principal's tenant scope.
    """
    authz = (ctx or {}).get("authorization") or {}
    tok = authz.get("bearer") or (ctx or {}).get("bearer")
    return str(tok) if tok else None


async def dispatch(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Hand one approved action to NivXForge EDR. Never executes locally."""
    action_id = (ctx or {}).get("action_id") or ""
    verb = EDR_ACTION_VERBS.get(action_id)
    if not verb:
        return {"ok": False, "error": "no_edr_verb_for_action",
                "result": {"dispatch_mode": "REAL_PRODUCT_API",
                           "reason": f"{action_id} has no NivXForge EDR verb"}}

    url = base_url()
    if not url:
        return {"ok": False, "error": "edr_not_configured",
                "result": {"dispatch_mode": "REAL_PRODUCT_API",
                           "reason": "NIVX_BASE_URL is unset — the response "
                                     "plane has no endpoint product to dispatch "
                                     "to, so nothing was attempted"}}

    token = _bearer(ctx)
    if not token:
        return {"ok": False, "error": "no_acting_principal",
                "result": {"dispatch_mode": "REAL_PRODUCT_API",
                           "reason": "no acting principal was forwarded; the "
                                     "response plane will not act outside a "
                                     "real analyst's tenant scope"}}

    endpoint_id = (params.get("host_id")
                   or params.get("endpoint_id")
                   or (ctx.get("canonical") or {}).get("endpoint_id")
                   or str((ctx.get("canonical") or {}).get("asset") or "")
                       .replace("asset:", "") or None)
    if not endpoint_id:
        return {"ok": False, "error": "unresolved_target",
                "result": {"dispatch_mode": "REAL_PRODUCT_API",
                           "reason": "no endpoint_id resolved for dispatch"}}

    target: Dict[str, Any] = {}
    if verb == "KILL_PROCESS":
        # The EDR requires a real observed pid, not a bare integer we
        # invent here; it resolves the pid against real process evidence
        # and refuses TARGET_IDENTITY_UNPROVEN otherwise.
        for k in ("pid", "process_iid", "sha256", "path"):
            if params.get(k) is not None:
                target[k] = params[k]

    headers = {"Authorization": f"Bearer {token}"}
    body = {"endpoint_id": str(endpoint_id), "action": verb,
            "target": target,
            "reason": (ctx.get("reason")
                       or f"XDR response orchestration · execution "
                          f"{ctx.get('execution_id') or ''}".strip())}

    async with httpx.AsyncClient(timeout=timeout()) as cx:
        try:
            r = await cx.post(f"{url}/api/edr/response/actions",
                              json=body, headers=headers)
        except Exception as exc:                                # noqa: BLE001
            return {"ok": False, "error": f"edr_unreachable: {type(exc).__name__}",
                    "result": {"dispatch_mode": "REAL_PRODUCT_API",
                               "reason": "the endpoint product did not answer; "
                                         "the action is NOT dispatched"}}

        if r.status_code >= 400:
            detail = _json(r)
            return {"ok": False,
                    "error": f"edr_rejected_{r.status_code}",
                    "result": {"dispatch_mode": "REAL_PRODUCT_API",
                               "http_status": r.status_code,
                               "edr_detail": detail,
                               "reason": "NivXForge EDR refused the action — "
                                         "the refusal is the authoritative "
                                         "outcome and is not softened here"}}

        accepted = _json(r) or {}

    command_id = accepted.get("command_id") or accepted.get("id")
    readback = None
    if command_id:
        async with httpx.AsyncClient(timeout=timeout()) as cx:
            try:
                rb = await cx.get(
                    f"{url}/api/edr/response/actions/{command_id}",
                    headers=headers)
                if rb.status_code < 400:
                    readback = _json(rb)
            except Exception:                                   # noqa: BLE001
                readback = None

    authoritative = readback or accepted
    return {
        "ok": True,
        "result": {
            "dispatch_mode":        "REAL_PRODUCT_API",
            "dispatched_to":        "nivxforge-edr",
            "edr_command_id":       command_id,
            "edr_action":           verb,
            "edr_endpoint_id":      str(endpoint_id),
            "edr_tenant_id":        authoritative.get("tenant_id"),
            # The EDR's own lifecycle position and proof grade, verbatim.
            "edr_state":            authoritative.get("state"),
            "edr_proof":            authoritative.get("proof"),
            "edr_verification":     authoritative.get("verification"),
            "edr_requested_by":     authoritative.get("requested_by"),
            "honesty_note":         ("NivXForge EDR ACCEPTED and now owns this "
                                     "action. Acceptance is not execution and "
                                     "execution is not verification — read "
                                     "edr_state / edr_proof for the "
                                     "authoritative position."),
        },
        # An isolate is reversible via RELEASE_ISOLATION, but the reversal
        # identifier is the EDR's command id — this service mints none.
        "reversal_id": command_id if verb == "ISOLATE_ENDPOINT" else None,
    }


def _json(r: "httpx.Response") -> Any:
    try:
        return r.json()
    except Exception:                                           # noqa: BLE001
        return {"raw": r.text[:400]}
