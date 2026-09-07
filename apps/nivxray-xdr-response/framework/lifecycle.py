"""Authoritative response LIFECYCLE projection.

The response SSOT is unchanged — it remains the existing sqlite
`ExecutionStore`. Nothing here persists a new column, table or
collection. The lifecycle is **derived** from the retained SSOT plus the
authoritative EDR record the dispatch adapter carried back, so there is
exactly one source of truth for response state.

The whole point of this module is to make four collapses impossible:

    approved   ≠ dispatched
    dispatched ≠ executing
    executing  ≠ executed
    executed   ≠ verified

The engine's internal terminal state `SUCCEEDED` means "the adapter
returned and evidence was forwarded". For a REAL product dispatch that
is only ever **dispatched** — the endpoint product owns everything after
it. Only NivXForge EDR's own `EXECUTED` may become `executed`, and only
its `proof.verified == True` may become `verified`. A stub adapter can
never reach any of them; it terminates at `simulated`.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# The operational vocabulary the EDR Response Surface will render.
REQUESTED           = "requested"
PENDING_APPROVAL    = "pending_approval"
APPROVED            = "approved"
DISPATCHED          = "dispatched"
EXECUTING           = "executing"
EXECUTED            = "executed"
VERIFIED            = "verified"
# terminal / exception
REJECTED            = "rejected"
CANCELLED           = "cancelled"
DISPATCH_FAILED     = "dispatch_failed"
EXECUTION_FAILED    = "execution_failed"
TIMED_OUT           = "timed_out"
VERIFICATION_FAILED = "verification_failed"
SIMULATED           = "simulated"

#: Dispatch modes. Surfaced on every action and every execution so no
#: consumer can mistake a stub for a real control action.
REAL_PRODUCT_API      = "REAL_PRODUCT_API"
STUB_NO_SIDE_EFFECT   = "STUB_NO_SIDE_EFFECT"

_ORDER = [REQUESTED, PENDING_APPROVAL, APPROVED, DISPATCHED,
          EXECUTING, EXECUTED, VERIFIED]

#: EDR lifecycle → our lifecycle. The EDR is authoritative for
#: everything from the moment it accepts the action.
_EDR_MAP = {
    "REQUESTED":           DISPATCHED,
    "AUTHORIZED":          DISPATCHED,
    "DISPATCHED":          DISPATCHED,
    "CLAIMED":             EXECUTING,
    "EXECUTING":           EXECUTING,
    "EXECUTED":            EXECUTED,
    "VERIFIED":            VERIFIED,
    "VERIFICATION_FAILED": VERIFICATION_FAILED,
    "FAILED":              EXECUTION_FAILED,
    "TIMED_OUT":           TIMED_OUT,
    "EXPIRED":             TIMED_OUT,
}


def project(row: Dict[str, Any], *, dispatch_mode: Optional[str] = None
            ) -> Dict[str, Any]:
    """Derive the lifecycle facts for one execution row."""
    state = row.get("state")
    result = row.get("adapter_result") or row.get("adapter_result_json") or {}
    if not isinstance(result, dict):
        result = {}
    mode = dispatch_mode or result.get("dispatch_mode") or STUB_NO_SIDE_EFFECT
    dry = bool(row.get("dry_run"))
    approval_required = bool(row.get("approval_required"))
    approval_status = row.get("approval_status")

    edr_state = result.get("edr_state")
    edr_proof = result.get("edr_proof") or {}
    edr_verified = bool(edr_proof.get("verified")) if isinstance(edr_proof, dict) else False

    # ── exception / terminal first ────────────────────────────────
    if state == "REJECTED":
        lifecycle, reason = REJECTED, row.get("rejection_reason") or row.get("failure_reason")
    elif state == "FAILED_APPROVAL":
        lifecycle, reason = REJECTED, row.get("rejection_reason") or "approval_rejected"
    elif state == "FAILED_TARGET":
        lifecycle, reason = REJECTED, row.get("failure_reason") or "unresolved_target"
    elif state == "FAILED_EXECUTION":
        # The adapter never handed the action over → dispatch failed.
        # It is NOT an endpoint execution failure unless the EDR said so.
        lifecycle = (EXECUTION_FAILED if edr_state else DISPATCH_FAILED)
        reason = row.get("failure_reason") or row.get("adapter_error")
    elif state == "FAILED_FORWARDING":
        lifecycle, reason = DISPATCH_FAILED, row.get("forwarding_error") or "evidence_forwarding_failed"
    elif state == "WAITING_APPROVAL":
        lifecycle, reason = PENDING_APPROVAL, None
    elif state in ("QUEUED", "RUNNING"):
        lifecycle = (APPROVED if (approval_required and approval_status == "approved")
                     else REQUESTED)
        reason = None
    elif state in ("EXECUTING", "FORWARDING_EVIDENCE"):
        lifecycle, reason = DISPATCHED, None
    elif state in ("SUCCEEDED", "FAILED_RECOVERED"):
        if dry:
            lifecycle, reason = SIMULATED, "dry_run — no side effect was attempted"
        elif mode != REAL_PRODUCT_API:
            lifecycle, reason = SIMULATED, (
                "this action has no real product adapter — the engine "
                "exercised its own lifecycle only, nothing was executed")
        elif edr_state:
            lifecycle = _EDR_MAP.get(str(edr_state), DISPATCHED)
            # A record cannot be `verified` without the product's own proof.
            if lifecycle == VERIFIED and not edr_verified:
                lifecycle = EXECUTED
            reason = None
        else:
            lifecycle, reason = DISPATCHED, (
                "accepted by the endpoint product; it has not reported "
                "execution yet")
    else:
        lifecycle, reason = REQUESTED, None

    return {
        "lifecycle":       lifecycle,
        "lifecycle_reason": reason,
        "dispatch_mode":   mode,
        "engine_state":    state,
        # The four invariants, stated as data so a UI cannot infer them wrong.
        "facts": {
            "requested":  True,
            "approved":   bool(approval_status == "approved") or not approval_required,
            "dispatched": _at_least(lifecycle, DISPATCHED),
            "executing":  _at_least(lifecycle, EXECUTING),
            "executed":   _at_least(lifecycle, EXECUTED),
            "verified":   lifecycle == VERIFIED,
        },
        "authoritative_for_execution": ("nivxforge-edr" if mode == REAL_PRODUCT_API
                                        else None),
        "edr": {
            "command_id":   result.get("edr_command_id"),
            "action":       result.get("edr_action"),
            "endpoint_id":  result.get("edr_endpoint_id"),
            "state":        edr_state,
            "proof":        edr_proof or None,
            "verification": result.get("edr_verification"),
        } if mode == REAL_PRODUCT_API else None,
        "honesty_note": _note(lifecycle, mode),
    }


def _at_least(lifecycle: str, floor: str) -> bool:
    if lifecycle not in _ORDER or floor not in _ORDER:
        return False
    return _ORDER.index(lifecycle) >= _ORDER.index(floor)


def _note(lifecycle: str, mode: str) -> str:
    if mode != REAL_PRODUCT_API:
        return ("STUB_NO_SIDE_EFFECT — no control action left this service. "
                "This can never read as executed or verified.")
    if lifecycle == DISPATCHED:
        return ("DISPATCHED means NivXForge EDR accepted ownership. "
                "Acceptance is not execution.")
    if lifecycle == EXECUTING:
        return "The endpoint has claimed the command but has not reported a result."
    if lifecycle == EXECUTED:
        return ("EXECUTED is the sensor's own claim. It is NOT proof of effect — "
                "only post-action evidence can make it verified.")
    if lifecycle == VERIFIED:
        return ("VERIFIED — NivXForge EDR gathered post-action evidence and its "
                "proof block confirms the effect.")
    if lifecycle == VERIFICATION_FAILED:
        return ("The action ran but its effect could NOT be proven. Treat the "
                "endpoint as uncontained.")
    if lifecycle == DISPATCH_FAILED:
        return "The action never reached the endpoint product. Nothing was executed."
    return ""
