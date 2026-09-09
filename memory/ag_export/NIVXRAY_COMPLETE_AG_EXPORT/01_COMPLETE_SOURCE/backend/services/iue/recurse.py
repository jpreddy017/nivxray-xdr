"""Recursive re-entry facade (STEP 3 §5 · STEP 4 §3.2).

Discovered content MUST re-enter at Intake, never directly at IUE.
Cycle detection and depth-cap semantics reuse the existing UAIE ledger
via `services.uaie.ledger.Ledger` and `format_skip_reason`.  This
module is a **facade** — it does not schedule work, it does not
duplicate UAIE's orchestrator loop.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from services.uaie.ledger import Ledger, format_skip_reason
from .failure import IUEFailure


UAIE_MAX_DEPTH = 12   # matches services.uaie.orchestrator.max_depth


def _fingerprint(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def recurse(discovered_bytes: bytes,
             *,
             ledger: Ledger,
             parent_input_id: str,
             tenant_id: str,
             discovery_depth: int):
    """Route discovered content back through the intake head.

    Returns either the `IntakeDecision` produced by ``intake()`` or an
    ``IUEFailure`` (cycle / depth cap).  Never raises.
    """
    fp = _fingerprint(discovered_bytes)

    # Cycle check — ledger seen scan by fingerprint (linear but bounded
    # by UAIE_MAX_DEPTH * fanout in practice).
    for entry in ledger:
        if entry.input_summary == f"fp={fp}":
            ledger.append(
                artifact_uri=f"iue:recurse:{fp[:12]}",
                action="skip", actor="iue.recurse",
                input_summary=f"fp={fp}",
                output_summary=format_skip_reason("cycle"),
            )
            return IUEFailure(
                status="recoverable", stage="recurse",
                error_code="recurse_cycle_detected",
                message="fingerprint already seen on this branch",
                recoverable=True,
                input_id=parent_input_id,
                tenant_id=tenant_id,
            )

    if discovery_depth + 1 > UAIE_MAX_DEPTH:
        ledger.append(
            artifact_uri=f"iue:recurse:{fp[:12]}",
            action="skip", actor="iue.recurse",
            input_summary=f"fp={fp}",
            output_summary=format_skip_reason(
                "depth_cap", detail=f"depth={discovery_depth}"),
        )
        return IUEFailure(
            status="recoverable", stage="recurse",
            error_code="recurse_depth_exceeded",
            message=f"depth {discovery_depth} would exceed cap {UAIE_MAX_DEPTH}",
            recoverable=True,
            input_id=parent_input_id,
            tenant_id=tenant_id,
        )

    ledger.append(
        artifact_uri=f"iue:recurse:{fp[:12]}",
        action="reenter", actor="iue.recurse",
        input_summary=f"fp={fp}",
        output_summary=f"depth={discovery_depth + 1}",
    )

    # Local import to avoid cycle at module load time.
    from .intake import intake
    return intake(
        discovered_bytes,
        parent_input_id=parent_input_id,
        tenant_id=tenant_id,
        discovery_depth=discovery_depth + 1,
    )
