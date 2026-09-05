"""v2/investigation/shadow_hook.py · Security State Asynchronous Shadow Dispatcher.

Hook that connects native NivXRay case investigations to the Security State
computing and causal reasoning substrate.

Guarantees:
1. ZERO WORK on disabled: If NIVX_FLAG_SECURITY_STATE is 'disabled', returns
   immediately without importing security_state or performing any DB/CPU work.
2. NON-BLOCKING: Shadow evaluation runs asynchronously in a daemon thread.
   Case query latency remains unaffected.
3. FAILURE ISOLATION: Any failure in Security State is caught and isolated to DLQ;
   authoritative case investigation response NEVER fails.
4. READ-ONLY w.r.t. Authoritative Data: Never mutates frames, IKG, verdicts,
   verdict scores, Attack Story, or v2_cases documents.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nivxray.v2.shadow_hook")


def maybe_dispatch_security_state_shadow(
    case_id: str,
    tenant_id: str = "default",
    frames: Optional[List[Dict[str, Any]]] = None,
    ikg: Optional[Dict[str, Any]] = None,
    *,
    sync: bool = False,
) -> None:
    """Zero-overhead dispatcher: inline check returns immediately if flag is disabled.
    
    If enabled/shadow, dispatches Security State evaluation asynchronously in background.
    """
    raw_flag = os.environ.get("NIVX_FLAG_SECURITY_STATE", "disabled").strip().lower()
    if raw_flag not in ("shadow", "enabled", "sidecar", "1", "true"):
        # LITERALLY ZERO SECURITY STATE EXECUTION, ZERO DB CALLS, ZERO IMPORTS
        return

    # Prepare inputs
    case_frames = list(frames or [])
    case_ikg = dict(ikg or {})

    def _worker():
        try:
            # Lazy import to guarantee zero module import cost when flag is disabled
            from security_state.hydration.case_hydrator import CaseSecurityStateHydrator
            hydrator = CaseSecurityStateHydrator()
            hydrator.hydrate_and_persist(
                case_id=case_id,
                tenant_id=tenant_id,
                frames=case_frames,
                ikg=case_ikg,
            )
            logger.info("Security State shadow hydration succeeded for case %s (tenant: %s)", case_id, tenant_id)
        except Exception as e:
            logger.warning("Security State shadow hydration failed for case %s: %s (Isolated to DLQ)", case_id, e)
            try:
                from security_state.streaming.dlq import DeadLetterQueueService, DLQFailureClass
                dlq_svc = DeadLetterQueueService()
                dlq_svc.record_failure(
                    tenant_id=tenant_id,
                    event_id=f"case-hydrate-{case_id}",
                    raw_envelope={"case_id": case_id, "frame_count": len(case_frames)},
                    failure_class=DLQFailureClass.HANDLER_EXCEPTION,
                    error_message=f"Shadow hydration failure: {str(e)}",
                )
            except Exception as dlq_err:
                logger.error("Failed to record shadow failure to DLQ: %s", dlq_err)

    if sync:
        _worker()
    else:
        # Non-blocking background thread
        thread = threading.Thread(
            target=_worker,
            name=f"sec-state-shadow-{case_id}",
            daemon=True,
        )
        thread.start()
