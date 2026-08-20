"""IUE observability (v3 §22 · STEP 3 §4).

Thin adapter over stdlib logging + the existing UAIE ledger.  Emits
one structured record per module boundary with the mandatory
provenance quintuple.  Does NOT invent a new logging framework.
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Optional


_logger = logging.getLogger("iue")


@contextmanager
def span(*, stage: str, input_id: str, tenant_id: str,
          parent_input_id: Optional[str] = None,
          discovery_depth: int = 0,
          content_fingerprint: str = ""):
    """Emit `stage_enter` and `stage_exit` with elapsed_ms.  Non-fatal:
    if logging fails the yielded context still runs."""
    t0 = time.perf_counter()
    base = {
        "stage": stage, "input_id": input_id, "tenant_id": tenant_id,
        "parent_input_id": parent_input_id,
        "discovery_depth": discovery_depth,
        "content_fingerprint": content_fingerprint,
    }
    try:
        _logger.debug("iue_stage_enter", extra=base)
    except Exception:
        pass
    try:
        yield base
    finally:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        try:
            _logger.debug("iue_stage_exit",
                           extra={**base, "elapsed_ms": elapsed_ms})
        except Exception:
            pass
