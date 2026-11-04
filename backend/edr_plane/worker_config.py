"""Bounded per-process concurrency for durable EDR processing."""
import logging
import os

def processing_worker_count():
    """Default to one; invalid/out-of-range settings retain the safe default."""
    value = os.environ.get("NIVX_EDR_PROCESSING_WORKERS", "1")
    try:
        count = int(value)
    except (ValueError, TypeError):
        count = 0
    if not 1 <= count <= 8:
        logging.getLogger(__name__).warning(
            "Invalid NIVX_EDR_PROCESSING_WORKERS; using 1 (allowed 1..8)"
        )
        return 1
    return count
