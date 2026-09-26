"""NivXRay Security State Streaming Adapter Package (Phase 4C)."""
from .adapter import StreamingEventAdapter
from .coalescer import SlidingWindowCoalescer
from .dedup import PersistentDeduplicationService
from .dlq import DeadLetterQueueService
from .fingerprint import generate_event_fingerprint, quantize_timestamp_1s
from .models import (
    CoalescePolicy,
    DLQFailureClass,
    DLQRecord,
    LateEventReconciliationMode,
    StreamingEventEnvelope,
    StreamingMetrics,
    WatermarkArrivalStatus,
    WatermarkPolicy,
)
from .replay import ReplayEquivalenceVerifier, ReplayStreamingSource
from .watermark import WatermarkService

__all__ = [
    "StreamingEventAdapter",
    "SlidingWindowCoalescer",
    "PersistentDeduplicationService",
    "DeadLetterQueueService",
    "generate_event_fingerprint",
    "quantize_timestamp_1s",
    "CoalescePolicy",
    "DLQFailureClass",
    "DLQRecord",
    "LateEventReconciliationMode",
    "StreamingEventEnvelope",
    "StreamingMetrics",
    "WatermarkArrivalStatus",
    "WatermarkPolicy",
    "ReplayStreamingSource",
    "ReplayEquivalenceVerifier",
    "WatermarkService",
]
