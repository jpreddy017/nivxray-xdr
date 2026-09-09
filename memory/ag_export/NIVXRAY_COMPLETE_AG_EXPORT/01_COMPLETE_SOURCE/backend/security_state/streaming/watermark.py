"""Watermark and Event-Time Processing Service for NivXRay Streaming Telemetry."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .models import WatermarkArrivalStatus, WatermarkPolicy


class WatermarkService:
    """Tracks event time, ingest time, and processing time to advance stream watermarks."""

    def __init__(self, policy: Optional[WatermarkPolicy] = None) -> None:
        self.policy = policy or WatermarkPolicy()
        self._max_event_time_epoch: float = 0.0
        self._current_watermark_epoch: float = 0.0

    @property
    def current_watermark_iso(self) -> str:
        if self._current_watermark_epoch <= 0.0:
            return "1970-01-01T00:00:00Z"
        return datetime.fromtimestamp(self._current_watermark_epoch, tz=timezone.utc).isoformat()

    @property
    def current_watermark_epoch(self) -> float:
        return self._current_watermark_epoch

    def process_timestamp(
        self,
        event_timestamp_iso: str,
        ingest_timestamp_iso: Optional[str] = None,
    ) -> Tuple[WatermarkArrivalStatus, float, float]:
        """Assess event arrival status relative to the current watermark.

        Returns:
            (status, event_processing_lag_ms, watermark_lag_ms)
        """
        now_epoch = time.time()

        try:
            event_dt = datetime.fromisoformat(event_timestamp_iso.replace("Z", "+00:00"))
            event_epoch = event_dt.timestamp()
        except Exception:
            event_epoch = now_epoch

        # 1. Clock skew check (future-dated)
        if event_epoch > now_epoch + self.policy.allowed_clock_skew_seconds:
            return WatermarkArrivalStatus.CLOCK_SKEW_FUTURE, 0.0, 0.0

        # Calculate lag metrics
        event_lag_ms = max(0.0, (now_epoch - event_epoch) * 1000.0)
        watermark_lag_ms = max(0.0, (now_epoch - self._current_watermark_epoch) * 1000.0)

        # 2. Check if event is late (strictly below the current watermark)
        if self._current_watermark_epoch > 0.0 and event_epoch < self._current_watermark_epoch:
            return WatermarkArrivalStatus.LATE, event_lag_ms, watermark_lag_ms

        # 3. Check if out-of-order vs in-order
        if event_epoch < self._max_event_time_epoch:
            status = WatermarkArrivalStatus.OUT_OF_ORDER
        else:
            status = WatermarkArrivalStatus.IN_ORDER
            self._max_event_time_epoch = event_epoch
            # Advance watermark
            new_watermark = event_epoch - self.policy.watermark_delay_seconds
            if new_watermark > self._current_watermark_epoch:
                self._current_watermark_epoch = new_watermark

        return status, event_lag_ms, watermark_lag_ms

    def reset(self) -> None:
        """Reset watermark state for new replay run."""
        self._max_event_time_epoch = 0.0
        self._current_watermark_epoch = 0.0
