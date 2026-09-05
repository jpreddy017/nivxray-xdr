"""Phase 4 Wave 1 · Observation Store.

Persists every `verdict_shadow` payload to MongoDB collection
`verdict_shadow_observations` for later analysis. Fire-and-forget:
persistence failures MUST NOT block the primary verdict path.

Owner-mandated (2026-08-10):
    * Observation window is time-bounded but coverage-gated. We need
      enough investigations across `minimal/sparse/moderate/rich`
      completeness classes to make Wave 2 decisions.
    * Missing-bucket frequencies must surface upstream ingestion gaps,
      not scoring gaps.

Schema (per record)
────────────────────
    {
      "run_id":            str,  # investigation identifier
      "recorded_at":       ISO8601 UTC,
      "shadow_engine":     "canonical-v2-verdict-1.0",
      "existing_label":    str,  # engine A output
      "existing_conf_pct": int,
      "canonical_label":   str,
      "canonical_conf_pct":int,
      "completeness_pct":  int,
      "coverage_class":    "minimal"|"sparse"|"moderate"|"rich",
      "buckets_populated": {bucket_name: bool},
      "missing_buckets":   [str],   # buckets NOT populated
      "divergence_class":  str,
      "shadow_latency_ms": float,
      "error":             str | null,
    }
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any


_LOG = logging.getLogger(__name__)
_COLLECTION = "verdict_shadow_observations"


def _to_record(run_id: str, shadow: dict[str, Any],
                    latency_ms: float) -> dict[str, Any]:
    """Flatten the verbose shadow payload to a queryable record shape."""
    if not isinstance(shadow, dict):
        shadow = {}

    existing  = shadow.get("existing_verdict")  or {}
    canonical = shadow.get("verdict_canonical") or {}
    complete  = shadow.get("input_completeness") or {}
    diverge   = shadow.get("divergence")         or {}

    buckets_populated = complete.get("buckets_populated") or {}
    missing = sorted([k for k, v in buckets_populated.items() if not v])

    return {
        "run_id":             str(run_id or "")[:120],
        "recorded_at":        datetime.now(timezone.utc).isoformat(),
        "shadow_engine":      shadow.get("shadow_engine", ""),
        "existing_label":     str(existing.get("label") or ""),
        "existing_conf_pct":  int(existing.get("confidence_pct") or 0),
        "canonical_label":    str(canonical.get("label") or ""),
        "canonical_conf_pct": int(canonical.get("confidence_pct") or 0),
        "completeness_pct":   int(complete.get("completeness_pct") or 0),
        "coverage_class":     str(complete.get("coverage_class") or ""),
        "buckets_populated":  buckets_populated,
        "missing_buckets":    missing,
        "divergence_class":   str(diverge.get("class") or ""),
        "shadow_latency_ms":  round(float(latency_ms), 3),
        "error":              shadow.get("shadow_error"),
    }


async def _persist_async(record: dict[str, Any]) -> None:
    """Persist a single record. Swallows exceptions — the observation
    store MUST NEVER block the primary verdict."""
    try:
        from deps import db
        await db[_COLLECTION].insert_one(record)
    except Exception:  # noqa: BLE001
        _LOG.exception("verdict_shadow_observations persist failed (non-blocking)")


def record_observation(run_id: str, shadow: dict[str, Any] | None,
                            latency_ms: float) -> None:
    """Fire-and-forget observation persistence.

    Safe to call from sync or async contexts:
      * If a running event loop exists → schedule as background task.
      * Otherwise → run to completion synchronously via `asyncio.run`.

    NEVER raises. NEVER blocks the caller for MongoDB latency."""
    if not shadow:
        return
    try:
        record = _to_record(run_id, shadow, latency_ms)
    except Exception:  # noqa: BLE001
        _LOG.exception("verdict_shadow_observations record shaping failed")
        return
    try:
        loop = asyncio.get_running_loop()
        # Schedule as background task; don't await.
        loop.create_task(_persist_async(record))
    except RuntimeError:
        # No running loop — persist inline (rare: unit-test contexts).
        try:
            asyncio.run(_persist_async(record))
        except Exception:  # noqa: BLE001
            _LOG.exception("verdict_shadow_observations inline persist failed")


__all__ = ["record_observation"]
