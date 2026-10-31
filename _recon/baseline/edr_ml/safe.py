"""Bounded, attacker-safe primitives. All telemetry is treated as hostile."""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Optional

MAX_TEXT = 8192
MAX_ENTROPY_CHARS = 4096
MAX_TOKEN = 256
MAX_KEY_TEXT = 1024


def finite(x: Any) -> Optional[float]:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    f = float(x)
    return f if math.isfinite(f) else None


def text(v: Any, limit: int = MAX_TEXT) -> Optional[str]:
    if not isinstance(v, str) or not v:
        return None
    return v[:limit]


def token(v: Any, limit: int = MAX_TOKEN) -> Optional[str]:
    t = text(v, limit)
    return t.replace("\\", "/").lower() if t else None


def entropy(s: str) -> float:
    """Shannon entropy in bits/char over at most MAX_ENTROPY_CHARS characters."""
    s = s[:MAX_ENTROPY_CHARS]
    if not s:
        return 0.0
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in sorted(Counter(s).values())), 6)


def clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def r6(x: float) -> float:
    return round(float(x), 6)


def time_ok(ts: Any, now: datetime, max_future: timedelta) -> bool:
    return isinstance(ts, datetime) and ts.tzinfo is not None and ts <= now + max_future
