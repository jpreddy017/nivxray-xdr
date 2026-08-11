"""In-process sliding-window rate limiter · P0 Security Hardening Gate.

Rationale (per PRD.md P0 directive):
- NivXRay runs single-worker uvicorn today (ADR-0007 §36) — in-process
  state is authoritative. When we move to multi-worker in P5 we will
  swap the backend for Redis or a shared store; that swap is an
  interface change, not a semantic one.
- Deterministic errors: exceeds → HTTP 429 with structured payload +
  ``Retry-After`` header. Clock is monotonic; state resets automatically
  when the window rolls off. No lockout escalation logic (kept simple).

Config surface (environment):

    NIVX_LOGIN_RATE_MAX_FAILS     = "5"     # failed attempts per window
    NIVX_LOGIN_RATE_WINDOW_SEC    = "300"   # window length (5 min)
    NIVX_LOGIN_RATE_LOCKOUT_SEC   = "900"   # lockout after limit hit (15 min)

Every guarded caller is keyed by (route, identity, client_ip). "identity"
defaults to the ``email`` on the login body. If either identity or IP
is missing we key on whichever exists — the guard MUST fail-safe (i.e.
block), not fail-open.

Nothing here reads or writes any NIVX_FLAG_*.
"""
from __future__ import annotations
import os
import time
import threading
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple
from collections import deque


def _cfg_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "").strip() or default)
        return max(1, v)
    except Exception:
        return default


def _now() -> float:
    return time.monotonic()


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int  # seconds; 0 when allowed
    reason: str       # "ok" | "throttled" | "locked"


class SlidingWindowLimiter:
    """Per-key failure counter with rolling window + soft lockout.

    - ``check(key)``          — call BEFORE the action; returns whether allowed.
    - ``record_failure(key)`` — call AFTER an unsuccessful action.
    - ``record_success(key)`` — call AFTER a successful action (clears state).

    A key is locked when it hits ``max_fails`` inside the window; the
    lockout lasts ``lockout_sec`` from the moment of the last failure.
    """

    def __init__(
        self,
        max_fails: Optional[int] = None,
        window_sec: Optional[int] = None,
        lockout_sec: Optional[int] = None,
    ) -> None:
        self.max_fails   = max_fails   or _cfg_int("NIVX_LOGIN_RATE_MAX_FAILS", 5)
        self.window_sec  = window_sec  or _cfg_int("NIVX_LOGIN_RATE_WINDOW_SEC", 300)
        self.lockout_sec = lockout_sec or _cfg_int("NIVX_LOGIN_RATE_LOCKOUT_SEC", 900)
        self._events: Dict[str, Deque[float]]  = {}
        self._lock_until: Dict[str, float]     = {}
        self._mu = threading.Lock()

    # ── internal helpers ─────────────────────────────────────────────
    def _prune(self, key: str, now: float) -> Deque[float]:
        q = self._events.setdefault(key, deque())
        cutoff = now - self.window_sec
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def _locked(self, key: str, now: float) -> Tuple[bool, int]:
        lk = self._lock_until.get(key)
        if lk and lk > now:
            return True, int(lk - now) + 1
        return False, 0

    # ── public API ───────────────────────────────────────────────────
    def check(self, key: str) -> RateLimitResult:
        """Is this key currently allowed?

        Semantics: the lockout is authoritative. If the lockout has
        expired, the request is allowed EVEN IF the event window is
        still populated — those events will roll off on their own
        schedule, and the next failure will re-trip the lockout if
        appropriate.
        """
        with self._mu:
            now = _now()
            locked, retry = self._locked(key, now)
            if locked:
                return RateLimitResult(False, 0, retry, "locked")
            q = self._prune(key, now)
            remaining = max(0, self.max_fails - len(q))
            return RateLimitResult(True, remaining, 0, "ok")

    def record_failure(self, key: str) -> RateLimitResult:
        with self._mu:
            now = _now()
            q = self._prune(key, now)
            q.append(now)
            remaining = max(0, self.max_fails - len(q))
            if remaining <= 0:
                self._lock_until[key] = now + self.lockout_sec
                return RateLimitResult(False, 0, self.lockout_sec, "throttled")
            return RateLimitResult(True, remaining, 0, "ok")

    def record_success(self, key: str) -> None:
        with self._mu:
            self._events.pop(key, None)
            self._lock_until.pop(key, None)

    def reset(self) -> None:
        """Test-only helper. Clears all state."""
        with self._mu:
            self._events.clear()
            self._lock_until.clear()


# Module-level singleton — one limiter per shared config family.
LOGIN_LIMITER = SlidingWindowLimiter()
