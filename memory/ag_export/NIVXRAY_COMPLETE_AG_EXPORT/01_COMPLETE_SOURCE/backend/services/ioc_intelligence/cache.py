"""
IOC Intelligence · in-memory TTL cache (2026-03-02)
────────────────────────────────────────────────────
Process-local cache to make repeat look-ups instant.  Deterministic
key (kind + normalized value) + monotonic TTL.  Zero external
dependency; a Redis/Mongo backend can slot in later behind the same
`get / set` protocol without touching consumers.
"""
from __future__ import annotations
import time
from threading import Lock
from typing import Any, Dict, Optional, Tuple

_TTL_SECONDS = 6 * 60 * 60          # 6h — refreshed on next miss
_MAX_ENTRIES  = 4096                 # hard cap → simple FIFO eviction

_STORE: Dict[Tuple[str, str], Tuple[float, Any]] = {}
_ORDER: list = []
_LOCK = Lock()


def _key(kind: str, value: str) -> Tuple[str, str]:
    return (kind.strip().lower(), value.strip().lower())


def get(kind: str, value: str) -> Optional[Any]:
    k = _key(kind, value)
    with _LOCK:
        item = _STORE.get(k)
        if not item: return None
        expires_at, payload = item
        if expires_at < time.time():
            _STORE.pop(k, None)
            try: _ORDER.remove(k)
            except ValueError: pass
            return None
        return payload


def set(kind: str, value: str, payload: Any,
         ttl: int = _TTL_SECONDS) -> None:
    k = _key(kind, value)
    with _LOCK:
        _STORE[k] = (time.time() + ttl, payload)
        try: _ORDER.remove(k)
        except ValueError: pass
        _ORDER.append(k)
        while len(_ORDER) > _MAX_ENTRIES:
            old = _ORDER.pop(0)
            _STORE.pop(old, None)


def clear() -> None:              # test / admin
    with _LOCK:
        _STORE.clear()
        _ORDER.clear()
