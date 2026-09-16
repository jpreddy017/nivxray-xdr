"""
DIE · Preprocessor · Decode Telemetry (Rule R24 · guarantee #5)
──────────────────────────────────────────────────────────────
Layer-by-layer trace of every decode / decompress transition that
happens during ``preprocess()`` — surfaced on the SSOT as
``metadata.performance.decode_layers[]``.

Each entry has shape::

    {
      "layer":       1,                # 1-indexed
      "stage":       "base64",         # base64 | utf16le | gzip | zlib | powershell_ast | ...
      "bytes_in":    1416,
      "bytes_out":   1024,
      "ratio":       0.72,             # bytes_out / bytes_in
      "elapsed_ms":  0.42,
      "meta":        {"padding": 3, ...},   # optional extras
    }

Deterministic ordering — first decoder to run reports layer 1, next
layer 2, etc.  Cleared at the start of every ``preprocess()`` call so
the buffer never leaks between invocations.

Usage from any decoder::

    from services.die.preprocessor.decode_telemetry import record_layer
    _t0 = perf_counter()
    out_bytes = base64.b64decode(padded)
    record_layer("base64", bytes_in=len(padded), bytes_out=len(out_bytes),
                  elapsed_ms=(perf_counter() - _t0) * 1000)
"""
from __future__ import annotations

import threading
from time      import perf_counter
from typing    import Any, Dict, List


_local = threading.local()


def _buf() -> List[Dict[str, Any]]:
    b = getattr(_local, "layers", None)
    if b is None:
        b = []
        _local.layers = b
    return b


def reset() -> None:
    """Clear the per-call buffer.  Called at the top of preprocess."""
    _local.layers = []


def snapshot() -> List[Dict[str, Any]]:
    """Return a *copy* of the current buffer so callers can freeze
    the trace before the next preprocess() call wipes it."""
    return [dict(x) for x in _buf()]


def record_layer(stage: str,
                  bytes_in: int,
                  bytes_out: int,
                  elapsed_ms: float = 0.0,
                  meta: Dict[str, Any] | None = None) -> None:
    """Append a decode-layer record to the current buffer."""
    b = _buf()
    ratio = (bytes_out / bytes_in) if bytes_in else 0.0
    b.append({
        "layer":       len(b) + 1,
        "stage":       stage,
        "bytes_in":    int(bytes_in),
        "bytes_out":   int(bytes_out),
        "ratio":       round(ratio, 4),
        "elapsed_ms":  round(float(elapsed_ms), 3),
        "meta":        dict(meta or {}),
    })


# ── Timing helper — context manager wrapping any decode call ────
class timed_layer:
    """Context manager that records a decode layer at exit.  Usage::

        with timed_layer("base64", bytes_in=len(padded)) as t:
            out = base64.b64decode(padded)
            t.bytes_out = len(out)     # set before exit
    """
    def __init__(self, stage: str, bytes_in: int,
                  meta: Dict[str, Any] | None = None):
        self.stage     = stage
        self.bytes_in  = int(bytes_in)
        self.bytes_out = 0
        self.meta      = dict(meta or {})
        self._t0       = 0.0

    def __enter__(self):
        self._t0 = perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        # Even on exception we record the attempt so failed decoders
        # are visible in the trace.  The metadata gets a `failed` flag.
        if exc_type is not None:
            self.meta = {**self.meta, "failed": True, "error": type(exc).__name__}
        elapsed_ms = (perf_counter() - self._t0) * 1000.0
        record_layer(self.stage, self.bytes_in, self.bytes_out,
                       elapsed_ms=elapsed_ms, meta=self.meta)
        # Do NOT swallow exceptions — R23: decoder failure is logged
        # and reported by higher-level try/except.
        return False
