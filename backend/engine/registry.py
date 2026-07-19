"""DecoderRegistry — process-wide plugin registry for L2.

Auto-discovery: on first access, walks `backend.decoders` package and imports
every submodule; each submodule registers its decoder instance at import time.

Ordering: candidates are returned sorted by (confidence desc, cost asc), so
cheap high-confidence decoders run first.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
from typing import Iterable, List, Optional, Tuple

from .decoder_base import BaseDecoder
from .models import AnalysisContext, DetectResult, Fingerprint

log = logging.getLogger("nivx.engine.registry")

_lock = threading.RLock()   # reentrant — register() is called during autodiscover
_decoders: dict[str, BaseDecoder] = {}
_discovered = False


class DecoderRegistry:
    """Static facade. Not instantiated; keeps API discoverable and mockable in tests."""

    @staticmethod
    def register(decoder: BaseDecoder) -> None:
        with _lock:
            if decoder.id in _decoders:
                log.debug("Decoder %r already registered — overwriting", decoder.id)
            _decoders[decoder.id] = decoder

    @staticmethod
    def unregister(decoder_id: str) -> None:
        with _lock:
            _decoders.pop(decoder_id, None)

    @staticmethod
    def get(decoder_id: str) -> Optional[BaseDecoder]:
        DecoderRegistry._ensure_discovered()
        return _decoders.get(decoder_id)

    @staticmethod
    def all() -> List[BaseDecoder]:
        DecoderRegistry._ensure_discovered()
        return list(_decoders.values())

    @staticmethod
    def candidates(
        payload: str,
        fingerprint: Fingerprint,
        ctx: AnalysisContext,
        *,
        min_confidence: float = 0.05,
        top_n: Optional[int] = None,
    ) -> List[Tuple[BaseDecoder, DetectResult]]:
        """Run detect() on every registered decoder and return the ranked list."""
        DecoderRegistry._ensure_discovered()
        results: List[Tuple[BaseDecoder, DetectResult]] = []
        for dec in _decoders.values():
            try:
                dr = dec.detect(payload, fingerprint, ctx)
            except Exception as exc:                      # pragma: no cover
                log.warning("detect() raised for %s: %s", dec.id, exc)
                continue
            if dr.confidence >= min_confidence:
                results.append((dec, dr))
        results.sort(key=lambda t: (-t[1].confidence, t[0].cost))
        if top_n is not None:
            results = results[:top_n]
        return results

    @staticmethod
    def _ensure_discovered() -> None:
        global _discovered
        if _discovered:
            return
        with _lock:
            if _discovered:
                return
            _autodiscover()
            _discovered = True

    @staticmethod
    def reset() -> None:
        """Test helper — clears registry and forces re-discovery on next access."""
        global _discovered
        with _lock:
            _decoders.clear()
            _discovered = False


def _autodiscover() -> None:
    """Import every module in backend.decoders so their `register()` calls fire."""
    try:
        import backend.decoders as pkg                 # type: ignore
    except ImportError:
        # backend is run as a top-level module in the current supervisor setup
        import decoders as pkg                        # type: ignore
    for _, name, _ in pkgutil.iter_modules(pkg.__path__):
        if name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{pkg.__name__}.{name}")
        except Exception as exc:                       # pragma: no cover
            log.error("Failed to import decoder plugin %r: %s", name, exc)
    log.info("Decoder registry ready — %d plugins loaded", len(_decoders))
