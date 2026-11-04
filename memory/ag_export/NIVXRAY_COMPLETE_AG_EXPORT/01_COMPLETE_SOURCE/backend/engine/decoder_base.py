"""BaseDecoder — abstract plugin contract for L2 decoders and L3 intelligence plugins.

Every plugin subclasses this. The contract:
    - `id`, `name`, `category`, `cost`, `tags`, `schema_version` (class attrs)
    - `detect(payload, fingerprint, ctx) -> DetectResult`
    - `decode(payload, args, ctx)      -> PluginResult`
    - `explain(result)                 -> str`   (optional, default empty)

Categories
----------
    encoding      byte→byte transform (base64, hex, url, ascii85, ...)
    compression   inflate/deflate (gzip, brotli, lzma, zlib)
    cipher        keyed transform (xor, rot13, aes)
    reconstruct   syntactic rebuild (char-array-join, chr(), -f format)
    normalize     canonicalise (tick-strip, case-fold, homoglyph)
    intelligence  no output transform — emits family/mitre/lolbas signals
                  (meterpreter_detector, family_asyncrat, lolbas_matcher, ...)

Guidelines
----------
* detect() must be cheap — it may run for many candidates per layer.
* decode() may be more expensive; runs at most `max_branches` per layer.
* Intelligence plugins typically return the input unchanged in `output` and
  populate `mitre_hints` / `family_hints` / `lolbas_hits` / `tradecraft`.
* Neither method should raise on ordinary "does not apply" — return low
  confidence or an empty output. Uncaught exceptions ARE caught by the
  orchestrator but are treated as bugs.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from .models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    PluginResult,
)


class BaseDecoder(ABC):
    id: str = "base"
    name: str = "Base Plugin"
    category: str = "encoding"
    cost: int = 1
    tags: tuple[str, ...] = ()
    schema_version: str = "1.0"

    @abstractmethod
    def detect(
        self,
        payload: str,
        fingerprint: Fingerprint,
        ctx: AnalysisContext,
    ) -> DetectResult: ...

    @abstractmethod
    def decode(
        self,
        payload: str,
        args: Dict[str, Any],
        ctx: AnalysisContext,
    ) -> PluginResult: ...

    def explain(self, result: PluginResult) -> str:
        """Optional: return analyst-friendly prose about what this transform means.

        Default: empty. Plugins opt in when they have something meaningful to say
        (e.g. Meterpreter detector explains what family was identified and why).
        Aggregated across all trace steps to build the deterministic
        `executive_summary` on the AnalystReport.
        """
        return ""

    def __repr__(self) -> str:                       # pragma: no cover
        return f"<{self.__class__.__name__} id={self.id!r} v{self.schema_version}>"
