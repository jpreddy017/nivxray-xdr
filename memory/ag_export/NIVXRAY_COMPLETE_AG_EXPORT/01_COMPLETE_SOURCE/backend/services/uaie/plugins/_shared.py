"""Shared plugin helpers · R26.

Wraps a legacy ``Optional[Tuple[str, Dict[str, Any]]]`` decoder into a
UAIE ``Capability`` result — one child artifact + one Recognition-style
Evidence + notes with the legacy meta dict.
"""
from __future__ import annotations

from time import perf_counter
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..artifact   import Artifact, make_artifact
from ..capability import CapabilityResult
from ..evidence   import Evidence, make_evidence


LegacyDecoder = Callable[[str], Optional[Tuple[str, Dict[str, Any]]]]


def artifact_to_text(artifact: Artifact) -> str:
    """UAIE artifacts carry raw bytes; the legacy decoders expect
    a str.  Use UTF-8 with ``errors="replace"`` — identical to how
    the legacy pipeline reads input from the wire."""
    try:
        return artifact.payload.decode("utf-8", errors="replace")
    except Exception:
        return ""


def wrap_legacy_decoder(
    *,
    plugin_name: str,
    child_type: str,
    legacy: LegacyDecoder,
) -> Callable[[Artifact], CapabilityResult]:
    """Return a Capability.execute function that:
      1. Reads text from the artifact.
      2. Invokes the legacy decoder (byte-identical).
      3. Emits one child Artifact carrying the decoded text + meta.
      4. Emits Evidence with the plugin name + reason.
    """
    def _execute(artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        text = artifact_to_text(artifact)
        try:
            hit = legacy(text)
        except Exception as e:
            return CapabilityResult(
                elapsed_ms=(perf_counter() - t0) * 1000.0,
                failed=True,
                error=f"{type(e).__name__}: {e}",
            )
        elapsed = (perf_counter() - t0) * 1000.0
        if hit is None:
            return CapabilityResult(elapsed_ms=elapsed)
        out_text, meta = hit
        child = make_artifact(
            payload=out_text.encode("utf-8", errors="replace"),
            artifact_type=child_type,
            parent_uri=artifact.uri,
            depth=artifact.depth + 1,
            discovered_by=plugin_name,
            meta=dict(meta or {}),
        )
        ev = make_evidence(
            artifact_uri=artifact.uri,
            kind="decode_layer",
            value=child_type,
            source_capability=plugin_name,
            confidence=0.90,
            severity="info",
            location=f"depth={artifact.depth}",
            meta={"legacy_meta": dict(meta or {}),
                  "child_uri": child.uri,
                  "elapsed_ms": elapsed},
        )
        return CapabilityResult(
            evidence=[ev],
            child_artifacts=[child],
            notes={"legacy_meta": dict(meta or {})},
            elapsed_ms=elapsed,
        )
    return _execute
