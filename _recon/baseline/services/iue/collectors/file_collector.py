"""Lane-C · File / Artifact collector.

Owner directive (Lane C spec):
    Artifact upload → Artifact Router → existing artifact-specific
    analyzer → canonical artifact evidence → LogicalEvent(lane="artifact")
    → IUE / T2 wire → existing StructuredEvidenceTab (pure projection)

This module is a THIN WRAPPER. It:
  1. Enforces the same size cap the log collector uses.
  2. Hashes the payload deterministically.
  3. Delegates artifact-type identification to the existing
     ``services.artifact_intelligence.dispatch()`` — never re-implements
     magic-byte detection or static analysis in the IUE package.
  4. Emits a labelled envelope (`FileRawPayload`) with provenance.

STAGE-1 RULES honoured:
  - Static analysis only. Zero execution. Zero network. Zero sandbox.
  - Artifact-first: identify → analyse → (later) optionally decode.
    This module STOPS at "identify + static analysis result". Any
    recursive decoding of embedded scripts/macros/executables is a
    downstream concern (Stage 2 / Lane C-Recursive).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from canonical.ssot.models import Provenance
from .._prov import collect_prov
from ..failure import IUEFailure
from ..security import enforce_raw_size, SecurityCapExceeded


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _md5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def _sha1_hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


@dataclass(frozen=True)
class FileRawPayload:
    """Labelled envelope for a single file/artifact upload.

    Mirrors ``services.iue.collectors.log_collector.RawPayload`` but
    also carries the AnalysisResult dict emitted by the Artifact
    Intelligence dispatcher (SHA-256 hash, artifact_type, display_name,
    static-analysis findings) so downstream parsers/normalizers can
    project it into canonical.artifact.* fields.
    """
    bytes_: bytes
    filename: str
    mime: str
    source_file_id: str
    input_id: str
    tenant_id: str
    artifact_dispatch: Dict[str, Any]      # AnalysisResult.to_dict()
    parent_input_id: Optional[str] = None
    discovery_depth: int = 0
    provenance: Provenance = field(default_factory=collect_prov)

    def to_dict(self) -> dict:
        d = asdict(self)
        # bytes_ isn't JSON-serialisable — replace with size marker.
        d["bytes_len"] = len(self.bytes_)
        d.pop("bytes_", None)
        # artifact_dispatch is already a plain dict
        d["artifact_dispatch"] = dict(self.artifact_dispatch or {})
        return d


def collect_file(payload_bytes: bytes,
                  *, filename: str,
                  mime: str,
                  input_id: str,
                  tenant_id: str,
                  upstream: Optional[Provenance] = None,
                  parent_input_id: Optional[str] = None,
                  discovery_depth: int = 0):
    """Return either a ``FileRawPayload`` or an ``IUEFailure``.

    Never raises.  Delegates artifact-type identification to
    ``services.artifact_intelligence.dispatch()`` — the existing
    registry (PDF / DOCX/Office / PE / ELF …) picks the analyser.
    """
    # Size cap — same envelope as Lane A.
    try:
        enforce_raw_size(len(payload_bytes))
    except SecurityCapExceeded as e:
        return IUEFailure(
            status="terminal", stage="collect",
            error_code="collect_size_exceeded",
            message=str(e), recoverable=False,
            hint="Increase IUE_MAX_RAW_BYTES or split the file.",
            input_id=input_id, tenant_id=tenant_id,
        )

    # Artifact-first identification via the existing dispatcher.
    dispatch_dict: Dict[str, Any] = {}
    try:
        from services.artifact_intelligence import dispatch as _dispatch
        result = _dispatch(payload_bytes)
        dispatch_dict = result.to_dict() if result is not None else {}
    except Exception as e:  # noqa: BLE001 — dispatcher must never crash the lane
        # Graceful degradation: emit an "unknown" envelope so the
        # downstream parser/normalizer still produce a record.
        dispatch_dict = {
            "artifact_type":        "unknown",
            "display_name":         "Unknown Artifact",
            "confidence":           0,
            "size":                 len(payload_bytes),
            "hashes":               {
                "md5":    _md5_hex(payload_bytes),
                "sha1":   _sha1_hex(payload_bytes),
                "sha256": _sha256_hex(payload_bytes),
            },
            "analysis":             {"available": False, "error": type(e).__name__,
                                       "message": "artifact dispatcher raised"},
            "capability_available": False,
            "detected_by":          "collector_fallback",
            "fallback_reason":      f"dispatcher_error:{type(e).__name__}",
        }

    source_file_id = _sha256_hex(payload_bytes)[:32]
    return FileRawPayload(
        bytes_=payload_bytes,
        filename=filename or "",
        mime=mime or "application/octet-stream",
        source_file_id=source_file_id,
        input_id=input_id,
        tenant_id=tenant_id,
        artifact_dispatch=dispatch_dict,
        parent_input_id=parent_input_id,
        discovery_depth=discovery_depth,
        provenance=collect_prov(upstream=upstream, own_id=source_file_id),
    )
