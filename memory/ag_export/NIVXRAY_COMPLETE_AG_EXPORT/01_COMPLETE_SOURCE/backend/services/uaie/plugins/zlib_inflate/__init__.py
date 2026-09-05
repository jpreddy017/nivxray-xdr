"""Plugin · Zlib Inflate (R26 · wraps ``_decode_zlib_bytes``)."""
from __future__ import annotations

from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, HIGH
from ...capability import Capability, CapabilityResult, register
from .._shared     import wrap_legacy_decoder, artifact_to_text
from services.die.preprocessor.recursive_decoder import (
    _decode_zlib_bytes as _LEGACY_DECODE,
    _extract_rawbytes  as _LEGACY_EXTRACT,
)
from .. import register_plugin


NAME    = "zlib.inflate"
VERSION = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        text = artifact_to_text(artifact)
        hit = _LEGACY_EXTRACT(text or "")
        if not hit:
            return []
        raw, _s, _e = hit
        if len(raw) < 2 or raw[0] != 0x78 or raw[1] not in (0x01, 0x5E, 0x9C, 0xDA):
            return []
        return [Recognition(
            artifact_type="zlib_bytes",
            confidence=HIGH,
            reasons=[Reason("magic_bytes", 0.85, "0x78 (zlib)")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["text", "base64_decoded", "zlib_bytes"]
    requires_evidence      = []

    def __init__(self):
        self._exec = wrap_legacy_decoder(
            plugin_name=NAME,
            child_type="zlib_decoded",
            legacy=_LEGACY_DECODE,
        )

    def execute(self, artifact: Artifact) -> CapabilityResult:
        # ── R28.7.4 · Native raw-bytes fast-path ─────────────────
        buf = artifact.payload or b""
        if (len(buf) >= 2 and buf[0] == 0x78
                and buf[1] in (0x01, 0x5E, 0x9C, 0xDA)):
            import zlib as _zlib
            try:
                inflated = _zlib.decompress(buf)
            except Exception:
                return self._exec(artifact)
            from ...artifact   import make_artifact
            from ...evidence   import make_evidence
            child = make_artifact(
                inflated, "zlib_decoded",
                parent_uri=artifact.uri,
                depth=artifact.depth + 1,
                discovered_by=NAME,
                meta={"bytes_in": len(buf), "bytes_out": len(inflated),
                        "path": "native_raw_bytes"},
            )
            ev = make_evidence(
                artifact_uri=artifact.uri, kind="decode_layer",
                value="zlib_decoded",
                source_capability=NAME, confidence=0.95, severity="info",
                location=f"depth={artifact.depth}",
                meta={"bytes_in": len(buf), "bytes_out": len(inflated),
                        "child_uri": child.uri, "path": "native_raw_bytes"},
            )
            return CapabilityResult(evidence=[ev], child_artifacts=[child])
        return self._exec(artifact)


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._decode_zlib_bytes")
