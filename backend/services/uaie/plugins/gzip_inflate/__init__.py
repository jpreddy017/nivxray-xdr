"""Plugin · GZip Inflate (R26 · wraps ``_decode_gzip_bytes``).

Detects the ``@@RAWBYTES@@…`` sentinel + GZip magic (0x1F 0x8B) and
inflates in place.  Also surfaces embedded C2 IOCs when the inflated
payload is raw shellcode (Sophos/Cobalt Strike terminal layer).
"""
from __future__ import annotations

from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, CERTAIN
from ...capability import Capability, CapabilityResult, register
from .._shared     import wrap_legacy_decoder, artifact_to_text
from services.die.preprocessor.recursive_decoder import (
    _decode_gzip_bytes as _LEGACY_DECODE,
    _extract_rawbytes as _LEGACY_EXTRACT,
)
from .. import register_plugin


NAME    = "gzip.inflate"
VERSION = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        text = artifact_to_text(artifact)
        hit = _LEGACY_EXTRACT(text or "")
        if not hit:
            return []
        raw, _s, _e = hit
        if len(raw) < 4 or raw[0] != 0x1F or raw[1] != 0x8B:
            return []
        return [Recognition(
            artifact_type="gzip_bytes",
            confidence=CERTAIN,
            reasons=[Reason("magic_bytes", 0.95, "0x1F 0x8B (gzip)")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["text", "base64_decoded", "gzip_bytes"]
    requires_evidence      = []

    def __init__(self):
        self._exec = wrap_legacy_decoder(
            plugin_name=NAME,
            child_type="gzip_decoded",
            legacy=_LEGACY_DECODE,
        )

    def execute(self, artifact: Artifact) -> CapabilityResult:
        return self._exec(artifact)


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._decode_gzip_bytes")
