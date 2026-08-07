"""Plugin · [Convert]::FromBase64String("…") (R26 · wraps
``_decode_frombase64string``).
"""
from __future__ import annotations

from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, HIGH
from ...capability import Capability, CapabilityResult, register
from .._shared     import wrap_legacy_decoder, artifact_to_text
from services.die.preprocessor.recursive_decoder import (
    _decode_frombase64string as _LEGACY_DECODE,
    _FROM_B64_RE            as _LEGACY_RE,
)
from .. import register_plugin


NAME    = "base64.from_base64_string"
VERSION = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        text = artifact_to_text(artifact)
        if not _LEGACY_RE.search(text or ""):
            return []
        return [Recognition(
            artifact_type="base64_from_base64_string",
            confidence=HIGH,
            reasons=[Reason("grammar", 0.75, "[Convert]::FromBase64String literal")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["text", "powershell", "base64_from_base64_string"]
    requires_evidence      = []

    def __init__(self):
        self._exec = wrap_legacy_decoder(
            plugin_name=NAME,
            child_type="base64_decoded",
            legacy=_LEGACY_DECODE,
        )

    def execute(self, artifact: Artifact) -> CapabilityResult:
        return self._exec(artifact)


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._decode_frombase64string")
