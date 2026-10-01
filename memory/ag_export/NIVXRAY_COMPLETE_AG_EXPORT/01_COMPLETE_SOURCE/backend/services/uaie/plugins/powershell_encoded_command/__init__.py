"""Plugin · PowerShell -EncodedCommand (base64 → UTF-16LE).
(R26 · wraps ``_decode_ps_encoded_command``.)
"""
from __future__ import annotations

from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, CERTAIN
from ...capability import Capability, CapabilityResult, register
from .._shared     import wrap_legacy_decoder, artifact_to_text
from services.die.preprocessor.recursive_decoder import (
    _decode_ps_encoded_command as _LEGACY_DECODE,
    _ENC_CMD_RE               as _LEGACY_RE,
)
from .. import register_plugin


NAME    = "powershell.encoded_command"
VERSION = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        text = artifact_to_text(artifact)
        if not _LEGACY_RE.search(text or ""):
            return []
        return [Recognition(
            artifact_type="powershell_encoded_command",
            confidence=CERTAIN,
            reasons=[Reason("grammar", 0.90,
                            "powershell -EncodedCommand pattern")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["text", "powershell", "powershell_encoded_command"]
    requires_evidence      = []

    def __init__(self):
        self._exec = wrap_legacy_decoder(
            plugin_name=NAME,
            child_type="powershell",
            legacy=_LEGACY_DECODE,
        )

    def execute(self, artifact: Artifact) -> CapabilityResult:
        return self._exec(artifact)


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._decode_ps_encoded_command")
