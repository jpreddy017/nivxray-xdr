"""Plugin · Bare Base64 Blob (R26 · wraps ``_decode_bare_base64``).

Recognizes a standalone long base64 blob (>= 120 chars, single match)
and produces one decoded child artifact.
"""
from __future__ import annotations

import re
from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, LIKELY, HIGH
from ...capability import Capability, CapabilityResult, register
from .._shared     import wrap_legacy_decoder, artifact_to_text
from services.die.preprocessor.recursive_decoder import (
    _decode_bare_base64 as _LEGACY_DECODE,
    _BARE_B64_RE       as _LEGACY_RE,
)
from .. import register_plugin


NAME     = "base64.bare"
VERSION  = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        text = artifact_to_text(artifact)
        matches = _LEGACY_RE.findall(text or "")
        # Legacy requires exactly one match AND length >= 120.
        if len(matches) != 1 or len(matches[0]) < 120:
            return []
        return [Recognition(
            artifact_type="base64_bare",
            confidence=HIGH,
            reasons=[
                Reason("grammar",  0.60, "single bare base64 blob"),
                Reason("length",   0.30, f"len={len(matches[0])}"),
            ],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["text", "base64_bare"]
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
                wraps_legacy="recursive_decoder._decode_bare_base64")
