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
        # ── R28.7.4 · Binary-fidelity fast path ─────────────────
        import base64 as _b64
        text = artifact_to_text(artifact)
        m = _LEGACY_RE.search(text or "")
        if m:
            import re as _re
            b64 = _re.sub(r"\s+", "", m.group("b64"))
            padded = b64 + "=" * (-len(b64) % 4)
            try:
                raw = _b64.b64decode(padded, validate=False)
            except Exception:
                raw = b""
            target = _magic_type(raw) if raw else None
            if target is not None:
                from ...artifact import make_artifact
                from ...evidence import make_evidence
                child = make_artifact(
                    raw, target,
                    parent_uri=artifact.uri,
                    depth=artifact.depth + 1,
                    discovered_by=NAME,
                    meta={"b64_len": len(padded), "path": "raw_bytes_fast_path"},
                )
                ev = make_evidence(
                    artifact_uri=artifact.uri, kind="decode_layer",
                    value=target,
                    source_capability=NAME, confidence=0.95, severity="info",
                    location=f"depth={artifact.depth}",
                    meta={"child_uri": child.uri, "raw_size": len(raw),
                            "path": "raw_bytes_fast_path"},
                )
                return CapabilityResult(evidence=[ev], child_artifacts=[child])
        return self._exec(artifact)


def _magic_type(buf: bytes):
    if len(buf) < 2:
        return None
    if buf[0] == 0x1F and buf[1] == 0x8B:                       return "gzip_bytes"
    if buf[0] == 0x78 and buf[1] in (0x01, 0x5E, 0x9C, 0xDA):   return "zlib_bytes"
    if buf[:2] == b"MZ":                                         return "pe_bytes"
    if buf[:4] == b"PK\x03\x04":                                 return "zip_bytes"
    if buf[:4] == b"\x7fELF":                                    return "elf_bytes"
    if buf[:4] == b"%PDF":                                       return "pdf_bytes"
    if buf[:4] == b"\x00asm":                                    return "wasm_bytes"
    if buf[:6] == b"\xfd7zXZ\x00":                               return "xz_bytes"
    if buf[:3] == b"BZh":                                        return "bzip2_bytes"
    return None


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._decode_frombase64string")
