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
        # ── R28.7.4 · Binary-fidelity fast path ─────────────────
        # The legacy decoder round-trips bytes through latin-1 → UTF-8
        # text (``_mostly_printable`` branch), which mangles the byte
        # layout when the decoded content is actually compressed /
        # executable data.  If we detect a known binary magic in the
        # raw base64 output, emit a first-class typed child carrying
        # the raw bytes so downstream capabilities (gzip.inflate,
        # zlib.inflate, pe.extractor, …) see the unmutated header.
        import base64 as _b64
        import re as _re
        text = artifact_to_text(artifact)
        matches = _re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])",
                              text or "")
        if len(matches) == 1 and len(matches[0]) >= 120:
            b64 = matches[0]
            padded = b64 + "=" * (-len(b64) % 4)
            try:
                raw = _b64.b64decode(padded, validate=False)
            except Exception:
                raw = b""
            if raw and _magic_type(raw) is not None:
                from ...artifact import make_artifact
                from ...evidence import make_evidence
                target = _magic_type(raw)
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
        # Fallback: legacy text-mode decode (@@RAWBYTES@@ sentinel).
        return self._exec(artifact)


# Magic-byte table — MUST mirror analyzer_magic_byte_retyper.
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
                wraps_legacy="recursive_decoder._decode_bare_base64")
