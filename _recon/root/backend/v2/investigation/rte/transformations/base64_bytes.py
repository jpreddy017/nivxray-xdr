"""base64_bytes · decode a base64 blob to opaque bytes.

Last-resort base64 transformation used when the blob decodes to a
non-textual payload (compressed data, PE bytes, etc.). We surface the
bytes as a hex-encoded string so subsequent transformations (gzip,
zlib, PE parsing) can recognise the layer. The byte-hash is recorded
in ``meta`` for provenance.

Confidence is intentionally modest — only fires when neither
UTF-16LE nor UTF-8 decoding produced printable text.
"""
from __future__ import annotations

import base64
import hashlib
import re

from ...evidence import Evidence
from ..models import Artifact
from ._util import printable_ratio, strip_quotes

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
# Magic bytes we recognise as ``interesting`` post-decode. These drive
# the confidence up because downstream compression/PE decoders can
# take over.
_KNOWN_MAGIC = {
    b"\x1f\x8b":       "gzip",
    b"\x78\x9c":       "zlib_default",
    b"\x78\x01":       "zlib_none",
    b"\x78\xda":       "zlib_best",
    b"MZ":             "pe_header",
    b"PK\x03\x04":     "zip",
    b"BZh":            "bzip2",
}


def _magic(raw: bytes) -> str | None:
    for prefix, name in _KNOWN_MAGIC.items():
        if raw.startswith(prefix):
            return name
    return None


class Base64BytesTransformation:
    NAME = "base64_bytes"

    def _candidate(self, artifact: Artifact) -> str | None:
        text = strip_quotes(artifact.content).strip()
        if len(text) < 24:
            return None
        compact = "".join(text.split())
        if len(compact) % 4 != 0:
            return None
        if not _B64_RE.match(compact):
            return None
        return compact

    def applicable(self, artifact: Artifact) -> Evidence | None:
        blob = self._candidate(artifact)
        if blob is None:
            return None
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            return None
        # Only fires when text-decoders would fail — otherwise the
        # higher-priority utf16le / utf8 plugins take precedence.
        for enc in ("utf-16-le", "utf-8"):
            try:
                if printable_ratio(raw.decode(enc)) >= 0.90:
                    return None
            except UnicodeDecodeError:
                pass
        magic = _magic(raw)
        confidence = 80 if magic else 55
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=f"base64 blob of {len(blob)} chars → {len(raw)} bytes"
                        + (f" (magic: {magic})" if magic else ""),
            confidence=confidence,
            rationale=(
                "Well-formed base64 blob whose bytes are non-textual — "
                "surfaced as a hex artefact so downstream compression / "
                "binary transformations can take over."
                + (f" Magic bytes indicate {magic}." if magic else "")
            ),
            meta={"byte_length": len(raw), "magic": magic},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        blob = self._candidate(artifact)
        assert blob is not None
        raw = base64.b64decode(blob, validate=True)
        digest = hashlib.sha256(raw).hexdigest()[:16]
        # Surface as hex — grep-friendly, deterministic, greppable.
        hex_form = raw.hex()
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=f"sha256[:16]={digest} · {len(raw)} bytes",
            confidence=80 if _magic(raw) else 55,
            rationale=(
                "Decoded base64 to opaque bytes; presented as hex so the "
                "next stage (gzip / zlib / PE / …) can recognise it."
            ),
            meta={
                "in_len":      len(artifact.content),
                "out_bytes":   len(raw),
                "sha256":      digest,
                "magic":       _magic(raw),
                "output_kind": "hex_bytes",
            },
        )
        return hex_form, [ev]


TRANSFORMATION = Base64BytesTransformation()
