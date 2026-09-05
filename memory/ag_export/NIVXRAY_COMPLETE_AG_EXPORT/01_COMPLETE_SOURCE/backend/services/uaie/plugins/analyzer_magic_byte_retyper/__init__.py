"""Plugin · analyzer.magic_byte_retyper  (R28.7.4 · Generic Retyper)

Universal magic-byte-based *Recognizer* AND fallback Capability.

Recognizer  (primary):
    Inspects the first 8 bytes of any artifact's payload and emits
    ``Recognition`` records for every well-known magic header.  The
    orchestrator's ``matched_types`` union then invites every
    capability registered for that type to run — WITHOUT modifying
    the payload or introducing URI collisions.

Capability  (secondary):
    Only fires when the artifact's payload is wrapped in the legacy
    ``@@RAWBYTES@@<hex>`` sentinel produced by pre-UAIE text-mode
    decoders.  Extracts the real bytes and emits a first-class
    typed child (``gzip_bytes`` / ``pe_bytes`` / etc.) whose payload
    is the raw bytes so downstream capabilities can consume them
    natively.

Both paths share the SAME magic-byte table (below) — this is 100 %
generic; extend freely.  Zero malware-family knowledge lives here.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ...artifact   import Artifact, make_artifact
from ...capability import CapabilityResult
from ...contract   import (CAT_ANALYZER, CAT_RECOGNIZER,
                              CapabilityContract, IMPROVES_ANALYSIS,
                              register)
from ...recognizer import Recognition, Reason, HIGH


_RAWBYTES_RE = re.compile(rb"@@RAWBYTES@@([0-9a-fA-F]+)")


# ── Magic → target type (single source of truth, generic) ──────────
def _detect_magic(buf: bytes) -> Optional[str]:
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


_TARGET_TYPES = {
    "gzip_bytes", "zlib_bytes", "pe_bytes", "zip_bytes", "elf_bytes",
    "pdf_bytes", "wasm_bytes", "xz_bytes", "bzip2_bytes",
}


def _extract_bytes(payload: bytes) -> Tuple[bytes, str]:
    """Return ``(raw_bytes, source)`` where ``source`` is ``"sentinel"``
    (payload contained ``@@RAWBYTES@@<hex>``) or ``"raw"``."""
    m = _RAWBYTES_RE.search(payload)
    if m:
        try:
            return bytes.fromhex(m.group(1).decode("ascii")), "sentinel"
        except ValueError:
            return payload, "raw"
    return payload, "raw"


# ══════════════════════════════════════════════════════════════════
# Recognizer — adds a matched_type entry when payload starts with
# a known magic.  Registered through ``all_recognizers`` so it
# participates in the orchestrator's Recognition phase.
# ══════════════════════════════════════════════════════════════════
class _Recognizer:
    name = "analyzer.magic_byte_retyper"

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        # Skip if the artifact is already typed correctly — nothing
        # to add.
        if artifact.artifact_type in _TARGET_TYPES:
            return []
        # Only inspect raw payloads (not the sentinel form — the
        # Capability handles that).  We inspect the first 8 bytes of
        # the actual payload directly.
        buf = artifact.payload or b""
        if not buf:
            return []
        target = _detect_magic(buf)
        if not target:
            return []
        return [Recognition(
            artifact_type=target,
            confidence=HIGH,
            reasons=[Reason("magic_bytes", 0.90,
                             f"first bytes {buf[:4].hex()} → {target}")],
            recognizer=self.name,
        )]


# ══════════════════════════════════════════════════════════════════
# Capability — sentinel-extraction path (legacy compatibility)
# ══════════════════════════════════════════════════════════════════
class _Impl:
    name = "analyzer.magic_byte_retyper"
    requires_artifact_type = ["*"]
    requires_evidence      = []

    def execute(self, artifact) -> CapabilityResult:
        # Only handle the sentinel form — the raw-bytes case is
        # covered by the Recognizer above (no artifact copy required).
        if artifact.artifact_type in _TARGET_TYPES:
            return CapabilityResult()
        payload = artifact.payload or b""
        if not payload or not _RAWBYTES_RE.search(payload):
            return CapabilityResult()
        raw, source = _extract_bytes(payload)
        if source != "sentinel":
            return CapabilityResult()
        target = _detect_magic(raw)
        if not target:
            return CapabilityResult()
        child = make_artifact(
            raw, target,
            parent_uri=artifact.uri,
            depth=artifact.depth + 1,
            discovered_by=self.name,
            meta={
                "retyped_from":  artifact.artifact_type,
                "extraction":    source,
                "original_size": artifact.size,
                "retyped_size":  len(raw),
            },
        )
        return CapabilityResult(child_artifacts=[child])


recognizer = _Recognizer()
_impl      = _Impl()


register(
    CapabilityContract(
        id="analyzer.magic_byte_retyper",
        version="1.1",
        category=CAT_ANALYZER,
        requires=("*",),
        produces=tuple(sorted(_TARGET_TYPES)),
        improves=(IMPROVES_ANALYSIS,),
        confidence_gain=0.20,
        produces_confidence=(("analysis_confidence", 0.20),),
        cost=1,
        priority_hint=1,
        parallelizable=True,
        deterministic=True,
        description=(
            "Universal magic-byte retyper.  Emits Recognition records "
            "for raw-byte artifacts whose header matches a well-known "
            "magic (gzip, zlib, PE, ZIP, ELF, PDF, WASM, XZ, BZIP2), "
            "AND unwraps the legacy ``@@RAWBYTES@@<hex>`` sentinel into "
            "first-class typed children.  No malware-family logic."
        ),
    ),
    impl=_impl,
)


# ── Register with the plugin loader so all_recognizers() includes us ─
from .. import register_plugin
register_plugin(
    _impl.name, "1.1", recognizer, _impl,
    wraps_legacy="none — first-class contract",
)


__all__ = ["_impl", "recognizer"]
