"""Plugin · PE Embedded Extractor (Priority 6 · frozen).

Deterministically finds embedded ``MZ`` / PE binaries inside ANY
peeled artifact (base64_decoded, gzip_decoded, zlib_decoded,
xor_decoded, crypto_decoded, shellcode_bytes, text) and emits them
as ``pe_bytes`` child artifacts.

Once emitted, the existing ``pe.analyzer`` plugin (already wired at
Planner priority 51) picks the child up automatically — so decoded
loaders continue through PE → Imports / Sections / Metadata /
IOC-extraction / Family without any second pass.

R26 compliance
──────────────
    · Pure byte-level scan — no heuristics beyond DOS+PE header math.
    · No re-implementation of PE parsing — that is the job of the
      ``services.pe_analyzer`` module invoked by ``pe.analyzer``.
    · Emits at most 3 PEs per artifact (defensive; real loaders
      almost never carry more).
"""
from __future__ import annotations

import struct
from time    import perf_counter
from typing  import List

from ...artifact   import Artifact, make_artifact
from ...recognizer import Recognition, Reason, HIGH, CERTAIN, LIKELY
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin


NAME    = "pe.extractor"
VERSION = "1.0.0"

# Every peeled type that can plausibly carry an embedded PE.
_HOST_TYPES = (
    "text", "unknown",
    "base64_decoded", "gzip_decoded", "zlib_decoded",
    "xor_decoded", "crypto_decoded",
    "shellcode_bytes",
    "powershell_normalized",
)

_MZ = b"MZ"
_PE = b"PE\x00\x00"
_MAX_EXTRACT_PER_ARTIFACT = 3
_MIN_PE_SIZE              = 512     # smaller than this is almost certainly noise


def _find_pe_offsets(buf: bytes) -> List[int]:
    """Return every offset where a valid MZ + e_lfanew + PE\\0\\0 signature
    is present.  Uses the classic DOS-header/e_lfanew redirection rather
    than trusting the raw ``MZ`` bytes, so ``MZ`` prefixes in ASCII noise
    do not produce false positives.
    """
    hits: List[int] = []
    if not buf or len(buf) < _MIN_PE_SIZE:
        return hits
    start = 0
    while True:
        i = buf.find(_MZ, start)
        if i < 0 or i + 0x40 > len(buf):
            break
        # e_lfanew lives at offset 0x3C from the DOS header start.
        try:
            e_lfanew = struct.unpack_from("<I", buf, i + 0x3C)[0]
        except struct.error:
            break
        # Bound-check the PE signature offset before touching bytes.
        pe_off = i + e_lfanew
        if 0 < e_lfanew < 0x1000 and pe_off + 4 <= len(buf):
            if buf[pe_off:pe_off + 4] == _PE:
                hits.append(i)
                if len(hits) >= _MAX_EXTRACT_PER_ARTIFACT:
                    break
        start = i + 2   # step past this MZ and keep scanning
    return hits


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        # Cheap prefilter: any candidate MZ present at all?
        if _MZ not in artifact.payload:
            return []
        offsets = _find_pe_offsets(artifact.payload)
        if not offsets:
            return []
        # If MZ is at offset 0 the artifact IS a PE; give the PE analyzer
        # a direct signal without going through extraction.  Otherwise we
        # signal ``pe_extraction_candidate`` and let the capability peel it.
        if offsets == [0] and artifact.artifact_type != "pe_bytes":
            return [Recognition(
                artifact_type="pe_bytes",
                confidence=CERTAIN,
                reasons=[Reason("mz_at_offset_0", 0.95, "root MZ+PE header")],
                recognizer=NAME,
            )]
        return [Recognition(
            artifact_type=artifact.artifact_type or "unknown",
            confidence=HIGH if len(offsets) >= 2 else LIKELY,
            reasons=[Reason("embedded_pe", 0.75,
                              f"{len(offsets)} embedded PE(s) found")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = list(_HOST_TYPES)
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        offsets = _find_pe_offsets(artifact.payload)
        if not offsets:
            return CapabilityResult(
                notes={"pe_extractor_status": "no_embedded_pe"},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )

        evidence  = []
        children  = []
        for idx, off in enumerate(offsets):
            # We don't know the PE's exact size without parsing sections,
            # so extract from the offset to end-of-buffer.  ``pe.analyzer``
            # (which wraps pefile) does the section-based trimming itself.
            pe_bytes = artifact.payload[off:]
            if len(pe_bytes) < _MIN_PE_SIZE:
                continue
            children.append(make_artifact(
                payload=pe_bytes,
                artifact_type="pe_bytes",
                parent_uri=artifact.uri,
                depth=artifact.depth + 1,
                discovered_by=NAME,
                meta={"pe_offset":    off,
                        "extract_index": idx,
                        "host_type":     artifact.artifact_type},
            ))
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind="embedded_pe",
                value=f"PE @ offset 0x{off:x} ({len(pe_bytes)} bytes)",
                source_capability=NAME,
                confidence=0.90,
                severity="high",
                mitre_techniques=["T1027.009"],  # Embedded Payloads
                kill_chain=["defense-evasion"],
                location=f"pe_extractor.offset_{off}",
                meta={"offset": off, "size": len(pe_bytes)},
            ))

        return CapabilityResult(
            evidence=evidence,
            child_artifacts=children,
            notes={"pe_extractor_status": "extracted",
                     "pe_count": len(children)},
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="(new · deterministic MZ+PE offset scanner)")
