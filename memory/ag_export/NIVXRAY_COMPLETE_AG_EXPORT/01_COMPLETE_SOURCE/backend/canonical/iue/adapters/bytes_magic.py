"""Adapter · Bytes-Magic (IUE-4).

Wraps services/uil/classifier.classify — the only sub-classifier that
natively handles bytes/binary. Required for Amendment 1 T1.7.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from services.uil.classifier import classify as uil_classify, InputKind

from ..models import IUEEvidence, Provenance, RawInput


PROV = Provenance(engine="canonical.iue.adapters.bytes_magic",
                  version="1.0.0",
                  at="phase1",
                  upstream_evidence_ids=[])


# Confidence per InputKind — binary/rich formats get high confidence
# because they are magic-byte-detected; textual defaults get lower.
_HIGH_CONF = {
    InputKind.PE_BINARY, InputKind.ELF_BINARY, InputKind.MACHO_BINARY,
    InputKind.APK, InputKind.PDF, InputKind.DOCX, InputKind.PPTX,
    InputKind.XLSX, InputKind.ZIP_ARCHIVE, InputKind.SEVEN_Z,
    InputKind.RAR_ARCHIVE, InputKind.ISO, InputKind.EVTX, InputKind.PCAP,
    InputKind.IMAGE, InputKind.EMAIL_MSG, InputKind.EMAIL_EML,
}


def bytes_magic_evidence(raw: RawInput) -> Tuple[Optional[str], List[IUEEvidence]]:
    """Return (canonical_primary_type_from_bytes | None, evidence[])."""
    # UIL accepts bytes directly — Phase 1 uses it as the byte-safe classifier.
    payload = raw.payload if isinstance(raw.payload, (bytes, str)) else str(raw.payload)
    kind = uil_classify(payload, filename=raw.filename)

    conf = 95 if kind in _HIGH_CONF else 55
    obs = f"bytes-magic classified as {kind.value}"
    rationale = (
        f"UIL bytes-magic sniff on {raw.size()} bytes"
        f"{' (filename=' + raw.filename + ')' if raw.filename else ''}"
    )

    ev = IUEEvidence(
        id="ev.bytes_magic.0001",
        source="bytes_magic",
        observation=obs,
        confidence=conf,
        rationale=rationale,
        meta={
            "input_kind": kind.value,
            "size_bytes": raw.size(),
            "byte_signature": raw.as_bytes()[:16].hex(),
        },
        provenance=PROV,
    )
    return kind.value, [ev]
