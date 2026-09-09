"""
UIL · Preprocessor (2026-03-02)
────────────────────────────────
Normalise every InputKind into a canonical text + metadata bundle.
The Workspace/Session pipeline downstream never sees raw bytes.

Binary formats (PDF · DOCX · image · EML · PCAP · PE) are DETECTED
today but their preprocessors return `pending` so the analyst gets
an honest status message.  Adding a real preprocessor later is a
drop-in: just replace the corresponding branch.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .classifier import InputKind, KIND_LABEL


@dataclass
class NormalizedInput:
    kind:        InputKind
    kind_label:  str
    text:        str                     # canonical analyst text (may be empty for pending)
    metadata:    Dict[str, Any] = field(default_factory=dict)
    fragments:   List[Dict[str, str]] = field(default_factory=list)  # from mixed-input split
    ready:       bool = True             # False → preprocessor pending
    reason:      str  = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind":       self.kind.value,
            "kind_label": self.kind_label,
            "text":       self.text,
            "metadata":   self.metadata,
            "fragments":  self.fragments,
            "ready":      self.ready,
            "reason":     self.reason,
        }


_PENDING_BINARY = {
    InputKind.PDF:          "PDF preprocessor pending — add pdfplumber to unlock",
    InputKind.DOCX:         "DOCX preprocessor pending — add python-docx to unlock",
    InputKind.PPTX:         "PPTX preprocessor pending",
    InputKind.XLSX:         "XLSX preprocessor pending",
    InputKind.IMAGE:        "Image OCR preprocessor pending — add pytesseract to unlock",
    InputKind.EMAIL_EML:    "EML preprocessor: raw text ready, header parsing pending",
    InputKind.EMAIL_MSG:    "MSG preprocessor pending — add extract-msg to unlock",
    InputKind.ZIP_ARCHIVE:  "Archive preprocessor pending",
    InputKind.SEVEN_Z:      "Archive preprocessor pending",
    InputKind.RAR_ARCHIVE:  "Archive preprocessor pending",
    InputKind.ISO:          "ISO preprocessor pending",
    InputKind.EVTX:         "EVTX preprocessor pending",
    InputKind.PCAP:         "PCAP preprocessor pending — add scapy to unlock",
    InputKind.PE_BINARY:    "PE preprocessor pending — add pefile to unlock",
    InputKind.ELF_BINARY:   "ELF preprocessor pending",
    InputKind.MACHO_BINARY: "Mach-O preprocessor pending",
    InputKind.APK:          "APK preprocessor pending",
}


def normalize(payload: Union[bytes, str],
                kind: InputKind,
                filename: Optional[str] = None) -> NormalizedInput:
    label = KIND_LABEL.get(kind, kind.value)

    # Empty input
    if kind is InputKind.EMPTY:
        return NormalizedInput(kind, label, "", ready=False, reason="empty")

    # Text-native kinds — payload is already text (or decodable).
    if isinstance(payload, (bytes, bytearray)):
        try:    text_payload = payload.decode("utf-8", "replace")
        except Exception: text_payload = ""
    else:
        text_payload = payload or ""

    # Binary formats where we DON'T have a preprocessor yet.
    if kind in _PENDING_BINARY:
        # EML is a lucky case — .eml files are actually RFC 5322 text.
        # Give the analyst the raw text so downstream extractors can
        # still pull IOCs from headers + body.
        if kind is InputKind.EMAIL_EML:
            return NormalizedInput(
                kind, label, text_payload,
                metadata={"note": "header-level parsing pending"},
                ready=True,
                reason="raw text passthrough — attachment recursion pending",
            )
        return NormalizedInput(
            kind, label, "",
            metadata={"filename": filename, "bytes": len(payload) if isinstance(payload, (bytes, bytearray)) else 0},
            ready=False,
            reason=_PENDING_BINARY[kind],
        )

    # All text-native kinds: pass through the text as-is.  The
    # existing IDA-1 artifact splitter + DIE / ICE / IOC pipeline
    # handle interpretation.
    return NormalizedInput(
        kind, label, text_payload,
        metadata={"filename": filename} if filename else {},
        ready=True,
    )
