"""PE analyzer plugin — wraps `services.pe_analyzer` under the
Artifact Intelligence Layer contract (Phase 3 · Cycle A · 2026-02).

This preserves the existing deterministic PE analysis exactly — the
retrofit is a thin adapter, not a rewrite.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from services.pe_analyzer import analyze_pe, is_available as _pefile_available


class PEAnalyzer:
    artifact_type = "pe"
    display_name  = "Portable Executable (PE)"

    def magic_matcher(self, data: bytes) -> Optional[int]:
        # DOS/PE binaries begin with 'MZ'. High confidence only when
        # the surrounding window is non-printable (guard against a
        # sentence that starts with the letters "MZ").
        if not data.startswith(b"MZ"):
            return None
        window = data[:512]
        printable = sum(1 for b in window if 0x20 <= b < 0x7f) / max(1, len(window))
        if printable > 0.85:
            return None
        # Optional NT signature check bumps confidence.
        try:
            e_lfanew = int.from_bytes(data[60:64], "little")
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return 99
        except Exception:
            pass
        return 85

    def is_available(self) -> bool:
        return _pefile_available()

    def analyze(self, data: bytes) -> Dict[str, Any]:
        return analyze_pe(data)


__all__ = ["PEAnalyzer"]
