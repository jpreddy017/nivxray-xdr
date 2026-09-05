"""Shellcode analyzer plugin for Artifact Intelligence Layer.

Wraps `services.analyzers.shellcode` under the Analyzer protocol.
Detects raw shellcode prologues, high-entropy machine code, and disassembles
via Capstone without payload execution or network access.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from services.analyzers.shellcode import (
    analyze as _analyze_shellcode,
    is_shellcode,
    starts_with_known_prologue,
)


class ShellcodeAnalyzer:
    artifact_type = "shellcode"
    display_name  = "Raw Shellcode / Machine Code"

    def magic_matcher(self, data: bytes) -> Optional[int]:
        if not data or len(data) < 4:
            return None
        # Strict known prologue (x86_64, x86, ARM, ARM64)
        if starts_with_known_prologue(data):
            return 95
        # Heuristic classifier (high entropy + non-printable ratio)
        if is_shellcode(data):
            return 80
        return None

    def is_available(self) -> bool:
        # Analyzer is pure Python with optional Capstone
        return True

    def analyze(self, data: bytes) -> Dict[str, Any]:
        result = _analyze_shellcode(data)
        result["available"] = True
        return result


__all__ = ["ShellcodeAnalyzer"]
