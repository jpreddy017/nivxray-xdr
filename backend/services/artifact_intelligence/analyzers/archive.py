"""Archive & Container Analyzer for Artifact Intelligence Layer.

Identifies compressed archives and containers:
- ZIP (PK\\x03\\x04)
- 7z (7z\\xbc\\xaf\\x27\\x1c)
- RAR (Rar!\\x1a\\x07)
- CAB (MSCF)
- ACE (**ACE**)
- TAR (ustar)

Performs safe metadata inspection without disk extraction or execution.
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from typing import Any, Dict, List, Optional


class ArchiveAnalyzer:
    artifact_type = "archive"
    display_name  = "Compressed Archive / Container"

    _SIGNATURES = [
        (b"PK\x03\x04", "zip", 90),
        (b"7z\xbc\xaf\x27\x1c", "7z", 95),
        (b"Rar!\x1a\x07", "rar", 95),
        (b"MSCF", "cab", 95),
    ]

    def magic_matcher(self, data: bytes) -> Optional[int]:
        if not data or len(data) < 8:
            return None
        # Fast signature matching
        for sig, _, conf in self._SIGNATURES:
            if data.startswith(sig):
                # If it has office markers, let OfficeAnalyzer take precedence
                if sig == b"PK\x03\x04" and (b"word/" in data[:4096] or b"xl/" in data[:4096] or b"[Content_Types].xml" in data[:4096]):
                    return None
                return conf
        # ACE archive detection: "**ACE**" signature appears at offset 7 of archive header
        if len(data) >= 14 and data[7:14] == b"**ACE**":
            return 98
        if data.startswith(b"**ACE**"):
            return 98
        # TAR format: 'ustar' at offset 257
        if len(data) >= 262 and data[257:262] == b"ustar":
            return 90
        return None

    def is_available(self) -> bool:
        return True

    def analyze(self, data: bytes) -> Dict[str, Any]:
        subtype = "unknown"
        if data.startswith(b"PK\x03\x04"):
            subtype = "zip"
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
            subtype = "7z"
        elif data.startswith(b"Rar!\x1a\x07"):
            subtype = "rar"
        elif data.startswith(b"MSCF"):
            subtype = "cab"
        elif (len(data) >= 14 and data[7:14] == b"**ACE**") or data.startswith(b"**ACE**"):
            subtype = "ace"
        elif len(data) >= 262 and data[257:262] == b"ustar":
            subtype = "tar"

        files: List[Dict[str, Any]] = []
        suspicious_indicators: List[str] = []

        # Safe ZIP inspection
        if subtype == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    for info in zf.infolist():
                        files.append({
                            "filename": info.filename,
                            "size": info.file_size,
                            "compress_size": info.compress_size,
                            "is_dir": info.is_dir(),
                        })
                        if ".." in info.filename or info.filename.startswith("/"):
                            suspicious_indicators.append(f"Directory traversal path: {info.filename}")
                        if info.filename.lower().endswith((".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".hta")):
                            suspicious_indicators.append(f"Executable/script payload in archive: {info.filename}")
            except Exception as e:
                suspicious_indicators.append(f"Corrupted or partial zip stream: {e}")

        # Safe TAR inspection
        elif subtype == "tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                    for member in tf.getmembers():
                        files.append({
                            "filename": member.name,
                            "size": member.size,
                            "is_dir": member.isdir(),
                        })
                        if ".." in member.name or member.name.startswith("/"):
                            suspicious_indicators.append(f"Directory traversal path: {member.name}")
            except Exception as e:
                suspicious_indicators.append(f"Corrupted tar stream: {e}")

        # ACE container specific detection
        elif subtype == "ace":
            suspicious_indicators.append("ACE archive detected (potential CVE-2019-2025 UNACE directory traversal risk)")

        return {
            "available": True,
            "subtype": subtype,
            "size": len(data),
            "file_count": len(files),
            "files": files[:50],  # bounded to first 50 files
            "suspicious_indicators": suspicious_indicators,
        }


__all__ = ["ArchiveAnalyzer"]
