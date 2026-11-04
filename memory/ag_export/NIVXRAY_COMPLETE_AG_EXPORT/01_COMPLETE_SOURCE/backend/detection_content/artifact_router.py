"""
NivXRay XDR — Artifact-First Analysis Router.
Implements the authoritative workflow:
    Downloaded/attached artifact
              ↓
        Artifact Router
              ↓
  artifact-specific analyzer
              ↓
     YARA / static analysis
              ↓
 embedded payload discovery
              ↓
 decoder only when required
              ↓
      semantic analysis
              ↓
       Security State

Reuses the frozen Universal Decoder, specialized analyzers, and YARA engine
without modifying their internal architectures.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import math
import os
import re
from typing import Any, Dict, List, Optional

from .yara_engine import YARA_ENGINE, YaraRuleMatch


def compute_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1
    for f in frequencies:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass
class ArtifactAnalysisReport:
    artifact_id: str
    filename: str
    artifact_type: str
    size_bytes: int
    entropy: float
    hashes: Dict[str, str]
    magic_description: str
    specialized_analysis: Dict[str, Any]
    yara_matches: List[Dict[str, Any]]
    embedded_payloads_discovered: List[Dict[str, Any]]
    decoder_invoked: bool
    decoded_results: Optional[Dict[str, Any]]
    semantic_intelligence: Dict[str, Any]
    security_state_impact: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ArtifactRouter:
    """Authoritative dispatcher and orchestrator for file artifacts and evidence."""

    @classmethod
    def identify_artifact_type(cls, data: bytes) -> Tuple[str, str]:
        """Classify payload by magic bytes and header structure."""
        if len(data) >= 2 and data[:2] == b"MZ":
            return "windows_pe", "Windows Portable Executable (MZ header)"
        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "linux_elf", "Linux Executable and Linkable Format (ELF header)"
        if len(data) >= 4 and data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
            return "macos_macho", "macOS Mach-O Binary"
        if len(data) >= 4 and data[:4] == b"PK\x03\x04":
            if b"[Content_Types].xml" in data:
                return "office_ooxml", "Microsoft Office OpenXML Document (DOCX/XLSX/PPTX)"
            return "archive_zip", "Zip Compressed Archive (PKZIP)"
        if len(data) >= 8 and data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return "office_ole", "Microsoft Office OLE Compound Document"
        if len(data) >= 4 and data[:4] == b"%PDF":
            return "pdf_document", "Adobe Portable Document Format (PDF)"
        if len(data) >= 6 and data[:6] in (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"):
            return "archive_compressed", "Compressed Archive (7-Zip / RAR)"

        # Text and Script check
        try:
            text = data.decode("utf-8")
            if any(term in text.lower() for term in ("powershell", "function", "param(", "cmd.exe", "invoke-", "iex")):
                return "script_powershell", "PowerShell Script Text"
            if any(term in text.lower() for term in ("#!/bin/bash", "#!/bin/sh", "curl ", "wget ", "chmod +x")):
                return "script_shell", "Unix Shell Script Text"
            if len(data) > 32 and re.match(r'^[A-Za-z0-9+/=\s]+$', text[:1024]):
                return "encoded_blob", "Base64 / Hex Encoded ASCII Blob"
            return "plain_text", "Plain Text / Script"
        except UnicodeDecodeError:
            pass

        return "unknown_binary", "Unknown Raw Binary Artifact"

    @classmethod
    def route_and_analyze(
        cls,
        data: bytes,
        filename: str = "artifact.bin",
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactAnalysisReport:
        """Executes full Artifact Router pipeline without modifying Universal Decoder."""
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        entropy = compute_shannon_entropy(data)
        artifact_type, magic_desc = cls.identify_artifact_type(data)

        # 1. Specialized static analysis
        specialized: Dict[str, Any] = {"analyzer": artifact_type, "status": "analyzed"}
        embedded_payloads: List[Dict[str, Any]] = []

        if artifact_type == "windows_pe":
            specialized["architecture"] = "PE32+" if b"PE\x00\x00d\x86" in data else "PE32"
            specialized["has_suspicious_sections"] = any(sec in data for sec in (b".upx", b".themida", b".vmp"))
            # Search for embedded PowerShell or URLs in strings
            matches = re.findall(rb'https?://[a-zA-Z0-9\.\-_/:\?=%&]+', data)
            if matches:
                specialized["extracted_urls"] = [m.decode('latin-1') for m in matches[:5]]
            ps_match = re.findall(rb'powershell(?:\.exe)?\s+[^\x00\r\n]{10,}', data, re.IGNORECASE)
            if ps_match:
                for pm in ps_match[:3]:
                    embedded_payloads.append({
                        "type": "embedded_powershell_command",
                        "raw_bytes": pm.decode('latin-1', errors='replace'),
                        "requires_decoding": True,
                    })

        elif artifact_type in ("office_ooxml", "office_ole"):
            specialized["has_vba_macros"] = b"vbaProject.bin" in data or b"Attribut" in data
            if specialized["has_vba_macros"]:
                # Look for auto-exec markers
                specialized["auto_exec_markers"] = [
                    marker.decode('ascii') for marker in (b"AutoOpen", b"Document_Open", b"Workbook_Open")
                    if marker in data
                ]
                # Look for embedded base64 or shell strings
                b64_matches = re.findall(rb'[A-Za-z0-9+/]{40,}={0,2}', data)
                if b64_matches:
                    for b64 in b64_matches[:2]:
                        embedded_payloads.append({
                            "type": "macro_base64_payload",
                            "raw_bytes": b64.decode('ascii', errors='replace'),
                            "requires_decoding": True,
                        })

        elif artifact_type == "pdf_document":
            specialized["has_javascript"] = b"/JavaScript" in data or b"/JS" in data
            specialized["has_launch_action"] = b"/Launch" in data or b"/EmbeddedFiles" in data

        elif artifact_type in ("script_powershell", "encoded_blob"):
            embedded_payloads.append({
                "type": "script_or_encoded_command",
                "raw_bytes": data.decode('latin-1', errors='replace'),
                "requires_decoding": True,
            })

        # 2. First-class YARA Static Inspection
        yara_hits = YARA_ENGINE.scan_artifact(data, filename)
        yara_report = [
            {
                "rule_name": hit.rule_name,
                "threat_family": hit.threat_family,
                "confidence": hit.confidence,
                "tags": hit.tags,
                "matched_count": hit.matched_count,
                "matched_strings": [asdict(s) for s in hit.matched_strings[:5]],
                "mitre_attack": hit.mitre_attack,
            }
            for hit in yara_hits
        ]

        # 3. Embedded Payload Discovery & Conditional Decoding
        decoder_invoked = False
        decoded_results: Optional[Dict[str, Any]] = None

        if any(p.get("requires_decoding") for p in embedded_payloads):
            # Only invoke decoder when payload discovery reveals encoded command
            decoder_invoked = True
            # Safely invoke existing DDO / smart decoder without modifying engine
            try:
                from ..services.decoder.engine import UniversalDecoderEngine
                dec_engine = UniversalDecoderEngine()
                sample_payload = next(p["raw_bytes"] for p in embedded_payloads if p.get("requires_decoding"))
                dec_res = dec_engine.decode(sample_payload)
                decoded_results = {
                    "final_payload": dec_res.final_payload,
                    "depth": dec_res.depth,
                    "stages_count": len(dec_res.stages),
                    "stop_reason": dec_res.stop_reason,
                }
            except Exception as e:
                decoded_results = {"error": f"Decoder execution failed: {str(e)}"}

        # 4. Semantic Intelligence & Security State Impact
        threat_families = [y["threat_family"] for y in yara_report if y["threat_family"] != "UnknownMalware"]
        threat_fam = threat_families[0] if threat_families else "SuspiciousArtifact"

        mitre_ttps: List[str] = ["T1204.002"]  # User Execution: Malicious File
        if specialized.get("has_vba_macros"):
            mitre_ttps.append("T1059.005")  # Visual Basic
        if yara_hits:
            for yh in yara_hits:
                mitre_ttps.extend(yh.mitre_attack)

        semantic_intel = {
            "threat_family": threat_fam,
            "is_malicious": len(yara_hits) > 0 or entropy > 7.2 or bool(specialized.get("has_vba_macros")),
            "mitre_ttps": sorted(list(set(mitre_ttps))),
            "intent": "code_execution_via_artifact",
        }

        sec_state_impact = {
            "evidence_type": "artifact_discovery",
            "proven_capability": "malware_artifact_delivery",
            "threat_family": threat_fam,
            "escalated_abuse_state": "CONFIRMED_ATTACK" if yara_hits else "SUSPICIOUS_ANOMALY",
            "reachability_factors": ["host_filesystem_exposure", "user_execution_risk"],
        }

        return ArtifactAnalysisReport(
            artifact_id=f"ART-{sha256[:12].upper()}",
            filename=filename,
            artifact_type=artifact_type,
            size_bytes=len(data),
            entropy=entropy,
            hashes={"md5": md5, "sha1": sha1, "sha256": sha256},
            magic_description=magic_desc,
            specialized_analysis=specialized,
            yara_matches=yara_report,
            embedded_payloads_discovered=embedded_payloads,
            decoder_invoked=decoder_invoked,
            decoded_results=decoded_results,
            semantic_intelligence=semantic_intel,
            security_state_impact=sec_state_impact,
        )


ARTIFACT_ROUTER = ArtifactRouter()
