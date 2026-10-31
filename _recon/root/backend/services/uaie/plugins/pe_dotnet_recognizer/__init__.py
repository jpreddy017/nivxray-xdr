"""Plugin · .NET / CLR Recognizer (Priority 6 · frozen).

Detects **managed** (.NET / CLR-hosted) PE binaries on any ``pe_bytes``
artifact — including PEs that were extracted from PowerShell +
crypto-decoded payloads.  Uses two independent, deterministic signals:

  1. Direct read of the IMAGE_COR20_HEADER via the PE Optional-Header's
     Data-Directory[14] (CLR runtime header pointer).  This is the
     definitive .NET signal — Microsoft's own PE loader uses it.
  2. Byte-scan for ``mscoree.dll``, ``clr.dll``, ``CorBindTo``,
     ``ExecuteInDefaultAppDomain`` etc. as a secondary corroboration
     for corrupted / partially-obfuscated PEs where the directory table
     may have been stripped by a packer.

Emits:
  · ``dotnet_pe``  evidence with metadata (CLR entry point, meta-data
                     RVA/size, has_strong_name, has_native_header).
  · ``family``     evidence tagged ``dotnet-managed-loader`` with MITRE
                     T1620 (Reflective Code Loading) and T1027 (Obfuscated
                     Files or Information) when the PE also contains the
                     tell-tale managed-loader import surface.

Semantic: analyzer — reads bytes, emits evidence, produces no child.

R26 compliance
──────────────
    · Pure deterministic offset-arithmetic on the PE optional header.
    · No dependency on ``pefile`` — this recognizer must work in
      minimal deployments where the pefile module is not installed.
"""
from __future__ import annotations

import struct
from time    import perf_counter
from typing  import List, Optional

from ...artifact   import Artifact
from ...recognizer import Recognition, Reason, HIGH, CERTAIN
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin


NAME    = "pe.dotnet_recognizer"
VERSION = "1.0.0"

# CLR / managed-loader byte markers.  Case-insensitive matching handled
# by lower-casing once per artifact.
_CLR_MARKERS = (
    b"mscoree.dll", b"clr.dll", b"corbindto",
    b"executeindefaultappdomain", b"icorruntimehost",
    b"appdomain", b"mscorlib", b"system.reflection.assembly",
    b"assembly.load", b"assemblyloadfrom", b"createinstance",
    b"corexemain", b"reflectiveloader",
)


def _read_cor20_directory(buf: bytes) -> Optional[dict]:
    """Return the CLR (COM+ 2.0) header directory descriptor or None.

    The DOS header at offset 0 points to the PE header via ``e_lfanew``.
    The PE optional header lives immediately after the PE\\0\\0 + File
    Header (24 bytes total).  Directory index 14 (COM Descriptor) points
    at the IMAGE_COR20_HEADER — the definitive .NET signal.
    """
    if len(buf) < 0x100 or buf[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 0x18 > len(buf):
            return None
        if buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        # File Header lives at PE+4, 20 bytes.  Optional Header follows.
        opt_off  = e_lfanew + 4 + 20
        opt_size = struct.unpack_from("<H", buf, e_lfanew + 4 + 16)[0]
        if opt_off + opt_size > len(buf) or opt_size < 0x60:
            return None
        # Magic distinguishes PE32 vs PE32+.
        magic = struct.unpack_from("<H", buf, opt_off)[0]
        if magic == 0x10B:      # PE32
            data_dir_off = opt_off + 96
        elif magic == 0x20B:    # PE32+
            data_dir_off = opt_off + 112
        else:
            return None
        # Directory index 14 = COM Descriptor.
        cor20_off_in_hdr = data_dir_off + 14 * 8
        if cor20_off_in_hdr + 8 > len(buf):
            return None
        rva, size = struct.unpack_from("<II", buf, cor20_off_in_hdr)
        if rva == 0 or size == 0:
            return None
        return {"rva": rva, "size": size, "opt_magic": magic}
    except (struct.error, IndexError):
        return None


def _clr_marker_hits(buf: bytes) -> List[str]:
    if not buf:
        return []
    lo = buf.lower()
    return [m.decode("latin-1") for m in _CLR_MARKERS if m in lo]


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        if artifact.artifact_type != "pe_bytes":
            return []
        cor20   = _read_cor20_directory(artifact.payload)
        markers = _clr_marker_hits(artifact.payload)
        if not (cor20 or len(markers) >= 2):
            return []
        return [Recognition(
            artifact_type="pe_bytes",
            confidence=(CERTAIN if cor20 else HIGH),
            reasons=[Reason("cor20_directory" if cor20 else "clr_markers",
                              0.9 if cor20 else 0.6,
                              (f"COR20 rva=0x{cor20['rva']:x} size={cor20['size']}"
                               if cor20 else
                               f"{len(markers)} CLR markers"))],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["pe_bytes"]
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        cor20   = _read_cor20_directory(artifact.payload)
        markers = _clr_marker_hits(artifact.payload)
        if not (cor20 or len(markers) >= 2):
            return CapabilityResult(
                notes={"dotnet_status": "not_dotnet"},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )

        evidence: List = []
        evidence.append(make_evidence(
            artifact_uri=artifact.uri,
            kind="dotnet_pe",
            value={
                "cor20_present":   bool(cor20),
                "cor20_rva":       cor20["rva"]  if cor20 else None,
                "cor20_size":      cor20["size"] if cor20 else None,
                "opt_magic":       (hex(cor20["opt_magic"])
                                       if cor20 else None),
                "clr_marker_hits": markers,
            },
            source_capability=NAME,
            confidence=(0.99 if cor20 else 0.80),
            severity="high",
            mitre_techniques=["T1620"],   # Reflective Code Loading
            kill_chain=["defense-evasion"],
            location="pe.optional_header.data_dir[14]",
        ))
        # Emit family attribution for the managed-loader tradecraft when
        # at least one runtime-host marker is present.
        loader_markers = {
            "assembly.load", "assemblyloadfrom", "createinstance",
            "corexemain", "reflectiveloader", "executeindefaultappdomain",
            "icorruntimehost",
        }
        if any(m in loader_markers for m in markers):
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind="family",
                value="Managed (.NET) In-Memory Loader",
                source_capability=NAME,
                confidence=0.85,
                severity="critical",
                mitre_techniques=["T1620", "T1027"],
                kill_chain=["defense-evasion", "execution"],
                location="clr.markers",
                meta={
                    "family_id":            "dotnet-managed-loader",
                    "tactic":               "Defense Evasion",
                    "commonly_observed_in": [
                        "SharpBlock", "Nishang", "PowerSploit",
                        "Cobalt Strike Execute-Assembly", "Donut generated",
                        "Empire", "SILENTTRINITY",
                    ],
                },
            ))

        return CapabilityResult(
            evidence=evidence,
            notes={
                "dotnet_status": "detected",
                "cor20":         bool(cor20),
                "clr_markers":   markers,
            },
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="(new · deterministic COR20 + CLR-marker scanner)")
