"""Plugin · Shellcode String Scan
(R26 · wraps ``_shellcode_string_scan``).

Extracts ASCII-embedded IPs / URLs / domains from raw byte payloads
(the terminal-layer bug fix for Sophos / Cobalt Strike loaders).
This plugin operates on raw ``bytes`` artifacts — its Capability
emits one Evidence per finding but NO child artifacts (this is a
terminal decoder).
"""
from __future__ import annotations

from time   import perf_counter
from typing import List

from ...artifact   import Artifact
from ...recognizer import Recognizer, Recognition, Reason, HIGH
from ...capability import Capability, CapabilityResult, register
from ...evidence   import make_evidence
from services.die.preprocessor.recursive_decoder import (
    _shellcode_string_scan as _LEGACY_SCAN,
    _extract_rawbytes      as _LEGACY_EXTRACT,
)
from .. import register_plugin


NAME    = "shellcode.string_scan"
VERSION = "1.0.0"


def _bytes_from_artifact(artifact: Artifact) -> bytes:
    """Prefer the raw payload; if the payload is a ``@@RAWBYTES@@``
    sentinel-wrapped hex blob (mid-pipeline shape) unwrap it so the
    plugin matches the legacy behaviour bit-for-bit."""
    text = artifact.payload.decode("utf-8", errors="replace")
    hit = _LEGACY_EXTRACT(text or "")
    if hit:
        return hit[0]
    return artifact.payload


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        raw = _bytes_from_artifact(artifact)
        if not raw:
            return []
        findings = _LEGACY_SCAN(raw)
        if not findings:
            return []
        return [Recognition(
            artifact_type="shellcode_bytes",
            confidence=HIGH,
            reasons=[Reason("embedded_iocs", 0.80,
                            f"{len(findings)} ASCII IOCs found")],
            recognizer=NAME,
        )]


_KIND_MAP = {"ip": "ipv4", "url": "url", "domain": "domain"}


class _Capability:
    name = NAME
    requires_artifact_type = ["shellcode_bytes", "gzip_decoded",
                              "base64_decoded", "text"]
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        raw = _bytes_from_artifact(artifact)
        findings = _LEGACY_SCAN(raw or b"")
        evidence = []
        for f in findings:
            # legacy format: "kind:value"
            kind, _, value = f.partition(":")
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind=_KIND_MAP.get(kind, kind),
                value=value,
                source_capability=NAME,
                confidence=0.85,
                severity="high",
                location="shellcode-string-scan",
                meta={"legacy_tag": f},
            ))
        return CapabilityResult(
            evidence=evidence,
            child_artifacts=[],  # terminal decoder
            notes={"findings_raw": list(findings)},
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="recursive_decoder._shellcode_string_scan")
