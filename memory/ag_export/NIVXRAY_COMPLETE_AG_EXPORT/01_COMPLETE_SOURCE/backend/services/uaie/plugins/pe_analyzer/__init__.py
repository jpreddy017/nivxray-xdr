"""Plugin · PE Analyzer (Capability Pack 1 · #2) · WRAPPER.

Wraps the existing 499-line ``services.pe_analyzer.analyze_pe`` into a
UAIE Capability that consumes ``pe_bytes`` artifacts (emitted by
``shellcode.analyzer`` when it detects an embedded MZ/PE header).

R26 compliance
──────────────
Pure wrapper.  Same input → same output as the underlying module.
No hidden state.  No queue access.  No LLM.  No reimplementation.
"""
from __future__ import annotations

from time    import perf_counter
from typing  import List

from ...artifact   import Artifact
from ...recognizer import Recognition, Reason, HIGH, CERTAIN
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin

from services.pe_analyzer import analyze_pe as _pe_analyze


NAME    = "pe.analyzer"
VERSION = "1.0.0"


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        raw = artifact.payload
        if not raw or len(raw) < 64 or raw[:2] != b"MZ":
            return []
        return [Recognition(
            artifact_type="pe_bytes",
            confidence=CERTAIN,
            reasons=[Reason("mz_header", 0.95, "MZ magic present")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    requires_artifact_type = ["pe_bytes"]
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        report = _pe_analyze(artifact.payload)
        evidence = []
        # Availability guard — pefile may not be installed in every deploy.
        if not report.get("available"):
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="pe_analysis_unavailable",
                value=report.get("reason") or "unknown",
                source_capability=NAME, confidence=0.5, severity="info",
                location="services.pe_analyzer",
            ))
            return CapabilityResult(
                evidence=evidence,
                notes={"pe_report": report},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )
        if report.get("error"):
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="pe_parse_error",
                value=report.get("error"),
                source_capability=NAME, confidence=0.5, severity="info",
                location="services.pe_analyzer.analyze_pe",
                meta={"message": report.get("message", "")},
            ))
            return CapabilityResult(
                evidence=evidence,
                notes={"pe_report": report},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )

        overview = report.get("overview") or {}
        hashes   = report.get("hashes") or {}
        imports  = report.get("imports") or []
        findings = report.get("findings") or []

        # Full-report as one evidence blob — analyst UI reads from the SSOT.
        evidence.append(make_evidence(
            artifact_uri=artifact.uri, kind="pe_report",
            value={
                "size":         overview.get("size"),
                "machine":      overview.get("machine"),
                "subsystem":    overview.get("subsystem"),
                "timestamp":    overview.get("timestamp"),
                "entrypoint":   overview.get("entrypoint"),
                "sha256":       hashes.get("sha256"),
                "imphash":      hashes.get("imphash"),
                "sections":     len(report.get("sections") or []),
                "imports":      len(imports),
                "exports":      len(report.get("exports") or []),
                "resources":    len(report.get("resources") or []),
                "strings":      len(report.get("strings") or []),
                "packer_hints": report.get("packer_hints") or [],
            },
            source_capability=NAME, confidence=0.90, severity="high",
            location="services.pe_analyzer.analyze_pe",
        ))

        # SHA256 as an IOC (analysts hunt by hash).
        if hashes.get("sha256"):
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="sha256",
                value=hashes["sha256"],
                source_capability=NAME, confidence=0.99, severity="high",
                mitre_techniques=["T1027"],
                location="pe.hashes",
            ))

        # Structured findings from the production module.
        for f in findings:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind=f.get("kind", "pe_finding"),
                value=f.get("title") or f.get("value") or "",
                source_capability=NAME,
                confidence=float(f.get("confidence") or 0.7),
                severity=f.get("severity") or "medium",
                mitre_techniques=(f.get("mitre") or f.get("mitre_techniques") or []),
                location="pe.analyzer.findings",
                meta=f,
            ))

        return CapabilityResult(
            evidence=evidence,
            notes={
                "pe_available":  True,
                "pe_size":       overview.get("size"),
                "pe_sha256":     hashes.get("sha256"),
                "packer_hints":  report.get("packer_hints") or [],
            },
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="services.pe_analyzer.analyze_pe")
