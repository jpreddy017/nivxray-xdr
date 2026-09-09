"""Plugin · Shellcode Analyzer (Capability Pack 1 · #1) · WRAPPER.

**Not** a re-implementation.  A thin R26 plugin wrapper around the
existing production-grade ``/app/backend/shellcode_analyzer.py`` (543
LOC) that has been quietly powering the legacy pipeline all along.

Existing capability inventory (shellcode_analyzer.py)
─────────────────────────────────────────────────────
  · shannon_entropy(data)
  · is_shellcode(data)                — heuristic classification
  · starts_with_known_prologue(data)  — MSF / CS x86/x64 sled detect
  · detect_arch(data), disassemble(…) — Capstone-backed disassembly
  · extract_iocs(data)                — ASCII + UTF-16LE URLs / IPs
  · _family_recognise(data)           — Metasploit / CS / others
  · annotate_shellcode(data)          — analyst card
  · analyze(data)                     — full bundled analyzer

Everything above is already deterministic, tested, and integrated with
Capstone.  This wrapper simply exposes it to the UAIE orchestrator so
the analyzer loop can invoke it during Recognize → Execute → Emit →
Enqueue.  Zero duplicated logic — one source of truth.

R26 compliance
──────────────
Pure wrapper.  Same input → same output as the underlying module.
No hidden state.  No queue access.  No LLM.
"""
from __future__ import annotations

from time    import perf_counter
from typing  import List

from ...artifact   import Artifact, make_artifact
from ...recognizer import Recognition, Reason, HIGH, LIKELY
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin

# The existing production module — DO NOT REIMPLEMENT.
import shellcode_analyzer as _sca


NAME    = "shellcode.analyzer"
VERSION = "1.0.0"


def _bytes_from_artifact(artifact: Artifact) -> bytes:
    """Prefer raw payload; unwrap ``@@RAWBYTES@@<hex>`` if present."""
    from services.die.preprocessor.recursive_decoder import _extract_rawbytes
    text = artifact.payload.decode("utf-8", errors="replace")
    hit = _extract_rawbytes(text)
    return hit[0] if hit else artifact.payload


# ─── Recognizer ──────────────────────────────────────────────────────
class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        raw = _bytes_from_artifact(artifact)
        if not raw or len(raw) < 32:
            return []
        # Route into the existing production classifier.
        is_sc     = _sca.is_shellcode(raw)
        prologue  = _sca.starts_with_known_prologue(raw)
        if not (is_sc or prologue):
            return []
        reasons: List[Reason] = []
        if prologue:
            reasons.append(Reason("known_prologue", 0.60, "MSF/CS sled"))
        entropy = _sca.shannon_entropy(raw)
        if entropy >= 6.5:
            reasons.append(Reason("entropy", 0.30, f"H={entropy:.2f}"))
        return [Recognition(
            artifact_type="shellcode_bytes",
            confidence=(HIGH if prologue else LIKELY),
            reasons=reasons,
            recognizer=NAME,
        )]


# ─── Capability ──────────────────────────────────────────────────────
class _Capability:
    name = NAME
    requires_artifact_type = ["shellcode_bytes"]
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        raw = _bytes_from_artifact(artifact)
        if not raw:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        # Run the existing production analyzer — no reimplementation.
        report = _sca.analyze(raw)
        family, family_mitre = _sca._family_recognise(raw)

        evidence = []
        children = []

        # Family evidence (MITRE-mapped, high severity).
        if family:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="family", value=family,
                source_capability=NAME, confidence=0.85, severity="critical",
                mitre_techniques=([family_mitre] if family_mitre else []),
                kill_chain=["command-and-control"] if family_mitre else [],
                reasons=[Reason("family_fingerprint", 0.85, family)],
                location="raw-bytes-scan",
            ))

        # IOC evidence with MITRE mapping.  The production ``extract_iocs``
        # returns plural keys (urls/ips/domains); normalise to the
        # canonical singular kinds used elsewhere in the SSOT.
        _KIND_NORMALISE = {
            "urls": "url", "ips": "ipv4", "domains": "domain",
            "sha256": "sha256", "sha1": "sha1", "md5": "md5",
        }
        iocs = report.get("iocs", {}) or {}
        for raw_kind, values in iocs.items():
            kind = _KIND_NORMALISE.get(raw_kind, raw_kind)
            for v in values or []:
                mitre = (["T1071.001"] if kind in ("url", "domain")
                         else ["T1105"] if kind == "ipv4"
                         else [])
                evidence.append(make_evidence(
                    artifact_uri=artifact.uri, kind=kind, value=v,
                    source_capability=NAME, confidence=0.80, severity="high",
                    mitre_techniques=mitre,
                    kill_chain=(["command-and-control"] if mitre else []),
                    location="shellcode_analyzer.extract_iocs",
                ))

        # Disassembly summary — first N instructions as one evidence blob
        # so the analyst UI can render the Capstone panel from the SSOT
        # without re-running Capstone.
        disasm = report.get("disassembly") or []
        if disasm:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="disassembly",
                value=f"{len(disasm)} instructions ({report.get('arch')})",
                source_capability=NAME, confidence=0.90, severity="info",
                location="capstone",
                meta={
                    "arch":  report.get("arch"),
                    "count": len(disasm),
                    "preview": disasm[:16],
                },
            ))

        # Terminal-layer summary evidence — carries entropy + shellcode
        # verdict so downstream verdict-card logic can consume it.
        evidence.append(make_evidence(
            artifact_uri=artifact.uri, kind="shellcode_report",
            value={
                "size":         report.get("size"),
                "entropy":      report.get("entropy"),
                "is_shellcode": report.get("is_shellcode"),
                "arch":         report.get("arch"),
                "hex_preview":  report.get("hex_preview"),
            },
            source_capability=NAME, confidence=0.90, severity="high",
            location="shellcode_analyzer.analyze",
        ))

        return CapabilityResult(
            evidence=evidence,
            child_artifacts=children,
            notes={
                "family":       family,
                "family_mitre": family_mitre,
                "arch":         report.get("arch"),
                "entropy":      report.get("entropy"),
            },
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="shellcode_analyzer.analyze")
