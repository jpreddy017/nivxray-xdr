"""UAIE · Capability Registry Adapter (semantic-typed).

Bridges the legacy ``engine.registry.DecoderRegistry`` (BaseDecoder
subclasses) into the UAIE Capability system WITHOUT collapsing every
module into a "decoder".  Modules retain their semantic type:

    Decoder           → transforms an artifact into a child artifact
    Recognizer        → classifies an artifact (no children, no evidence)
    Analyzer          → emits structured evidence (no children)
    Transformer       → transforms in-place, no new artifact identity
    EvidenceEmitter   → surfaces IOC/MITRE/severity evidence only
    FamilyBuilder     → identifies a family taxonomy row

Registration
────────────
    from services.uaie.capability_adapter import adapt_and_register

    adapt_and_register(
        legacy=XorBruteDecoder,
        semantic="decoder",
        child_artifact_type="xor_decoded",
        artifact_types=["shellcode_bytes", "gzip_decoded", "base64_decoded"],
    )

The adapter never mutates the legacy module.  The result is a
UAIE ``Recognizer + Capability`` pair registered on the UAIE side —
and a metadata entry (``semantic``, ``wraps_legacy``, ``profiles``)
attached to the plugin registry entry so the Planner can filter.

R26 compliance: pure wrapper; same input → same output.
"""
from __future__ import annotations

from time    import perf_counter
from typing  import Any, Dict, Iterable, List, Optional, Type

from .artifact   import Artifact
from .recognizer import Recognition, Reason, HIGH, LIKELY, CERTAIN
from .capability import CapabilityResult, register as _register_cap
from .evidence   import make_evidence
from . import plugins as _plugin_registry


SEMANTIC_TYPES = (
    "decoder",           # emits child artifact
    "recognizer",        # emits Recognition only
    "analyzer",          # emits evidence, no children
    "transformer",       # in-place, no new identity
    "evidence_emitter",  # IOC/MITRE only
    "family_builder",    # family taxonomy
)


def _make_engine_ctx(payload_str: str):
    """Build a valid ``(Fingerprint, AnalysisContext)`` pair for the legacy
    engine — pydantic-strict ``Fingerprint`` requires ``input_len``.
    Returns ``(None, None)`` on any failure so the adapter degrades
    gracefully to just calling the legacy module."""
    try:
        from engine.models import AnalysisContext, Fingerprint
        fp  = Fingerprint(input_len=len(payload_str))
        ctx = AnalysisContext()
        return fp, ctx
    except Exception:
        return None, None


class _AdaptedRecognizer:
    def __init__(self, *, plugin_name: str, legacy_instance: Any,
                 artifact_types: List[str]):
        self.name = plugin_name
        self._legacy = legacy_instance
        self._types = artifact_types

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        # Delegate to the legacy .detect() call.  Signature:
        #     detect(payload_str, fingerprint, ctx) -> DetectResult
        try:
            payload_str = artifact.payload.decode("latin-1", errors="ignore")
            fp, ctx = _make_engine_ctx(payload_str)
            d = self._legacy.detect(payload_str, fp, ctx)
        except Exception:
            return []
        conf = float(getattr(d, "confidence", 0.0) or 0.0)
        if conf < 0.4:
            return []
        # Route confidence into UAIE band.
        band = CERTAIN if conf >= 0.9 else HIGH if conf >= 0.7 else LIKELY
        return [Recognition(
            artifact_type=self._types[0] if self._types else "text",
            confidence=band,
            reasons=[Reason("legacy_detect", conf,
                              getattr(d, "why", "") or "legacy detect")],
            recognizer=self.name,
        )]


class _AdaptedCapability:
    def __init__(self, *, plugin_name: str, semantic: str,
                 legacy_instance: Any,
                 artifact_types: List[str],
                 child_artifact_type: Optional[str]):
        self.name = plugin_name
        self._legacy = legacy_instance
        self._semantic = semantic
        self._child_type = child_artifact_type
        self.requires_artifact_type = list(artifact_types)
        self.requires_evidence = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        payload_str = artifact.payload.decode("latin-1", errors="ignore")
        fp, ctx = _make_engine_ctx(payload_str)
        try:
            det = self._legacy.detect(payload_str, fp, ctx)
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)
        if not det or float(getattr(det, "confidence", 0) or 0) < 0.4:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)
        try:
            result = self._legacy.decode(
                payload_str, dict(getattr(det, "args", {}) or {}), ctx,
            )
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        evidence = []
        children = []
        notes: Dict[str, Any] = {"semantic": self._semantic,
                                   "legacy_detect_why": getattr(det, "why", "")}

        # Lift structured surfaces from PluginResult uniformly.
        iocs         = dict(getattr(result, "iocs", None) or {})
        family_hints = list(getattr(result, "family_hints", None) or [])
        mitre_hints  = list(getattr(result, "mitre_hints",  None) or [])
        tradecraft   = list(getattr(result, "tradecraft",   None) or [])
        output       = getattr(result, "output", "") or ""

        _NORM = {"urls": "url", "ips": "ipv4", "domains": "domain",
                 "user_agents": "user_agent"}
        for raw_kind, values in iocs.items():
            kind = _NORM.get(raw_kind, raw_kind)
            for v in (values or []):
                mitre = (["T1071.001"] if kind in ("url", "domain")
                          else ["T1105"] if kind == "ipv4" else [])
                evidence.append(make_evidence(
                    artifact_uri=artifact.uri, kind=kind, value=v,
                    source_capability=self.name, confidence=0.85,
                    severity="high", mitre_techniques=mitre,
                    kill_chain=(["command-and-control"] if mitre else []),
                    location=f"{self.name}.iocs",
                ))
        for fh in family_hints:
            fam = str(getattr(fh, "family", "") or "")
            if not fam:
                continue
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="family", value=fam,
                source_capability=self.name,
                confidence=float(getattr(fh, "confidence", 0.8) or 0.8),
                severity="high",
                mitre_techniques=list(getattr(fh, "mitre_techniques", []) or []),
                kill_chain=["command-and-control"],
                location=f"{self.name}.family",
            ))
        for mh in mitre_hints:
            mid = str(getattr(mh, "id", "") or "")
            if not mid:
                continue
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="mitre_hint", value=mid,
                source_capability=self.name, confidence=0.85,
                severity="medium", mitre_techniques=[mid],
                location=str(getattr(mh, "source", "") or ""),
                meta={"evidence": str(getattr(mh, "evidence", "") or "")},
            ))
        for tc in tradecraft:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind=f"tradecraft.{getattr(tc, 'flag', 'flag')}",
                value=getattr(tc, "flag", "") or "",
                source_capability=self.name, confidence=0.85,
                severity=str(getattr(tc, "severity", "medium") or "medium"),
                location=f"{self.name}.tradecraft",
                meta=dict(getattr(tc, "metadata", None) or {}),
            ))

        # Semantic-typed handling:
        if self._semantic == "decoder" and self._child_type and output:
            from .artifact import make_artifact
            children.append(make_artifact(
                payload=(output.encode("utf-8", errors="replace")
                         if isinstance(output, str) else bytes(output)),
                artifact_type=self._child_type,
                parent_uri=artifact.uri,
                depth=artifact.depth + 1,
                discovered_by=self.name,
                meta={"legacy_notes": list(getattr(result, "notes", []) or [])},
            ))

        return CapabilityResult(
            evidence=evidence,
            child_artifacts=children,
            notes=notes,
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


# ═════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════
def adapt_and_register(
    *,
    legacy: Type[Any],
    semantic: str,
    artifact_types: Iterable[str],
    child_artifact_type: Optional[str] = None,
    profiles: Optional[Iterable[str]] = None,
    name_override: Optional[str] = None,
    version: str = "1.0.0",
) -> Dict[str, Any]:
    """Adapt a legacy BaseDecoder-shaped class into UAIE and register it.

    Returns the registered plugin dict.
    """
    if semantic not in SEMANTIC_TYPES:
        raise ValueError(f"semantic must be one of {SEMANTIC_TYPES}; "
                         f"got {semantic!r}")
    instance = legacy()
    name = name_override or getattr(instance, "id", None) or legacy.__name__
    artifact_types = list(artifact_types) or ["text"]

    recognizer = _AdaptedRecognizer(
        plugin_name=name, legacy_instance=instance,
        artifact_types=artifact_types,
    )
    capability = _AdaptedCapability(
        plugin_name=name, semantic=semantic, legacy_instance=instance,
        artifact_types=artifact_types, child_artifact_type=child_artifact_type,
    )
    _register_cap(capability)
    _plugin_registry.register_plugin(
        name, version, recognizer, capability,
        wraps_legacy=f"{legacy.__module__}.{legacy.__name__}",
    )
    # Stamp semantic + profiles onto the last-registered plugin dict.
    plugins = _plugin_registry.all_plugins()
    if plugins and plugins[-1]["name"] == name:
        plugins[-1]["semantic"]        = semantic
        plugins[-1]["profiles"]        = list(profiles or ["universal"])
        plugins[-1]["artifact_types"]  = list(artifact_types)
        plugins[-1]["child_artifact_type"] = child_artifact_type
    return plugins[-1]


__all__ = ["adapt_and_register", "SEMANTIC_TYPES"]
