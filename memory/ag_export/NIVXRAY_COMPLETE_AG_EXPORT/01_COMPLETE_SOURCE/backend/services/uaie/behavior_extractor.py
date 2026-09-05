"""UAIE Behavior Extractor — the last architectural piece.

Converts a live ``OrchestratorResult`` (from any UAIE input:
PowerShell, Office document, PE, command line, base64, XOR, etc.)
into a deterministic list of ``Behavior`` objects.

Once this bridge runs upstream of ``ssot_projector.project()``, every
UAIE investigation — not just URL-ingested reports — flows through
the same semantic layer.  Recommendations, provenance, projections
and the future Evidence Summary become input-agnostic.

Contract (per user directive · 2026-02-05):
    · Producer-only.  This module is a ``BehaviorProducer``: it
      consumes UAIE Evidence and emits Behaviors.  It does NOT
      consume Behaviors and does NOT produce projections /
      recommendations.
    · Deterministic lookups only.  No prose inference, no LLM.
    · Nothing invented — Behaviors are only emitted when a
      recognizable UAIE artifact/evidence entry actually exists.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Set

from services.ida.behaviors import (
    Behavior, LOLBAS_BINARY_TO_BEHAVIORS, classify_command,
)


def extract_behaviors(orchestrator_result: Any) -> List[Behavior]:
    """Emit ``Behavior`` objects from a UAIE ``OrchestratorResult``.

    Sources consulted (deterministic · in this order):
        1. ``commandline`` artifacts → classify_command()
        2. LOLBAS-named artifact payloads (e.g. ``powershell.exe``
           embedded in a command) → LOLBAS lookup
        3. ``base64_decoded`` artifacts whose parent is a
           PowerShell command → ``powershell_encoded_command``
        4. Evidence entries with ``kind == "lolbas"`` (when a
           future UAIE plugin emits them)
    """
    behaviors: List[Behavior] = []
    seen: Set[tuple] = set()

    def _emit(b: Behavior) -> None:
        key = (b.behavior_type, b.source_ref)
        if key in seen:
            return
        seen.add(key)
        behaviors.append(b)

    artifacts = _iter_artifacts(orchestrator_result)

    # ── 1. commandline / text artifacts → classify_command ────
    # ``powershell_normalized`` is a UAIE internal transform-report
    # artifact (not evidence of PS execution) — we deliberately
    # exclude it from behavior classification.
    _COMMANDLINE_TYPES = ("commandline", "text")
    for a in artifacts:
        if getattr(a, "artifact_type", None) not in _COMMANDLINE_TYPES:
            continue
        payload = _text_payload(a)
        if not payload:
            continue
        head    = _detect_head(payload)
        label, btype = classify_command(payload, head)
        if btype:
            _emit(Behavior(
                behavior_type = btype,
                label         = label,
                source        = "uaie_command_classifier",
                source_ref    = f"artifact:{getattr(a, 'artifact_id', '')}",
                provenance    = "command_execution",
                evidence      = {"command": payload[:512], "head": head},
                observed_at   = {"artifact_id":
                                   getattr(a, "artifact_id", "")},
            ))

        # ── 2. LOLBAS binaries embedded in the command ───────
        # Match both ``vssadmin.exe`` and bare ``vssadmin`` (as
        # observed in UAIE text artifacts).  Deterministic
        # substring lookup — no regex, no inference.
        lowered = payload.lower()
        for binname, btypes in LOLBAS_BINARY_TO_BEHAVIORS.items():
            bare = binname[:-4] if binname.endswith(".exe") else binname
            if binname in lowered or (bare and _bare_binary_present(
                                                      bare, lowered)):
                for lb in btypes:
                    _emit(Behavior(
                        behavior_type = lb,
                        label         = f"LOLBAS binary observed: {binname}",
                        source        = "uaie_lolbas_scanner",
                        source_ref    = f"artifact:{getattr(a, 'artifact_id','')}:{binname}",
                        provenance    = "lolbas_binary_reference",
                        evidence      = {"binary": binname,
                                             "artifact_payload_preview":
                                                 payload[:256]},
                        observed_at   = {"artifact_id":
                                             getattr(a, "artifact_id", "")},
                    ))

    # ── 3. base64_decoded whose parent is a PowerShell context ─
    for a in artifacts:
        atype = getattr(a, "artifact_type", None)
        if atype not in ("base64_decoded", "powershell_normalized"):
            continue
        parent = _parent(orchestrator_result, a)
        parent_head = _detect_head(_text_payload(parent)) if parent else ""
        if parent_head.startswith("powershell") or parent_head.startswith("pwsh"):
            _emit(Behavior(
                behavior_type = "powershell_encoded_command",
                label         = "PowerShell EncodedCommand peeled",
                source        = "uaie_ps_normalizer",
                source_ref    = f"artifact:{getattr(a, 'artifact_id', '')}",
                provenance    = "command_execution",
                evidence      = {"decoded_preview":
                                     _text_payload(a)[:256]},
                observed_at   = {"artifact_id":
                                     getattr(a, "artifact_id", "")},
            ))

    # ── 4. Evidence entries with kind=lolbas (future plugins) ─
    for ev in _iter_evidence(orchestrator_result):
        if getattr(ev, "kind", None) == "lolbas":
            binname = str(getattr(ev, "value", "")).lower()
            for lb in LOLBAS_BINARY_TO_BEHAVIORS.get(binname, ()):
                _emit(Behavior(
                    behavior_type = lb,
                    label         = f"LOLBAS binary observed: {binname}",
                    source        = "uaie_evidence_stream",
                    source_ref    = f"lolbas:{binname}",
                    provenance    = "lolbas_binary_reference",
                    evidence      = {"binary": binname},
                ))

    return behaviors


# ── UAIE result-shape adapters (defensive · no direct coupling) ──
def _iter_artifacts(result: Any) -> Iterable[Any]:
    arts = getattr(result, "artifacts", None) or {}
    return list(arts.values()) if isinstance(arts, dict) else list(arts)


def _iter_evidence(result: Any) -> Iterable[Any]:
    return getattr(result, "evidence", ()) or ()


def _text_payload(artifact: Any) -> str:
    if artifact is None:
        return ""
    p = getattr(artifact, "payload", "")
    if isinstance(p, (bytes, bytearray)):
        try:
            return p.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(p or "")


def _detect_head(payload: str) -> str:
    """Best-effort extraction of the invoked executable head."""
    if not payload:
        return ""
    stripped = payload.strip().lstrip('"\'').split(None, 1)[0]
    return stripped.split("\\")[-1].split("/")[-1].lower()


def _parent(result: Any, artifact: Any) -> Any:
    parent_id = getattr(artifact, "parent_id", None) or \
                    getattr(artifact, "parent", None)
    if not parent_id:
        return None
    arts = getattr(result, "artifacts", None) or {}
    if isinstance(arts, dict):
        return arts.get(parent_id)
    return None


def _bare_binary_present(bare: str, lowered_payload: str) -> bool:
    """Return True if the bare binary name appears in the payload
    as a word (word-boundary style).  Deterministic substring
    check.  Avoids spurious matches like ``msi`` matching inside
    ``msiexec`` when the caller intended ``msi`` alone."""
    if not bare or len(bare) < 3:
        return False
    # Simple word-boundary check without regex — inspect neighbours.
    idx = lowered_payload.find(bare)
    while idx >= 0:
        left  = lowered_payload[idx-1] if idx > 0 else " "
        right = (lowered_payload[idx+len(bare)]
                    if idx+len(bare) < len(lowered_payload) else " ")
        left_ok  = not left.isalnum()  and left  not in "._"
        right_ok = not right.isalnum() and right not in "._"
        if left_ok and right_ok:
            return True
        idx = lowered_payload.find(bare, idx + 1)
    return False


__all__ = ["extract_behaviors"]
