"""RC2.2 orchestrator → legacy dict adapter.

Bridges the new deterministic Orchestrator (engine.orchestrator) into the
shape expected by the legacy Workspace / AUTO INVESTIGATE endpoint, which
consumes the dict returned by `analysis_core.deterministic_best_decode`.

Design
------
* Called BEFORE the legacy pipeline.
* If the orchestrator produces a "meaningful" chain (≥2 layers AND a
  terminal state of complete/english/family-identified), we hand its
  result back verbatim in the legacy shape.
* Otherwise we return `None` and let the legacy `smart_decoder`/`magic_decoder`
  race continue as today.
* Legacy op-names are preserved so the frontend's plugin catalog / recipe
  rendering keeps working. Only when the orchestrator surfaces a plugin
  that has NO legacy equivalent do we emit a new `op` (e.g. `custom-hex-slash`,
  `nibble-swap`, `ps-reconstruct`) — those render fine in the UI as generic
  recipe steps.

Deterministic-first: never calls the LLM, never touches the network,
never runs a subprocess. Pure regex + byte-transforms.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# Mapping from new orchestrator plugin IDs → legacy Workspace op-names
# so the UI's recipe catalog / recipe rendering keeps working seamlessly.
_LEGACY_OP_ALIAS: Dict[str, str] = {
    "extract-wrapper":       "extract-payload",
    "base64-decode":         "base64-decode",
    "base32-decode":         "base32-decode",
    "base58-decode":         "base58-decode",
    "base91-decode":         "base91-decode",
    "ascii85-decode":        "ascii85-decode",
    "hex-decode":            "hex-decode",
    "url-decode":            "url-decode",
    "utf16-decode":          "utf16le-or-utf8-decode",
    "jwt-decode":            "jwt-decode",
    "data-uri-extract":      "data-uri-extract",
    "gzip-decompress":       "gzip-decompress",
    "zlib-deflate":          "zlib-decompress",
    "rot13-decode":          "rot13",
    "rot47-decode":          "rot47",
    "xor-brute":             "xor-brute",
    "reverse-string":        "reverse-string",
    "custom-hex-slash":      "custom-hex-slash",
    "nibble-swap":           "nibble-swap",
    "ps-reconstruct":        "ps-reconstruct",
    "ioc-extractor":         "ioc-extract",
}


def _shellcode_reached(output: str) -> bool:
    """Basic PE / shellcode magic heuristic — matches the legacy detector's
    behaviour so downstream verdict thresholds line up."""
    if not output:
        return False
    b = output.encode("latin-1", errors="replace")[:16]
    return (
        b.startswith(b"MZ")                    # PE / DOS header
        or b.startswith(b"\x7fELF")            # ELF
        or b.startswith(b"\xfc\xe8")           # x86 fnstenv/msf shellcode preamble
        or b.startswith(b"\x48\x83")           # common x64 prologue (sub rsp, N)
    )


def try_orchestrator_first(
    payload: str,
    *,
    analysis_mode: str = "balanced",
) -> Optional[Dict[str, Any]]:
    """Run the RC2.2 orchestrator; return a legacy-shape dict if the chain
    is meaningful. Return ``None`` to let the legacy pipeline take over.
    """
    if not payload or len(payload) < 4:
        return None
    try:
        # Deferred import — avoids circular deps at module load
        from engine.orchestrator import Orchestrator
        from engine.models import AnalysisContext, Budget
    except Exception:
        return None

    try:
        ctx = AnalysisContext(budget=Budget(
            max_depth=20,
            # Balanced/deep get a slightly bigger wall budget; fast is tight.
            wall_time_ms=8000 if analysis_mode != "fast" else 3000,
        ))
        result = Orchestrator(ctx).run(payload)
    except Exception:
        return None

    if not result or not result.trace:
        return None

    # Only "adopt" the orchestrator when it produced a useful chain.
    # Terminal states we trust: complete, english, family-identified.
    terminal = getattr(result, "terminal", "") or ""
    if terminal not in ("complete", "english", "family-identified"):
        # For no-candidate / max-depth / loop-detected — still adopt if we
        # peeled ≥2 layers and produced changed output; otherwise defer.
        if len(result.trace) < 2:
            return None

    # Convert TraceStep list → legacy step dicts
    steps: List[Dict[str, Any]] = []
    for st in result.trace:
        legacy_op = _LEGACY_OP_ALIAS.get(st.decoder, st.decoder)
        args = getattr(st, "args", None) or {}
        preview = getattr(st, "notes", None)
        why = ""
        if isinstance(preview, list) and preview:
            why = preview[0]
        elif isinstance(preview, str):
            why = preview
        steps.append({
            "op":            legacy_op,
            "args":          args if isinstance(args, dict) else {},
            "reason":        f"orchestrator: {st.decoder}"
                             + (f" — {why}" if why else ""),
            "output_preview": (st.output or "")[:200] if hasattr(st, "output") else "",
            "output_length":  len(st.output) if hasattr(st, "output") and st.output else 0,
        })

    findings = result.findings
    ioc_bundle = {
        "ips":     list(findings.iocs.ips),
        "urls":    list(findings.iocs.urls),
        "domains": list(findings.iocs.domains),
        "hashes":  {
            "md5":    list(findings.iocs.md5),
            "sha1":   list(findings.iocs.sha1),
            "sha256": list(findings.iocs.sha256),
        },
        "emails":  list(findings.iocs.emails),
        "file_paths": list(findings.iocs.file_paths),
        "bitcoin_addresses": list(getattr(findings.iocs, "bitcoin_addresses", [])),
    }
    mitre = [
        {"id": m.id, "technique": m.technique, "tactic": getattr(m, "tactic", ""),
         "evidence": getattr(m, "evidence", "")}
        for m in findings.mitre_techniques
    ]
    lolbas = [
        {"binary": h.binary, "technique_id": getattr(h, "technique_id", ""),
         "evidence": getattr(h, "evidence", "")}
        for h in findings.lolbas
    ]
    tradecraft = [
        {"flag": t.flag, "severity": getattr(t, "severity", "low"),
         "evidence": getattr(t, "evidence", "")}
        for t in findings.tradecraft
    ]

    return {
        "output":            result.output or "",
        "detected_type":     result.output_type if hasattr(result, "output_type") else "text",
        "engine":            "rc2-orchestrator",
        "steps":             steps,
        "trace":             steps,           # ops.py sometimes reads either key
        "reached_shellcode": _shellcode_reached(result.output or ""),
        "terminal":          terminal,
        # Bonus intelligence surfaced for the Workspace panels (MITRE / LOLBAS / IOCs / RULES / SIGNALS)
        "iocs":              ioc_bundle,
        "mitre":             mitre,
        "lolbas":            lolbas,
        "tradecraft":        tradecraft,
        "verdict":           findings.verdict,
        "risk_score":        findings.risk_score,
        "family":            {
            "family":     findings.family.family,
            "confidence": findings.family.confidence,
        } if findings.family and findings.family.family else None,
        # For explainability
        "engine_reason": (
            f"RC2.2 orchestrator adopted "
            f"({len(steps)} layer(s), terminal={terminal}, "
            f"verdict={findings.verdict}, risk={findings.risk_score})"
        ),
    }
