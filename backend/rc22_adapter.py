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
    # RC2.2 hotfix — Prod 2026-07-19 (2nd pass): legacy `smart+magic+reasoning`
    # race can hang the HTTP request for the full 60 s frontend timeout on
    # ANY moderately-sized input where the orchestrator finds no candidate.
    # We now force the orchestrator to own the response for payloads > 4 KB
    # (was 8 KB) — catches the 7850-char timeout case from the Prod screenshot.
    force_orchestrator = len(payload) > 4 * 1024
    try:
        # Deferred import — avoids circular deps at module load
        from engine.orchestrator import Orchestrator
        from engine.models import AnalysisContext, Budget
    except Exception:
        return None

    try:
        ctx = AnalysisContext(budget=Budget(
            max_depth=20,
            # Tight wall budget — the orchestrator is deterministic and O(n)
            # per layer, but LARGE inputs (>5 KB) can hit the ceiling.  We
            # cap at 3 s per analysis so the total round trip stays under
            # the frontend's 60 s HTTP timeout even on legacy fallback.
            # (Lowered from 4 s → 3 s after Prod 2026-07-19 evidence of a
            # 7850-char payload still hitting the 60 s ceiling.)
            wall_time_ms=3000 if analysis_mode != "fast" else 1500,
        ))
        # HARD wall-clock ceiling — some payload shapes cause the
        # candidate-picker to iterate thousands of times before
        # respecting `Budget.wall_time_ms`. We enforce an absolute
        # ceiling via a background daemon that raises on the main thread.
        #
        # RC4.6.2 mitigation (Feb 21, 2026):
        # Raised from 15 s → 45 s. Prod measurements showed the same
        # in-process work that completes in 1.9 s on the Preview
        # container takes ~30 s on the Prod container, with the ratio
        # (~6×) holding across all CPU-bound payload sizes and NOT
        # holding for network / auth / non-CPU work. This looks like a
        # Prod-side CPU-allocation delta vs Preview that Emergent
        # Support is investigating. Until they confirm parity, 45 s
        # keeps legitimate Prod decodes from hitting the safe-fallback.
        # Cloudflare's proxy timeout is 100 s, so 45 s still leaves a
        # 55 s safety margin against 524 timeouts.
        #
        # This is a MITIGATION, not the permanent fix. If Prod CPU
        # parity is restored, this ceiling never fires (Preview at 1.9 s
        # is 24× below 45 s). Revert to 15 s once the infra issue is
        # confirmed resolved.
        _HARD_CEILING_S = 45.0
        import threading
        result_holder: Dict[str, Any] = {}
        def _run():
            try:
                result_holder["r"] = Orchestrator(ctx).run(payload)
            except Exception as e:
                result_holder["err"] = e
        th = threading.Thread(target=_run, daemon=True)
        th.start()
        th.join(timeout=_HARD_CEILING_S)
        if th.is_alive():
            # Orchestrator is still churning — abandon it, return safe fallback
            return {
                "output": payload,
                "detected_type": "text",
                "engine": "rc2-orchestrator-hard-ceiling",
                "steps": [], "trace": [],
                "reached_shellcode": False,
                "terminal": f"hard-ceiling-{int(_HARD_CEILING_S)}s",
                "iocs": {"ips": [], "urls": [], "domains": [], "emails": [],
                         "file_paths": [], "bitcoin_addresses": [],
                         "hashes": {"md5": [], "sha1": [], "sha256": []}},
                "mitre": [], "lolbas": [], "tradecraft": [],
                "verdict": "needs_review", "risk_score": 0,
                "family": None,
                "engine_reason": (
                    f"Orchestrator exceeded {int(_HARD_CEILING_S)} s hard ceiling on {len(payload)}B "
                    "input; returning raw so the request stays under the HTTP timeout."
                ),
            }
        if "err" in result_holder:
            raise result_holder["err"]
        result = result_holder.get("r")
    except Exception:
        # If the orchestrator itself blew up on a huge input, return a
        # minimal legacy-shape dict so the endpoint responds instead of
        # falling through to legacy which will hang.
        if force_orchestrator:
            return {
                "output": payload,
                "detected_type": "text",
                "engine": "rc2-orchestrator-safe-fallback",
                "steps": [],
                "trace": [],
                "reached_shellcode": False,
                "terminal": "orchestrator-exception",
                "iocs": {"ips": [], "urls": [], "domains": [], "emails": [],
                         "file_paths": [], "bitcoin_addresses": [],
                         "hashes": {"md5": [], "sha1": [], "sha256": []}},
                "mitre": [], "lolbas": [], "tradecraft": [],
                "verdict": "needs_review", "risk_score": 0,
                "family": None,
                "engine_reason": (
                    f"Input {len(payload)}B exceeded orchestrator safety cap; "
                    "returning raw to prevent legacy pipeline hang."
                ),
            }
        return None

    if not result or not result.trace:
        if force_orchestrator:
            # Even with an empty trace, if the input is huge, return a
            # minimal shape so the request returns quickly.
            return {
                "output": (result.output if result else payload) or payload,
                "detected_type": "text",
                "engine": "rc2-orchestrator-no-op",
                "steps": [],
                "trace": [],
                "reached_shellcode": False,
                "terminal": (getattr(result, "terminal", "no-candidate") if result else "no-candidate"),
                "iocs": {"ips": [], "urls": [], "domains": [], "emails": [],
                         "file_paths": [], "bitcoin_addresses": [],
                         "hashes": {"md5": [], "sha1": [], "sha256": []}},
                "mitre": [], "lolbas": [], "tradecraft": [],
                "verdict": "needs_review", "risk_score": 0,
                "family": None,
                "engine_reason": (
                    f"Input {len(payload)}B — orchestrator found no candidate; "
                    "skipping legacy pipeline to prevent HTTP timeout."
                ),
            }
        return None

    # Adopt the orchestrator result AGGRESSIVELY.
    #
    # Rationale — Prod bug 2026-07-19: on very large inputs (≥5 KB) the
    # orchestrator sometimes stops with terminal="max-depth" or
    # "wall-time" while the legacy `smart_decode + magic_decode +
    # reasoning` fallback then hangs for the full HTTP timeout window.
    # Any orchestrator chain with ≥1 layer is objectively better than
    # legacy running for 60 s and returning garbage.
    terminal = getattr(result, "terminal", "") or ""
    # Clean terminals → always adopt
    clean_terminals = ("complete", "english", "family-identified")
    if terminal in clean_terminals:
        pass  # always adopt
    elif len(result.trace) >= 1:
        # Partial chain — still adopt so legacy doesn't hang the request.
        # The Recipe panel will show the layers we did peel, and if the
        # analyst wants more, they can add manual ops from the catalog.
        pass
    else:
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
