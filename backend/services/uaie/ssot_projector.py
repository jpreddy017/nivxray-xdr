"""UAIE · SSOT Projector · Priorities 1+2 · WRAPPER (no reimplementation).

Turns an ``OrchestratorResult`` into the canonical Workspace SSOT
bundle so the analyst UI can render Timeline / Verdict / Evidence /
Attack Story / MITRE / IOC panels directly from the UAIE loop —
without going through the legacy ``analysis_core`` convergence path.

Design (frozen per R25/R26/R27/R28)
────────────────────────────────────
  · Pure projection.  No decoders.  No LLM.  No new business logic.
  · The Verdict Card is produced by the EXISTING production module
    ``evidence_extractor.build_verdict_card`` — this wrapper only
    normalises inputs from the orchestrator's Evidence stream and
    calls it.  One source of truth.
  · Output shape matches the persisted SSOT (see ``services.ssot_store``
    and NIVXRAY_ARCHITECTURE_V1.md · R27).

Inputs
──────
  · ``root_input``  — the analyst's original paste (str).
  · ``root_output`` — the final decoded text (str) — usually
    ``last_child.payload.decode()`` for the deepest artifact.
  · ``orchestrator_result`` — the OrchestratorResult from a full loop.

Outputs
───────
  A dict with the canonical SSOT keys the Workspace expects:
    verdict_card, analysis, mitre, lolbas, iocs, chain, decode_trace,
    reached_shellcode, semantic, iedde, canonical_confidence,
    predicted_tree(=None), understanding(=None), analyst_narrative(=None),
    inline_story_preproc(=None), investigation_mode(=False).

The four ``None`` entries are populated by the DIE understand / narrate
pipeline elsewhere — they are NOT UAIE's responsibility.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .orchestrator import OrchestratorResult


# ─── Kind → normalisation used everywhere in the SSOT ───────────────
_IOC_KIND_MAP = {
    "url":     "urls",
    "ipv4":    "ips",
    "domain":  "domains",
    "sha256":  "sha256",
    "sha1":    "sha1",
    "md5":     "md5",
}


def _collect_iocs(result: OrchestratorResult) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for ev in result.evidence:
        bucket = _IOC_KIND_MAP.get(ev.kind)
        if not bucket:
            continue
        v = str(ev.value)
        out.setdefault(bucket, [])
        if v not in out[bucket]:
            out[bucket].append(v)
    return out


def _collect_mitre(result: OrchestratorResult) -> List[Dict[str, str]]:
    seen: set = set()
    out: List[Dict[str, str]] = []
    for ev in result.evidence:
        for t in (ev.mitre_techniques or []):
            if t in seen:
                continue
            seen.add(t)
            out.append({"id": t, "name": ""})
    return out


def _collect_lolbas(result: OrchestratorResult) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: set = set()
    for ev in result.evidence:
        if ev.kind != "lolbas":
            continue
        v = str(ev.value)
        if v in seen:
            continue
        seen.add(v)
        out.append({"binary": v})
    return out


def _collect_family(result: OrchestratorResult) -> Any:
    for ev in result.evidence:
        if ev.kind == "family":
            return ev.value
    return None


def _build_chain(result: OrchestratorResult) -> List[Dict[str, Any]]:
    """Reconstruct the analyst-facing decode chain from the ledger."""
    chain: List[Dict[str, Any]] = []
    for entry in list(result.ledger):
        # Ledger.action of 'execute' with a non-analyzer name IS a decode
        # step in the current plugin roster.
        if entry.action != "execute":
            continue
        chain.append({
            "op":            entry.actor,
            "reason":        entry.output_summary or "",
            "output_preview": "",
        })
    return chain


def _decode_trace(result: OrchestratorResult) -> List[Dict[str, Any]]:
    """Per-layer decode trace lifted from the ledger's ``execute`` +
    ``enqueue`` sequence — one row per child artifact.  Each row is
    enriched with ``evidence_extractor.layer_metadata`` (entropy,
    ascii-ness, hex preview, integrity flag) so the analyst UI can
    render the forensic per-layer panel from the SSOT alone."""
    from evidence_extractor import layer_metadata  # existing prod module
    # Build a lookup of child uri → payload so we can pass "after"
    # bytes to layer_metadata.
    child_by_uri: Dict[str, Any] = {}
    for a in result.artifacts.values():
        if a.depth > 0:
            child_by_uri[a.uri] = a
    trace: List[Dict[str, Any]] = []
    idx = 0
    for entry in list(result.ledger):
        if entry.action != "enqueue":
            continue
        child_type = ""
        for tok in (entry.output_summary or "").split():
            if tok.startswith("type="):
                child_type = tok.split("=", 1)[1]
                break
        child = child_by_uri.get(entry.artifact_uri)
        row: Dict[str, Any] = {
            "layer":   idx,
            "op":      child_type or entry.actor,
            "reason":  entry.output_summary,
            "out_len": (child.size if child else 0),
        }
        # Enrichment · evidence_extractor.layer_metadata
        try:
            after_text = (child.payload.decode("utf-8", errors="replace")
                          if child else "")
            row["metadata"] = layer_metadata(
                op_id=row["op"],
                after=after_text,
                integrity_ok=True,
            )
        except Exception:
            pass
        trace.append(row)
        idx += 1
    return trace


def _root_payload_bytes(result: OrchestratorResult) -> bytes:
    """The ``depth == 0`` artifact is the root the analyst pasted."""
    for a in result.artifacts.values():
        if a.depth == 0:
            return a.payload
    return b""


def _terminal_payload_text(result: OrchestratorResult) -> str:
    """Deepest artifact — surfaced as ``output`` in the SSOT."""
    deepest = None
    for a in result.artifacts.values():
        if deepest is None or a.depth > deepest.depth:
            deepest = a
    if deepest is None:
        return ""
    try:
        return deepest.payload.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _reached_shellcode(result: OrchestratorResult) -> bool:
    return any(a.artifact_type in ("shellcode_bytes", "cs_config_raw",
                                     "pe_bytes")
                for a in result.artifacts.values())


def project(orchestrator_result: OrchestratorResult,
             *,
             root_input: str = "",
             root_output: str = "") -> Dict[str, Any]:
    """Project the OrchestratorResult into the canonical Workspace SSOT.

    Wraps ``evidence_extractor.build_verdict_card`` — no reimplementation.
    """
    # Prefer explicit arguments; fall back to the artifacts.
    if not root_input:
        try:
            root_input = _root_payload_bytes(orchestrator_result).decode(
                "utf-8", errors="replace")
        except Exception:
            root_input = ""
    if not root_output:
        root_output = _terminal_payload_text(orchestrator_result)

    chain         = _build_chain(orchestrator_result)
    decode_trace  = _decode_trace(orchestrator_result)
    iocs          = _collect_iocs(orchestrator_result)
    mitre         = _collect_mitre(orchestrator_result)
    lolbas        = _collect_lolbas(orchestrator_result)
    family        = _collect_family(orchestrator_result)
    reached_sc    = _reached_shellcode(orchestrator_result)

    # ── Invoke the EXISTING production Verdict Card builder ───────
    from evidence_extractor import build_verdict_card
    findings: Dict[str, Any] = {
        "iocs":             iocs,
        "mitre_techniques": mitre,
        "lolbas":           lolbas,
    }
    if family:
        findings["family"] = family
    verdict_card = build_verdict_card(
        input_text=root_input,
        output_text=root_output,
        chain=chain,
        corrupted_container=None,
        findings=findings,
    )

    return {
        "verdict_card":               verdict_card,
        "analysis":                   {"iocs":   iocs,
                                       "mitre":  mitre,
                                       "ai_verdict": (verdict_card or {}).get("verdict")},
        "mitre":                      mitre,
        "lolbas":                     lolbas,
        "chain":                      chain,
        "steps":                      [{"op": c["op"], "args": {}} for c in chain],
        "decode_trace":               decode_trace,
        "reached_shellcode":          reached_sc,
        "corrupted_container":        None,
        "semantic":                   {"family": family} if family else {},
        "iedde":                      None,
        "iedde_terminal_state":       None,
        "canonical_confidence":       (verdict_card or {}).get("confidence"),
        "canonical_confidence_reason": "uaie_orchestrator_loop",
        # These are set by the DIE understand + narrate pipeline — not
        # UAIE's responsibility.  Restore-is-Rendering compliant.
        "understanding":              None,
        "analyst_narrative":          None,
        "inline_story_preproc":       None,
        "investigation_object":       None,
        "investigation_mode":         False,
        "predicted_tree":             None,
        # Provenance so downstream can distinguish UAIE-produced SSOTs.
        "source_engine":              "uaie",
        "uaie_stats": {
            "artifacts":  len(orchestrator_result.artifacts),
            "evidence":   len(orchestrator_result.evidence),
            "ledger":     len(orchestrator_result.ledger),
            # NOTE: total_ms deliberately excluded — non-deterministic
            # timing must NOT enter the canonical SSOT (R28 purity).
        },
    }


__all__ = ["project"]
