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

from typing import Any, Dict, List, Optional

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


def _termination_reason(result: OrchestratorResult) -> Dict[str, Any]:
    """R25.2 · Explain WHY the loop stopped.

    Precedence:
      1. max_artifacts / max_depth cap hit          → 'safety_cap'
      2. any 'error' entry in the ledger tail       → 'capability_failed'
      3. queue drained with no work last iteration  → 'stable_graph'
      4. queue drained with unrecognised artifacts  → 'unsupported_artifact'
      5. fallback                                    → 'unknown'
    """
    warnings = result.warnings or []
    if any("cap" in w.lower() for w in warnings):
        return {"reason": "safety_cap", "detail": "; ".join(warnings)}
    tail = list(result.ledger)[-8:] if result.ledger else []
    errored = [e for e in tail if getattr(e, "action", "") == "error"]
    if errored:
        return {"reason": "capability_failed",
                "detail": errored[-1].output_summary or errored[-1].actor}
    # Any artifacts that no capability could execute against?
    executed = {e.artifact_uri for e in result.ledger if e.action == "execute"}
    all_uris = set(result.artifacts.keys())
    unsupported = all_uris - executed
    if unsupported:
        types = sorted({result.artifacts[u].artifact_type
                        for u in unsupported if u in result.artifacts})
        return {"reason": "unsupported_artifact",
                "detail": f"artifact_types={types!r}"}
    return {"reason": "stable_graph",
            "detail": "queue drained · no new artifacts, no new evidence"}


def _confidence_evolution(result: OrchestratorResult) -> List[Dict[str, Any]]:
    """R25.3 · Confidence-evolution trace (analyst-visible).

    Walks the ledger and records the winning recognition confidence
    for every artifact in the order it was discovered.  Analysts see
    the exact chain:

        text            0.31
          → utf16       0.82
          → base64      0.96
          → gzip        0.99
          → shellcode   1.00
          → pe          1.00

    which makes it obvious at which stage certainty jumped and where
    it plateaued.  Purely derived from the ledger — no re-analysis.
    """
    from .ledger import ACTION_RECOGNIZE
    by_uri: Dict[str, Dict[str, Any]] = {}
    seq_by_uri: Dict[str, int] = {}
    for e in result.ledger:
        if e.action != ACTION_RECOGNIZE or e.confidence is None:
            continue
        cur = by_uri.get(e.artifact_uri)
        # Keep the highest-confidence recognition per artifact.
        if cur is None or (e.confidence or 0) > (cur.get("confidence") or 0):
            by_uri[e.artifact_uri] = {
                "artifact_uri":  e.artifact_uri,
                "artifact_type": e.output_summary,
                "recognizer":    e.actor,
                "confidence":    float(e.confidence),
            }
            seq_by_uri.setdefault(e.artifact_uri, e.seq)
    # Order by first-discovery seq so the chain reads root-to-leaf.
    steps = sorted(by_uri.values(),
                   key=lambda x: seq_by_uri.get(x["artifact_uri"], 0))
    # Enrich each step with the artifact's declared type + depth.
    for step in steps:
        art = result.artifacts.get(step["artifact_uri"])
        if art is not None:
            step["declared_type"] = art.artifact_type
            step["depth"]         = art.depth
    return steps


def _capability_coverage(result: OrchestratorResult,
                          all_plugin_names: List[str]) -> Dict[str, Any]:
    """R25.2 · Per-capability outcome across the whole loop.

    Buckets every registered plugin into:
      · executed        — at least one 'execute' ledger entry
      · skipped         — schedule_skip entry (grouped by skip_reason)
      · failed          — schedule_skip with reason=capability_error
      · not_applicable  — recognizer never matched, no skip logged

    The ``skip_reasons`` sub-map lets the analyst see, per capability,
    exactly why it didn't run (structured `skip_reason=<code>` codes
    from the ledger).
    """
    from .ledger import ACTION_EXECUTE, ACTION_SCHEDULE_SKIP, SKIP_CAPABILITY_ERROR
    executed: set = set()
    failed:   set = set()
    skipped:  set = set()
    skip_reasons: Dict[str, str] = {}
    for e in result.ledger:
        if e.action == ACTION_EXECUTE:
            executed.add(e.actor)
            continue
        if e.action == ACTION_SCHEDULE_SKIP:
            # Parse structured `skip_reason=<code>` prefix (canonical
            # format from ledger.format_skip_reason).
            out = e.output_summary or ""
            code = ""
            if out.startswith("skip_reason="):
                code = out[len("skip_reason="):].split(" ", 1)[0]
            if code == SKIP_CAPABILITY_ERROR:
                failed.add(e.actor)
            else:
                skipped.add(e.actor)
            # First-seen reason wins so we surface the *initial* cause.
            skip_reasons.setdefault(e.actor, code or "unknown")
    covered = executed | failed | skipped
    not_applicable = [n for n in all_plugin_names if n not in covered]
    return {
        "executed":       sorted(executed),
        "skipped":        sorted(skipped - executed),
        "failed":         sorted(failed - executed),
        "not_applicable": sorted(not_applicable),
        # Analyst-visible "why" — {capability_name: skip_reason_code}
        "skip_reasons":   {k: v for k, v in sorted(skip_reasons.items())
                             if k not in executed},
    }


def project(orchestrator_result: OrchestratorResult,
             *,
             root_input: str = "",
             root_output: str = "",
             all_plugin_names: Optional[List[str]] = None) -> Dict[str, Any]:
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
        # R25.2 · Loop transparency for analysts (why the loop stopped
        # + which capabilities considered the investigation).
        "termination":         _termination_reason(orchestrator_result),
        "capability_coverage": _capability_coverage(
            orchestrator_result,
            list(all_plugin_names or []),
        ),
        # R25.3 · Confidence-evolution trace — how certainty grew at
        # each stage of the peel.  Analyst-visible; pure ledger read.
        "confidence_evolution": _confidence_evolution(orchestrator_result),
    }


__all__ = ["project"]
