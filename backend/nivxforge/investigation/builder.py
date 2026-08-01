"""ADR-0014 · Slice-A + Slice-B CIO Builder.

Assembles an Evidence Graph and Canonical Investigation Object from a
`FactSubstrate` — the same substrate the ADR-0009 CIM composer already
reads from. This preserves §1.1.6 (additive migration) and §1.1.8
(input-agnostic: any surface that populates a FactSubstrate gets a CIO).

Slice-A guarantees:
    - Every artifact node, decoded_fragment node, ioc node,
      mitre_technique node, lolbin node, family_match node, and
      behaviour node is added.
    - Every promotion is linked via a `produces` or `contributes_to`
      edge from the parent artifact/fragment.
    - MITRE techniques reference the artifact (or a decoded fragment
      if provenance points to one).
    - Deterministic construction: same FactSubstrate → same graph
      (identical node ids, identical edge order after
      `deterministic_serialize`).

Slice-B guarantees (§1.1.7):
    - Every promotion emits a ReasoningStep with input_nodes,
      output_nodes, confidence_before, confidence_after, rule id,
      and analyst-facing explanation.
    - Timeline is derived deterministically from the ReasoningStep
      stream — a read-only view (no independent data).
    - Aggregate `confidence` becomes the confidence_after of the last
      reasoning step, giving a replayable derivation.

Slice-C (verdict engine unification) is out of scope here.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from nivxforge.cim.fact_substrate import FactSubstrate
from nivxforge.investigation.graph import Edge, EvidenceGraph, Node
from nivxforge.investigation.models import CIO, CIOSource, ReasoningStep


# ─── Deterministic id helpers ───────────────────────────────────────────

def _short_hash(s: str, n: int = 8) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:n]


class _IdGen:
    """Dense monotonic id generator scoped to a single CIO build."""
    def __init__(self, prefix: str) -> None:
        self._prefix = prefix
        self._counter = 0

    def next(self) -> str:
        self._counter += 1
        return f"{self._prefix}-{self._counter:03d}"


# ─── LOLBIN detection (heuristic, deterministic) ────────────────────────

_LOLBINS = {
    "regsvr32", "rundll32", "mshta", "certutil", "bitsadmin", "wmic",
    "installutil", "msbuild", "msiexec", "schtasks", "powershell",
    "cmd", "cscript", "wscript", "reg",
}


def _detect_lolbins(text: str) -> List[str]:
    lower = text.lower()
    hits = []
    for name in sorted(_LOLBINS):
        if name in lower:
            hits.append(name)
    return hits


# ─── Deterministic timestamp base ──────────────────────────────────────
#
# ReasoningStep timestamps must be deterministic (same input → same CIO).
# We derive from a fixed epoch anchored by the input hash so replays
# match. This is required by §1.1.7 (replayable reasoning).

_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _det_timestamp(step_no: int, input_text: str) -> datetime:
    """Deterministic timestamp: epoch + step offset (input-invariant)."""
    from datetime import timedelta
    return _EPOCH + timedelta(seconds=step_no)


# ─── Confidence heuristic (Slice-A: derived from evidence density) ──────

def _aggregate_confidence(graph: EvidenceGraph) -> float:
    scored = [n.confidence for n in graph.nodes if n.kind != "artifact"]
    if not scored:
        return 0.0
    return round(sum(scored) / len(scored), 4)


# ─── Explanation phrases (rule id → analyst-facing text) ────────────────

def _explain_decoder(op: str) -> str:
    op = (op or "decode").lower()
    if "base64" in op or "b64" in op:
        return "Base64 payload decoded — one obfuscation layer peeled."
    if "gzip" in op or "deflate" in op:
        return "Compressed payload inflated — stream layer removed."
    if "xor" in op:
        return "XOR-obfuscated payload recovered — key derived from stream."
    if "encoded" in op or "powershell" in op:
        return "PowerShell -EncodedCommand block decoded."
    if "utf" in op or "unicode" in op:
        return "Unicode-encoded payload normalised to plain text."
    if "hex" in op:
        return "Hex-encoded payload converted to bytes."
    return f"Decoder '{op}' peeled one layer of the payload."


def _explain_ioc(kind: str, value: str, stages_context: bool) -> str:
    kind_pretty = {
        "ip": "IP address", "domain": "domain",
        "url": "URL", "hash": "file hash", "email": "email address",
    }.get(kind, kind)
    caveat = "" if stages_context else " (syntactic-only match — context gate did not fire)"
    return f"Recovered {kind_pretty} `{value}` from the decoded payload{caveat}."


def _explain_mitre(tid: str, name: Optional[str]) -> str:
    label = name or "technique"
    return f"Mapped to ATT&CK {tid} · {label} — inferred from the decoded payload's behaviour."


def _explain_lolbin(name: str) -> str:
    return (
        f"Detected LOLBIN reference to `{name}` — signed binary can proxy "
        f"execution and evade allow-lists."
    )


def _explain_family(provider: str, label: str) -> str:
    return f"Threat-intel provider `{provider}` labels this as `{label}`."


def _explain_behaviour(note: str) -> str:
    return f"Observed behaviour: {note.strip()[:160]}"


# ─── Builder ────────────────────────────────────────────────────────────

def build_cio(
    fs: FactSubstrate,
    *,
    cio_id: Optional[str] = None,
) -> CIO:
    """Build a CIO from a FactSubstrate.

    Pure function of its input. Never touches network, DB, or HTTP.
    Emits a ReasoningStep for every promotion (Slice-B, §1.1.7).
    """
    nid = _IdGen("N")
    rid = _IdGen("RS")
    graph = EvidenceGraph()
    steps: List[ReasoningStep] = []
    running_conf = 0.0

    def _emit_step(
        rule: str,
        input_nodes: List[str],
        output_nodes: List[str],
        explanation: str,
        conf_delta: float = 0.0,
    ) -> None:
        nonlocal running_conf
        before = running_conf
        running_conf = min(1.0, max(0.0, before + conf_delta))
        step_id = rid.next()
        # step_no from id ("RS-001" -> 1)
        step_no = int(step_id.split("-")[1])
        steps.append(ReasoningStep(
            step_id=step_id,
            timestamp=_det_timestamp(step_no, fs.input_text),
            rule=rule,
            input_nodes=list(input_nodes),
            output_nodes=list(output_nodes),
            confidence_before=round(before, 4),
            confidence_after=round(running_conf, 4),
            explanation=explanation,
        ))

    # ── artifact node (root of every graph) ──────────────────────────
    artifact_node = graph.add_node(Node(
        id=nid.next(),
        kind="artifact",
        label=f"Input · {fs.input_kind}",
        value=None,
        confidence=1.0,
        provenance="input",
        attrs={"input_kind": fs.input_kind, "length": len(fs.input_text)},
    ))
    _emit_step(
        rule="input.ingest",
        input_nodes=[],
        output_nodes=[artifact_node.id],
        explanation=(
            f"Received {fs.input_kind} artifact ({len(fs.input_text)} chars) "
            f"for investigation."
        ),
        conf_delta=0.0,
    )

    # ── decoded_fragment nodes ───────────────────────────────────────
    fragment_by_idx: Dict[int, str] = {}
    prev_id = artifact_node.id
    for layer in fs.decoder_chain:
        f_id = nid.next()
        graph.add_node(Node(
            id=f_id,
            kind="decoded_fragment",
            label=f"Layer {layer.idx}: {layer.op}",
            value=layer.output_preview or None,
            confidence=0.85,
            provenance=f"decoder:{layer.op}",
            attrs={
                "idx": layer.idx,
                "op": layer.op,
                "input_kind": layer.input_kind,
                "output_kind": layer.output_kind,
            },
        ))
        graph.add_edge(Edge(source=prev_id, target=f_id, kind="produces", weight=1.0))
        fragment_by_idx[layer.idx] = f_id
        _emit_step(
            rule=f"decoder.{layer.op}",
            input_nodes=[prev_id],
            output_nodes=[f_id],
            explanation=_explain_decoder(layer.op),
            conf_delta=+0.05,
        )
        prev_id = f_id

    terminal_fragment_id = prev_id

    # ── ioc nodes ────────────────────────────────────────────────────
    ioc_seen: Dict[str, str] = {}
    for rec in fs.iocs:
        key = f"{rec.kind}:{rec.value}"
        if key in ioc_seen:
            continue
        context_gated = "context" in rec.stage_passed
        conf = 0.9 if context_gated else 0.6
        i_id = nid.next()
        graph.add_node(Node(
            id=i_id,
            kind="ioc",
            label=f"{rec.kind.upper()} · {rec.value}",
            value=rec.value,
            confidence=conf,
            provenance="extractor:ioc",
            attrs={
                "ioc_kind": rec.kind,
                "normalized": rec.normalized_value or rec.value,
                "stages": list(rec.stage_passed),
            },
        ))
        graph.add_edge(Edge(source=terminal_fragment_id, target=i_id, kind="produces", weight=1.0))
        ioc_seen[key] = i_id
        _emit_step(
            rule=f"ioc.{rec.kind}.extract",
            input_nodes=[terminal_fragment_id],
            output_nodes=[i_id],
            explanation=_explain_ioc(rec.kind, rec.value, context_gated),
            conf_delta=+0.1 if context_gated else +0.03,
        )

    # ── mitre_technique nodes ────────────────────────────────────────
    tech_seen: Dict[str, str] = {}
    for hit in fs.mitre_hits:
        tid = hit.technique_id.strip()
        if not tid or tid in tech_seen:
            continue
        t_id = nid.next()
        graph.add_node(Node(
            id=t_id,
            kind="mitre_technique",
            label=hit.name or tid,
            value=tid,
            confidence=0.8,
            provenance=f"mitre:{hit.provenance or 'inferred'}",
            attrs={"technique_id": tid, "tactic": hit.tactic or "", "name": hit.name or ""},
        ))
        graph.add_edge(Edge(source=terminal_fragment_id, target=t_id, kind="references", weight=0.8))
        tech_seen[tid] = t_id
        _emit_step(
            rule=f"mitre.map.{tid}",
            input_nodes=[terminal_fragment_id],
            output_nodes=[t_id],
            explanation=_explain_mitre(tid, hit.name),
            conf_delta=+0.08,
        )

    # ── lolbin nodes ─────────────────────────────────────────────────
    scan_text = fs.input_text or ""
    for layer in fs.decoder_chain:
        scan_text += "\n" + (layer.output_preview or "")
    lolbin_seen: Dict[str, str] = {}
    for name in _detect_lolbins(scan_text):
        if name in lolbin_seen:
            continue
        l_id = nid.next()
        graph.add_node(Node(
            id=l_id,
            kind="lolbin",
            label=f"LOLBIN · {name}",
            value=name,
            confidence=0.7,
            provenance="rule:lolbin_scan",
            attrs={"binary": name},
        ))
        graph.add_edge(Edge(source=terminal_fragment_id, target=l_id, kind="references", weight=0.7))
        lolbin_seen[name] = l_id
        _emit_step(
            rule=f"lolbin.detect.{name}",
            input_nodes=[terminal_fragment_id],
            output_nodes=[l_id],
            explanation=_explain_lolbin(name),
            conf_delta=+0.05,
        )

    # ── family_match nodes (from TI hits) ────────────────────────────
    family_seen: Dict[str, str] = {}
    for hit in fs.ti_hits:
        label = (hit.label or "").strip()
        if not label:
            continue
        key = f"{hit.provider}:{label}"
        if key in family_seen:
            continue
        fam_id = nid.next()
        graph.add_node(Node(
            id=fam_id,
            kind="family_match",
            label=f"{hit.provider} · {label}",
            value=label,
            confidence=0.75,
            provenance=f"ti:{hit.provider}",
            attrs={"provider": hit.provider, "subject": hit.subject or ""},
        ))
        graph.add_edge(Edge(source=terminal_fragment_id, target=fam_id, kind="contributes_to", weight=0.75))
        family_seen[key] = fam_id
        _emit_step(
            rule=f"ti.family.{hit.provider}",
            input_nodes=[terminal_fragment_id],
            output_nodes=[fam_id],
            explanation=_explain_family(hit.provider, label),
            conf_delta=+0.07,
        )

    # ── behaviour nodes (from reasoning notes, if any) ───────────────
    for i, note in enumerate(fs.reasoning_notes[:10]):
        if not (note or "").strip():
            continue
        b_id = nid.next()
        graph.add_node(Node(
            id=b_id,
            kind="behaviour",
            label=(note or "").strip()[:120],
            value=None,
            confidence=0.6,
            provenance="reasoning:notes",
            attrs={"idx": i},
        ))
        graph.add_edge(Edge(source=terminal_fragment_id, target=b_id, kind="contributes_to", weight=0.6))
        _emit_step(
            rule="behaviour.observe",
            input_nodes=[terminal_fragment_id],
            output_nodes=[b_id],
            explanation=_explain_behaviour(note),
            conf_delta=+0.04,
        )

    # ── CIO assembly ─────────────────────────────────────────────────
    input_seed = f"{fs.source_endpoint or 'unknown'}::{fs.input_text[:64]}"
    resolved_id = cio_id or f"CIO-{_short_hash(input_seed, 12)}"

    decode_chain = [
        {
            "idx": layer.idx,
            "op": layer.op,
            "input_kind": layer.input_kind,
            "output_kind": layer.output_kind,
            "preview": layer.output_preview,
            "reason": layer.reason,
            "node_id": fragment_by_idx.get(layer.idx),
        }
        for layer in fs.decoder_chain
    ]

    # ── P1-02c hotfix · Shellcode-detected synthetic node ──────────
    # When the pipeline reached shellcode, inject a synthetic HIGH
    # attack-chain node so the verdict engine surfaces this signal AND
    # attach the shellcode analysis onto the last decoded_fragment so
    # the projector can render the proper analyst card.
    sc = (getattr(fs, "verdict_metadata", None) or {}).get("shellcode")
    if isinstance(sc, dict) and sc.get("is_shellcode"):
        sc_nid = nid.next()
        graph.add_node(Node(
            id=sc_nid,
            kind="behaviour",
            label=f"Shellcode detected · {sc.get('family')} · {sc.get('arch') or 'unknown arch'}",
            value="shellcode_detected",
            confidence=0.95,
            provenance="nivxforge/shellcode-analyzer",
            attrs={
                "synthetic": True,
                "signal": "shellcode_detected",
                "family": sc.get("family"),
                "arch": sc.get("arch"),
                "size": sc.get("size"),
                "entropy": sc.get("entropy"),
                "c2_ips": sc.get("c2_ips") or [],
                "c2_urls": sc.get("c2_urls") or [],
                "user_agents": sc.get("user_agents") or [],
                "hex_preview": sc.get("hex_preview"),
                "family_mitre": sc.get("family_mitre"),
            },
        ))
        # Also decorate the last decoded_fragment (if present) so the
        # X-Lab decoded-output preview picks up the shellcode summary.
        last_frag_id = None
        for _f_idx in sorted(fragment_by_idx.keys(), reverse=True):
            last_frag_id = fragment_by_idx[_f_idx]
            break
        if last_frag_id:
            for node in graph.nodes:
                if node.id == last_frag_id:
                    node.attrs["is_shellcode"] = True
                    node.attrs["shellcode_summary"] = {
                        "family":  sc.get("family"),
                        "arch":    sc.get("arch"),
                        "size":    sc.get("size"),
                        "entropy": sc.get("entropy"),
                        "c2_ips":  sc.get("c2_ips") or [],
                        "user_agents": sc.get("user_agents") or [],
                    }
                    break

    # ADR-0014 Slice-C · unified verdict engine reads the graph +
    # optional Workspace-parity metadata (Rules · LOLBAS · Recipes · TI).
    from nivxforge.investigation.verdict_engine import compute_verdict
    _verdict = compute_verdict(graph, metadata=getattr(fs, "verdict_metadata", None))

    # Emit a verdict node into the graph itself, linked from the
    # contributing nodes. The graph is the investigation (§1.1.2).
    v_id = nid.next()
    graph.add_node(Node(
        id=v_id,
        kind="verdict",
        label=f"Verdict · {_verdict.label}",
        value=_verdict.label,
        confidence=_verdict.confidence,
        provenance="engine:unified-verdict",
        attrs={"confidence_pct": _verdict.confidence_pct},
    ))
    for c in _verdict.contributors[:20]:
        try:
            graph.add_edge(Edge(
                source=c.node_id, target=v_id,
                kind="contributes_to", weight=min(1.0, c.weight / 10.0),
            ))
        except Exception:
            pass
    # If no contributors linked to the verdict node, tether it to the
    # artifact root so it does not become a G2 orphan.
    if not _verdict.contributors:
        try:
            graph.add_edge(Edge(
                source=artifact_node.id, target=v_id,
                kind="contributes_to", weight=0.0,
            ))
        except Exception:
            pass
    _emit_step(
        rule="verdict.compute",
        input_nodes=[c.node_id for c in _verdict.contributors[:20]],
        output_nodes=[v_id],
        explanation=_verdict.reason,
        conf_delta=0.0,
    )

    # Aggregate confidence: use the verdict engine's weighted mean —
    # replayable, engine-authoritative (§1.1.3).
    final_conf = _verdict.confidence

    cio = CIO(
        cio_id=resolved_id,
        source=CIOSource(
            surface=fs.source_surface or "api",
            endpoint=fs.source_endpoint,
            correlation_id=fs.correlation_id,
        ),
        input_text=fs.input_text,
        input_kind=fs.input_kind,
        decode_chain=decode_chain,
        evidence_graph=graph,
        reasoning_steps=steps,
        confidence=round(final_conf, 4),
        verdict=_verdict.model_dump(mode="json"),
        timeline=[
            {
                "step_id": s.step_id,
                "at": s.timestamp.isoformat(),
                "rule": s.rule,
                "explanation": s.explanation,
                "input_nodes": s.input_nodes,
                "output_nodes": s.output_nodes,
            }
            for s in steps
        ],
        summary={},
        recommendations=[],
        reports={},
        metadata={
            "adr": "0014",
            "slice": "D",
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "reasoning_step_count": len(steps),
            "verdict_engine": _verdict.engine,
            # P1-02c hotfix · surface the shellcode summary at CIO top-
            # level metadata so the projector renders a proper analyst
            # banner instead of dumping raw bytes.
            **({"shellcode": sc} if isinstance(sc, dict) and sc.get("is_shellcode") else {}),
        },
    )

    # P1-02d · Investigation Truth Model — the canonical projection
    # Story · Executive Summary · Reports · Verdict · Timeline · Ledger
    # · Notebook all consume. Pure derivation of the current CIO state.
    # P0.1 FIX · Truth MUST be built BEFORE the summary so the customer
    # report (composed inside compose_summary) can read
    # `cio.truth.findings` and `cio.truth.recommendations` — otherwise
    # the critic drops those sections as "empty" even though the CIO
    # carries them.
    from nivxforge.investigation.truth_model import build_truth
    cio.truth = build_truth(cio).model_dump(mode="json")

    # ADR-0014 Slice-D · compose the canonical Summary. Backend owns
    # summary composition (§1.1.9). Frontend never writes prose.
    from nivxforge.investigation.summary_composer import compose_summary
    cio.summary = compose_summary(cio).model_dump(mode="json")
    cio.recommendations = list(cio.summary.get("recommendations", []) or [])

    return cio


__all__ = ["build_cio"]

