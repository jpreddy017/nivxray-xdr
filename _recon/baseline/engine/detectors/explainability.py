"""RC5 · Phase 8 · Explainability Compiler.

See § 11 (Explainability Contract) and § 14 (AI Persona Role) of
`/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`.

Assembles a fully-deterministic "explain" bundle for a single analysis:

  * `evidence_tree` — drill-down chain:
        Verdict → TopReason → Behavior → ExecNode → SIRNode →
        decoded-layer → original input.
    Every analyst conclusion is traceable back to its origin.

  * `confidence_breakdown` — per-stage confidence:
        decode → semantic_reconstruction → behavior → mitre → verdict.

  * `why_not_malicious` — for Benign / Suspicious verdicts only, an
    explicit list of the DETERMINISTIC signals that were absent
    (persistence, network activity, credential access, process injection,
    stealth markers, LOLBIN executions, …).

  * `narrative` placeholder — always empty in the deterministic bundle.
    Phase 14 (§ 14 invariant) permits an AI advisor to fill this field
    LATER, out-of-band; it MUST NOT influence any deterministic value.

Architectural invariants:
  * Consumes `ExecGraph`, `SIRTree`, `Behavior[]`, `MitreMapping[]`,
    `LolbinRow[]`, `Verdict`. Never reads raw `result["output"]` text.
  * Deterministic (byte-equal outputs for byte-equal inputs).
  * No `emergentintegrations` import — AI is out-of-band per § 14.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..exec_graph import Behavior, ExecGraph, ExecNode, NodeKind, SCHEMA_VERSION, TacticKind
from ..semantic_ir import SIRNode, SIRTree
from .lolbin_v2 import LolbinRow, LolbinState
from .mitre_mapper import MitreMapping
from .verdict_v2 import Verdict, VerdictTier


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class EvidenceLink(BaseModel):
    """One drill-down chain: verdict-reason → behavior → nodes → layers."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str
    dimension: str
    contribution: int
    behavior_id: str
    behavior_tactic: str
    behavior_sub_kind: Optional[str] = None
    behavior_reconstructed: str = ""
    exec_node_ids: Tuple[str, ...]
    exec_node_kinds: Tuple[str, ...] = ()
    exec_node_reconstructed: Tuple[str, ...] = ()
    sir_node_ids: Tuple[str, ...] = ()
    decode_layers: Tuple[int, ...] = ()
    source_spans: Tuple[Tuple[int, int], ...] = ()

    @field_validator("exec_node_ids")
    @classmethod
    def _one(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("EvidenceLink.exec_node_ids must be non-empty")
        return v


class ConfidenceBreakdown(BaseModel):
    """Per-stage confidence — every conclusion carries a five-stage trail."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    decode: int                           # median layer confidence over graph
    semantic_reconstruction: int          # median non-unresolved node confidence
    behavior: int                         # min behavior confidence (0 if empty)
    mitre: int                            # min mapping confidence (0 if empty)
    verdict: int                          # 100 - dispersion penalty
    weighted_overall: int                 # single number for header display
    weights: Dict[str, float] = Field(default_factory=lambda: {
        "decode":                  0.15,
        "semantic_reconstruction": 0.25,
        "behavior":                0.25,
        "mitre":                   0.15,
        "verdict":                 0.20,
    })

    @field_validator("decode", "semantic_reconstruction", "behavior",
                     "mitre", "verdict", "weighted_overall")
    @classmethod
    def _clamp(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"confidence stage out of [0,100]: {v}")
        return v


class WhyNotMalicious(BaseModel):
    """Deterministic 'missing signal' explanation for non-malicious verdicts."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    applicable: bool                      # False when verdict is malicious/critical
    verdict: str
    missing_signals: Tuple[str, ...]      # e.g. "no persistence"
    guardrails_applied: Tuple[str, ...]   # cap_applied / floor_applied surfaced
    summary: str = ""


class Explanation(BaseModel):
    """Top-level explain-bundle attached to `/api/rc5/parse`."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    evidence_tree: Tuple[EvidenceLink, ...]
    confidence_breakdown: ConfidenceBreakdown
    why_not_malicious: WhyNotMalicious
    narrative: str = ""                   # Locked empty; AI fills out-of-band
    narrative_origin: str = "advisor"     # Marker enforcing § 14 boundary
    narrative_model: Optional[str] = None
    schema_version: int = SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------
class ExplainabilityCompiler:
    """Emits an `Explanation` object from a full pipeline snapshot."""

    def compile(
        self,
        *,
        original_input: str,
        sir: SIRTree,
        graph: ExecGraph,
        behaviors: List[Behavior],
        mitre: List[MitreMapping],
        lolbins: List[LolbinRow],
        verdict: Verdict,
    ) -> Explanation:
        evidence_tree = self._build_evidence_tree(verdict, behaviors, graph, sir)
        confidence = self._compute_confidence(graph, behaviors, mitre, verdict)
        why_not = self._why_not_malicious(verdict, behaviors, lolbins)

        digest = hashlib.sha1(
            f"{verdict.id}|{[l.behavior_id for l in evidence_tree]}|"
            f"{confidence.weighted_overall}|{why_not.applicable}"
            .encode("utf-8")
        ).hexdigest()[:12]
        return Explanation(
            id="e_" + digest,
            evidence_tree=tuple(evidence_tree),
            confidence_breakdown=confidence,
            why_not_malicious=why_not,
        )

    # ── evidence tree ────────────────────────────────────────────────
    def _build_evidence_tree(
        self,
        verdict: Verdict,
        behaviors: List[Behavior],
        graph: ExecGraph,
        sir: SIRTree,
    ) -> List[EvidenceLink]:
        by_id = {b.id: b for b in behaviors}
        # Cross-index SIR nodes by their source span so exec nodes → SIR nodes
        # can be resolved via overlap.
        sir_by_span: List[SIRNode] = _flatten_sir(sir.root)
        out: List[EvidenceLink] = []
        for r in verdict.top_reasons:
            for bid in r.evidence_behavior_ids:
                b = by_id.get(bid)
                if b is None:
                    # LOLBIN-uplift synthetic behavior id — skip (no exec node graph)
                    continue
                exec_nodes = [graph.find(nid) for nid in b.evidence_nodes]
                exec_nodes = [n for n in exec_nodes if n is not None]
                if not exec_nodes:
                    continue
                kinds = tuple(n.kind.value for n in exec_nodes)
                recons = tuple(n.reconstructed for n in exec_nodes if n.reconstructed)
                spans = tuple(n.source_span for n in exec_nodes if n.source_span)
                layers = tuple(sorted({n.parent_layer for n in exec_nodes
                                       if n.parent_layer is not None}))
                sir_ids: List[str] = []
                for n in exec_nodes:
                    if n.source_span is None:
                        continue
                    lo, hi = n.source_span
                    for s in sir_by_span:
                        if s.source_span is None:
                            continue
                        slo, shi = s.source_span
                        if slo <= lo and shi >= hi:
                            sir_ids.append(s.id)
                            break
                out.append(EvidenceLink(
                    reason=r.reason,
                    dimension=r.dimension,
                    contribution=r.contribution,
                    behavior_id=b.id,
                    behavior_tactic=b.tactic.value,
                    behavior_sub_kind=b.sub_kind,
                    behavior_reconstructed=b.reconstructed,
                    exec_node_ids=tuple(n.id for n in exec_nodes),
                    exec_node_kinds=kinds,
                    exec_node_reconstructed=recons,
                    sir_node_ids=tuple(sir_ids),
                    decode_layers=layers,
                    source_spans=spans,
                ))
        return out

    # ── confidence breakdown ─────────────────────────────────────────
    def _compute_confidence(
        self,
        graph: ExecGraph,
        behaviors: List[Behavior],
        mitre: List[MitreMapping],
        verdict: Verdict,
    ) -> ConfidenceBreakdown:
        det_nodes = [n for n in graph.nodes if n.origin == "deterministic"]
        # decode = median confidence over decode/normalize/unresolved boundary
        decode_nodes = [n for n in det_nodes if n.kind in
                        (NodeKind.decode, NodeKind.normalize)]
        decode = _median([n.confidence for n in decode_nodes]) \
            if decode_nodes else _median([n.confidence for n in det_nodes]) or 100

        # semantic_reconstruction = median confidence over non-unresolved nodes.
        non_unresolved = [n for n in det_nodes if n.kind != NodeKind.unresolved]
        unresolved = [n for n in det_nodes if n.kind == NodeKind.unresolved]
        sem = _median([n.confidence for n in non_unresolved]) if non_unresolved else 100
        # Penalise for unresolved presence
        if unresolved:
            sem = max(0, sem - min(30, 5 * len(unresolved)))

        behavior_conf = min((b.confidence for b in behaviors), default=100)
        mitre_conf = min((m.confidence for m in mitre), default=100)

        # verdict = 100 - dispersion penalty (max_score - min_score) / 4
        scores = list(verdict.scores.values())
        if scores:
            dispersion = max(scores) - min(scores)
            verdict_conf = max(0, 100 - dispersion // 4)
        else:
            verdict_conf = 100

        weights = {
            "decode":                  0.15,
            "semantic_reconstruction": 0.25,
            "behavior":                0.25,
            "mitre":                   0.15,
            "verdict":                 0.20,
        }
        weighted = int(round(
            weights["decode"] * decode
            + weights["semantic_reconstruction"] * sem
            + weights["behavior"] * behavior_conf
            + weights["mitre"] * mitre_conf
            + weights["verdict"] * verdict_conf
        ))
        return ConfidenceBreakdown(
            decode=decode, semantic_reconstruction=sem,
            behavior=behavior_conf, mitre=mitre_conf, verdict=verdict_conf,
            weighted_overall=max(0, min(100, weighted)),
            weights=weights,
        )

    # ── why not malicious ────────────────────────────────────────────
    def _why_not_malicious(
        self,
        verdict: Verdict,
        behaviors: List[Behavior],
        lolbins: List[LolbinRow],
    ) -> WhyNotMalicious:
        applicable = verdict.verdict in (VerdictTier.benign, VerdictTier.suspicious)
        if not applicable:
            return WhyNotMalicious(
                applicable=False,
                verdict=verdict.verdict.value,
                missing_signals=(),
                guardrails_applied=(),
                summary=f"Verdict is {verdict.verdict.value} — 'why-not-malicious' not applicable.",
            )
        signals: List[str] = []
        tactics = {b.tactic for b in behaviors}
        subkinds = {(b.tactic.value, b.sub_kind) for b in behaviors}

        if TacticKind.persistence not in tactics \
                and TacticKind.wmi_subscription not in tactics:
            signals.append("no persistence installed (no autorun / task / service / WMI sub)")
        if TacticKind.credential_access not in tactics:
            signals.append("no credential access / credential dumping")
        if TacticKind.command_and_control not in tactics \
                and TacticKind.dns_query not in tactics:
            signals.append("no network activity (no download, no HTTP/DNS beacon)")
        if TacticKind.exfiltration not in tactics:
            signals.append("no data exfiltration channel")
        if ("execution", "shellcode_exec") not in subkinds:
            signals.append("no shellcode / reflective execution observed")
        if ("defense_evasion", "reflection") not in subkinds:
            signals.append("no reflective assembly load")
        if ("defense_evasion", "bypass_amsi") not in subkinds \
                and ("defense_evasion", "bypass_etw") not in subkinds:
            signals.append("no AMSI / ETW bypass")
        if TacticKind.impact not in tactics:
            signals.append("no destructive impact behavior (no file destruction)")
        executed_lolbins = [l for l in lolbins if l.state == LolbinState.executed]
        if not executed_lolbins:
            signals.append("no LOLBIN executed (only referenced or expanded, if any)")
        if verdict.scores["capability"] <= 20:
            signals.append(f"low capability score ({verdict.scores['capability']}/100)")
        if verdict.scores["impact"] <= 20:
            signals.append(f"low impact score ({verdict.scores['impact']}/100)")

        guardrails: List[str] = []
        if verdict.cap_applied:
            guardrails.append(f"cap applied: {verdict.cap_applied}")
        if verdict.floor_applied:
            guardrails.append(f"floor applied: {verdict.floor_applied}")

        summary = (
            f"Verdict {verdict.verdict.value} because "
            + "; ".join(signals[:4])
            + ("." if signals else "")
        )
        return WhyNotMalicious(
            applicable=True,
            verdict=verdict.verdict.value,
            missing_signals=tuple(signals),
            guardrails_applied=tuple(guardrails),
            summary=summary,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _flatten_sir(node: SIRNode, acc: Optional[List[SIRNode]] = None) -> List[SIRNode]:
    if acc is None:
        acc = []
    acc.append(node)
    for c in node.children:
        _flatten_sir(c, acc)
    return acc


def _median(values: List[int]) -> int:
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    return int(s[n // 2] if n % 2 == 1 else (s[n // 2 - 1] + s[n // 2]) / 2)


# ---------------------------------------------------------------------------
# Module-level accessor
# ---------------------------------------------------------------------------
_INSTANCE = ExplainabilityCompiler()


def compile_explanation(
    *,
    original_input: str,
    sir: SIRTree,
    graph: ExecGraph,
    behaviors: List[Behavior],
    mitre: List[MitreMapping],
    lolbins: List[LolbinRow],
    verdict: Verdict,
) -> Explanation:
    return _INSTANCE.compile(
        original_input=original_input, sir=sir, graph=graph,
        behaviors=behaviors, mitre=mitre, lolbins=lolbins, verdict=verdict,
    )


def get_explainability_compiler() -> ExplainabilityCompiler:
    return _INSTANCE


__all__ = [
    "Explanation",
    "EvidenceLink",
    "ConfidenceBreakdown",
    "WhyNotMalicious",
    "ExplainabilityCompiler",
    "compile_explanation",
    "get_explainability_compiler",
]
