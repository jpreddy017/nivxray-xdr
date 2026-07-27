"""Unified Investigation Pipeline — the single source-of-truth entry
point analysts should use.

Analysts should not have to know that Input Understanding, Command
Reconstruction, Recursive Transformation, and Semantic Intent are
separate engines. They should experience a single investigation
flow:

    text
     │
     ▼
    Input Understanding      ← what is this artefact?
     │
     ▼
    Command Reconstruction   ← what will actually execute?
     │
     ▼
    Recursive Transformation ← reveal the hidden payload
     │
     ▼
    Semantic Intent          ← why does it matter?

The pipeline is deterministic, evidence-preserving, and Phase-5-
Evidence-Graph-ready.

Every intermediate output is exposed on the returned
``InvestigationResult`` so downstream engines (verdict, behaviour
correlation, analyst report generator) can consume the SAME payload
without re-invoking the underlying engines.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .analyst_report import AnalystReport, generate as build_report
from .behavior import BehaviorGraph, build as build_behavior
from .cre import reconstruct
from .cre.models import CommandReconstruction
from .graph import EvidenceGraph, build as build_graph
from .intent import IntentAssessment, assess as assess_intent
from .iu import classify
from .iu.models import ArtefactClassification, Capability
from .rte import TransformationChain, transform as run_rte
from .verdict import Verdict, assess_verdict

# Every capability the Brain currently supports. The pipeline
# emits a ``coverage`` map so callers can see WHICH stages fired
# on this specific artefact — an audit trail for regression proofs.
_SUPPORTED = {"iu", "cre", "rte", "intent", "behavior", "verdict", "graph", "report"}


# ── Atomic-IOC grammars ────────────────────────────────────────
# Bare filenames / domains / URLs / IPs / paths / registry keys /
# hashes are NOT decoding candidates. Applying XOR/ROT/base64
# brute-force to a bare filename produces meaningless "sc|nc%ini"
# garbage. When the ENTIRE input matches one of these grammars we
# short-circuit the pipeline with a BENIGN verdict and an honest
# "no decoding required" rationale — the atomic IOC surfaces as an
# IOC in the report, nothing more.
_ATOMIC_IOC_GRAMMARS: list[tuple[str, "re.Pattern[str]"]] = [
    ("filename",     re.compile(r"^[A-Za-z0-9._\-]{1,120}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|py|sh|jar|apk|elf)$")),
    ("url",          re.compile(r"^https?://[^\s]{1,2000}$")),
    ("ipv4",         re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")),
    ("domain",       re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$")),
    ("windows_path", re.compile(r"^[A-Za-z]:\\[^\s'\"|<>]{1,400}$")),
    ("registry",     re.compile(r"(?i)^HK(?:LM|CU|CR|U|CC)[:\\][^\s'\"]{1,400}$")),
    ("sha256",       re.compile(r"^[A-Fa-f0-9]{64}$")),
    ("sha1",         re.compile(r"^[A-Fa-f0-9]{40}$")),
    ("md5",          re.compile(r"^[A-Fa-f0-9]{32}$")),
]


def _atomic_ioc_kind(text: str) -> str | None:
    """Return the IOC kind if ``text`` is a bare atomic IOC, else None."""
    t = (text or "").strip().strip("'").strip('"')
    if not t or "\n" in t:
        return None
    for kind, pattern in _ATOMIC_IOC_GRAMMARS:
        if pattern.match(t):
            return kind
    return None


@dataclass
class InvestigationResult:
    """Full investigation output — one homogeneous payload the UI,
    Evidence Graph, verdict engine, and report generator can all
    consume without re-running any engine.
    """
    input:              str
    iu:                 ArtefactClassification
    cre:                CommandReconstruction | None
    rte:                TransformationChain
    intent:             IntentAssessment
    behavior:           BehaviorGraph
    verdict:            Verdict
    graph:              EvidenceGraph
    report:             AnalystReport | None = None
    coverage:           list[str] = field(default_factory=list)
    determinism_hash:   str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "input":             self.input,
            "iu":                self.iu.to_dict(),
            "cre":               self.cre.to_dict() if self.cre else None,
            "rte":               self.rte.to_dict(),
            "intent":            self.intent.to_dict(),
            "behavior":          self.behavior.to_dict(),
            "verdict":           self.verdict.to_dict(),
            "graph":             self.graph.to_dict(),
            "report":            self.report.to_dict() if self.report else None,
            "coverage":          list(self.coverage),
            "determinism_hash":  self.determinism_hash,
        }


def investigate(text: str) -> InvestigationResult:
    """Run the full Investigation Brain pipeline against ``text``.

    Pipeline order (all deterministic, all evidence-preserving):

        1. Input Understanding  (`iu.classify`)
        2. Command Reconstruction Engine  (`cre.reconstruct`) — only
           when IU dispatched ``Capability.CRE``.
        3. Recursive Transformation Engine (`rte.transform`) on the
           CRE effective payload if available, otherwise on the raw
           input.
        4. Semantic Intent Layer  (`intent.assess`) on the RTE final
           artefact — the deepest plaintext the Brain could reach.
    """
    text = text or ""
    coverage: list[str] = []

    # ── 0. Atomic-IOC short-circuit ────────────────────────────
    # If the input is a bare filename / URL / IP / domain / path /
    # registry key / hash there is NOTHING to decode. Skip the whole
    # pipeline and return a coherent "no decoding required" result so
    # heuristic brute-forcers cannot invent meaningless output.
    atomic_kind = _atomic_ioc_kind(text)

    # ── 1. Input Understanding ─────────────────────────────────
    iu_result = classify(text)
    coverage.append("iu")

    # ── 2. Command Reconstruction (only when dispatched) ───────
    cre_result: CommandReconstruction | None = None
    effective_payload = text
    if atomic_kind is None and Capability.CRE in iu_result.dispatch:
        try:
            cre_result = reconstruct(text)
            coverage.append("cre")
            if cre_result.effective_payload:
                effective_payload = cre_result.effective_payload
        except Exception:
            # CRE must never crash the pipeline. Fall back to raw text.
            cre_result = None

    # ── 3. Recursive Transformation ────────────────────────────
    # SKIP the recursive transformation loop when the input is a bare
    # atomic IOC — there is nothing to peel and any transformation
    # would be a hallucination.
    if atomic_kind is None:
        rte_result = run_rte(effective_payload)
    else:
        rte_result = run_rte("")   # produces an EMPTY_INPUT chain with layer 0
    coverage.append("rte")

    # ── 4. Semantic Intent — on the deepest layer we can reach ─
    final_text = rte_result.final.content if rte_result.artifacts else effective_payload
    intent_meta = {
        "iu_primary_type":    iu_result.primary_type.value,
        "iu_dispatch":        [c.value for c in iu_result.dispatch],
        "cre_dispatch_hint":  cre_result.dispatch_hint if cre_result else None,
        "rte_depth":          rte_result.depth,
        "rte_stop_reason":    rte_result.stop_reason.value,
    }
    intent_result = assess_intent(final_text, meta=intent_meta)
    coverage.append("intent")

    # ── 4b. Atomic-IOC honesty override ────────────────────────
    # A bare filename / domain / URL / path / hash cannot fire any
    # intent — force the intent list empty so downstream verdict
    # aggregation cannot invent adversarial signal.
    if atomic_kind is not None:
        intent_result = assess_intent("")   # empty → zero intents, safe summary

    # ── 5. Canonical Behaviour Graph ───────────────────────────
    # Lightweight abstraction over the Intent Layer that gives the
    # Verdict Engine, Analyst Report, and future Behaviour Correlation
    # a single normalised vocabulary. Deterministic — same intent set
    # always produces the same graph.
    behavior_graph = build_behavior(intent_result, final_text)
    coverage.append("behavior")

    # ── 6. Verdict Uplift — deterministic aggregation ──────────
    verdict_result = assess_verdict(intent_result.intents)
    # Atomic IOC: force verdict confidence to 0 so the analyst-facing
    # band renders as "unknown" (not "low"), honestly reflecting that
    # NO analysis was performed on the isolated artefact.
    if atomic_kind is not None:
        verdict_result.confidence = 0
        verdict_result.reason = (
            f"Bare {atomic_kind.replace('_', ' ')} in isolation — no "
            "adversarial signal is observable without surrounding context."
        )
    coverage.append("verdict")

    # ── 6. Evidence Graph — homogeneous DAG for explainability ─
    graph = build_graph(
        input_text=text, iu=iu_result, cre=cre_result,
        rte=rte_result, intent=intent_result,
    )
    coverage.append("graph")

    result = InvestigationResult(
        input=text,
        iu=iu_result,
        cre=cre_result,
        rte=rte_result,
        intent=intent_result,
        behavior=behavior_graph,
        verdict=verdict_result,
        graph=graph,
        coverage=coverage,
    )
    # ── 7. Analyst Report — flagship deterministic MDR output ──
    result.report = build_report(result)
    # ── 7b. Atomic-IOC honesty override in the report ──────────
    if atomic_kind is not None and result.report is not None:
        from .analyst_report.models import IOC
        result.report.executive_summary = (
            f"Input is a bare {atomic_kind.replace('_', ' ')} "
            f"(`{text.strip()}`). No decoding, transformation, or intent "
            "inference was performed — atomic IOCs cannot be assessed as "
            "malicious or benign in isolation. The artefact is surfaced as "
            "an IOC only; verdict is left BENIGN because no adversarial "
            "signal is observable without additional context."
        )
        # Ensure the atomic IOC itself is present in the IOC list.
        already = {(i.kind, i.value) for i in result.report.iocs}
        if (atomic_kind, text.strip()) not in already:
            result.report.iocs = [
                IOC(kind=atomic_kind, value=text.strip(),
                    context="Atomic IOC — analysed in isolation"),
                *result.report.iocs,
            ]
        # Clear recommendations / unknowns / MITRE / behaviours — an
        # atomic IOC has nothing to recommend acting on.
        result.report.recommendations  = []
        result.report.unknowns         = [
            f"The {atomic_kind} `{text.strip()}` was analysed in isolation. "
            "It cannot be assessed as malicious or benign without the "
            "surrounding investigation context that produced it."
        ]
        result.report.mitre            = []
        result.report.observed_behaviors = []
        result.report.intent_narrative = []
        result.report.evidence         = []
        result.report.behavior_graph   = {"nodes": [], "edges": []}
        result.report.confidence_signals = {
            "confidence":        "unknown",
            "evidence_strength": "insufficient",
            "unknowns_present":  "yes",
            "reasoning":         "atomic_ioc_no_analysis",
        }
    result.coverage.append("report")
    result.determinism_hash = _hash(result)
    return result


def _hash(result: InvestigationResult) -> str:
    """Deterministic hash of the full investigation — proves replay
    across every runtime."""
    blob = json.dumps({
        "iu_hash":     result.iu.determinism_hash,
        "cre_hash":    result.cre.determinism_hash if result.cre else None,
        "rte_hash":    result.rte.determinism_hash,
        "intent_hash": result.intent.determinism_hash,
        "verdict":     result.verdict.band.value,
        "verdict_conf": result.verdict.confidence,
        "graph_size": [len(result.graph.nodes), len(result.graph.edges)],
        "behavior_shape": result.behavior.kinds(),
        "coverage":    result.coverage,
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


__all__ = ["investigate", "InvestigationResult"]
