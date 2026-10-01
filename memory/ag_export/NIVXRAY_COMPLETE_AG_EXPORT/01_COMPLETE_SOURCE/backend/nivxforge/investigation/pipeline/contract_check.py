"""Contract #11 · Investigation Acceptance Contract.

Every completed investigation MUST answer 12 questions from the Graph
alone (per Addendum B). This module implements the deterministic
answer-check that operates on `InvestigationState`.

If an answer is unavailable → return
`"Cannot determine from available evidence"`. Never guess.
Every affirmative answer traces to a `graph_node_ids` list so the
narrative can cite specific evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .graph_builder import InvestigationGraph
from .orchestrator import InvestigationState


UNKNOWN = "Cannot determine from available evidence"


@dataclass(frozen=True)
class ContractAnswer:
    question: str
    answer: str
    graph_node_ids: Tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.0


@dataclass(frozen=True)
class ContractReport:
    answers: Tuple[ContractAnswer, ...]

    @property
    def answered_count(self) -> int:
        return sum(1 for a in self.answers if a.answer != UNKNOWN)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "answered": self.answered_count,
            "total": len(self.answers),
            "answers": [
                {
                    "question": a.question,
                    "answer": a.answer,
                    "graph_node_ids": list(a.graph_node_ids),
                    "confidence": a.confidence,
                } for a in self.answers
            ],
        }


def check_contract11(state: InvestigationState) -> ContractReport:
    """Answer all 12 Contract #11 questions from the graph alone."""
    g = state.graph
    ans: List[ContractAnswer] = []

    # 1. What happened?
    detections = g.nodes_of("detection")
    if detections:
        top = max(detections, key=lambda n: len(g.edges_from(n.id)) + len(g.edges_to(n.id)))
        ans.append(ContractAnswer(
            "What happened?",
            f"Detection '{top.value}' triggered.",
            (top.id,),
            top.confidence,
        ))
    elif g.nodes_of("command"):
        cmd = g.nodes_of("command")[0]
        ans.append(ContractAnswer(
            "What happened?",
            f"Command executed: {cmd.value[:120]}",
            (cmd.id,),
            cmd.confidence,
        ))
    else:
        ans.append(ContractAnswer("What happened?", UNKNOWN, tuple(), 0.0))

    # 2. How do we know? (evidence coverage)
    total_ev = sum(len(n.evidence_refs) for n in g.nodes)
    if total_ev:
        ans.append(ContractAnswer(
            "How do we know?",
            f"{total_ev} evidence references across {len(g.nodes)} graph nodes.",
            tuple(n.id for n in g.nodes[:5]),
            0.9,
        ))
    else:
        ans.append(ContractAnswer("How do we know?", UNKNOWN, tuple(), 0.0))

    # 3. What artifacts were observed?
    artifact_kinds = ("command", "url", "ip", "domain", "hash", "file",
                       "registry", "dns")
    obs = {k: len(g.nodes_of(k)) for k in artifact_kinds if g.nodes_of(k)}
    if obs:
        obs_text = ", ".join(f"{v} {k}" for k, v in obs.items())
        ans.append(ContractAnswer(
            "What artifacts were observed?",
            obs_text,
            tuple(n.id for k in artifact_kinds for n in g.nodes_of(k)[:1]),
            0.85,
        ))
    else:
        ans.append(ContractAnswer(
            "What artifacts were observed?", UNKNOWN, tuple(), 0.0))

    # 4. What was decoded?
    dp = g.nodes_of("decoded_payload")
    if dp:
        first = dp[0]
        ans.append(ContractAnswer(
            "What was decoded?",
            f"{len(dp)} decoded payload(s). First: {first.value[:120]}…",
            tuple(n.id for n in dp[:3]),
            first.confidence,
        ))
    else:
        ans.append(ContractAnswer(
            "What was decoded?", "No encoded payloads required decoding.",
            tuple(), 0.8))

    # 5. Who / what was affected?
    hosts = g.nodes_of("host")
    users = g.nodes_of("user")
    parts = []
    ids: List[str] = []
    if hosts:
        parts.append(f"{len(hosts)} host(s): " +
                      ", ".join(h.value for h in hosts[:3]))
        ids.extend(h.id for h in hosts[:3])
    if users:
        parts.append(f"{len(users)} user(s): " +
                      ", ".join(u.value for u in users[:3]))
        ids.extend(u.id for u in users[:3])
    ans.append(ContractAnswer(
        "Who / what was affected?",
        "; ".join(parts) if parts else UNKNOWN,
        tuple(ids),
        0.85 if parts else 0.0,
    ))

    # 6. What ATT&CK techniques apply? (Phase 1: none yet — deferred)
    ans.append(ContractAnswer(
        "What ATT&CK techniques apply?",
        UNKNOWN + " (Phase 2 · Attack Chain Builder)",
        tuple(),
        0.0,
    ))

    # 7. What attack stage was reached? (Deferred)
    ans.append(ContractAnswer(
        "What attack stage was reached?",
        UNKNOWN + " (Phase 2 · Attack Chain Builder)",
        tuple(),
        0.0,
    ))

    # 8. What threat family or malware is most likely?
    fam_hits: Dict[str, int] = {}
    for det in g.nodes_of("detection"):
        fam = (det.attrs or {}).get("threat_family")
        if fam:
            fam_hits[fam] = fam_hits.get(fam, 0) + 1
    if fam_hits:
        top_family = max(fam_hits, key=fam_hits.get)
        ans.append(ContractAnswer(
            "What threat family or malware is most likely?",
            f"{top_family} (from vendor detection)",
            tuple(n.id for n in g.nodes_of("detection")
                   if (n.attrs or {}).get("threat_family") == top_family),
            0.7,
        ))
    else:
        ans.append(ContractAnswer(
            "What threat family or malware is most likely?",
            UNKNOWN + " (Phase 3 · Threat Family Resolution)",
            tuple(),
            0.0,
        ))

    # 9. What evidence supports that conclusion?
    if fam_hits:
        supporting = [n.id for n in g.nodes_of("detection")]
        ans.append(ContractAnswer(
            "What evidence supports that conclusion?",
            f"{len(supporting)} detection node(s) reference the family.",
            tuple(supporting[:5]),
            0.7,
        ))
    else:
        ans.append(ContractAnswer(
            "What evidence supports that conclusion?",
            UNKNOWN, tuple(), 0.0,
        ))

    # 10. What evidence contradicts it? (Deferred to Hypothesis Engine)
    ans.append(ContractAnswer(
        "What evidence contradicts it?",
        UNKNOWN + " (Phase 3 · Hypothesis Engine)",
        tuple(), 0.0,
    ))

    # 11. What visibility gaps remain?
    gaps = _visibility_gaps(g)
    ans.append(ContractAnswer(
        "What visibility gaps remain?",
        "; ".join(gaps) if gaps else "No obvious gaps in Phase 1 scope.",
        tuple(),
        0.6 if gaps else 0.7,
    ))

    # 12. What should the customer do next? (Deferred)
    ans.append(ContractAnswer(
        "What should the customer do next?",
        UNKNOWN + " (Phase 4 · Recommendation Engine)",
        tuple(), 0.0,
    ))

    return ContractReport(answers=tuple(ans))


def _visibility_gaps(g: InvestigationGraph) -> List[str]:
    gaps: List[str] = []
    if not g.nodes_of("host"):
        gaps.append("no host identity in evidence")
    if not g.nodes_of("user"):
        gaps.append("no user identity in evidence")
    if not g.nodes_of("process") and not g.nodes_of("command"):
        gaps.append("no process or command context")
    if not g.nodes_of("hash"):
        gaps.append("no file/process hashes available")
    return gaps


__all__ = ["ContractAnswer", "ContractReport", "check_contract11",
           "UNKNOWN"]
