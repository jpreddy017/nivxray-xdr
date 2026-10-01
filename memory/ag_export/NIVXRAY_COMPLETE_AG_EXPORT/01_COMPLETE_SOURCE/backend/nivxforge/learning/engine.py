"""NivXRay Learning Engine.

One reusable service every composer calls to retrieve past analyst
knowledge that applies to the CIO under investigation. Keeps the
investigation pipeline deterministic:

    CIO  ──►  fingerprint  ──►  retrieve similar cases  ──►
        learning_context { matches[], terminology{}, patterns{} }

Consumers:
  * Executive Summary / Story composer     — inject learning_context
  * Verdict Explanation composer           — weight by past agreement
  * Recommendations composer               — reuse ordering + wording
  * X-Lab UI                                — render "Learning Applied" panel

Design principles enforced here:
  * Facts NEVER come from past analyses. Only terminology + structure +
    ordering + confidence-weighting come from learning.
  * Retrieval is deterministic (Jaccard on fingerprint sets, verdict must
    match exactly). No LLM required to compute the learning context.
  * Learning is transparent — every consumer receives a report with
    per-match similarity scores, source ids, and applied hints.
  * "Wrong"-marked cases never propagate their content forward; they only
    lower the confidence of similar patterns and surface as candidates
    for new deterministic rules.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from deps import db

__all__ = [
    "fingerprint_cio", "similarity", "retrieve_similar",
    "learning_context",
    "Fingerprint", "SimilarMatch", "LearningContext",
]

# ── Fingerprinting ────────────────────────────────────────────────────
#
# A deterministic tuple derived from the CIO's investigation outcome.
# Same fingerprint means "same shape of case", not "same input string".

@dataclass(frozen=True)
class Fingerprint:
    verdict_label: str
    mitre_ids: Tuple[str, ...]
    ioc_kinds: Tuple[str, ...]
    lolbins: Tuple[str, ...]
    families: Tuple[str, ...]

    @property
    def hash(self) -> str:
        h = hashlib.blake2b(digest_size=10)
        h.update(self.verdict_label.encode())
        for group in (self.mitre_ids, self.ioc_kinds, self.lolbins, self.families):
            h.update(b"|")
            for v in group:
                h.update(v.encode())
                h.update(b",")
        return h.hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict_label": self.verdict_label,
            "mitre_ids": list(self.mitre_ids),
            "ioc_kinds": list(self.ioc_kinds),
            "lolbins": list(self.lolbins),
            "families": list(self.families),
            "hash": self.hash,
        }


def fingerprint_cio(cio: Any) -> Fingerprint:
    """Compute a deterministic fingerprint from the CIO. Accepts either
    a Pydantic model with `.evidence_graph.nodes` or a raw dict."""
    if hasattr(cio, "model_dump"):
        cio = cio.model_dump()
    v = (cio or {}).get("verdict") or {}
    verdict_label = str(v.get("label") or "Undetermined").strip()

    graph = (cio or {}).get("evidence_graph") or {}
    nodes = graph.get("nodes") or []

    mitre_ids: Set[str] = set()
    ioc_kinds: Set[str] = set()
    lolbins: Set[str] = set()
    families: Set[str] = set()

    for n in nodes:
        kind = (n.get("kind") or "").lower()
        attrs = n.get("attrs") or {}
        if kind == "mitre_technique":
            tid = attrs.get("technique_id") or n.get("label") or n.get("id")
            if tid:
                mitre_ids.add(str(tid).strip())
        elif kind == "ioc":
            ik = (attrs.get("ioc_kind") or attrs.get("type") or "").lower()
            if ik:
                ioc_kinds.add(ik)
        elif kind == "lolbin":
            lb = (attrs.get("binary") or n.get("label") or "").lower().strip()
            if lb:
                # Strip .exe suffix so "powershell.exe" and "powershell" match.
                lolbins.add(re.sub(r"\.exe$", "", lb))
        elif kind in {"family", "malware_family"}:
            fam = (n.get("label") or attrs.get("name") or "").lower().strip()
            if fam:
                families.add(fam)

    return Fingerprint(
        verdict_label=verdict_label,
        mitre_ids=tuple(sorted(mitre_ids)),
        ioc_kinds=tuple(sorted(ioc_kinds)),
        lolbins=tuple(sorted(lolbins)),
        families=tuple(sorted(families)),
    )


# ── Similarity ────────────────────────────────────────────────────────
#
# Jaccard-of-Jaccards across MITRE / LOLBIN / IOC-kind / family sets, hard
# gated by verdict-label equality. Two cases that ended up as different
# verdicts are never considered similar even if they share techniques —
# that would leak "Suspicious" style into "Malicious" writeups.

_GROUP_WEIGHTS = {
    "mitre_ids":  0.45,
    "lolbins":    0.25,
    "ioc_kinds":  0.15,
    "families":   0.15,
}


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def similarity(f1: Fingerprint, f2: Fingerprint) -> float:
    """Return a 0..1 similarity between two fingerprints.
    Verdict label must match exactly — otherwise similarity is 0.0."""
    if f1.verdict_label != f2.verdict_label:
        return 0.0
    total = 0.0
    for group, weight in _GROUP_WEIGHTS.items():
        total += weight * _jaccard(getattr(f1, group), getattr(f2, group))
    return round(total, 4)


# ── Similarity retrieval ──────────────────────────────────────────────
#
# We store analyst summaries in `analyst_corrections` (surface="summary")
# and a mirror in `summary_overrides`. The Learning Engine reads from
# `analyst_corrections` because that is the single learner corpus every
# feedback surface writes into — reads there stay unified.

@dataclass
class SimilarMatch:
    correction_id: str
    cio_id: Optional[str]
    case_id: Optional[str]
    surface: str
    analyst_text: str
    fingerprint: Fingerprint
    similarity: float
    author_email: str
    created_at: str
    verdict_label: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.correction_id,
            "cio_id": self.cio_id,
            "case_id": self.case_id,
            "surface": self.surface,
            "analyst_text": self.analyst_text[:400],
            "fingerprint": self.fingerprint.to_dict(),
            "similarity": self.similarity,
            "author": self.author_email,
            "created_at": self.created_at,
            "verdict_label": self.verdict_label,
        }


async def retrieve_similar(
    fp: Fingerprint,
    *,
    surface: str = "summary",
    limit: int = 5,
    min_similarity: float = 0.35,
) -> List[SimilarMatch]:
    """Pull candidate corrections for the given fingerprint's verdict
    label and rank by similarity. Excludes 'Wrong'-marked cases so
    unreliable analyst calls never propagate their content forward."""
    query: Dict[str, Any] = {
        "surface": surface,
        "verdict_snapshot.label": fp.verdict_label,
    }
    # For surfaces that don't stamp verdict_snapshot yet, fall back to
    # matching on the tags list.
    fallback_query = {"surface": surface}

    matches: List[SimilarMatch] = []
    async def _scan(q: Dict[str, Any]) -> None:
        cursor = db.analyst_corrections.find(q).sort("created_at", -1).limit(200)
        async for doc in cursor:
            # Never learn from documents explicitly flagged as wrong.
            if (doc.get("verdict") or "") in {"incorrect-verdict", "poisoned"}:
                continue
            fp2 = _fingerprint_from_correction(doc)
            if fp2 is None:
                continue
            sim = similarity(fp, fp2)
            if sim < min_similarity:
                continue
            matches.append(SimilarMatch(
                correction_id=str(doc.get("id") or doc.get("_id") or ""),
                cio_id=doc.get("cio_id"),
                case_id=doc.get("case_id"),
                surface=doc.get("surface") or surface,
                analyst_text=(doc.get("correct_prompt") or doc.get("analyst_summary") or "").strip(),
                fingerprint=fp2,
                similarity=sim,
                author_email=str(doc.get("author_email") or "unknown"),
                created_at=str(doc.get("created_at") or ""),
                verdict_label=fp2.verdict_label,
            ))

    try:
        await _scan(query)
        if not matches:
            await _scan(fallback_query)
    except Exception:  # noqa: BLE001
        # Non-fatal — learning is a hint, never a blocker for the pipeline.
        return []

    matches.sort(key=lambda m: m.similarity, reverse=True)
    return matches[:limit]


def _fingerprint_from_correction(doc: Dict[str, Any]) -> Optional[Fingerprint]:
    """Rebuild a fingerprint from a stored correction. Newer records
    stamp `fingerprint` explicitly; older ones we backfill from the tags
    field where possible."""
    fp = doc.get("fingerprint") or {}
    if fp:
        return Fingerprint(
            verdict_label=str(fp.get("verdict_label") or "Undetermined"),
            mitre_ids=tuple(fp.get("mitre_ids") or []),
            ioc_kinds=tuple(fp.get("ioc_kinds") or []),
            lolbins=tuple(fp.get("lolbins") or []),
            families=tuple(fp.get("families") or []),
        )
    # Backfill fallback — no fingerprint means the correction was written
    # before the Learning Engine landed. Treat as an "empty" fingerprint
    # that only matches on verdict label. Better than dropping the record.
    label = (doc.get("verdict_snapshot") or {}).get("label")
    if not label:
        return None
    return Fingerprint(
        verdict_label=str(label),
        mitre_ids=(), ioc_kinds=(), lolbins=(), families=(),
    )


# ── Learning Context ──────────────────────────────────────────────────
#
# The single value a composer consumes. Composers do NOT read the raw
# corpus — they receive a LearningContext with:
#   * matches[]         — top-K similar cases, ranked
#   * applied           — whether learning would meaningfully influence
#                         the output (true when matches[] is non-empty
#                         and top match ≥ APPLY_THRESHOLD)
#   * confidence        — "high" / "medium" / "low" for UI display
#   * fingerprint       — the fingerprint of the current CIO (for audit)
#   * summary_seed      — best-effort short seed text taken from the top
#                         match's analyst_text (for surfacing in the UI;
#                         composers still write their own prose)

APPLY_THRESHOLD = 0.60
HIGH_CONF_THRESHOLD = 0.80


@dataclass
class LearningContext:
    fingerprint: Fingerprint
    matches: List[SimilarMatch] = field(default_factory=list)
    applied: bool = False
    confidence: str = "none"      # none | low | medium | high
    summary_seed: str = ""
    top_similarity: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "applied": self.applied,
            "confidence": self.confidence,
            "top_similarity": self.top_similarity,
            "matches": [m.to_dict() for m in self.matches],
            "match_count": len(self.matches),
            "fingerprint": self.fingerprint.to_dict(),
            "summary_seed": self.summary_seed,
            "apply_threshold": APPLY_THRESHOLD,
        }


async def learning_context(cio: Any, *, surface: str = "summary", limit: int = 5) -> LearningContext:
    """Compute the LearningContext for the given CIO. Safe to call
    from any composer — always returns a valid context (empty when the
    corpus is cold-start)."""
    fp = fingerprint_cio(cio)
    matches = await retrieve_similar(fp, surface=surface, limit=limit)

    if not matches:
        return LearningContext(fingerprint=fp)

    top = matches[0].similarity
    if top >= HIGH_CONF_THRESHOLD:
        confidence = "high"
    elif top >= APPLY_THRESHOLD:
        confidence = "medium"
    else:
        confidence = "low"

    applied = top >= APPLY_THRESHOLD
    seed = matches[0].analyst_text[:400] if applied else ""

    return LearningContext(
        fingerprint=fp,
        matches=matches,
        applied=applied,
        confidence=confidence,
        summary_seed=seed,
        top_similarity=top,
    )
