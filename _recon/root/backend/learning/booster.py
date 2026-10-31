"""Booster — combine signal-kind + KB entries + user history frequency
into a ranked list of decoder-chain candidates.

Sources of priors (weighted, higher = tried first):
    1. Personal history frequency  (per-user chain success counter)  · weight 3
    2. KB entries matching signal_kind (via aggregated common_chains) · weight 2
    3. DEFAULT_CHAIN_PRIORS (built-in heuristic per kind)             · weight 1

The output includes `source`, `confidence`, and `alternatives`, so the UI can
show WHERE the boost came from and let the analyst disable it.
"""
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from deps import db
from learning.signals import compute_signals, signal_kind, DEFAULT_CHAIN_PRIORS


def _chain_key(chain: List[str]) -> str:
    return " → ".join(chain)


async def _history_frequency(user_email: str, min_confidence: int = 60,
                              max_docs: int = 200) -> Counter:
    """Return a Counter of chain-keys weighted by success (confidence)."""
    freq: Counter = Counter()
    cur = db.investigations.find(
        {"user_email": user_email, "confidence": {"$gte": min_confidence}},
        {"chain": 1, "confidence": 1, "reached_shellcode": 1},
    ).sort("ts", -1).limit(max_docs)
    async for d in cur:
        chain = d.get("chain") or []
        if not chain:
            continue
        # weight: base 1 + shellcode bonus + high-confidence bonus
        w = 1
        if d.get("reached_shellcode"): w += 1
        if (d.get("confidence") or 0) >= 85: w += 1
        freq[_chain_key(chain)] += w
    return freq


async def _kb_chains_for_kind(user_email: str, kind: str) -> List[str]:
    """Return `common_chains` from KB entries plausibly matching this signal kind."""
    # KB entry MITRE tokens implicitly encode kind. We do a simple text match on
    # slug + title + summary.  This is intentionally imprecise — a broad match
    # is fine because the booster stacks multiple sources.
    out: List[str] = []
    q = {"user_email": user_email}
    async for e in db.kb_entries.find(q, {"common_chains": 1, "slug": 1, "title": 1,
                                          "summary": 1, "investigation_count": 1}):
        blob = " ".join([
            e.get("slug", ""),
            e.get("title", ""),
            e.get("summary", ""),
        ]).lower()
        tokens = kind.split("-")
        if any(t in blob for t in tokens if len(t) >= 3):
            for c in (e.get("common_chains") or []):
                if c and c != "(no-op)":
                    out.append(c)
    return out


async def _thumbs_up_down(user_email: str) -> Tuple[Counter, Counter]:
    """Return per-chain up-votes and down-votes."""
    up, down = Counter(), Counter()
    doc = await db.learning_feedback.find_one({"_id": user_email}) or {}
    for k, v in (doc.get("up_votes") or {}).items():   up[k] = int(v)
    for k, v in (doc.get("down_votes") or {}).items(): down[k] = int(v)
    return up, down


async def boost(raw: str, user_email: str) -> Dict[str, Any]:
    """Return the boost decision for this raw payload.

    Response shape (public):
        {
          "enabled": bool,
          "signal_kind": str,
          "chain": [op, op, ...] | None,      # top boosted chain
          "source": "history" | "kb" | "default" | None,
          "confidence": 0.0-1.0,
          "alternatives": [ {chain:[...], score, source}, ... ],
          "signals": {...},                   # for UI transparency
        }
    """
    sig = compute_signals(raw or "")
    kind = signal_kind(sig)

    hist_freq = await _history_frequency(user_email)
    kb_chains = await _kb_chains_for_kind(user_email, kind)
    up_votes, down_votes = await _thumbs_up_down(user_email)

    scores: Counter = Counter()

    # 1. History frequency
    for k, w in hist_freq.items():
        scores[k] += 3 * w
    # 2. KB matches
    for c in kb_chains:
        scores[c] += 2
    # 3. Built-in priors
    for c in DEFAULT_CHAIN_PRIORS.get(kind, []):
        scores[_chain_key(c)] += 1

    # Analyst feedback overlay
    for k, w in up_votes.items():   scores[k] += 2 * w
    for k, w in down_votes.items(): scores[k] -= 3 * w

    if not scores:
        return {
            "enabled": False,
            "signal_kind": kind,
            "chain": None,
            "source": None,
            "confidence": 0.0,
            "alternatives": [],
            "signals": sig,
        }

    ranked = scores.most_common(5)
    # Compute confidence from the top score relative to max theoretical
    top_key, top_score = ranked[0]
    conf = max(0.0, min(1.0, top_score / 12.0))

    def _which_source(key: str) -> str:
        if hist_freq.get(key): return "history"
        if key in [_chain_key(c) if isinstance(c, list) else c for c in kb_chains]: return "kb"
        return "default"

    def _parse(k: str) -> List[str]:
        return [p.strip() for p in k.split("→") if p.strip()]

    return {
        "enabled": conf > 0.0,
        "signal_kind": kind,
        "chain":  _parse(top_key),
        "source": _which_source(top_key),
        "confidence": round(conf, 3),
        "alternatives": [
            {"chain": _parse(k), "score": s, "source": _which_source(k)}
            for k, s in ranked[1:]
        ],
        "signals": sig,
    }
