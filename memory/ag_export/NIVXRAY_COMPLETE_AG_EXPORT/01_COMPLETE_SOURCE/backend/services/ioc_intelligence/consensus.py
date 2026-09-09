"""
Consensus Engine · 2026-03-02
─────────────────────────────
Aggregates every ProviderResult for a single IOC into ONE analyst-
ready verdict + trust score.  Deterministic, weighted, transparent.

Verdict lattice (ascending severity):
    unknown · clean · suspicious · malicious

Trust-score model:
    trust = clamp01(  Σ (weight_i · signal_i)  ÷  Σ weight_i )
    signal_i ∈ {0, 0.4, 0.7, 1.0} depending on the provider verdict
    weight_i is provider-specific (higher for widely-consulted sources)

Every card carries an evidence list — one bullet per contributing
provider — so the analyst can audit HOW consensus was reached.
"""
from __future__ import annotations
from typing import Dict, List

from .schema import IocCard, ProviderResult, ProviderVerdict


# Provider weights — trusted sources contribute more to consensus.
# `pending` and `error` states have weight 0 so a card with only
# unavailable providers gets `unknown` (never falsely "clean").
_WEIGHTS = {
    "malwarebazaar":   1.2,
    "threatfox":       1.1,
    "urlhaus":         1.1,
    "urlscan":         1.0,
    "talos":           1.0,
    "dshield":         0.8,
    "virustotal":      1.4,
    "abuseipdb":       0.9,
    "hybrid-analysis": 1.1,
    "any.run":         0.8,
    "whois":           0.2,
    "passivedns":      0.3,
    "asn":             0.1,
}

_SIGNAL = {
    "malicious":  1.0,
    "suspicious": 0.7,
    "clean":      0.0,
    "unknown":    0.0,
    "pending":    0.0,
    "error":      0.0,
}

_VERDICT_RANK = {
    "unknown":    0,
    "clean":      1,
    "suspicious": 2,
    "malicious":  3,
}


def build_card(kind: str,
                 value: str,
                 normalized: str,
                 provider_results: List[ProviderResult],
                 fetched_at: str,
                 duration_ms: int,
                 from_cache: bool = False) -> IocCard:
    """Roll up provider results → single IOC Intelligence card."""
    verdicts = [r.verdict for r in provider_results]
    sources  = [v.to_dict() for v in verdicts]

    trust, top_verdict, evidence = _consensus(verdicts)

    # Timeline & related — union of every provider's contribution.
    first_seen = _min_date([r.first_seen for r in provider_results])
    last_seen  = _max_date([r.last_seen  for r in provider_results])
    still_active = last_seen is not None and _within_90d(last_seen)

    families   = _dedupe_flatten([r.families   for r in provider_results])
    campaigns  = _dedupe_flatten([r.campaigns  for r in provider_results])
    ttypes     = _dedupe_flatten([r.threat_types for r in provider_results])
    r_urls     = _dedupe_flatten([r.related_urls    for r in provider_results])
    r_hashes   = _dedupe_flatten([r.related_hashes  for r in provider_results])
    r_domains  = _dedupe_flatten([r.related_domains for r in provider_results])
    r_ips      = _dedupe_flatten([r.related_ips     for r in provider_results])
    tags       = _dedupe_flatten([r.tags       for r in provider_results])
    refs       = _dedupe_flatten([r.references for r in provider_results])

    confidence_label = ("high"   if trust >= 0.75
                        else "medium" if trust >= 0.45
                        else "low")

    return IocCard(
        kind=kind, value=value, normalized=normalized,
        consensus={
            "verdict":            top_verdict,
            "trust_score":        round(trust, 3),
            "confidence_percent": int(round(trust * 100)),
            "confidence_label":   confidence_label,
            "evidence":           evidence,
            "source_count":       sum(1 for v in verdicts
                                        if v.source in ("live", "cache")),
            "pending_count":      sum(1 for v in verdicts if v.source == "pending"),
        },
        sources=sources,
        timeline={
            "first_seen":   first_seen,
            "last_seen":    last_seen,
            "still_active": still_active,
        },
        related={
            "families":         families,
            "campaigns":        campaigns,
            "threat_types":     ttypes,
            "related_urls":     r_urls,
            "related_hashes":   r_hashes,
            "related_domains":  r_domains,
            "related_ips":      r_ips,
            "tags":             tags,
            "references":       refs,
        },
        fetched_at=fetched_at,
        duration_ms=duration_ms,
        from_cache=from_cache,
    )


# ── Helpers ───────────────────────────────────────────────────────
def _consensus(verdicts: List[ProviderVerdict]):
    """Return (trust_score, top_verdict, evidence_bullets)."""
    total_weight = 0.0
    weighted     = 0.0
    top_rank     = -1
    top_verdict  = "unknown"
    evidence: List[Dict[str, str]] = []

    for v in verdicts:
        w = _WEIGHTS.get(v.provider, 0.5)
        # Providers that returned nothing (pending / error) still show
        # up in the evidence list so the analyst sees the audit trail.
        if v.source in ("pending", "error"):
            evidence.append({
                "provider": v.provider,
                "state":    v.source,
                "detail":   v.detail or ("credentials required"
                                          if v.source == "pending"
                                          else v.error),
            })
            continue

        s = v.score if v.score is not None else _SIGNAL.get(v.verdict, 0.0)
        total_weight += w
        weighted     += w * s
        rank = _VERDICT_RANK.get(v.verdict, 0)
        if rank > top_rank:
            top_rank    = rank
            top_verdict = v.verdict
        evidence.append({
            "provider": v.provider,
            "state":    v.source,
            "verdict":  v.verdict,
            "detail":   v.detail or "",
        })

    trust = (weighted / total_weight) if total_weight > 0 else 0.0
    if top_verdict == "unknown" and trust == 0.0 and any(
            v.source in ("pending", "error") for v in verdicts):
        top_verdict = "unknown"                # no live data → honest unknown
    return trust, top_verdict, evidence


def _dedupe_flatten(lists: List[List[str]]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for xs in lists or []:
        for x in xs or []:
            if not x: continue
            k = x.strip().lower()
            if k in seen: continue
            seen.add(k)
            out.append(x)
    return out


def _min_date(dates):
    xs = [d for d in dates if d]
    return sorted(xs)[0] if xs else None


def _max_date(dates):
    xs = [d for d in dates if d]
    return sorted(xs)[-1] if xs else None


def _within_90d(iso_date: str) -> bool:
    from datetime import datetime, timezone, timedelta
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt) < timedelta(days=90)
    except Exception:
        return False
