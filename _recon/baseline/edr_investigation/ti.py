"""DT TI view contract: per-provider rows built from dt-i1e.ti.v1 normalized results; providers untouched.

A legacy "clean" label is never an affirmative known-good assertion, so it never maps to BENIGN.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .contracts import TIResult
from .ti_contracts import TI_SCHEMA, adapt_ioc_intelligence, normalize_observable

_MAP = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "known_good": "BENIGN",
        "clean": "UNKNOWN", "benign": "UNKNOWN", "harmless": "UNKNOWN", "unknown": "UNKNOWN",
        "no_data": "NO_DATA", "not_found": "NO_HIT", "no_hit": "NO_HIT", "stale": "STALE",
        "pending": "UNAVAILABLE", "unavailable": "UNAVAILABLE", "timeout": "UNAVAILABLE",
        "rate_limited": "RATE_LIMITED", "quota_exceeded": "RATE_LIMITED", "error": "ERROR"}


def normalize_provider_result(indicator: str, indicator_type: str, provider: Any, verdict: Any,
                              provenance: Dict[str, Any] = None) -> TIResult:
    state = _MAP.get(str(verdict or "").strip().lower(), "UNKNOWN")
    prov = dict(provenance or {})
    if state in ("MALICIOUS", "SUSPICIOUS", "BENIGN") and not provider:
        state = "UNKNOWN"  # reputation without a provider is not a fact
    prov["source_verdict"] = str(verdict)[:32] if verdict is not None else None
    return TIResult(indicator=str(indicator)[:512], indicator_type=str(indicator_type)[:16], state=state,
                    provider=str(provider)[:64] if provider else None, provenance=prov)


def normalize_ioc_card(card: Dict[str, Any]) -> List[TIResult]:
    """One TIResult per provider via the C adapter; no consensus collapse (disagreement stays visible)."""
    ind, typ = card.get("ioc") or card.get("indicator"), card.get("ioc_type") or card.get("type") or "unknown"
    out = []
    for p in card.get("providers") or []:
        pv = p.get("verdict") if isinstance(p.get("verdict"), dict) else {**p, "verdict": p.get("verdict")}
        pv = {"provider": p.get("provider") or p.get("name"), **pv}
        try:
            obs = normalize_observable(typ, ind)
        except ValueError:
            out.append(TIResult(str(ind)[:512], str(typ)[:16], "ERROR", pv.get("provider"),
                                {"reason": "observable failed normalization", "schema_version": TI_SCHEMA}))
            continue
        n = adapt_ioc_intelligence(pv, obs, lookup_at=p.get("fetched_at"))
        out.append(TIResult(obs.value, obs.ioc_type, n.state, n.provider,
                            {"source_verdict": n.provenance.source_verdict, "failure_reason": n.failure_reason,
                             "cache_state": n.cache_state, "schema_version": TI_SCHEMA}))
    if not out:
        out.append(normalize_provider_result(ind, typ, None, "no_data"))
    return out
