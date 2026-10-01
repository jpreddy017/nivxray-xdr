"""DT-I1E TI view contract: map existing ioc_intelligence vocabulary without touching providers."""
from __future__ import annotations

from typing import Any, Dict, List

from .contracts import TIResult

# services/ioc_intelligence verdicts: malicious · suspicious · clean · unknown · pending · error
_MAP = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "clean": "BENIGN", "benign": "BENIGN",
        "harmless": "BENIGN", "unknown": "UNKNOWN", "no_data": "NO_DATA", "not_found": "NO_DATA",
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
    """One TIResult per provider; no consensus collapse (engine disagreement stays visible)."""
    ind, typ = card.get("ioc") or card.get("indicator"), card.get("ioc_type") or card.get("type") or "unknown"
    out = []
    for p in card.get("providers") or []:
        out.append(normalize_provider_result(ind, typ, p.get("provider") or p.get("name"),
                                             (p.get("verdict") or {}).get("verdict")
                                             if isinstance(p.get("verdict"), dict) else p.get("verdict"),
                                             {"fetched_at": p.get("fetched_at"), "cached": p.get("cached")}))
    if not out:
        out.append(normalize_provider_result(ind, typ, None, "no_data"))
    return out
