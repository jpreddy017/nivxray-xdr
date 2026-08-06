"""
IOC Intelligence · shared schema (2026-03-02)
─────────────────────────────────────────────
Deterministic dataclasses shared across every provider and the
consensus engine.  UI depends on the STABLE shape below — providers
never leak raw payloads into the card.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ProviderVerdict:
    """A single provider's contribution to a consensus decision."""
    provider:      str
    verdict:       str                                # malicious · suspicious · clean · unknown · pending
    score:         Optional[float] = None            # 0..1 confidence contributed by this provider
    detail:        str            = ""               # short analyst-facing evidence line
    raw:           Dict[str, Any] = field(default_factory=dict)  # provider-native fields kept for drill-down
    source:        str            = "live"           # "live" · "cache" · "pending" · "error"
    error:         str            = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderResult:
    """One provider's full result for one IOC — verdict + related
    intelligence (families, campaigns, timeline, related IOCs)."""
    verdict:            ProviderVerdict
    first_seen:         Optional[str] = None
    last_seen:          Optional[str] = None
    families:           List[str] = field(default_factory=list)
    campaigns:          List[str] = field(default_factory=list)
    threat_types:       List[str] = field(default_factory=list)
    related_urls:       List[str] = field(default_factory=list)
    related_hashes:     List[str] = field(default_factory=list)
    related_domains:    List[str] = field(default_factory=list)
    related_ips:        List[str] = field(default_factory=list)
    tags:               List[str] = field(default_factory=list)
    references:         List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IocCard:
    """Analyst-ready IOC Intelligence card.  This is the ONLY shape
    the UI consumes — provider payloads are hidden inside `sources`."""
    kind:            str                       # hash · url · domain · ip
    value:           str
    normalized:      str
    consensus:       Dict[str, Any] = field(default_factory=dict)   # verdict · confidence · trust score · evidence[]
    sources:         List[Dict[str, Any]] = field(default_factory=list)  # ProviderVerdict.to_dict() list
    timeline:        Dict[str, Any] = field(default_factory=dict)   # first_seen · last_seen · still_active
    related:         Dict[str, Any] = field(default_factory=dict)   # families · campaigns · related_hashes · …
    fetched_at:      str = ""
    duration_ms:     int = 0
    from_cache:      bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
