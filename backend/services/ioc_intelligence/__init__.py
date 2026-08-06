"""
IOC Intelligence Engine · 2026-03-02
─────────────────────────────────────
Isolated, provider-agnostic intelligence layer.  Consumers pass IOCs
(hash / domain / url / ip) and receive a single **IOC Intelligence
Card** per IOC — a consensus verdict backed by parallel, cached
provider look-ups.

Public entry points:

    enrich_iocs(iocs) → List[IocCard]
        Async batch enrichment with parallel fan-out across every
        registered provider.

    enrich_ioc(kind, value) → IocCard
        Single-IOC convenience.

Architecture (never leak provider names to the analyst):

    IOC
     │
     ▼
    Normalize (canonical form)
     │
     ▼
    Cache lookup ────► hit ──► return
     │
     ▼ miss
    Fan-out (asyncio.gather)
       Talos · MalwareBazaar · ThreatFox · URLhaus · VirusTotal
       · AbuseIPDB · Hybrid Analysis · Any.Run · WHOIS · PDNS · ASN
     │
     ▼
    Consensus Engine  (verdict + trust score + evidence bullets)
     │
     ▼
    Cache write
     │
     ▼
    IocCard  (schema stable · UI never sees provider raw payloads)

Providers gracefully degrade: missing API keys or transient outages
render the field as `{"source": "pending"}` — the consensus engine
weights those correctly (their signal is 0, they never damage a card).
"""
from .engine    import enrich_iocs, enrich_ioc                  # noqa: F401
from .schema    import IocCard, ProviderResult, ProviderVerdict  # noqa: F401
