"""P1-01 · Live OSINT Wiring — CIO IOC Enricher.

Reuses the exact same two Workspace services X-Lab must share:

  1. `routers.auto_investigate._osint_lookup`  — local threat-intel corpus
     lookup against `db.iocs` (populated by `ti_feed_sync`).
  2. `osint.enrich_iocs`                        — live provider queries
     (VirusTotal · AbuseIPDB · OTX · URLScan · Shodan · GreyNoise ·
     IPinfo · Hybrid Analysis) gated by API keys in `db.settings.osint_keys`.

No new engine. No forked pipeline. This module ONLY:

  • extracts IOC nodes from the CIO evidence graph,
  • dispatches them to the two shared services in parallel,
  • projects each raw provider record into an 11-field card
    ({name · state · malicious · suspicious · harmless · reputation ·
      detail · first_seen · last_seen · tags · link}),
  • attaches the card list to `node.attrs["enrichment"]`,
  • stashes the raw bundle under `cio.metadata["osint"]` for parity.

Deterministic-within-cache (5 min TTL) · offline-safe (all provider
errors caught, state='error' recorded) · zero verdict-engine impact.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


# ─── In-memory cache (5 min TTL, deterministic within window) ──────────
_CACHE_TTL_S = 300.0
_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    hit = _CACHE.get(key)
    if not hit:
        return None
    ts, payload = hit
    if (time.monotonic() - ts) > _CACHE_TTL_S:
        _CACHE.pop(key, None)
        return None
    return payload


def _cache_put(key: str, payload: Dict[str, Any]) -> None:
    _CACHE[key] = (time.monotonic(), payload)


def _cache_clear() -> None:  # for tests
    _CACHE.clear()


# ─── IOC extraction from CIO nodes ─────────────────────────────────────
_IOC_KIND_TO_BUCKET = {
    "ip": "ips",
    "domain": "domains",
    "url": "urls",
    "hash": "sha256",   # unknown-algo hashes → sha256 bucket
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "email": "emails",
}


def _extract_ioc_index(cio) -> tuple[Dict[str, List[str]], Dict[str, List[Any]]]:
    """Return `(iocs_bucketed, node_index_by_value)`.

    `iocs_bucketed` is the shape the shared services accept.
    `node_index_by_value` maps every IOC value → list of CIO Node
    references so we can decorate them post-lookup.
    """
    buckets: Dict[str, List[str]] = {
        "ips": [], "domains": [], "urls": [],
        "sha256": [], "sha1": [], "md5": [], "emails": [],
    }
    by_value: Dict[str, List[Any]] = {}
    seen: set[tuple[str, str]] = set()
    graph = getattr(cio, "evidence_graph", None)
    if not graph:
        return buckets, by_value
    for node in graph.nodes:
        if node.kind != "ioc":
            continue
        ioc_kind = (node.attrs or {}).get("ioc_kind") or ""
        bucket = _IOC_KIND_TO_BUCKET.get(ioc_kind.lower())
        value = node.value or ""
        if not (bucket and value):
            continue
        if (bucket, value) not in seen:
            buckets[bucket].append(value)
            seen.add((bucket, value))
        by_value.setdefault(value, []).append(node)
    return buckets, by_value


# ─── Provider record projection (11 fields, uniform shape) ─────────────
_PROVIDER_LABELS = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "otx": "AlienVault OTX",
    "urlscan": "URLScan.io",
    "urlhaus": "URLhaus",
    "shodan": "Shodan",
    "greynoise": "GreyNoise",
    "ipinfo": "IPinfo",
    "hybrid_analysis": "Hybrid Analysis",
}

# IOC-kind → which providers can theoretically answer (for state='no-key').
_PROVIDERS_BY_KIND: Dict[str, List[str]] = {
    "ip":     ["virustotal", "abuseipdb", "otx", "shodan", "greynoise", "ipinfo"],
    "domain": ["virustotal", "otx", "urlscan"],
    "url":    ["virustotal", "otx", "urlscan", "urlhaus"],
    "hash":   ["virustotal", "otx", "hybrid_analysis"],
    "sha256": ["virustotal", "otx", "hybrid_analysis"],
    "sha1":   ["virustotal", "otx", "hybrid_analysis"],
    "md5":    ["virustotal", "otx", "hybrid_analysis"],
}


def _empty_card(name: str, state: str = "pending", detail: str = "") -> Dict[str, Any]:
    """11-field IOC provider card (uniform shape · never null-shape)."""
    return {
        "name": name,
        "state": state,        # hit · no-hit · pending · no-key · error · no-hash
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "reputation": None,
        "detail": detail,
        "first_seen": None,
        "last_seen": None,
        "tags": [],
        "link": None,
    }


def _vt_link(kind: str, value: str) -> str:
    import base64
    if kind in ("sha256", "sha1", "md5", "hash"):
        return f"https://www.virustotal.com/gui/file/{value}"
    if kind == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{value}"
    if kind == "domain":
        return f"https://www.virustotal.com/gui/domain/{value}"
    if kind == "url":
        b = base64.urlsafe_b64encode(value.encode("utf-8", errors="ignore")).decode().rstrip("=")
        return f"https://www.virustotal.com/gui/url/{b}"
    return ""


def _project_virustotal(kind: str, value: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    card = _empty_card(_PROVIDER_LABELS["virustotal"])
    card["link"] = _vt_link(kind, value)
    if not raw:
        card["state"] = "no-hit"
        return card
    mal = raw.get("malicious") or 0
    sus = raw.get("suspicious") or 0
    hrm = raw.get("harmless") or 0
    card["malicious"] = mal
    card["suspicious"] = sus
    card["harmless"] = hrm
    card["reputation"] = raw.get("reputation")
    card["state"] = "hit" if (mal + sus) > 0 else "no-hit"
    detail_parts = []
    for k in ("threat_label", "meaningful_name", "type_description", "final_url"):
        v = raw.get(k)
        if v:
            detail_parts.append(str(v))
    cats = raw.get("categories") or {}
    if isinstance(cats, dict) and cats:
        detail_parts.append(", ".join(sorted({str(v) for v in cats.values()})[:3]))
    card["detail"] = " · ".join(detail_parts) if detail_parts else (
        f"VT stats · {mal} malicious · {sus} suspicious · {hrm} harmless"
    )
    if raw.get("asn"):
        card["tags"] = [f"ASN {raw['asn']}"] + ([raw["as_owner"]] if raw.get("as_owner") else [])
    return card


def _project_abuseipdb(value: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    card = _empty_card(_PROVIDER_LABELS["abuseipdb"])
    card["link"] = f"https://www.abuseipdb.com/check/{value}"
    if not raw:
        card["state"] = "no-hit"
        return card
    score = raw.get("abuse_confidence_score")
    reports = raw.get("total_reports") or 0
    card["reputation"] = score
    card["state"] = "hit" if (score or 0) >= 25 or reports > 0 else "no-hit"
    card["detail"] = (
        f"Abuse score {score if score is not None else '—'}/100 · "
        f"{reports} reports · {raw.get('usage_type') or 'unknown usage'}"
    )
    card["last_seen"] = raw.get("last_reported_at")
    tags = []
    if raw.get("is_tor"):
        tags.append("Tor exit")
    if raw.get("country_code"):
        tags.append(str(raw["country_code"]))
    if raw.get("isp"):
        tags.append(str(raw["isp"]))
    card["tags"] = tags
    return card


def _project_otx(kind: str, value: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    card = _empty_card(_PROVIDER_LABELS["otx"])
    card["link"] = f"https://otx.alienvault.com/indicator/{('file' if kind in ('sha256','sha1','md5','hash') else kind)}/{value}"
    if not raw:
        card["state"] = "no-hit"
        return card
    pulses = raw.get("pulse_count") or 0
    card["reputation"] = raw.get("reputation")
    card["state"] = "hit" if pulses > 0 else "no-hit"
    pulse_list = raw.get("pulses") or []
    if pulse_list:
        names = [p.get("name") for p in pulse_list if p.get("name")]
        card["detail"] = f"{pulses} OTX pulses · {'; '.join(names[:2])}"
        tags: List[str] = []
        for p in pulse_list[:3]:
            for t in (p.get("tags") or [])[:3]:
                if t not in tags:
                    tags.append(t)
        card["tags"] = tags[:6]
    else:
        card["detail"] = f"{pulses} OTX pulses"
    return card


def _project_urlscan(value: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    card = _empty_card(_PROVIDER_LABELS["urlscan"])
    card["link"] = f"https://urlscan.io/search/#{value}"
    if not raw:
        card["state"] = "no-hit"
        return card
    total = raw.get("total") or 0
    results = raw.get("results") or []
    mal_hits = sum(1 for r in results if r.get("verdict"))
    card["malicious"] = mal_hits
    card["state"] = "hit" if mal_hits > 0 else ("no-hit" if total == 0 else "hit")
    card["detail"] = f"{total} URLScan submissions · {mal_hits} flagged malicious"
    if results:
        card["link"] = f"https://urlscan.io/result/{results[0].get('scan_id')}/" if results[0].get("scan_id") else card["link"]
    return card


def _project_urlhaus_from_ti(value: str, ti_rec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """URLhaus data reaches the enricher via the local TI corpus
    (`_osint_lookup`) which is populated by `ti_feed_sync` from URLhaus
    directly. We surface it here as a first-class provider row so the
    OSINT card always shows URLhaus as an attribution."""
    card = _empty_card(_PROVIDER_LABELS["urlhaus"])
    card["link"] = f"https://urlhaus.abuse.ch/url/{value}"
    if not ti_rec:
        card["state"] = "no-hit"
        return card
    src_names = [s for s in (ti_rec.get("sources") or []) if "urlhaus" in str(s).lower()]
    if not src_names:
        card["state"] = "no-hit"
        return card
    families = ti_rec.get("malware_families") or []
    card["state"] = "hit"
    card["reputation"] = ti_rec.get("confidence")
    card["first_seen"] = ti_rec.get("first_seen")
    card["last_seen"] = ti_rec.get("last_seen")
    card["tags"] = families[:5]
    card["detail"] = (
        f"URLhaus flagged · {ti_rec.get('severity', 'medium')} · "
        f"{', '.join(families[:3]) if families else 'no family label'}"
    )
    return card


# ─── Main entry ────────────────────────────────────────────────────────
async def enrich_cio(
    cio,
    *,
    keys: Optional[Dict[str, str]] = None,
    max_per_type: int = 6,
    timeout_s: float = 20.0,
) -> Any:
    """Enrich a CIO in-place with live + local OSINT.

    Mutates:
      * every IOC node's `attrs["enrichment"]` block
      * `cio.metadata["osint"]` (raw unified bundle)

    Safe under failure: never raises. Returns the same CIO for chaining.
    """
    buckets, node_index = _extract_ioc_index(cio)
    total = sum(len(v) for v in buckets.values())
    metadata = getattr(cio, "metadata", None)
    if metadata is None:
        # CIO subclasses without a metadata attr — bail gracefully.
        return cio
    if total == 0:
        metadata["osint"] = {
            "local":   {"summary": {"total_lookups": 0, "matches": 0}, "by_value": {}, "sources": {}},
            "live":    {"ips": [], "domains": [], "urls": [], "hashes": [], "sources_used": []},
            "providers_used": [],
            "engine":  "shared:workspace",
        }
        return cio

    keys = {k: v for k, v in (keys or {}).items() if v}

    # ── Deterministic per-batch cache key ────────────────────────────
    import hashlib as _h, json as _j
    cache_key = _h.sha256(
        _j.dumps({
            "b": {k: sorted(v[:max_per_type]) for k, v in buckets.items()},
            "keys": sorted(keys.keys()),
        }, sort_keys=True).encode()
    ).hexdigest()
    cached = _cache_get(cache_key)

    if cached is not None:
        unified = cached
    else:
        # ── Fan out to Workspace's TWO shared services in parallel ───
        async def _local():
            try:
                from routers.auto_investigate import _osint_lookup
                # We pass buckets as both entities + iocs so the shared
                # service's `entities.get(x) or iocs.get(x)` picks it up.
                iocs_v2 = {
                    "ips": buckets["ips"], "domains": buckets["domains"],
                    "urls": buckets["urls"], "sha256": buckets["sha256"],
                    "sha1": buckets["sha1"], "md5": buckets["md5"],
                }
                return await _osint_lookup(entities={}, iocs=iocs_v2)
            except Exception as e:  # noqa: BLE001
                log.warning("shared _osint_lookup failed inside enrich_cio: %s", e)
                return {"by_value": {}, "by_kind": {}, "sources": {}, "summary": {"total_lookups": total, "matches": 0, "error": str(e)}}

        async def _live():
            try:
                from osint import enrich_iocs
                iocs_v2 = {
                    "ips": buckets["ips"][:max_per_type],
                    "domains": buckets["domains"][:max_per_type],
                    "urls": buckets["urls"][:max_per_type],
                    "sha256": buckets["sha256"][:max_per_type],
                    "sha1": buckets["sha1"][:max_per_type],
                    "md5": buckets["md5"][:max_per_type],
                }
                return await asyncio.wait_for(
                    enrich_iocs(iocs_v2, keys, max_per_type=max_per_type),
                    timeout=timeout_s,
                )
            except asyncio.TimeoutError:
                log.warning("enrich_iocs timed out after %ss", timeout_s)
                return {"ips": [], "domains": [], "urls": [], "hashes": [],
                        "sources_used": [], "error": f"timeout>{int(timeout_s)}s"}
            except Exception as e:  # noqa: BLE001
                log.warning("shared enrich_iocs failed inside enrich_cio: %s", e)
                return {"ips": [], "domains": [], "urls": [], "hashes": [],
                        "sources_used": [], "error": str(e)}

        local, live = await asyncio.gather(_local(), _live())
        unified = {"local": local, "live": live}
        # Provider attribution: exact set used in this investigation.
        providers_used: List[str] = []
        for label in (live.get("sources_used") or []):
            if label not in providers_used:
                providers_used.append(label)
        for src in (local.get("sources") or {}):
            if src not in providers_used:
                providers_used.append(src)
        unified["providers_used"] = providers_used
        unified["engine"] = "shared:workspace"
        _cache_put(cache_key, unified)

    # ── Decorate CIO IOC nodes with per-value provider cards ──────────
    live_by_value = _live_by_value_index(unified.get("live") or {})
    local_by_value = (unified.get("local") or {}).get("by_value") or {}

    for value, nodes in node_index.items():
        cards = _build_provider_cards(value, nodes[0], live_by_value.get(value) or {},
                                      local_by_value.get(value) or {}, keys)
        agg_reputation, first_seen, last_seen = _aggregate(cards)
        # Rewrite in place — Node.attrs is Dict[str, Any].
        for n in nodes:
            n.attrs["enrichment"] = {
                "providers": cards,
                "reputation": agg_reputation,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "hit_count": sum(1 for c in cards if c["state"] == "hit"),
                "provider_count": len(cards),
                "engine": "shared:workspace",
            }

    metadata["osint"] = unified
    return cio


# ─── Helpers ───────────────────────────────────────────────────────────
def _live_by_value_index(live: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for section in ("ips", "domains", "urls", "hashes"):
        for rec in (live.get(section) or []):
            v = rec.get("value")
            if v:
                idx[v] = rec
    return idx


def _build_provider_cards(value: str, node, live_rec: Dict[str, Any],
                          local_rec: Dict[str, Any], keys: Dict[str, str]) -> List[Dict[str, Any]]:
    """Compose the 11-field provider cards for one IOC."""
    ioc_kind = ((node.attrs or {}).get("ioc_kind") or "").lower()
    if not ioc_kind and node.kind == "ioc":
        # Best-effort infer from value shape (defensive).
        ioc_kind = "url" if value.startswith(("http://", "https://")) else "ip"
    expected = _PROVIDERS_BY_KIND.get(ioc_kind) or []
    cards: List[Dict[str, Any]] = []

    # VirusTotal
    if "virustotal" in expected:
        if not keys.get("virustotal"):
            c = _empty_card(_PROVIDER_LABELS["virustotal"], "no-key", "VT API key not configured")
        else:
            c = _project_virustotal(ioc_kind, value, live_rec.get("virustotal"))
        cards.append(c)

    # AbuseIPDB (IP only)
    if "abuseipdb" in expected:
        if not keys.get("abuseipdb"):
            c = _empty_card(_PROVIDER_LABELS["abuseipdb"], "no-key", "AbuseIPDB API key not configured")
        else:
            c = _project_abuseipdb(value, live_rec.get("abuseipdb"))
        cards.append(c)

    # OTX
    if "otx" in expected:
        if not keys.get("otx"):
            c = _empty_card(_PROVIDER_LABELS["otx"], "no-key", "OTX API key not configured")
        else:
            c = _project_otx(ioc_kind, value, live_rec.get("otx"))
        cards.append(c)

    # URLScan (domain/url)
    if "urlscan" in expected:
        c = _project_urlscan(value, live_rec.get("urlscan"))
        if not live_rec.get("urlscan") and not keys.get("urlscan"):
            c["state"] = "no-hit"  # URLScan search works without key
        cards.append(c)

    # URLhaus (url) — surfaces via the local corpus.
    if "urlhaus" in expected or ioc_kind == "url":
        c = _project_urlhaus_from_ti(value, local_rec)
        cards.append(c)

    # Guarantee at least one row (never render an empty card list).
    if not cards:
        cards.append(_empty_card("Local TI Corpus",
                                 "hit" if local_rec else "no-hit",
                                 (local_rec.get("sources") or ["no match"])[0] if local_rec else "no local TI match"))
    return cards


def _aggregate(cards: List[Dict[str, Any]]) -> tuple[Optional[int], Optional[str], Optional[str]]:
    """Aggregate reputation + first/last seen across cards."""
    reps: List[int] = []
    firsts: List[str] = []
    lasts: List[str] = []
    for c in cards:
        r = c.get("reputation")
        if isinstance(r, (int, float)):
            reps.append(int(r))
        if c.get("first_seen"):
            firsts.append(str(c["first_seen"]))
        if c.get("last_seen"):
            lasts.append(str(c["last_seen"]))
    rep = None
    if reps:
        # Use the strongest (most-negative or highest-abuse) signal.
        rep = int(sum(reps) / len(reps))
    return rep, (min(firsts) if firsts else None), (max(lasts) if lasts else None)


__all__ = ["enrich_cio"]
