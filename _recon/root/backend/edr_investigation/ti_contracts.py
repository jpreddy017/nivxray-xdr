"""DT-I1E threat-intelligence normalization contracts (dt-i1e.ti.v1). Store-independent; no network; no client imports.

A provider result is EVIDENCE, never final verdict authority. NO_DATA / NO_HIT / UNAVAILABLE / RATE_LIMITED / ERROR /
STALE never become BENIGN. BENIGN exists only where a provider affirmatively asserts known-good.
Adapters map the OUTPUT SHAPES of the existing E1 clients (A enrichment, B threat_intel_enrich, C ioc_intelligence,
H edr_plane.reputation); they never call or modify those clients.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

TI_SCHEMA = "dt-i1e.ti.v1"
ADAPTER_VERSION = "1"
STATES = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "NO_DATA", "NO_HIT", "UNAVAILABLE", "RATE_LIMITED",
          "ERROR", "STALE")
JUDGEMENTS = ("MALICIOUS", "SUSPICIOUS", "BENIGN")
FAILURES = ("UNAVAILABLE", "RATE_LIMITED", "ERROR")
INFORMATIVE = JUDGEMENTS + ("UNKNOWN", "NO_HIT", "NO_DATA")
IOC_TYPES = ("SHA256", "SHA1", "MD5", "IPV4", "IPV6", "DOMAIN", "URL")
CACHE_STATES = ("MISS", "HIT_FRESH", "HIT_STALE", "BYPASSED", "NOT_CACHEABLE")
FRESHNESS = ("FRESH", "STALE", "UNKNOWN")
SCOPES = ("GLOBAL", "TENANT")
VERDICT_ORIGINS = ("PROVIDER_NATIVE", "CLIENT_DERIVED", "NONE")
BASIS_KNOWN_GOOD = "PROVIDER_ASSERTED_KNOWN_GOOD"
SOURCE_CLIENTS = {"A": "backend/enrichment", "B": "backend/threat_intel_enrich", "C": "backend/services/ioc_intelligence",
                  "H": "backend/edr_plane/reputation", "SYN": "synthetic-test-route"}
INTEL_RETRO_TRIGGER = "INTEL_CHANGE"          # edr_investigation.contracts.RETRO_TRIGGERS
INTEL_REPLAY_REASON = "INTEL_CHANGED"         # edr_behavior.replay.REASONS
NO_HIT_ON_CLEAN = ("talos", "dshield", "threatfox", "malwarebazaar", "urlhaus", "hybrid_analysis")


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


# ── IOC normalization ───────────────────────────────────────────────
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_ALIASES = {"IP": "IP", "IPV4": "IP", "IPV6": "IP", "IP_ADDRESS": "IP", "HASH": "HASH", "SHA-256": "SHA256",
            "SHA256": "SHA256", "SHA1": "SHA1", "SHA-1": "SHA1", "MD5": "MD5", "DOMAIN": "DOMAIN",
            "HOSTNAME": "DOMAIN", "FQDN": "DOMAIN", "URL": "URL", "URI": "URL"}


def refang(v: str) -> str:
    v = v.strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[://]", "://")):
        v = v.replace(a, b)
    return re.sub(r"^h[xX]{2}p", "http", v)


@dataclass(frozen=True)
class Observable:
    ioc_type: str
    value: str
    raw: str = ""

    def __post_init__(self) -> None:
        _req(self.ioc_type in IOC_TYPES, f"bad IOC type {self.ioc_type!r}")
        _req(bool(self.value), "an observable needs a value")


def normalize_observable(ioc_type: Any, value: Any) -> Observable:
    raw = str(value or "")
    t, v = _ALIASES.get(str(ioc_type or "").strip().upper()), refang(raw)
    _req(t is not None and bool(v), f"unsupported IOC type {ioc_type!r} or empty value")
    if t in ("HASH", "SHA256", "SHA1", "MD5"):
        v = v.lower()
        kind = {64: "SHA256", 40: "SHA1", 32: "MD5"}.get(len(v))
        _req(bool(kind) and bool(_HEX.match(v)), "not a hex MD5/SHA1/SHA256")
        _req(t in ("HASH", kind), "hash length does not match the declared type")
        t = kind
    elif t == "IP":
        a = ipaddress.ip_address(v)
        declared = str(ioc_type).strip().upper()
        t = "IPV4" if a.version == 4 else "IPV6"
        _req(declared not in ("IPV4", "IPV6") or declared == t, "IP version does not match the declared type")
        v = str(a)
    elif t == "DOMAIN":
        v = v.lower().rstrip(".")
        _req(bool(_DOMAIN.match(v)), "not a domain name")
    else:
        p = urlsplit(v)
        _req(p.scheme.lower() in ("http", "https") and bool(p.netloc), "URL needs http(s) scheme and host")
        v = urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))
    return Observable(t, v, raw[:2048])


def cache_key(scope: str, provider: str, obs: Observable, tenant_id: Optional[str] = None) -> str:
    """GLOBAL intel is shareable; TENANT intel is keyed by tenant. No default tenant."""
    _req(scope in SCOPES, f"bad scope {scope!r}")
    if scope == "TENANT":
        _req(bool(tenant_id), "tenant-private intel needs tenant_id (no default tenant)")
        return f"ti:v1:tenant:{tenant_id}:{provider}:{obs.ioc_type}:{obs.value}"
    _req(not tenant_id, "global intel keys never carry a tenant")
    return f"ti:v1:global:{provider}:{obs.ioc_type}:{obs.value}"


# ── normalized result ───────────────────────────────────────────────
@dataclass(frozen=True)
class ProviderProvenance:
    provider: str
    source_client: str
    adapter: str
    adapter_version: str
    source_verdict: Optional[str]
    verdict_origin: str
    raw_ref: Optional[str] = None
    basis: Optional[str] = None

    def __post_init__(self) -> None:
        _req(bool(self.provider) and self.source_client in SOURCE_CLIENTS, "provenance needs provider and known client")
        _req(self.verdict_origin in VERDICT_ORIGINS, f"bad verdict origin {self.verdict_origin!r}")


@dataclass(frozen=True)
class NormalizedTIResult:
    provider: str
    state: str
    ioc_type: str
    observable: str
    lookup_at: Optional[str]
    provenance: ProviderProvenance
    scope: str = "GLOBAL"
    tenant_id: Optional[str] = None
    result_at: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    reputation: Dict[str, Any] = field(default_factory=dict)
    cache_state: str = "MISS"
    freshness: str = "UNKNOWN"
    stale_state: Optional[str] = None
    failure_reason: Optional[str] = None
    detail: str = ""
    schema_version: str = TI_SCHEMA

    def __post_init__(self) -> None:
        _req(self.state in STATES, f"bad TI state {self.state!r}")
        _req(self.ioc_type in IOC_TYPES and bool(self.observable), "result needs a normalized observable")
        _req(self.cache_state in CACHE_STATES and self.freshness in FRESHNESS, "bad cache/freshness state")
        _req(self.scope in SCOPES, f"bad scope {self.scope!r}")
        _req((self.scope == "TENANT") == bool(self.tenant_id), "TENANT scope needs tenant_id; GLOBAL never has one")
        _req(self.schema_version == TI_SCHEMA, "unknown schema version")
        if self.state in JUDGEMENTS:
            _req(bool(self.provenance.source_verdict) and self.failure_reason is None,
                 "a reputation judgement requires a returned provider verdict and no failure")
        if self.state == "BENIGN":
            _req(self.provenance.basis == BASIS_KNOWN_GOOD, "BENIGN requires an affirmative known-good assertion")
        if self.state in FAILURES:
            _req(bool(self.failure_reason) and self.verdict is None, "failures state why and carry no verdict")
        if self.state in ("NO_DATA", "NO_HIT"):
            _req(self.verdict is None, f"{self.state} carries no verdict")
        _req(self.confidence is None or (self.state in JUDGEMENTS and 0.0 <= self.confidence <= 1.0),
             "confidence only where a judgement was returned, in [0,1]")
        _req((self.state == "STALE") == (self.stale_state is not None), "STALE (and only STALE) names its prior state")
        _req(self.stale_state in (None,) + INFORMATIVE, "stale_state must be an informative state")
        _req((self.cache_state == "HIT_STALE") == (self.state == "STALE"), "a stale cache hit is always STALE")

    def to_dict(self) -> Dict[str, Any]:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__ if k != "provenance"}
        d["provenance"] = dict(self.provenance.__dict__)
        return d


def to_tenant_view(res: NormalizedTIResult, *, tenant_id: str, evidence_refs: Sequence[str]) -> Dict[str, Any]:
    """Attach tenant-private evidence at view time; shared GLOBAL intel never stores tenant evidence."""
    _req(bool(tenant_id), "tenant_id is mandatory (no default tenant)")
    _req(res.scope == "GLOBAL" or res.tenant_id == tenant_id, "cross-tenant TI result rejected")
    return {**res.to_dict(), "view_tenant_id": tenant_id, "evidence_refs": sorted(set(evidence_refs))}


def mark_stale(prior: NormalizedTIResult, *, failure_reason: Optional[str] = None) -> NormalizedTIResult:
    base = prior.stale_state or prior.state
    _req(base in INFORMATIVE, "only an informative answer can be served stale")
    return replace(prior, state="STALE", stale_state=base, cache_state="HIT_STALE", freshness="STALE",
                   confidence=None, failure_reason=failure_reason)


def _rate_limited(*texts: Any) -> bool:
    t = " ".join(str(x or "") for x in texts).lower()
    return "429" in t or "rate limit" in t or "rate-limit" in t or "quota" in t or "too many requests" in t


def _mk(client: str, provider: str, state: str, obs: Observable, *, lookup_at, source_verdict=None,
        origin="NONE", verdict=None, confidence=None, failure_reason=None, detail="", reputation=None,
        cache_state="MISS", scope="GLOBAL", tenant_id=None, basis=None, raw_ref=None, result_at=None):
    prov = ProviderProvenance(provider, client, f"{SOURCE_CLIENTS[client]}->{TI_SCHEMA}", ADAPTER_VERSION,
                              None if source_verdict is None else str(source_verdict)[:64], origin, raw_ref, basis)
    fresh = "FRESH" if lookup_at and cache_state in ("MISS", "HIT_FRESH", "BYPASSED") else "UNKNOWN"
    if state in FAILURES:
        verdict, confidence = None, None
    if state in ("NO_DATA", "NO_HIT"):
        verdict = None
    if state not in JUDGEMENTS:
        confidence = None
    return NormalizedTIResult(provider, state, obs.ioc_type, obs.value, lookup_at, prov, scope, tenant_id, result_at,
                              verdict, confidence, dict(reputation or {}), cache_state, fresh, None, failure_reason,
                              str(detail or "")[:300])


# ── adapters over EXISTING client output shapes ─────────────────────
def adapt_ioc_intelligence(pv: Dict[str, Any], obs: Observable, *, lookup_at: Optional[str],
                           raw_ref: Optional[str] = None) -> NormalizedTIResult:
    """C · services/ioc_intelligence ProviderVerdict.to_dict(). Its "clean" is never an affirmative known-good."""
    prov, v = str(pv.get("provider") or "unknown").lower(), str(pv.get("verdict") or "").lower()
    src, detail, err = str(pv.get("source") or "live").lower(), pv.get("detail") or "", pv.get("error") or ""
    kw = dict(lookup_at=lookup_at, source_verdict=v or None, detail=detail, raw_ref=raw_ref,
              cache_state="HIT_FRESH" if src == "cache" else "MISS")
    if src == "pending":
        return _mk("C", prov, "UNAVAILABLE", obs, failure_reason=f"NOT_CONFIGURED: {detail or 'provider key absent'}", **kw)
    if src == "error":
        st = "RATE_LIMITED" if _rate_limited(err, detail) else "ERROR"
        return _mk("C", prov, st, obs, failure_reason=(err or detail or "lookup failed")[:200], **kw)
    score = pv.get("score")
    conf = float(score) if isinstance(score, (int, float)) and 0 <= score <= 1 else None
    rep = {"score": score} if score is not None else {}
    if v in ("malicious", "suspicious"):
        return _mk("C", prov, v.upper(), obs, origin="CLIENT_DERIVED", verdict=v, confidence=conf, reputation=rep, **kw)
    if v == "clean":
        not_found = prov in NO_HIT_ON_CLEAN or ("not found" in detail.lower() or "no record" in detail.lower()
                                                or "404" in detail)
        if not_found:
            return _mk("C", prov, "NO_HIT", obs, **kw)
        return _mk("C", prov, "UNKNOWN", obs, origin="CLIENT_DERIVED", verdict="clean", reputation=rep,
                   **{**kw, "detail": f"client label 'clean' is not a known-good assertion · {detail}"})
    if _rate_limited(detail, err):
        return _mk("C", prov, "RATE_LIMITED", obs, failure_reason=(detail or err)[:200], **kw)
    return _mk("C", prov, "UNKNOWN", obs, reputation=rep, **kw)


def adapt_enrichment(res: Dict[str, Any], obs: Observable, *, lookup_at: Optional[str] = None) -> NormalizedTIResult:
    """A · backend/enrichment result {provider, verdict, score, sources, details, queried_at, _cached?}."""
    prov, v = str(res.get("provider") or "unknown").lower(), str(res.get("verdict") or "").lower()
    det = res.get("details") or {}
    kw = dict(lookup_at=res.get("queried_at") or lookup_at, source_verdict=v or None,
              cache_state="HIT_FRESH" if res.get("_cached") else "MISS", reputation={"score": res.get("score"),
              "sources": res.get("sources")})
    if v == "no-key":
        return _mk("A", prov, "UNAVAILABLE", obs, failure_reason="NOT_CONFIGURED: provider key absent", **kw)
    if v == "error":
        e = str(det.get("error") or "")
        return _mk("A", prov, "RATE_LIMITED" if _rate_limited(e) else "ERROR", obs, failure_reason=e[:200] or "error", **kw)
    if v in ("malicious", "suspicious"):
        s = res.get("score")
        return _mk("A", prov, v.upper(), obs, origin="CLIENT_DERIVED", verdict=v,
                   confidence=float(s) if isinstance(s, (int, float)) and 0 <= s <= 1 else None, **kw)
    if det.get("status") == 404 or "not-found" in str(det.get("reason") or ""):
        return _mk("A", prov, "NO_HIT", obs, **kw)
    if v == "clean":
        return _mk("A", prov, "UNKNOWN", obs, origin="CLIENT_DERIVED", verdict="clean",
                   detail="client label 'clean' (zero detections / low score) is not a known-good assertion", **kw)
    return _mk("A", prov, "UNKNOWN", obs, **kw)


def adapt_threat_intel_enrich(provider: str, res: Dict[str, Any], obs: Observable, *,
                              lookup_at: Optional[str]) -> NormalizedTIResult:
    """B · backend/threat_intel_enrich per-provider dict. B returns raw counts, never a verdict label."""
    prov, status = str(provider or "unknown").lower(), str(res.get("status") or "").lower()
    kw = dict(lookup_at=lookup_at, source_verdict=None, cache_state="HIT_FRESH" if res.get("_cached") else "MISS")
    if status in ("no-key", "disabled"):
        return _mk("B", prov, "UNAVAILABLE", obs, failure_reason=f"NOT_CONFIGURED: {status}", **kw)
    if status == "error":
        e = str(res.get("error") or "")
        return _mk("B", prov, "RATE_LIMITED" if _rate_limited(e) else "ERROR", obs, failure_reason=e[:200] or "error", **kw)
    if status == "not-found":
        return _mk("B", prov, "NO_HIT", obs, **kw)
    rep = {k: res[k] for k in ("malicious", "suspicious", "harmless", "undetected", "reputation", "pulse_count",
                               "abuse_confidence_score", "total_reports") if k in res}
    return _mk("B", prov, "UNKNOWN", obs, reputation=rep,
               detail="raw provider counts returned; normalization does not invent a verdict", **kw)


_H_STATE = {"KNOWN_MALICIOUS": "MALICIOUS", "KNOWN_GOOD": "BENIGN", "UNKNOWN": "NO_HIT", "LOOKUP_FAILED": "ERROR",
            "NOT_SUPPORTED": "NO_DATA"}
_H_CACHE = {"CACHE_MISS": "MISS", "CACHE_HIT_FRESH": "HIT_FRESH", "CACHE_HIT_STALE": "HIT_STALE",
            "CACHE_BYPASSED": "BYPASSED", "CACHE_NOT_CACHEABLE": "NOT_CACHEABLE"}


def adapt_edr_reputation(rr: Dict[str, Any], obs: Observable) -> NormalizedTIResult:
    """H · edr_plane.reputation ReputationResult.to_dict(). KNOWN_GOOD is the only affirmative BENIGN source."""
    v = str(rr.get("verdict") or "")
    state, tenant = _H_STATE.get(v, "UNKNOWN"), rr.get("tenant_scope") or None
    cache = _H_CACHE.get(str(rr.get("cache_state") or "CACHE_MISS"), "MISS")
    kw = dict(lookup_at=rr.get("queried_at"), source_verdict=v or None, scope="TENANT" if tenant else "GLOBAL",
              tenant_id=tenant, result_at=rr.get("intelligence_timestamp"), cache_state="MISS" if cache == "HIT_STALE" else cache)
    if state == "ERROR":
        fr = str(rr.get("failure_reason") or "lookup failed")
        return _mk("H", str(rr.get("provider_id")), "RATE_LIMITED" if _rate_limited(fr) else "ERROR", obs,
                   failure_reason=fr[:200], **kw)
    c = rr.get("confidence")
    res = _mk("H", str(rr.get("provider_id")), state, obs, origin="PROVIDER_NATIVE" if state in JUDGEMENTS else "NONE",
              verdict=v if state in JUDGEMENTS else None, basis=BASIS_KNOWN_GOOD if state == "BENIGN" else None,
              confidence=c if isinstance(c, (int, float)) and 0 <= c <= 1 else None,
              detail="NOT_SUPPORTED: provider cannot judge this observable type" if v == "NOT_SUPPORTED" else "", **kw)
    return mark_stale(res) if cache == "HIT_STALE" else res


# ── broker (wraps adapters; routes; cache/TTL/quota) ────────────────
@dataclass(frozen=True)
class ProviderRoute:
    provider: str
    supported_types: Tuple[str, ...]
    lookup: Callable[[Observable], Awaitable[Any]]
    adapt: Callable[[Any, Observable, str], NormalizedTIResult]
    scope: str = "GLOBAL"
    ttl_s: int = 3600
    quota: Optional[int] = None

    def __post_init__(self) -> None:
        _req(self.scope in SCOPES and self.ttl_s > 0, "bad route scope/ttl")
        _req(all(t in IOC_TYPES for t in self.supported_types), "bad supported IOC type")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse(ts: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class TIBroker:
    """One result per route; providers are never collapsed into a verdict. Failures never overwrite cached intel."""

    def __init__(self, routes: Sequence[ProviderRoute], *, clock: Callable[[], datetime],
                 cache: Optional[Dict[str, NormalizedTIResult]] = None) -> None:
        _req(len({r.provider for r in routes}) == len(routes), "one route per provider")
        self._routes = sorted(routes, key=lambda r: r.provider)
        self._clock, self._cache, self._used = clock, cache if cache is not None else {}, {}

    async def lookup(self, obs: Observable, *, tenant_id: str) -> List[NormalizedTIResult]:
        _req(bool(tenant_id), "tenant_id is mandatory (no default tenant)")
        out = []
        for r in self._routes:
            out.append(await self._one(r, obs, tenant_id))
        return out

    async def _one(self, r: ProviderRoute, obs: Observable, tenant_id: str) -> NormalizedTIResult:
        now, at = self._clock(), _iso(self._clock())
        scope_tenant = tenant_id if r.scope == "TENANT" else None
        if obs.ioc_type not in r.supported_types:
            return _mk("SYN", r.provider, "NO_DATA", obs, lookup_at=at, cache_state="NOT_CACHEABLE", scope=r.scope,
                       tenant_id=scope_tenant, detail=f"NOT_SUPPORTED: {r.provider} cannot judge {obs.ioc_type}")
        key = cache_key(r.scope, r.provider, obs, scope_tenant)
        hit = self._cache.get(key)
        if hit is not None:
            t = _parse(hit.lookup_at)
            if t is not None and (now - t).total_seconds() <= r.ttl_s:
                return replace(hit, cache_state="HIT_FRESH", freshness="FRESH")
        if r.quota is not None and self._used.get(r.provider, 0) >= r.quota:
            fail = "LOCAL_QUOTA_EXHAUSTED"
            return mark_stale(hit, failure_reason=fail) if hit else _mk(
                "SYN", r.provider, "RATE_LIMITED", obs, lookup_at=at, failure_reason=fail, scope=r.scope,
                tenant_id=scope_tenant, cache_state="NOT_CACHEABLE")
        self._used[r.provider] = self._used.get(r.provider, 0) + 1
        try:
            res = r.adapt(await r.lookup(obs), obs, at)
        except Exception as e:  # provider/client failure is a recorded state, not an answer
            res = _mk("SYN", r.provider, "ERROR", obs, lookup_at=at, failure_reason=f"EXCEPTION: {type(e).__name__}",
                      scope=r.scope, tenant_id=scope_tenant)
        _req(res.scope == r.scope and res.tenant_id == scope_tenant, "adapter returned a result outside its route scope")
        if res.state in FAILURES:
            return mark_stale(hit, failure_reason=res.failure_reason) if hit else res
        if res.state != "STALE":
            self._cache[key] = res
        return res


# ── reputation history + INTEL_CHANGE (consumed by future DT-I1G; no replay here) ──
@dataclass(frozen=True)
class HistoryEntry:
    version: int
    at: Optional[str]
    state: str
    cache_state: str
    failure_reason: Optional[str]


@dataclass(frozen=True)
class IntelChangeEvent:
    event_id: str
    provider: str
    ioc_type: str
    observable: str
    scope: str
    tenant_id: Optional[str]
    previous_state: str
    new_state: str
    previous_version: int
    new_version: int
    at: Optional[str]
    provenance_ref: Optional[str]
    reason: str = "PROVIDER_STATE_CHANGED"
    retro_trigger: str = INTEL_RETRO_TRIGGER
    behavior_replay_reason: str = INTEL_REPLAY_REASON
    schema_version: str = TI_SCHEMA

    def __post_init__(self) -> None:
        _req(self.previous_state in INFORMATIVE and self.new_state in INFORMATIVE, "INTEL_CHANGE needs informative states")
        _req(self.previous_state != self.new_state and self.new_version > self.previous_version, "not a change")
        _req((self.scope == "TENANT") == bool(self.tenant_id), "tenant scope mismatch")


class ReputationHistory:
    """Append-only per (scope, tenant, provider, observable). Failures/STALE are recorded but never change intel."""

    def __init__(self) -> None:
        self._h: Dict[str, List[HistoryEntry]] = {}

    def record(self, res: NormalizedTIResult) -> Optional[IntelChangeEvent]:
        key = cache_key(res.scope, res.provider, Observable(res.ioc_type, res.observable), res.tenant_id)
        if res.cache_state == "HIT_FRESH":
            return None  # re-serving a cached answer is not new intelligence
        entries = self._h.setdefault(key, [])
        prev = next((e for e in reversed(entries) if e.state in INFORMATIVE), None)
        entry = HistoryEntry(len(entries) + 1, res.lookup_at, res.state, res.cache_state, res.failure_reason)
        entries.append(entry)
        if res.state not in INFORMATIVE or prev is None or prev.state == res.state:
            return None
        eid = hashlib.sha256(f"{key}|{prev.version}|{entry.version}".encode()).hexdigest()[:16]
        return IntelChangeEvent(f"intel:{eid}", res.provider, res.ioc_type, res.observable, res.scope, res.tenant_id,
                                prev.state, res.state, prev.version, entry.version, res.lookup_at,
                                res.provenance.raw_ref)

    def history(self, key: str) -> Tuple[HistoryEntry, ...]:
        return tuple(self._h.get(key, ()))
