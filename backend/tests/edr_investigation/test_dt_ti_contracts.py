"""DT-I1E TI normalization contracts: recorded/synthetic provider shapes only; no network, no keys."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from edr_investigation import ti_contracts as T
from edr_investigation.contracts import RETRO_TRIGGERS
from edr_investigation.ti import normalize_ioc_card

REC = json.loads((Path(__file__).parent / "fixtures" / "ti_recorded_responses.json").read_text())
IP = T.normalize_observable("ip", "203.0.113[.]50")
SHA = T.normalize_observable("hash", "A" * 64)
AT = "2026-09-05T09:00:00.000Z"
NEVER_BENIGN = ("NO_DATA", "NO_HIT", "UNAVAILABLE", "RATE_LIMITED", "ERROR", "STALE")


def test_ioc_normalization():
    assert (IP.ioc_type, IP.value) == ("IPV4", "203.0.113.50")
    assert (SHA.ioc_type, SHA.value) == ("SHA256", "a" * 64)
    assert T.normalize_observable("domain", "Evil-Syn.EXAMPLE.").value == "evil-syn.example"
    assert T.normalize_observable("url", "hxxps://Evil.example/p?q=1#frag").value == "https://evil.example/p?q=1"
    assert T.normalize_observable("ipv6", "2001:DB8::1").value == "2001:db8::1"
    for bad in (("sha256", "a" * 40), ("hash", "zz" * 32), ("ipv4", "2001:db8::1"), ("domain", "not a domain"),
                ("url", "ftp://x.example"), ("email", "a@b.example"), ("ip", "")):
        with pytest.raises(ValueError):
            T.normalize_observable(*bad)


def test_ioc_intelligence_clean_is_never_benign():
    C = REC["C"]
    got = {k: T.adapt_ioc_intelligence(v, SHA if k.startswith(("vt", "mb")) else IP, lookup_at=AT).state for k, v in C.items()}
    assert got == {"vt_malicious": "MALICIOUS", "vt_404": "NO_HIT", "vt_zero": "UNKNOWN", "vt_pending": "UNAVAILABLE",
                   "vt_429": "RATE_LIMITED", "vt_500": "ERROR", "abuse_low": "UNKNOWN", "abuse_cached": "MALICIOUS",
                   "talos_miss": "NO_HIT", "mb_miss": "NO_HIT", "urlscan_429": "RATE_LIMITED"}
    cached = T.adapt_ioc_intelligence(C["abuse_cached"], IP, lookup_at=AT)
    assert cached.cache_state == "HIT_FRESH" and cached.provenance.verdict_origin == "CLIENT_DERIVED"
    assert T.adapt_ioc_intelligence(C["vt_pending"], SHA, lookup_at=AT).failure_reason.startswith("NOT_CONFIGURED")


def test_enrichment_and_threat_intel_enrich_adapters():
    A = {k: T.adapt_enrichment(v, IP).state for k, v in REC["A"].items()}
    assert A == {"vt_nokey": "UNAVAILABLE", "vt_404": "NO_HIT", "otx_clean": "UNKNOWN", "vt_mal": "MALICIOUS",
                 "abuse_err": "RATE_LIMITED"}
    B = {k: T.adapt_threat_intel_enrich(p, r, IP, lookup_at=AT) for k, (p, r) in REC["B"].items()}
    assert {k: v.state for k, v in B.items()} == {"vt_ok": "UNKNOWN", "vt_nf": "NO_HIT", "otx_err": "ERROR",
                                                    "abuse_nokey": "UNAVAILABLE"}
    assert B["vt_ok"].verdict is None and B["vt_ok"].reputation["malicious"] == 41  # counts kept, no invented verdict


def test_edr_reputation_adapter_is_the_only_benign_source():
    H = {k: T.adapt_edr_reputation(v, IP) for k, v in REC["H"].items()}
    assert {k: v.state for k, v in H.items()} == {"known_good": "BENIGN", "unknown": "NO_HIT", "failed": "ERROR",
                                                    "stale_mal": "STALE", "unsupported": "NO_DATA"}
    assert H["known_good"].provenance.basis == T.BASIS_KNOWN_GOOD and H["known_good"].scope == "TENANT"
    assert H["stale_mal"].stale_state == "MALICIOUS" and H["stale_mal"].cache_state == "HIT_STALE"


def test_absolute_rule_no_failure_or_absence_becomes_benign():
    every = [T.adapt_ioc_intelligence(v, IP, lookup_at=AT) for v in REC["C"].values()]
    every += [T.adapt_enrichment(v, IP) for v in REC["A"].values()]
    every += [T.adapt_threat_intel_enrich(p, r, IP, lookup_at=AT) for p, r in REC["B"].values()]
    benign = [r for r in every if r.state == "BENIGN"]
    assert benign == []  # no E1 client output shape (A/B/C) carries an affirmative known-good assertion
    base = T.adapt_ioc_intelligence(REC["C"]["vt_404"], SHA, lookup_at=AT)
    for st in NEVER_BENIGN:
        with pytest.raises(ValueError):
            T.NormalizedTIResult(**{**base.__dict__, "state": "BENIGN", "failure_reason": "x" if st in T.FAILURES else None})


def test_contract_invariants():
    base = T.adapt_ioc_intelligence(REC["C"]["vt_malicious"], SHA, lookup_at=AT)
    bad = [dict(state="BENIGN"), dict(state="RATE_LIMITED"), dict(state="ERROR", failure_reason="x"),
           dict(confidence=1.5), dict(state="NO_HIT"), dict(scope="TENANT"), dict(tenant_id="t1"),
           dict(state="STALE"), dict(cache_state="HIT_STALE"), dict(schema_version="v0"), dict(state="CLEAN")]
    for kw in bad:
        with pytest.raises(ValueError):
            T.NormalizedTIResult(**{**base.__dict__, **kw})
    d = base.to_dict()
    for k in ("provider", "state", "ioc_type", "observable", "lookup_at", "result_at", "verdict", "confidence",
              "provenance", "cache_state", "freshness", "failure_reason", "schema_version", "scope", "tenant_id"):
        assert k in d
    assert d["provenance"]["source_client"] == "C" and d["provenance"]["adapter_version"] == T.ADAPTER_VERSION


def test_tenant_safety():
    with pytest.raises(ValueError):
        T.cache_key("TENANT", "local_ioc", IP)
    with pytest.raises(ValueError):
        T.cache_key("GLOBAL", "virustotal", IP, "t1")
    assert T.cache_key("TENANT", "local_ioc", IP, "t1") != T.cache_key("TENANT", "local_ioc", IP, "t2")
    g = T.adapt_ioc_intelligence(REC["C"]["vt_malicious"], SHA, lookup_at=AT)
    assert "evidence_refs" not in g.to_dict()
    v = T.to_tenant_view(g, tenant_id="t1", evidence_refs=["cev_2", "cev_1"])
    assert v["evidence_refs"] == ["cev_1", "cev_2"] and v["view_tenant_id"] == "t1"
    priv = T.adapt_edr_reputation(REC["H"]["known_good"], IP)
    with pytest.raises(ValueError):
        T.to_tenant_view(priv, tenant_id="t2", evidence_refs=[])
    with pytest.raises(ValueError):
        T.to_tenant_view(g, tenant_id="", evidence_refs=[])


class _Clock:
    def __init__(self):
        self.t = datetime(2026, 9, 5, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t


def _route(provider, answers, **kw):
    calls = []

    async def lookup(obs):
        calls.append(obs.value)
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    adapt = lambda raw, obs, at: T.adapt_ioc_intelligence(raw, obs, lookup_at=at)
    return T.ProviderRoute(provider, ("IPV4", "SHA256"), lookup, adapt, **kw), calls


def test_broker_routing_cache_ttl_quota_and_failures():
    clk = _Clock()
    C = REC["C"]
    vt, vt_calls = _route("virustotal", [C["vt_malicious"], C["vt_429"], C["vt_500"]], ttl_s=600)
    ab, ab_calls = _route("abuseipdb", [RuntimeError("boom")], quota=1)
    b = T.TIBroker([vt, ab], clock=clk)
    run = lambda: asyncio.run(b.lookup(IP, tenant_id="t1"))
    with pytest.raises(ValueError):
        asyncio.run(b.lookup(IP, tenant_id=""))
    r1 = {r.provider: r for r in run()}
    assert r1["virustotal"].state == "MALICIOUS" and r1["virustotal"].cache_state == "MISS"
    assert r1["abuseipdb"].state == "ERROR" and r1["abuseipdb"].failure_reason == "EXCEPTION: RuntimeError"
    r2 = {r.provider: r for r in run()}
    assert r2["virustotal"].cache_state == "HIT_FRESH" and len(vt_calls) == 1
    assert r2["abuseipdb"].state == "RATE_LIMITED" and r2["abuseipdb"].failure_reason == "LOCAL_QUOTA_EXHAUSTED"
    clk.t += timedelta(seconds=601)
    r3 = {r.provider: r for r in run()}
    assert r3["virustotal"].state == "STALE" and r3["virustotal"].stale_state == "MALICIOUS"
    assert r3["virustotal"].failure_reason == "HTTP 429"  # rate limit never overwrote or faked a fresh answer
    dom = T.normalize_observable("domain", "evil-syn.example")
    assert {r.state for r in asyncio.run(b.lookup(dom, tenant_id="t1"))} == {"NO_DATA"}


def test_history_and_intel_change_event():
    h = T.ReputationHistory()
    C = REC["C"]
    seq = [C["vt_404"], C["vt_429"], C["vt_404"], C["vt_malicious"], C["vt_500"], C["vt_malicious"]]
    events = [h.record(T.adapt_ioc_intelligence(r, SHA, lookup_at=AT)) for r in seq]
    assert [e is not None for e in events] == [False, False, False, True, False, False]
    ev = events[3]
    assert (ev.previous_state, ev.new_state, ev.previous_version, ev.new_version) == ("NO_HIT", "MALICIOUS", 3, 4)
    assert ev.retro_trigger in RETRO_TRIGGERS and ev.behavior_replay_reason == "INTEL_CHANGED"
    assert len(h.history(T.cache_key("GLOBAL", "virustotal", SHA))) == 6  # append-only incl. failures
    assert h.record(T.adapt_ioc_intelligence(C["abuse_cached"], IP, lookup_at=AT)) is None  # cache replay ≠ new intel
    with pytest.raises(ValueError):
        T.IntelChangeEvent("x", "vt", "SHA256", "a", "GLOBAL", None, "ERROR", "MALICIOUS", 1, 2, AT, None)


def test_behavior_replay_reason_matches_engine_vocabulary():
    from edr_behavior.replay import REASONS
    assert T.INTEL_REPLAY_REASON in REASONS and T.INTEL_RETRO_TRIGGER in RETRO_TRIGGERS


def test_dt_view_uses_normalized_mapping():
    card = {"ioc": "203.0.113.50", "ioc_type": "ip", "providers": [
        {"provider": "abuseipdb", "verdict": {"provider": "abuseipdb", "verdict": "malicious", "source": "live"}},
        {"provider": "dshield", "verdict": "clean", "source": "live"},
        {"provider": "virustotal", "verdict": "unknown", "source": "error", "error": "HTTP 429"}]}
    rows = normalize_ioc_card(card)
    assert [r.state for r in rows] == ["MALICIOUS", "NO_HIT", "RATE_LIMITED"]
    assert all(r.provenance["schema_version"] == T.TI_SCHEMA for r in rows)
