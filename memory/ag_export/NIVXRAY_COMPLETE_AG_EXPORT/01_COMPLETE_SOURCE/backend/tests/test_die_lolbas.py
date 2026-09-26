"""
DIE · LOLBAS + IOC tests
────────────────────────
"""
from services.die.lolbas import lolbas_lookup, LOLBAS_REGISTRY
from services.die.ioc_semantic import extract_iocs, summarize_iocs


# ── LOLBAS registry ───────────────────────────────────────────────
def test_lookup_case_insensitive():
    assert lolbas_lookup("PowerShell.EXE") is not None
    assert lolbas_lookup("POWERSHELL.EXE") is not None
    assert lolbas_lookup("powershell.exe") is not None

def test_lookup_strips_path_prefix():
    entry = lolbas_lookup(r"C:\Windows\System32\certutil.exe")
    assert entry is not None
    assert "T1105" in entry["mitre"]

def test_lookup_without_extension():
    assert lolbas_lookup("certutil") is not None
    assert lolbas_lookup("bitsadmin") is not None

def test_lookup_unknown_returns_none():
    assert lolbas_lookup("notarealbinary.exe") is None

def test_registry_carries_mitre_for_shadow_delete():
    entry = lolbas_lookup("vssadmin.exe")
    assert entry is not None
    assert "T1490" in entry["mitre"]

def test_registry_size_sane():
    # Sanity — the built-in seed set should keep at least 20 entries.
    assert len(LOLBAS_REGISTRY) >= 20


# ── IOC extractor ─────────────────────────────────────────────────
def test_ipv4_public_vs_private():
    iocs = extract_iocs("connect to 8.8.8.8 and 192.168.1.10")
    kinds = {i["kind"]: i["value"] for i in iocs}
    assert kinds.get("ip") == "8.8.8.8"
    assert kinds.get("private-ip") == "192.168.1.10"

def test_url_extracted():
    iocs = extract_iocs("hit http://evil.example/a.ps1?x=1 for stage2")
    urls = [i["value"] for i in iocs if i["kind"] == "url"]
    assert any(u.startswith("http://evil.example") for u in urls)

def test_discord_webhook():
    src = "post to https://discord.com/api/webhooks/1234567890/AbCdEf-123_XYZ"
    iocs = extract_iocs(src)
    assert any(i["kind"] == "discord-webhook" for i in iocs)

def test_onion_address():
    src = "reach out to abcdefghijklmnop.onion:8443"
    iocs = extract_iocs(src)
    assert any(i["kind"] == "onion" for i in iocs)

def test_unc_path():
    src = r"copy \\evil-fs\share\payload.dll"
    iocs = extract_iocs(src)
    assert any(i["kind"] == "unc" for i in iocs)

def test_dedupe_stable_ordering():
    src = "http://a.example http://a.example http://b.example"
    a = extract_iocs(src)
    b = extract_iocs(src)
    assert a == b  # deterministic
    assert len([i for i in a if i["kind"] == "url"]) == 2

def test_summarize_shape():
    iocs = extract_iocs("http://x.example and 8.8.8.8")
    summary = summarize_iocs(iocs)
    assert isinstance(summary, dict)
    assert "url" in summary
    assert "ip" in summary

def test_noise_stripped():
    iocs = extract_iocs("uses microsoft.com and localhost trusted certs")
    values = {i["value"] for i in iocs}
    assert "microsoft.com" not in values
    assert "localhost" not in values
