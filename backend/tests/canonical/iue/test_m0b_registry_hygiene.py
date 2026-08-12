"""M0b · Passive Registry hygiene tests (ADR-0014).

Locks:
  1. Every adapter / analyzer ID from D0 §5 is registered.
  2. Every ID resolves to a real Python import.
  3. Duplicate registration is rejected.
  4. Registry ordering (via .ids()) is deterministic.
  5. Registry serialisation is deterministic (byte-identical across runs).
  6. No production code path consumes the registry today.  Grep-lock.
  7. Existing IUE baseline hashes remain byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.registry import (           # noqa: E402
    ADAPTER_REGISTRY,
    ANALYZER_REGISTRY,
    RegistryEntry,
    RegistryError,
    health_check,
)


# ── 1 · D0 §5 ID sets, verbatim ─────────────────────────────────────────────
EXPECTED_ADAPTER_IDS = {
    "url.acquire.v1", "file.gridfs.v1", "sysmon.xml.v1", "sysmon.evtx.v1",
    "archive.zip.v1", "pdf.text.v1", "docx.text.v1", "image.acquire.v1",
    "text.passthrough.v1",
}
EXPECTED_ANALYZER_IDS = {
    "die.command.v1", "die.recursive.v1", "report_extractor.v1", "image.ocr.v1",
    "csv.edr.symantec.v1", "ioc_enrichment.v1", "pe.header.v1",
    "narrative.canonical.v1", "mitre.regex_diag.v1", "verdict.risk_score.v1",
}


def test_all_expected_ids_registered():
    assert set(ADAPTER_REGISTRY.ids())  == EXPECTED_ADAPTER_IDS
    assert set(ANALYZER_REGISTRY.ids()) == EXPECTED_ANALYZER_IDS
    assert len(ADAPTER_REGISTRY)  == 9
    assert len(ANALYZER_REGISTRY) == 10


# ── 2 · Every implementation resolves cleanly ──────────────────────────────
def test_every_id_resolves():
    report = health_check()
    broken = {k: v for k, v in report.items() if not v["importable"]}
    assert not broken, (
        "Registry entries failed to import (M0b MUST register only "
        f"capabilities that actually exist):\n{json.dumps(broken, indent=2)}"
    )


# ── 3 · Duplicate id rejected ──────────────────────────────────────────────
def test_duplicate_id_rejected():
    e = RegistryEntry(
        entry_id="url.acquire.v1", kind="adapter", version="1",
        implementation_path="builtins:str", accepts_formats=frozenset({"url"}),
        role="dup", live_today=False,
    )
    with pytest.raises(RegistryError, match="duplicate id"):
        ADAPTER_REGISTRY.register(e)


def test_wrong_kind_rejected():
    e = RegistryEntry(
        entry_id="bogus.mismatch.v1", kind="adapter", version="1",
        implementation_path="builtins:str", accepts_formats=frozenset({"x"}),
        role="wrong kind", live_today=False,
    )
    with pytest.raises(RegistryError, match="does not match"):
        ANALYZER_REGISTRY.register(e)


def test_unknown_id_raises():
    with pytest.raises(RegistryError, match="unknown id"):
        ADAPTER_REGISTRY.get("does.not.exist.v1")


# ── 4 · Ordering deterministic ─────────────────────────────────────────────
def test_ids_sorted_deterministic():
    a1 = ADAPTER_REGISTRY.ids()
    a2 = ADAPTER_REGISTRY.ids()
    assert a1 == a2 == sorted(a1)


# ── 5 · Serialisation byte-identical across processes ──────────────────────
def _serialise() -> str:
    dump = {
        "adapters":  [e.__dict__ | {"accepts_formats": sorted(e.accepts_formats)}
                       for e in ADAPTER_REGISTRY.all()],
        "analyzers": [e.__dict__ | {"accepts_formats": sorted(e.accepts_formats)}
                       for e in ANALYZER_REGISTRY.all()],
    }
    return json.dumps(dump, sort_keys=True, default=str)


def test_registry_serialisation_is_deterministic():
    a = hashlib.sha256(_serialise().encode()).hexdigest()
    b = hashlib.sha256(_serialise().encode()).hexdigest()
    assert a == b, "in-process serialisation drift"

    # Cross-process determinism (fresh Python interpreter).
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, r'" + str(_BACKEND) + "'); "
         "import json, hashlib; from services.registry import ADAPTER_REGISTRY, ANALYZER_REGISTRY; "
         "dump={'adapters':[e.__dict__|{'accepts_formats':sorted(e.accepts_formats)} for e in ADAPTER_REGISTRY.all()],"
         "'analyzers':[e.__dict__|{'accepts_formats':sorted(e.accepts_formats)} for e in ANALYZER_REGISTRY.all()]};"
         "print(hashlib.sha256(json.dumps(dump,sort_keys=True,default=str).encode()).hexdigest())"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    fresh_hash = r.stdout.strip()
    assert fresh_hash == a, ("registry hash differs across processes — "
                              f"in-proc={a!r}, fresh={fresh_hash!r}")


# ── 6 · No production path imports the registry ─────────────────────────────
def test_registry_is_passive_no_production_imports():
    """Grep-lock: no file outside tests/ imports services.registry."""
    r = subprocess.run(
        ["grep", "-rln", "from services.registry",
         str(_BACKEND / "routers"), str(_BACKEND / "services"),
         str(_BACKEND / "server.py"), str(_BACKEND / "operations.py"),
         str(_BACKEND / "analysis_core.py"), str(_BACKEND / "evidence_extractor.py")],
        capture_output=True, text=True,
    )
    hits = [ln for ln in r.stdout.splitlines() if ln
            and "/services/registry/" not in ln
            and "/tests/" not in ln]
    assert not hits, (
        "M0b registry is expected to be PASSIVE — production imports found:\n"
        + "\n".join(hits)
    )


# ── 7 · M0a IUE baseline byte-identical ─────────────────────────────────────
def test_m0a_iue_response_hashes_unchanged():
    """M0b must not alter any IUE-produced envelope.  Zero behavioural delta."""
    from services.die.input_understanding import understand
    from dataclasses import asdict

    corpus = {
        "bare_url_medium_style": "https://systemweakness.com/some-report",
        "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
        "plain_english_short":   "the quick brown fox jumps over the lazy dog",
        "hex_ratio_long":        "4d5a" + "90" * 260,
    }
    expected = {
        "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
        "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
        "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
        "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
    }
    for name, txt in corpus.items():
        u = asdict(understand(txt, execute=False))
        canon = json.dumps(u, default=str, sort_keys=True)
        got = hashlib.sha256(canon.encode()).hexdigest()
        assert got == expected[name], (
            f"IUE response envelope drifted for {name!r} "
            f"(want {expected[name]}, got {got}). M0b MUST be zero-behaviour."
        )
