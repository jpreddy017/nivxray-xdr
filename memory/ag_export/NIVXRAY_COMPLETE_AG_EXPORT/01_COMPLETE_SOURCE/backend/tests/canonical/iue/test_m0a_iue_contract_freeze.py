"""M0a · Freeze current IUE contract as stable projection (characterisation).

Per ADR-0014 · M0a — records the OBSERVABLE shape of
`services/die/input_understanding.InputUnderstanding` as of 2026-02-15.

Zero behavioural change. Every assertion locks a fact that is TRUE right
now against the un-modified codebase. If any of these fail later, either:
  a) an intentional migration ran (update the baseline + ADR entry), or
  b) an unintended drift occurred (regression).

Real M0a discoveries locked here (not fixed under M0a):
  1. `execution_trace` embeds measured wall-time (`ms` field), so
     `understand(execute=True)` is NOT byte-idempotent today. Everything
     else IS idempotent. This is a deliberate legacy debt captured for
     M0e/M0f attention — see ADR-0014 §18.6.
  2. IUE has 18 top-level fields (not 13 as ADR-0013 informally listed).
     The additional fields are `confidence_matrix, contents, decode_reason,
     engine_version, hero_sentence, label, next_engine, next_engine_reason`.
     ADR-0013 §2.2 is amended by this baseline.
  3. `overall_status` does NOT exist on the dataclass. The status live in
     `execution_trace[-1]` and each `plan[i].status`. ADR-0013 §2.2 informal
     mention is amended.
  4. `_engines_selected` / `_engines_skipped` take TWO parameters
     `(input_type, decode_required)` — ADR-0013 §2.2 documented only one.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict, fields
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.die.input_understanding import (   # noqa: E402
    InputUnderstanding,
    classify,
    understand,
    _next_engine,
    _engines_selected,
    _engines_skipped,
)


# ── 18 top-level fields as of 2026-02-15 ────────────────────────────────────
EXPECTED_TOP_LEVEL_FIELDS = {
    "input_type", "hero_sentence", "label", "confidence", "confidence_matrix",
    "reasoning", "contents",
    "decode_required", "decode_reason", "decode_layers",
    "next_engine", "next_engine_reason",
    "plan", "execution_trace",
    "engines_selected", "engines_skipped", "pipeline_flow",
    "engine_version",
}


def test_frozen_dataclass_top_level_fields():
    got = {f.name for f in fields(InputUnderstanding)}
    added   = got - EXPECTED_TOP_LEVEL_FIELDS
    removed = EXPECTED_TOP_LEVEL_FIELDS - got
    assert not added and not removed, (
        f"IUE contract drift — added: {sorted(added)}, removed: {sorted(removed)}. "
        f"See ADR-0014 §14 for the compat rule and §18.7 for the corrected count."
    )
    assert len(EXPECTED_TOP_LEVEL_FIELDS) == 18


# ── 21 input types × _next_engine labels ────────────────────────────────────
FROZEN_INPUT_TYPES = [
    "powershell_encoded", "powershell_naked", "nested_shell_chain",
    "command_chain", "single_command", "pe_file", "rtf_document",
    "office_ole", "pdf_document", "base64_blob", "hex_blob", "gzip_blob",
    "registry_export", "windows_event_log", "sysmon_log", "process_tree",
    "vendor_json", "vendor_report_text", "url_only", "plain_text", "unknown",
]


def test_frozen_input_types_and_next_engine_labels_exist():
    for t in FROZEN_INPUT_TYPES:
        label, reason = _next_engine(t)
        assert isinstance(label, str) and label
        assert isinstance(reason, str) and reason
    unknown_label, unknown_reason = _next_engine("__bogus__")
    assert unknown_label == "Preprocessor" and unknown_reason == "Default route."


# ── url_only plan omits URL Acquisition (locked defect · ADR-0014 M4) ───────
def test_url_only_plan_omits_url_acquisition_today():
    selected = _engines_selected("url_only", False)
    assert selected == ["IOC Enrichment", "Report Generator"], (
        f"url_only engine selection drifted from the baseline: {selected}. "
        f"Any change here MUST be a deliberate M4 migration (ADR-0014)."
    )
    skipped = _engines_skipped("url_only", False)
    # Locked SUBSET — these engines MUST be in the skipped list today.
    must_be_skipped = {
        "Decoder", "CRE (Command Reconstruction)", "Preprocessor",
        "DIE (Semantic AST)", "DKP (Decoder Knowledge Pack)",
        "Chain Analyzer", "Attack Intent", "Attack Story",
        "Investigation Confidence", "Artifact Intelligence",
    }
    missing = must_be_skipped - set(skipped)
    assert not missing, (
        f"url_only engines_skipped baseline drifted — missing: {sorted(missing)}"
    )


# ── Deterministic classify() witnesses — actual current behaviour ───────────
_CORPUS = [
    # (name, text, expected_input_type, expected_hero, expected_confidence)
    ("bare_url_medium_style",
     "https://systemweakness.com/some-report",
     "url_only", "URL", 0.98),
    ("powershell_naked",
     "powershell.exe -EncodedCommand SGVsbG8=",
     "powershell_naked", "PowerShell Command / Script", 0.9),
    ("plain_english_short",
     "the quick brown fox jumps over the lazy dog",
     "single_command", "Single Command", 0.8),
    ("hex_ratio_long",
     "4d5a" + "90" * 260,
     "base64_blob", "Base64 Blob (no wrapper)", 0.9),
]


@pytest.mark.parametrize(
    "name,text,expected_type,expected_hero,expected_conf",
    _CORPUS,
    ids=[c[0] for c in _CORPUS],
)
def test_classify_witness_locked(name, text, expected_type, expected_hero, expected_conf):
    input_type, hero, conf, reasoning = classify(text)
    assert input_type == expected_type, (
        f"[{name}] classify() drift: expected {expected_type!r}, got {input_type!r}"
    )
    assert hero == expected_hero
    assert conf == pytest.approx(expected_conf, abs=1e-6)
    assert isinstance(reasoning, list) and len(reasoning) >= 1


# ── execute=False leaves execution_trace empty ──────────────────────────────
def test_understand_execute_false_produces_no_trace():
    u = understand("https://example.org/", execute=False)
    d = asdict(u)
    assert d["execution_trace"] == [], (
        f"execute=False produced trace lines: {d['execution_trace']!r}. "
        f"IUE contract requires empty trace when plan is not executed."
    )


# ── execute=True idempotence — locked exclusion of timing fields ────────────
_TIMING_FIELDS = {"ms"}   # baseline: only `ms` in each plan/trace step varies


@pytest.mark.parametrize("text", [c[1] for c in _CORPUS])
def test_execute_true_idempotent_modulo_timing(text):
    """`understand(execute=True)` is idempotent EXCEPT for wall-time `ms` fields.

    This is a REAL M0a finding — the IUE embeds measured ms in each plan
    step. The proper fix (or explicit accept) belongs to M0e when the
    IUE-v3 contract is minted. For M0a we only record the fact.
    """
    def _strip_timing(obj):
        if isinstance(obj, list):
            return [_strip_timing(x) for x in obj]
        if isinstance(obj, dict):
            return {k: _strip_timing(v) for k, v in obj.items() if k not in _TIMING_FIELDS}
        return obj

    a = _strip_timing(asdict(understand(text, execute=True)))
    b = _strip_timing(asdict(understand(text, execute=True)))
    assert a == b, ("IUE non-determinism beyond timing detected — "
                     "the M0a idempotence baseline was violated.")


# ── Baseline snapshot ──────────────────────────────────────────────────────
_BASELINE_DIR  = Path(__file__).resolve().parent / "_baseline"
_BASELINE_FILE = _BASELINE_DIR / "inputs.json"


def test_baseline_snapshot_captured_and_stable():
    current = {}
    for name, text, _t, _h, _c in _CORPUS:
        input_type, hero, conf, reasoning = classify(text)
        current[name] = {
            "input_type": input_type,
            "hero":       hero,
            "confidence": round(conf, 4),
            "reasoning":  reasoning,
        }
    if not _BASELINE_FILE.exists():
        _BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        _BASELINE_FILE.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"Baseline captured at {_BASELINE_FILE} — re-run to lock.")
    baseline = json.loads(_BASELINE_FILE.read_text())
    assert current == baseline, (
        "IUE baseline drift.\n"
        f"BASELINE: {json.dumps(baseline, indent=2, sort_keys=True)}\n"
        f"CURRENT:  {json.dumps(current,  indent=2, sort_keys=True)}\n"
        "Update ADR-0014 and delete the baseline file if the drift is intentional."
    )


# ── Canonical enumeration of current IUE consumers (documentation-in-code) ──
def test_documented_iue_consumers():
    consumers = [
        ("frontend/src/pages/WorkspacePage.jsx",
         "reads input_type/hero_sentence/label/confidence/plan[]/execution_trace/"
         "engines_selected/engines_skipped/pipeline_flow"),
        ("backend/services/die/investigation_results.py",
         "reads input_type for narrative branching"),
        ("backend/services/die/canonical.py",
         "materialises plan[] + input_type into canonical envelope"),
        ("backend/canonical/iue/adapters/text_structure.py",
         "bridges services/die IUE into canonical/iue"),
        ("backend/routers/ops.py:2495",
         "stamps IUE onto cio.metadata.input_understanding (advisory only)"),
        ("backend/routers/auto_investigate.py:739",
         "advisory IUE stamp via the nivxforge IUE mirror"),
        ("backend/routers/die.py:62",
         "exposes /api/die/understand endpoint"),
        ("backend/routers/ops.py:2760",
         "exposes /api/understand endpoint (calls the OTHER IUE)"),
    ]
    assert len(consumers) == 8, "consumer inventory drift"
