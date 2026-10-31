"""Golden Fixture Framework · RC3.2a runner.

Auto-discovers every ``tests/fixtures/plugin_regression/<plugin_id>.jsonl``
file and yields one parametrised pytest case per line. See the README
next to the fixture files for the schema.

Design principles:

* One test per case_id — pytest emits a self-describing id like
  ``base64-decode[b64-plain-cmd]`` so a regression names itself.
* Failure messages carry the case_id + description so the analyst knows
  which corpus entry regressed without digging.
* Zero orchestrator involvement — the plugin is invoked in isolation via
  the ``DecoderRegistry`` handle. Chain-level assertions live in
  ``rc23_benchmark`` / ``rc30_baseline`` where they belong.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import pytest

import decoders  # noqa: F401 — plugin auto-discovery side-effect
from engine.fingerprint_util import compute as _fp_compute
from engine.models import AnalysisContext, Budget
from engine.registry import DecoderRegistry

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "plugin_regression"


def _iter_fixtures() -> Iterable[Tuple[str, Dict[str, Any]]]:
    if not FIXTURE_DIR.exists():
        return
    for path in sorted(FIXTURE_DIR.glob("*.jsonl")):
        plugin_id = path.stem
        # RC3.4 · prod-cases.jsonl is a special "end-to-end regression"
        # bucket populated by tools/ir_export_to_fixture.py. Each entry
        # runs through the full Orchestrator instead of a single plugin.
        # The runner detects this via the reserved stem "prod-cases".
        if plugin_id == "prod-cases":
            for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:            # pragma: no cover
                    raise AssertionError(
                        f"{path.name}:{lineno} — invalid JSON: {exc}"
                    ) from exc
                entry.setdefault("case_id", f"line{lineno}")
                entry["_source_path"] = str(path)
                entry["_source_line"] = lineno
                entry["_end_to_end"] = True
                yield "_orchestrator_", entry
            continue
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:                # pragma: no cover
                raise AssertionError(
                    f"{path.name}:{lineno} — invalid JSON: {exc}"
                ) from exc
            entry.setdefault("case_id", f"line{lineno}")
            entry["_source_path"] = str(path)
            entry["_source_line"] = lineno
            yield plugin_id, entry


def _fixture_ids(item):
    if isinstance(item, str):
        return item
    return item.get("case_id", "?")


_ALL_FIXTURES = list(_iter_fixtures())


@pytest.mark.parametrize(
    ("plugin_id", "fixture"),
    _ALL_FIXTURES if _ALL_FIXTURES else [pytest.param("_none_", {"case_id": "no-fixtures"}, marks=pytest.mark.skip(reason="no plugin_regression fixtures on disk"))],
    ids=lambda x: _fixture_ids(x),
)
def test_plugin_golden_fixture(plugin_id: str, fixture: Dict[str, Any]) -> None:
    case_id = fixture.get("case_id", "?")
    desc = fixture.get("description", "")
    src = f"{fixture.get('_source_path','?')}:{fixture.get('_source_line','?')} ({case_id})"

    # RC3.4 · end-to-end prod-case regression path.
    if fixture.get("_end_to_end"):
        from engine import Orchestrator
        payload = fixture["input"]
        ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
        r = Orchestrator(ctx).run(payload)
        f = r.findings
        # Verdict floor
        exp_verdict = fixture.get("expected_verdict")
        if exp_verdict and exp_verdict != "unknown":
            order = {"unknown": 0, "needs_review": 1, "suspicious": 2, "malicious": 3}
            assert order.get(f.verdict, 0) >= order.get(exp_verdict, 0), (
                f"{src} — verdict downgrade: expected ≥ {exp_verdict!r} got {f.verdict!r}"
            )
        risk_min = int(fixture.get("expected_risk_min", 0))
        assert f.risk_score >= risk_min, (
            f"{src} — risk_score {f.risk_score} < floor {risk_min}"
        )
        # Chain-layer floor
        chain_min = int(fixture.get("expected_chain_layers_min", 0))
        assert len(r.trace) >= chain_min, (
            f"{src} — only {len(r.trace)} layer(s), expected ≥ {chain_min}"
        )
        # MITRE / LOLBAS / family
        mitre_ids = {h.id for h in f.mitre_techniques}
        for tid in fixture.get("expected_mitre", []) or []:
            assert tid in mitre_ids, f"{src} — expected MITRE {tid} lost (got {sorted(mitre_ids)})"
        lolbas = {h.binary.lower() for h in f.lolbas}
        for b in fixture.get("expected_lolbas_binaries", []) or []:
            assert b.lower() in lolbas, f"{src} — expected LOLBAS {b!r} lost"
        exp_fam = fixture.get("expected_family")
        if exp_fam and exp_fam != "unknown":
            assert f.family.family == exp_fam, (
                f"{src} — family drift: expected {exp_fam!r} got {f.family.family!r}"
            )
            floor_fam = float(fixture.get("expected_family_min_confidence", 0.5))
            assert f.family.confidence >= floor_fam, (
                f"{src} — family conf {f.family.confidence:.2f} < {floor_fam}"
            )
        return

    plugin = DecoderRegistry.get(plugin_id)
    assert plugin is not None, f"{src} — plugin {plugin_id!r} not registered"

    payload = fixture["input"]
    args = fixture.get("args") or {}

    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    fp = _fp_compute(payload)

    # ---- detect() gate ------------------------------------------------
    dr = plugin.detect(payload, fp, ctx)
    floor = float(fixture.get("detect_min_confidence", 0.5))
    assert dr.confidence >= floor, (
        f"{src} — detect() returned confidence {dr.confidence:.3f} < floor {floor}: "
        f"reason={dr.why!r} · desc={desc!r}"
    )

    # ---- decode() runs -----------------------------------------------
    r = plugin.decode(payload, args, ctx)
    out = r.output or ""
    must_produce = fixture.get("must_produce_output", True)
    if must_produce:
        assert out, f"{src} — decode() produced empty output (expected non-empty)"
    else:
        # Refuse-case: any output should be empty AND notes should say "Refused"
        assert not out, (
            f"{src} — refuse-case expected empty output but got "
            f"{len(out)} chars: {out[:120]!r}"
        )

    # ---- exact / substring match -------------------------------------
    if "expected_output" in fixture:
        assert out == fixture["expected_output"], (
            f"{src} — output mismatch:\n"
            f"  expected: {fixture['expected_output']!r}\n"
            f"  got:      {out!r}"
        )
    for token in fixture.get("expected_output_contains", []) or []:
        assert token in out, (
            f"{src} — expected substring {token!r} not in output "
            f"(first 200 chars): {out[:200]!r}"
        )

    # ---- MITRE subset -----------------------------------------------
    mitre_ids = {hint.id for hint in (r.mitre_hints or [])}
    for tid in fixture.get("expected_mitre", []) or []:
        assert tid in mitre_ids, (
            f"{src} — expected MITRE {tid} not emitted (got {sorted(mitre_ids)})"
        )

    # ---- Tradecraft subset ------------------------------------------
    tc_flags = {tc.flag for tc in (r.tradecraft or [])}
    for flag in fixture.get("expected_tradecraft", []) or []:
        assert flag in tc_flags, (
            f"{src} — expected tradecraft flag {flag!r} not emitted (got {sorted(tc_flags)})"
        )

    # ---- LOLBAS subset ----------------------------------------------
    lolbas_bins = {h.binary.lower() for h in (r.lolbas_hits or [])}
    for b in fixture.get("expected_lolbas_binaries", []) or []:
        assert b.lower() in lolbas_bins, (
            f"{src} — expected LOLBAS binary {b!r} not emitted (got {sorted(lolbas_bins)})"
        )

    # ---- Family-hint check (intelligence plugins) --------------------
    # Family plugins emit `family_hints` with a canonical family name +
    # confidence in the decode() pass. Their detect() confidence is
    # intentionally low (see FamilyPlugin base class), so the fixture
    # opts into a stronger post-decode assertion here.
    exp_family = fixture.get("expected_family")
    if exp_family:
        family_names = [h.family for h in (r.family_hints or [])]
        assert exp_family in family_names, (
            f"{src} — expected family {exp_family!r} not in family_hints "
            f"(got {family_names})"
        )
        floor_fam = float(fixture.get("expected_family_min_confidence", 0.5))
        hit = next(h for h in r.family_hints if h.family == exp_family)
        assert hit.confidence >= floor_fam, (
            f"{src} — family {exp_family!r} confidence {hit.confidence:.2f} < "
            f"floor {floor_fam}"
        )


def test_every_registered_plugin_has_fixture_file():
    """Discoverability lock — the moment we ship a new plugin it MUST land
    with a paired ``<plugin_id>.jsonl`` in ``plugin_regression/``. Skips
    intelligence-only plugins (family / lolbas matchers) and grandfathered
    plugins listed in ``_EXEMPT`` while backfill lands."""
    _EXEMPT = {
        # Intelligence-only plugins with no direct byte transform (they
        # emit findings on the input verbatim). Chain-level tests cover them.
        "ioc-extractor", "crypto-detect", "family-agenttesla",
        "family-asyncrat", "family-cobaltstrike", "family-darkgate",
        "family-lumma", "family-meterpreter", "family-quasarrat",
        "family-remcos", "family-snake-keylogger",
        # Key-required crypto plugins — the enriched schema in RC3.2c
        # already exercises them.
        "aes-cbc-decrypt", "rc4-decrypt",
    }
    # Skip the reserved end-to-end bucket
    fixture_files = {p.stem for p in FIXTURE_DIR.glob("*.jsonl") if p.stem != "prod-cases"}
    registered = {d.id for d in DecoderRegistry.all()}
    missing = registered - fixture_files - _EXEMPT
    assert not missing, (
        "Every registered decoder must have a paired fixture file. "
        f"Missing: {sorted(missing)}"
    )
