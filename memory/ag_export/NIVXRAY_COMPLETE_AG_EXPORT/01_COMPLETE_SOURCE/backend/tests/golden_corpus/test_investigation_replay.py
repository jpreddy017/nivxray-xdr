"""Golden Investigation Replay Harness — Phase 4 · P6.

Master architecture reference: `/app/memory/ARCHITECTURE.md` §10.

Every release replays the Golden Investigation Corpus and verifies each
entry produces byte-identical fingerprints. Any drift is a P0 release
blocker.

Fingerprint captured per entry (from the *canonical* pipeline, not from
raw analyzer output):

    {
        "cem_version":       str,
        "convergence":       {"reached": bool, "terminal_state": str},
        "artifact_types":    sorted list[str],
        "mitre_ids":         sorted list[str],
        "canonical_hashes":  sorted list[sha256],
        "event_kinds":       sorted list[str],
        "indicator_counts":  dict[kind→int],
        "signature_shape":   dict of keys (not values — values would
                             leak per-run state; we assert structural
                             stability here, plus a determinism check
                             within the same run).
    }

The harness runs the same entry twice in the same run and asserts the
two runs produce identical fingerprints — this catches non-determinism
introduced by refactors (wall-clock, dict ordering, randomness) even
when no baseline exists yet.

To update baselines after an intentional architectural change:
    pytest tests/golden_corpus/ --update-baseline
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
from typing import Any, Dict, List

import pytest

try:
    import yaml
except ImportError:                            # pragma: no cover
    yaml = None                                # noqa

from services.recipe_planner import plan_and_execute
from services.artifact_intelligence import dispatch
from services.cem import emit_cem
from services.attack_fingerprint import emit_fingerprint
from services.recursive_child_pipeline import process as recursive_process
from services.correlation_engine import build_evidence_signature


CORPUS_DIR = pathlib.Path(__file__).parent
MANIFEST_PATH = CORPUS_DIR / "manifest.yaml"
SAMPLES_DIR = CORPUS_DIR / "samples"
BASELINES_DIR = CORPUS_DIR / "baselines"


def pytest_addoption(parser):
    """Local option — also registered in conftest.py for pytest discovery.
    The duplicate is harmless (pytest reuses the existing definition) and
    keeps the top-of-file docstring's usage instruction accurate."""
    try:
        parser.addoption("--update-baseline", action="store_true", default=False,
                         help="Overwrite golden baselines with current fingerprints")
    except ValueError:
        # Already registered by conftest.py — fine.
        pass


# =====================================================================
# Manifest loading
# =====================================================================
def _load_manifest() -> List[Dict[str, Any]]:
    if yaml is None:
        pytest.skip("PyYAML not installed — cannot load Golden Corpus manifest")
    if not MANIFEST_PATH.exists():
        return []
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f) or {}
    return list(data.get("entries") or [])


ENTRIES = _load_manifest()


# =====================================================================
# Investigation execution — the "replay" step
# =====================================================================
def _run_investigation(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Push a golden entry through the same pipeline analysts use.

    Returns the synthesized case doc + CEM + evidence signature so the
    fingerprint step below can compress everything into a
    determinism-preserving dict.
    """
    sample_path = SAMPLES_DIR / os.path.basename(entry["sample"])
    if not sample_path.exists():
        pytest.skip(f"sample file missing: {sample_path}")

    source_kind = entry["source_kind"]
    routed = None
    recursive = []
    plan = None

    if source_kind == "file_upload":
        raw = sample_path.read_bytes()
        routed = dispatch(raw).to_dict()
        recursive = recursive_process(routed, depth=0)
        case = {
            "id": entry["slug"],
            "input": raw[:200].hex(),          # short deterministic marker
            "output": "",
            "iedde": {"binary_artifact": {
                "routed_analysis": routed,
                "recursive_children": _flatten(recursive),
            }},
            "iedde_terminal_state": "binary_artifact_recovered",
            "canonical_confidence": 100,
            "iocs": {}, "mitre": [], "chain": [],
        }
    elif source_kind == "workspace_input":
        text = sample_path.read_text(encoding="utf-8", errors="replace")
        plan = plan_and_execute(text)
        canonical = (plan.canonical_output or "")

        # Prefer the RTE's own recovered binary artifact (P2.3c). The
        # RTE hands off recovered binaries via `plan.binary_artifact`
        # once decoding reaches `binary_artifact_recovered`. Otherwise
        # fall back to a best-effort re-dispatch on the canonical
        # bytes so text-only wrappers still surface a routed analysis.
        routed = None
        if plan.binary_artifact and plan.binary_artifact.routed_analysis:
            routed = plan.binary_artifact.routed_analysis
        else:
            try:
                canonical_bytes = canonical.encode("latin-1", errors="ignore")
            except Exception:
                canonical_bytes = canonical.encode("utf-8", errors="ignore")
            if len(canonical_bytes) >= 4:
                try:
                    routed = dispatch(canonical_bytes).to_dict()
                except Exception:
                    routed = None
        case = {
            "id": entry["slug"],
            "input": text,
            "output": canonical,
            "iedde": ({"binary_artifact": {"routed_analysis": routed}}
                      if routed and routed.get("artifact_type") != "unknown"
                      else {}),
            "iedde_terminal_state": (plan.terminal_state
                                     if plan else "canonical"),
            "canonical_confidence": 100,
            "iocs": {}, "mitre": [], "chain": list(plan.final_techniques or []),
        }
    else:
        pytest.fail(f"unknown source_kind: {source_kind!r}")

    cem = emit_cem(case)
    sig = build_evidence_signature(case)
    # ▲ Phase A · Attack Fingerprint stability guard. The fingerprint
    # is emitted from the case (which now carries `cem` inline) so it
    # can flow through the same replay contract as the CEM fingerprint.
    case_with_cem = {**case, "cem": cem}
    attack_fp = emit_fingerprint(case_with_cem)
    return {"routed": routed, "recursive": recursive,
            "cem": cem, "signature": sig,
            "attack_fingerprint": attack_fp,
            "plan_terminal": getattr(plan, "terminal_state", None) if plan else None}


def _fingerprint(entry: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """Compress an investigation result into a determinism-preserving
    fingerprint. See module docstring for the exact schema."""
    cem = result["cem"]
    sig = result["signature"]
    artifact_types: set = set()
    if result["routed"]:
        atype = result["routed"].get("artifact_type")
        if atype:
            artifact_types.add(atype)
    for r in result["recursive"]:
        if r.get("routed_analysis"):
            at = r["routed_analysis"].get("artifact_type")
            if at:
                artifact_types.add(at)
    canonical_hashes = sorted({
        (a.get("sha256") or "") for a in cem["canonical_artifacts"]
        if a.get("sha256")
    })
    event_kinds = sorted({ev["kind"] for ev in cem["events"]})
    ind_counts: Dict[str, int] = {}
    for ind in cem["indicators"]:
        ind_counts[ind["kind"]] = ind_counts.get(ind["kind"], 0) + 1
    return {
        "cem_version":       cem["cem_version"],
        "convergence": {
            "reached":        cem["convergence"]["reached"],
            "terminal_state": cem["convergence"]["terminal_state"],
        },
        "artifact_types":    sorted(artifact_types),
        "mitre_ids":         sorted({m["id"] for m in cem["mitre"]}),
        "canonical_hashes":  canonical_hashes,
        "event_kinds":       event_kinds,
        "indicator_counts":  ind_counts,
        "signature_shape":   sorted(sig.keys()),
    }


def _fingerprint_hash(fp: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(fp, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# =====================================================================
# Contract assertions
# =====================================================================
def _assert_contract(entry: Dict[str, Any], result: Dict[str, Any]):
    fp = _fingerprint(entry, result)
    # 1 · Expected artifact types must all appear
    for expected in entry.get("expected_artifact_types") or []:
        assert expected in fp["artifact_types"], (
            f"[{entry['slug']}] expected artifact_type '{expected}' not "
            f"in {fp['artifact_types']}")
    # 2 · Expected MITRE techniques must all appear
    for expected in entry.get("expected_min_mitre") or []:
        assert expected in fp["mitre_ids"], (
            f"[{entry['slug']}] expected MITRE '{expected}' not in "
            f"{fp['mitre_ids']}")
    # 3 · Terminal state (workspace_input entries)
    ets = entry.get("expected_terminal_state")
    if ets:
        assert result.get("plan_terminal") == ets, (
            f"[{entry['slug']}] expected terminal_state={ets!r}, got "
            f"{result.get('plan_terminal')!r}")


def _assert_deterministic(entry: Dict[str, Any]):
    r1 = _run_investigation(entry)
    r2 = _run_investigation(entry)
    fp1 = _fingerprint(entry, r1)
    fp2 = _fingerprint(entry, r2)
    assert fp1 == fp2, (
        f"[{entry['slug']}] NON-DETERMINISTIC — the same golden "
        f"investigation produced two different fingerprints in one run "
        f"— this is a P0 architectural regression.\n"
        f"first  = {fp1}\nsecond = {fp2}")
    # Attack Fingerprint must also be deterministic across the same run.
    assert r1["attack_fingerprint"].get("hash") == r2["attack_fingerprint"].get("hash"), (
        f"[{entry['slug']}] NON-DETERMINISTIC Attack Fingerprint — "
        f"same investigation produced two different hashes:\n"
        f"first  = {r1['attack_fingerprint'].get('hash')}\n"
        f"second = {r2['attack_fingerprint'].get('hash')}")
    return r1, fp1


def _assert_baseline(entry: Dict[str, Any], fp: Dict[str, Any],
                     attack_fp: Dict[str, Any],
                     *, update: bool):
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    baseline_path = BASELINES_DIR / f"{entry['slug']}.json"
    fp_hash = _fingerprint_hash(fp)
    # Attack Fingerprint stability guard — independent hash so drift
    # in the analytical consumer surfaces separately from CEM drift.
    attack_hash = attack_fp.get("hash")
    if update or not baseline_path.exists():
        payload = {
            "fingerprint":            fp,
            "fingerprint_hash":       fp_hash,
            "attack_fingerprint":     attack_fp,
            "attack_fingerprint_hash": attack_hash,
        }
        baseline_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        if not baseline_path.exists():
            pytest.fail(f"[{entry['slug']}] wrote initial baseline but "
                        f"file still missing: {baseline_path}")
        return
    baseline = json.loads(baseline_path.read_text())
    expected = baseline.get("fingerprint")
    expected_hash = baseline.get("fingerprint_hash")
    assert fp_hash == expected_hash, (
        f"[{entry['slug']}] GOLDEN INVESTIGATION DRIFT (P0 release blocker)\n"
        f"  baseline: {baseline_path}\n"
        f"  expected fingerprint = {expected}\n"
        f"  current  fingerprint = {fp}\n"
        f"If this drift is intentional, re-run with --update-baseline "
        f"after owner review.")
    # Attack Fingerprint drift is also a P0 gate.
    expected_attack = baseline.get("attack_fingerprint_hash")
    assert attack_hash == expected_attack, (
        f"[{entry['slug']}] ATTACK FINGERPRINT DRIFT (P0 release blocker)\n"
        f"  baseline: {baseline_path}\n"
        f"  expected attack_fingerprint_hash = {expected_attack}\n"
        f"  current  attack_fingerprint_hash = {attack_hash}\n"
        f"If this drift is intentional, re-run with --update-baseline "
        f"after owner review.")


# =====================================================================
# Pytest parametrisation
# =====================================================================
@pytest.mark.parametrize(
    "entry",
    ENTRIES,
    ids=[e["slug"] for e in ENTRIES] if ENTRIES else [],
)
def test_golden_investigation_replay(entry, request):
    if not ENTRIES:
        pytest.skip("Golden corpus manifest is empty")
    # 1 · Determinism: same run, same fingerprint (twice).
    result, fp = _assert_deterministic(entry)
    # 2 · Contract: expected artifact types + MITRE + terminal state
    _assert_contract(entry, result)
    # 3 · Baseline: CEM fingerprint hash + Attack Fingerprint hash
    #     both match the committed baseline.
    _assert_baseline(entry, fp, result["attack_fingerprint"],
                     update=request.config.getoption("--update-baseline"))


# =====================================================================
# Helper
# =====================================================================
def _flatten(children, acc=None):
    if acc is None:
        acc = []
    for c in children or []:
        acc.append({
            "type":    c.get("type"),
            "label":   c.get("label"),
            "snippet": c.get("snippet"),
            "hash":    c.get("hash"),
            "depth":   c.get("depth"),
        })
        _flatten(c.get("children") or [], acc)
    return acc
