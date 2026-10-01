"""NVKC replay harness — Phase D · Stage 1.

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN)
NVKC governance: /app/backend/nvkc/README.md

Replays every corpus sample through the frozen v1.1 pipeline and
asserts every field of `expected` matches. Attack Fingerprint hash
drift is a P0 regression identical to the Golden Corpus contract.

Design:
  • Input runs through the *same* pipeline the router runs — no
    special dispatchers. This is the whole point of NVKC: it
    exercises the real production stack.
  • Determinism is enforced: each sample is replayed twice, and the
    two runs must produce identical (fingerprint hash, terminal
    state, artifact types).
  • Baselines live inside each `*.nvkc.yaml`. Owner-initiated updates
    flip `--nvkc-update-baseline` on the CLI.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml

from services.artifact_intelligence import dispatch
from services.attack_fingerprint import emit_fingerprint
from services.cem import emit_cem
from services.confidence_provenance import emit_provenance
from services.recipe_planner import plan_and_execute
from services.recursive_child_pipeline import (
    process as rcp_process,
    flatten_for_correlation,
)

from nvkc.schema import NvkcSample, ExpectedOutputs


# ─────────────────────────────────────────────────────────────────────
# Replay engine
# ─────────────────────────────────────────────────────────────────────
def replay(sample: NvkcSample) -> Dict[str, Any]:
    """Run the sample through the frozen v1.1 pipeline exactly the
    same way the router does. Return a synthesised case doc plus the
    emitted CEM + Attack Fingerprint."""
    payload = sample.load_payload()

    # Two entry paths — mirrors the dual-entry contract (§8).
    if sample.input_kind == "text":
        text = payload.decode("utf-8", errors="replace")
        plan = plan_and_execute(text)
        routed = None
        if plan.binary_artifact and plan.binary_artifact.routed_analysis:
            routed = plan.binary_artifact.routed_analysis
        case = {
            "id": sample.slug,
            "input": text,
            "output": plan.canonical_output,
            "iedde": ({"binary_artifact": {"routed_analysis": routed}}
                      if routed else {}),
            "iedde_terminal_state": plan.terminal_state,
            "canonical_confidence": 100 if plan.terminal_state
                                    in ("canonical", "binary_artifact_recovered")
                                    else 0,
            "iocs": {}, "mitre": [],
            "chain": list(plan.final_techniques or []),
        }
    else:
        # Binary / file entry — dispatch through the Artifact Router.
        routed = dispatch(payload).to_dict()
        kids = rcp_process(routed)
        case = {
            "id": sample.slug,
            "input": payload[:200].hex(),
            "output": "",
            "iedde": {
                "binary_artifact": {"routed_analysis": routed},
                "recursive_children": flatten_for_correlation(kids),
            },
            "iedde_terminal_state": "binary_artifact_recovered",
            "canonical_confidence": 100,
            "iocs": {}, "mitre": [], "chain": [],
        }

    cem = emit_cem(case)
    case_with_cem = {**case, "cem": cem}
    fp = emit_fingerprint(case_with_cem)
    provenance = emit_provenance(case_with_cem)
    return {"case": case, "cem": cem, "fingerprint": fp,
            "provenance": provenance}


# ─────────────────────────────────────────────────────────────────────
# Actual vs expected comparison
# ─────────────────────────────────────────────────────────────────────
def _actual_outputs(replay_result: Dict[str, Any]) -> Dict[str, Any]:
    cem = replay_result["cem"]
    fp = replay_result["fingerprint"]
    case = replay_result["case"]
    prov = replay_result["provenance"]

    # artifact types — walk canonical_artifacts + child_artifacts.
    types: Set[str] = set()
    for a in cem.get("canonical_artifacts") or []:
        t = a.get("type")
        if t and t != "text/plain":
            types.add(t)
    for c in cem.get("child_artifacts") or []:
        rt = c.get("routed_artifact_type")
        if rt:
            types.add(rt)

    # Analyst Decision Benchmark fields.
    timeline = [[str(ev.get("kind") or ""), str(ev.get("code") or "")]
                for ev in cem.get("events") or [] if isinstance(ev, dict)]
    parent = "root"
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("kind") == "binary_artifact":
            parent = str(a.get("type") or "root")
            break
    attack_chain = sorted({
        f"{parent}->{c.get('type') or ''}"
        for c in cem.get("child_artifacts") or [] if isinstance(c, dict)
    })

    return {
        "terminal_state":          case.get("iedde_terminal_state"),
        "artifact_types":          sorted(types),
        "mitre":                   sorted({m["id"].upper() for m in cem.get("mitre") or []
                                           if isinstance(m, dict) and m.get("id")}),
        "attack_fingerprint_hash": fp.get("hash"),
        "behavior_codes":          sorted({ev.get("code") for ev in cem.get("events") or []
                                           if isinstance(ev, dict)
                                           and ev.get("kind") == "analyzer.finding"
                                           and ev.get("code")}),
        "ioc_kinds":               sorted({i.get("kind") for i in cem.get("indicators") or []
                                           if isinstance(i, dict) and i.get("kind")}),
        "provenance_hash":         prov.get("provenance_hash"),
        "derived_verdict":         (prov.get("derived") or {}).get("verdict"),
        "derived_risk_score":      (prov.get("derived") or {}).get("risk_score"),
        "timeline":                timeline,
        "attack_chain":            attack_chain,
    }


def diff_expected(sample: NvkcSample, actual: Dict[str, Any]) -> List[str]:
    exp = sample.expected
    diffs: List[str] = []

    if exp.terminal_state and actual["terminal_state"] != exp.terminal_state:
        diffs.append(f"terminal_state: expected {exp.terminal_state!r}, "
                     f"got {actual['terminal_state']!r}")
    if exp.artifact_types and actual["artifact_types"] != exp.artifact_types:
        diffs.append(f"artifact_types: expected {exp.artifact_types}, "
                     f"got {actual['artifact_types']}")
    if exp.mitre and actual["mitre"] != exp.mitre:
        diffs.append(f"mitre: expected {exp.mitre}, got {actual['mitre']}")
    if exp.behavior_codes and actual["behavior_codes"] != exp.behavior_codes:
        diffs.append(f"behavior_codes: expected {exp.behavior_codes}, "
                     f"got {actual['behavior_codes']}")
    if exp.ioc_kinds and actual["ioc_kinds"] != exp.ioc_kinds:
        diffs.append(f"ioc_kinds: expected {exp.ioc_kinds}, got {actual['ioc_kinds']}")
    if exp.attack_fingerprint_hash \
            and actual["attack_fingerprint_hash"] != exp.attack_fingerprint_hash:
        diffs.append(
            f"attack_fingerprint_hash DRIFT — P0 gate\n"
            f"  expected: {exp.attack_fingerprint_hash}\n"
            f"  actual:   {actual['attack_fingerprint_hash']}")
    # ── Analyst Decision Benchmark ──
    if exp.provenance_hash \
            and actual["provenance_hash"] != exp.provenance_hash:
        diffs.append(
            f"provenance_hash DRIFT — P0 gate (Confidence Provenance)\n"
            f"  expected: {exp.provenance_hash}\n"
            f"  actual:   {actual['provenance_hash']}")
    if exp.derived_verdict and actual["derived_verdict"] != exp.derived_verdict:
        diffs.append(f"derived_verdict: expected {exp.derived_verdict!r}, "
                     f"got {actual['derived_verdict']!r}")
    if exp.derived_risk_score is not None \
            and actual["derived_risk_score"] != exp.derived_risk_score:
        diffs.append(f"derived_risk_score: expected {exp.derived_risk_score}, "
                     f"got {actual['derived_risk_score']}")
    if exp.timeline and actual["timeline"] != exp.timeline:
        diffs.append(f"timeline mismatch: expected {exp.timeline}, "
                     f"got {actual['timeline']}")
    if exp.attack_chain and actual["attack_chain"] != exp.attack_chain:
        diffs.append(f"attack_chain: expected {exp.attack_chain}, "
                     f"got {actual['attack_chain']}")
    return diffs


# ─────────────────────────────────────────────────────────────────────
# Baseline update
# ─────────────────────────────────────────────────────────────────────
def update_baseline_yaml(sample: NvkcSample, actual: Dict[str, Any]) -> None:
    """Rewrite the sample's `.nvkc.yaml` with the current actual output
    as the new baseline. Owner-only operation (invoked via the pytest
    flag `--nvkc-update-baseline`)."""
    doc = yaml.safe_load(sample.descriptor_path.read_text(encoding="utf-8")) or {}
    exp = doc.setdefault("expected", {})
    exp["terminal_state"]          = actual["terminal_state"]
    exp["artifact_types"]          = actual["artifact_types"]
    exp["mitre"]                   = actual["mitre"]
    exp["attack_fingerprint_hash"] = actual["attack_fingerprint_hash"]
    exp["behavior_codes"]          = actual["behavior_codes"]
    exp["ioc_kinds"]               = actual["ioc_kinds"]
    # Analyst Decision Benchmark
    exp["provenance_hash"]    = actual["provenance_hash"]
    exp["derived_verdict"]    = actual["derived_verdict"]
    exp["derived_risk_score"] = actual["derived_risk_score"]
    exp["timeline"]           = actual["timeline"]
    exp["attack_chain"]       = actual["attack_chain"]
    sample.descriptor_path.write_text(
        yaml.safe_dump(doc, sort_keys=True, default_flow_style=False),
        encoding="utf-8")


__all__ = ["replay", "_actual_outputs", "diff_expected", "update_baseline_yaml"]
