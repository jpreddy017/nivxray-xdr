"""3-way Verdict Engine Parity Snapshot · ADR-004 Step 1 gate.

Per ADR-004 §1, THREE verdict engines coexist today:

  A.  `backend/v2/verdict/engine.py::score(event, ctx)`         (CANONICAL, not wired)
  B.  `nivxforge/investigation/verdict_engine.py::compute_verdict(graph, meta)`
  C.  `services/uaie/orchestrator.py` (verdict signals via evidence)

Each has a **different input contract** — the engines cannot be
called with a uniform payload. This suite therefore:

  1. Feeds each of the 14 pinned Vendor Corpus v1 fixtures to every
     engine via its NATIVE contract (with a per-engine adapter).
  2. Captures verdict / band / confidence / label PER (fixture × engine)
     as a deterministic JSON snapshot.
  3. Writes the snapshot to
     `backend/corpus/vendor/v1/reports/baseline_verdict_engine_parity.json`.
  4. Asserts only that every engine returned SOME result for every
     fixture (or an explicit "error" record) — this is the "capture
     the divergence honestly" contract, not an agreement gate.

The snapshot becomes the parity gate for ADR-004 Step 1 (Verdict
Engine consolidation): post-migration outputs are diffed against this
baseline to distinguish `preserved / fixed / introduced` behaviour.

NOTE: This test does NOT wire the v2 engine into any production
router. It only invokes it in-process for measurement.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1


# ── Snapshot destination ──────────────────────────────────────────
_SNAPSHOT_PATH = (
    Path(__file__).resolve().parent.parent
    / "corpus" / "vendor" / "v1" / "reports"
    / "baseline_verdict_engine_parity.json"
)


# ══════════════════════════════════════════════════════════════════
# Per-engine adapters (best-effort, capture-honest)
# ══════════════════════════════════════════════════════════════════

def _run_engine_a_v2(fixture) -> Dict[str, Any]:
    """v2/verdict/engine.py — `score(event, ctx)`.

    Contract: event is an arbitrary dict, ctx is optional.
    We flatten the fixture's commands into a single event with a
    `command` field per command, and aggregate the max score.
    """
    try:
        from v2.verdict.engine import score
    except Exception as e:
        return {"engine": "v2", "error": f"import: {type(e).__name__}: {e!s}"}

    per_command: List[Dict[str, Any]] = []
    try:
        for cmd in fixture.commands:
            event = {
                "command":       cmd,
                "process":       {"cmdline": cmd},
                "input_text":    cmd,
                "artifacts":     [{"type": "command", "value": cmd}],
            }
            v = score(event, ctx={"fixture_id": fixture.fixture_id})
            per_command.append({
                "command":     cmd[:80],
                "score":       int(v.score),
                "band":        str(v.band),
                "explanation": v.explanation[:200],
                "n_signals":   len(v.breakdown),
            })
    except Exception as e:
        return {"engine": "v2", "error": f"{type(e).__name__}: {e!s}",
                    "per_command": per_command}

    max_score = max((r["score"] for r in per_command), default=0)
    top_band  = next((r["band"] for r in per_command
                          if r["score"] == max_score), "clean")
    return {
        "engine":      "v2",
        "max_score":    max_score,
        "band":         top_band,
        "n_commands":   len(per_command),
        "per_command":  per_command,
    }


def _build_evidence_graph_for(fixture) -> Any:
    """Deterministically build an EvidenceGraph for a fixture:
    one artifact node + one lolbin node per command head."""
    from nivxforge.investigation.graph import EvidenceGraph, Node, Edge

    g = EvidenceGraph()
    art = Node(id="N-001", kind="artifact",
                   label=f"fixture {fixture.fixture_id}",
                   value=" ; ".join(fixture.commands),
                   confidence=0.9, provenance="parity.test")
    g.add_node(art)

    for i, cmd in enumerate(fixture.commands, start=1):
        head = (cmd or "").split(None, 1)[0].split("\\")[-1]
        head = head.split(".")[0].lower() if head else "unknown"
        nid = f"N-{i+1:03d}"
        n = Node(id=nid, kind="lolbin",
                     label=head, value=head,
                     confidence=0.8, provenance="parity.test")
        g.add_node(n)
        g.add_edge(Edge(source=art.id, target=nid,
                             kind="produces", weight=1.0))
    return g


def _run_engine_b_nivxforge(fixture) -> Dict[str, Any]:
    """nivxforge/investigation/verdict_engine.py — `compute_verdict(graph, meta)`."""
    try:
        from nivxforge.investigation.verdict_engine import compute_verdict
    except Exception as e:
        return {"engine": "nivxforge", "error": f"import: {type(e).__name__}: {e!s}"}

    try:
        graph = _build_evidence_graph_for(fixture)
        meta = {
            "input_text_normalised": "\n".join(fixture.commands),
            "fixture_id":            fixture.fixture_id,
        }
        v = compute_verdict(graph, meta)
        contribs = getattr(v, "contributors", []) or []
        return {
            "engine":         "nivxforge",
            "label":          getattr(v, "label", None),
            "confidence":     round(float(getattr(v, "confidence", 0.0)), 4),
            "confidence_pct": int(getattr(v, "confidence_pct", 0) or 0),
            "reason":         (getattr(v, "reason", "") or "")[:200],
            "n_contributors": len(contribs),
            "n_not_counted":  len(getattr(v, "not_counted", []) or []),
        }
    except Exception as e:
        return {"engine": "nivxforge",
                    "error": f"{type(e).__name__}: {e!s}"}


def _run_engine_c_uaie(fixture) -> Dict[str, Any]:
    """UAIE orchestrator — extract verdict-relevant signals from evidence."""
    try:
        from services.uaie.orchestrator import Orchestrator
    except Exception as e:
        return {"engine": "uaie", "error": f"import: {type(e).__name__}: {e!s}"}

    try:
        # Feed the concatenated command block as a plain paste.
        payload = "\n".join(fixture.commands).encode("utf-8", errors="replace")
        orch = Orchestrator()
        res = orch.run(payload, root_type="unknown")

        evidence   = list(getattr(res, "evidence",  []) or [])
        artifacts  = dict(getattr(res, "artifacts", {}) or {})
        warnings   = list(getattr(res, "warnings",  []) or [])

        # Verdict-adjacent signals in evidence records:
        verdict_signals = 0
        mitre_hits: set = set()
        for ev in evidence:
            d = ev if isinstance(ev, dict) else getattr(ev, "__dict__", {}) or {}
            if any(k in d for k in ("verdict", "verdict_signal",
                                             "score", "risk")):
                verdict_signals += 1
            for k in ("mitre", "attack", "technique_id"):
                v = d.get(k)
                if isinstance(v, str) and v.startswith("T"):
                    mitre_hits.add(v)
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, str) and x.startswith("T"):
                            mitre_hits.add(x)
                        elif isinstance(x, dict) and isinstance(x.get("id"), str):
                            mitre_hits.add(x["id"])
        return {
            "engine":          "uaie",
            "n_artifacts":     len(artifacts),
            "n_evidence":      len(evidence),
            "n_warnings":      len(warnings),
            "verdict_signals": verdict_signals,
            "mitre_count":     len(mitre_hits),
        }
    except Exception as e:
        return {"engine": "uaie", "error": f"{type(e).__name__}: {e!s}"}


# ══════════════════════════════════════════════════════════════════
# Test — capture the 3-way parity snapshot
# ══════════════════════════════════════════════════════════════════
def test_verdict_engine_3way_parity_snapshot():
    """Capture the pre-migration behaviour of the 3 verdict engines
    on all 14 pinned Vendor Corpus v1 fixtures. Writes an authoritative
    snapshot that ADR-004 Step 1 will diff against post-migration."""
    entries: List[Dict[str, Any]] = []
    for f in VENDOR_CORPUS_V1:
        entries.append({
            "fixture_id":    f.fixture_id,
            "vendor":        f.vendor,
            "article_title": f.article_title,
            "commands":      list(f.commands),
            "engines": {
                "v2":        _run_engine_a_v2(f),
                "nivxforge": _run_engine_b_nivxforge(f),
                "uaie":      _run_engine_c_uaie(f),
            },
        })

    snapshot = {
        "schema_version":  "1.0",
        "purpose":         "ADR-004 Step 1 verdict-engine parity gate",
        "capture_kind":    "faithful pre-migration snapshot",
        "corpus_id":       "vendor-v1",
        "fixture_count":   len(entries),
        "engines_probed":  ["v2", "nivxforge", "uaie"],
        "entries":         entries,
    }
    _SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SNAPSHOT_PATH.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True))

    # Invariants — capture-honest, not agreement-gated:
    assert _SNAPSHOT_PATH.exists()
    assert snapshot["fixture_count"] == 14
    for e in entries:
        assert set(e["engines"].keys()) == {"v2", "nivxforge", "uaie"}
        for eng_result in e["engines"].values():
            # Every engine must produce SOMETHING (result or an
            # explicit error record). No engine may silently swallow.
            assert isinstance(eng_result, dict)
            assert (any(k in eng_result for k in
                             ("score", "label", "max_score", "n_evidence",
                              "verdict_signals"))
                        or "error" in eng_result)


def test_verdict_parity_snapshot_is_deterministic():
    """Two independent runs must produce the same snapshot bytes.
    Locks against non-determinism sneaking into any engine during
    migration."""
    # Run the capture logic twice in-process
    from copy import deepcopy
    e1: List[Dict[str, Any]] = []
    e2: List[Dict[str, Any]] = []
    for bucket, f in [(e1, VENDOR_CORPUS_V1[0]), (e2, VENDOR_CORPUS_V1[0])]:
        bucket.append({
            "v2":        _run_engine_a_v2(f),
            "nivxforge": _run_engine_b_nivxforge(f),
        })
    # v2 engine is a pure function — must be byte-identical.
    assert e1[0]["v2"] == e2[0]["v2"]
    # nivxforge invokes topology/correlation signal attachers on the
    # graph, which are also deterministic given the same graph.
    assert e1[0]["nivxforge"] == e2[0]["nivxforge"]
