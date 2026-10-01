"""
UAIE Phase 0 · Baseline Capture Engine
──────────────────────────────────────
Freezes today's production behaviour as the golden compatibility
contract for the UAIE migration (Rule R26).

Iterates every case folder under `tests/uaie_baseline/` and:
  1. Reads `input.txt`
  2. Runs `deterministic_best_decode` (the workspace pipeline)
  3. Extracts the R26 five-layer compare surface (evidence, behavior,
     graph, verdict, explainability) into a normalised shape
  4. Writes `expected.json`  (behaviour snapshot)
     Writes `execution_plan.json` (Recognizer→Capability order)
  5. Leaves `metadata.json` / `slo.json` untouched (human-authored)

Volatile fields (timings, telemetry_id, timestamps, memory) are
STRIPPED so the snapshot is byte-stable across runs.

Usage:
    python -m tests.uaie_baseline_capture --dry-run
    python -m tests.uaie_baseline_capture --write
    python -m tests.uaie_baseline_capture --compare
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing  import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASELINE_ROOT = Path(__file__).parent / "uaie_baseline"

# Volatile fields — never included in expected.json.
_STRIP_KEYS = {
    "telemetry_id", "backend_ms", "frontend_layout_ms",
    "frontend_render_ms", "frontend_paint_ms", "frontend_total_ms",
    "peak_memory_mb", "peak_rss_kb", "elapsed_ms", "recorded_at",
    "created_at", "updated_at", "session_id", "case_id", "id",
    "stages_ms", "recipe",
}


def _strip_volatile(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items()
                 if k not in _STRIP_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


def _extract_evidence(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """R26 L1 — Evidence surface (URLs / IPs / domains / hashes)."""
    iocs = ssot.get("iocs") or {}
    if isinstance(iocs, list):
        by_kind: Dict[str, List[str]] = {}
        for i in iocs:
            if isinstance(i, dict):
                k = (i.get("kind") or "").lower()
                v = i.get("value") or ""
                if k and v:
                    by_kind.setdefault(k, []).append(v)
        iocs = by_kind
    return {k: sorted(set(v)) for k, v in iocs.items()}


def _extract_behavior(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """R26 L2 — Behavior surface (behaviors / MITRE / timeline)."""
    inc = ssot.get("incident") or {}
    beh = []
    for b in (inc.get("behaviors") or []):
        beh.append({
            "label":         b.get("label") or b.get("title") or "",
            "mitre_tactics": sorted(set(b.get("mitre_tactics") or [])),
            "mitre":         sorted(set(m.get("id", "") if isinstance(m, dict) else m
                                          for m in (b.get("mitre") or [])
                                          if m)),
        })
    beh.sort(key=lambda x: (x["label"], tuple(x["mitre_tactics"])))
    tl = []
    for t in (inc.get("timeline") or []):
        tl.append({
            "kind":  t.get("kind") or "",
            "event": t.get("event") or "",
            "mitre_tactics": sorted(set(t.get("mitre_tactics") or [])),
        })
    return {"behaviors": beh, "timeline": tl}


def _extract_graph(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """R26 L3 — Graph structure (parent→child topology)."""
    perf = (ssot.get("metadata") or {}).get("performance") or {}
    layers = perf.get("decode_layers") or []
    return {
        "layer_count": len(layers),
        "stages":      [l.get("stage") for l in layers],
    }


def _extract_verdict(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """R26 L4 — Verdict (severity + family + confidence)."""
    v = ssot.get("verdict") or {}
    return {
        "severity":   v.get("severity") or v.get("level") or "",
        "family":     v.get("family") or "",
        "confidence": v.get("confidence"),
    }


def _extract_explainability(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """R26 L5 — Recognizer / capability sequence."""
    perf = (ssot.get("metadata") or {}).get("performance") or {}
    return {
        "engine_health": perf.get("engine_health") or {},
        "decoder_path":  [l.get("stage") for l in (perf.get("decode_layers") or [])],
    }


def build_expected(input_text: str) -> Dict[str, Any]:
    from services.die.investigation_results import render
    ssot = render(input_text)["object"]
    return {
        "evidence":       _extract_evidence(ssot),
        "behavior":       _extract_behavior(ssot),
        "graph":          _extract_graph(ssot),
        "verdict":        _extract_verdict(ssot),
        "explainability": _extract_explainability(ssot),
    }


def iter_cases():
    if not BASELINE_ROOT.exists():
        return
    for bucket in sorted(BASELINE_ROOT.iterdir()):
        if not bucket.is_dir() or bucket.name.startswith("_"):
            continue
        for case in sorted(bucket.iterdir()):
            if case.is_dir() and (case / "input.txt").exists():
                yield case


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True,
                                 default=str, ensure_ascii=False) + "\n",
                     encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write",   action="store_true",
                     help="Regenerate expected.json for every case")
    ap.add_argument("--compare", action="store_true",
                     help="Compare current output to expected.json")
    ap.add_argument("--dry-run", action="store_true", default=True)
    args = ap.parse_args()

    cases = list(iter_cases())
    if not cases:
        print("No cases under tests/uaie_baseline/ yet.")
        print("Drop input.txt + metadata.json into a bucket to enable Phase 0.")
        return 0

    fails = 0
    for case in cases:
        input_text = (case / "input.txt").read_text(encoding="utf-8", errors="replace")
        current = build_expected(input_text)
        current = _strip_volatile(current)
        expected_path = case / "expected.json"
        if args.write:
            _write_json(expected_path, current)
            print(f"  ✓ wrote  {case.relative_to(BASELINE_ROOT)}/expected.json")
            continue
        if args.compare and expected_path.exists():
            expected = json.loads(expected_path.read_text())
            expected = _strip_volatile(expected)
            if current != expected:
                fails += 1
                print(f"  ✗ MISMATCH  {case.relative_to(BASELINE_ROOT)}")
                # Compact diff summary — first differing key
                for k in ("evidence", "behavior", "graph", "verdict", "explainability"):
                    if current.get(k) != expected.get(k):
                        print(f"      layer differs: {k}")
                        break
            else:
                print(f"  ✓ match     {case.relative_to(BASELINE_ROOT)}")
        else:
            # dry-run
            print(f"  · would snapshot  {case.relative_to(BASELINE_ROOT)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
