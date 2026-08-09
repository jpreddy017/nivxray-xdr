"""Step 0 Baseline Snapshot Harness · ADR-004 Amendment A1.

Captures the four authoritative pre-migration snapshots that will
serve as parity gates for every subsequent ADR-004 migration step:

    1. baseline_verdicts.json         (per-fixture verdict / confidence / top techniques)
    2. baseline_chain_decodes.json    (per-command chain-decode output)
    3. baseline_bkb_projections.json  (BKB canonical behavior → technique projections)
    4. baseline_iocs.json             (per-fixture IOC extraction grouped by type)

Design:
    · Read-only against the current production pipeline
    · Deterministic (no wall-clock, no network, no LLM)
    · Faithful — captures pre-migration behaviour EXACTLY as it is today
    · Written to `backend/corpus/vendor/v1/reports/`

Invocation (from /app/backend):
    python -m tests.capture_baseline

Also invoked once by `test_baseline_snapshots_present.py` so the CI
green-checks the presence + shape of the snapshots.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List


# ══════════════════════════════════════════════════════════════════
# Locations
# ══════════════════════════════════════════════════════════════════
_HERE          = Path(__file__).resolve().parent
_REPORTS_DIR   = _HERE.parent / "corpus" / "vendor" / "v1" / "reports"
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════
# Corpus loader (uses the same pinned VENDOR_CORPUS_V1)
# ══════════════════════════════════════════════════════════════════
def _load_corpus():
    from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1
    return VENDOR_CORPUS_V1


# ══════════════════════════════════════════════════════════════════
# 1. Verdicts snapshot
# ══════════════════════════════════════════════════════════════════
def _fixture_text(f) -> str:
    """Compose the analyst-paste equivalent of a fixture."""
    return "\n".join([
        f"# {f.article_title}",
        f"# vendor={f.vendor} · fixture={f.fixture_id}",
        *f.commands,
    ])


def _verdict_for_fixture(f) -> Dict[str, Any]:
    """Run the current unified verdict engine on the fixture.
    Uses the nivxforge compute_verdict entry — this is the engine
    currently invoked by the auto_investigate router today."""
    from nivxforge.investigation.graph import EvidenceGraph, Node, Edge
    from nivxforge.investigation.verdict_engine import compute_verdict

    g = EvidenceGraph()
    art = Node(id="N-001", kind="artifact",
                   label=f.article_title,
                   value=_fixture_text(f),
                   confidence=0.9, provenance="baseline.harness")
    g.add_node(art)
    for i, cmd in enumerate(f.commands, start=1):
        head = (cmd or "").split(None, 1)[0].split("\\")[-1]
        head = head.split(".")[0].lower() if head else "unknown"
        nid = f"N-{i+1:03d}"
        g.add_node(Node(id=nid, kind="lolbin",
                             label=head, value=head,
                             confidence=0.8, provenance="baseline.harness"))
        g.add_edge(Edge(source=art.id, target=nid,
                             kind="produces", weight=1.0))
    meta = {"input_text_normalised": "\n".join(f.commands),
                "fixture_id": f.fixture_id}
    try:
        v = compute_verdict(g, meta)
    except Exception as e:
        return {"fixture_id": f.fixture_id, "error": f"{type(e).__name__}: {e!s}"}

    contribs = getattr(v, "contributors", []) or []
    # Deterministic top-technique surface: extract from contributor kinds
    top_kinds: List[str] = []
    for c in contribs[:8]:
        k = getattr(c, "kind", None) or (c.get("kind") if isinstance(c, dict) else None)
        if k:
            top_kinds.append(k)
    return {
        "fixture_id":       f.fixture_id,
        "vendor":           f.vendor,
        "label":            getattr(v, "label", None),
        "confidence":       round(float(getattr(v, "confidence", 0.0)), 4),
        "confidence_pct":   int(getattr(v, "confidence_pct", 0) or 0),
        "reason":           (getattr(v, "reason", "") or "")[:400],
        "n_contributors":   len(contribs),
        "n_not_counted":    len(getattr(v, "not_counted", []) or []),
        "top_kinds":        top_kinds,
    }


def capture_verdicts() -> Path:
    entries = [_verdict_for_fixture(f) for f in _load_corpus()]
    out = {
        "schema_version": "1.0",
        "purpose":        "ADR-004 Amendment A1 · verdict baseline",
        "corpus_id":      "vendor-v1",
        "fixture_count":  len(entries),
        "engine_probed":  "nivxforge.investigation.verdict_engine::compute_verdict",
        "entries":        entries,
    }
    path = _REPORTS_DIR / "baseline_verdicts.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True))
    return path


# ══════════════════════════════════════════════════════════════════
# 2. Chain decodes snapshot
# ══════════════════════════════════════════════════════════════════
async def _decode_one(payload: str, stage_index: int) -> Dict[str, Any]:
    from chain_analyzer import decode_single_stage
    try:
        return await decode_single_stage(payload, stage_index=stage_index)
    except Exception as e:
        return {
            "stage_index":   stage_index,
            "input_preview": payload[:200],
            "error":         f"{type(e).__name__}: {e!s}",
        }


def _summarise_stage(s: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic slim shape for the snapshot — avoids embedding
    huge decoded blobs while preserving the invariants we care about."""
    if "error" in s:
        return {"stage_index": s.get("stage_index"),
                    "error": s["error"]}
    steps = s.get("steps") or []
    return {
        "stage_index":       s.get("stage_index"),
        "engine":            s.get("engine"),
        "confidence":        s.get("confidence"),
        "reached_shellcode": bool(s.get("reached_shellcode")),
        "n_steps":           len(steps),
        "step_ops":          [(step.get("op") if isinstance(step, dict) else None)
                                       for step in steps],
        "output_bytes":      len((s.get("output") or "").encode("utf-8", "replace")),
        "n_iocs":            sum(len(v) for v in (s.get("iocs") or {}).values()),
        "n_mitre":           len(s.get("mitre") or []),
        "n_lolbas":          len(s.get("lolbas") or []),
        "n_yara":            len(s.get("yara") or []),
        "risk_verdict":      (s.get("risk") or {}).get("verdict"),
        "risk_level":        (s.get("risk") or {}).get("level"),
        "risk_score":        (s.get("risk") or {}).get("score"),
    }


def _chain_for_fixture(f) -> Dict[str, Any]:
    """Decode every command in the fixture as a single-stage payload."""
    async def _all():
        return [await _decode_one(cmd, i) for i, cmd in enumerate(f.commands)]
    stages = asyncio.run(_all())
    return {
        "fixture_id": f.fixture_id,
        "vendor":     f.vendor,
        "n_commands": len(f.commands),
        "stages":     [_summarise_stage(s) for s in stages],
    }


def capture_chain_decodes() -> Path:
    entries = [_chain_for_fixture(f) for f in _load_corpus()]
    out = {
        "schema_version": "1.0",
        "purpose":        "ADR-004 Amendment A1 · chain decode baseline",
        "corpus_id":      "vendor-v1",
        "fixture_count":  len(entries),
        "engine_probed":  "chain_analyzer::decode_single_stage",
        "entries":        entries,
    }
    path = _REPORTS_DIR / "baseline_chain_decodes.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True))
    return path


# ══════════════════════════════════════════════════════════════════
# 3. BKB projections snapshot
# ══════════════════════════════════════════════════════════════════
def capture_bkb_projections() -> Path:
    """Snapshot every canonical behavior → its full technique/tactic set."""
    try:
        from services.knowledge import behavior_registry as bkb
        snap    = bkb.snapshot()
        purpose = bkb.as_purpose_to_mitre()
    except Exception as e:
        snap    = {"error": f"{type(e).__name__}: {e!s}"}
        purpose = {}

    projections: Dict[str, Any] = {}
    for label, techniques in sorted(purpose.items()):
        projections[label] = {
            "n_techniques": len(techniques),
            "techniques": [
                (t if isinstance(t, str)
                     else {"id": t.get("id"), "name": t.get("name"), "tactic": t.get("tactic")})
                for t in techniques
            ],
        }
    out = {
        "schema_version":  "1.0",
        "purpose":         "ADR-004 Amendment A1 · BKB projection baseline",
        "engine_probed":   "services.knowledge.behavior_registry",
        "bkb_snapshot":    snap,
        "n_behaviors":     len(projections),
        "projections":     projections,
    }
    path = _REPORTS_DIR / "baseline_bkb_projections.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True))
    return path


# ══════════════════════════════════════════════════════════════════
# 4. IOC extraction snapshot
# ══════════════════════════════════════════════════════════════════
def _iocs_for_fixture(f) -> Dict[str, Any]:
    from services.ida.artifact_splitter import split_artifacts, summarise

    text = _fixture_text(f)
    arts = split_artifacts(text)
    # Group by type, deterministic order.
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for a in arts:
        by_type.setdefault(a.type, []).append({
            "value":     a.value[:200],
            "canonical": a.canonical[:200],
            "defanged":  bool(a.metadata.get("defanged")),
            "line":      a.source.get("line"),
        })
    for k in by_type:
        by_type[k].sort(key=lambda x: (x["canonical"], x["value"]))
    return {
        "fixture_id":  f.fixture_id,
        "vendor":      f.vendor,
        "n_artifacts": len(arts),
        "summary":     summarise(arts),
        "by_type":     by_type,
    }


def capture_iocs() -> Path:
    entries = [_iocs_for_fixture(f) for f in _load_corpus()]
    out = {
        "schema_version": "1.0",
        "purpose":        "ADR-004 Amendment A1 · IOC extraction baseline",
        "corpus_id":      "vendor-v1",
        "fixture_count":  len(entries),
        "engine_probed":  "services.ida.artifact_splitter::split_artifacts",
        "entries":        entries,
    }
    path = _REPORTS_DIR / "baseline_iocs.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True))
    return path


# ══════════════════════════════════════════════════════════════════
# 5. Public entry point
# ══════════════════════════════════════════════════════════════════
def capture_all() -> Dict[str, str]:
    """Capture all four snapshots. Returns the file-path map."""
    return {
        "verdicts":        str(capture_verdicts()),
        "chain_decodes":   str(capture_chain_decodes()),
        "bkb_projections": str(capture_bkb_projections()),
        "iocs":            str(capture_iocs()),
    }


if __name__ == "__main__":
    paths = capture_all()
    print(json.dumps(paths, indent=2))
