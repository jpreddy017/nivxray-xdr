"""Platform Metrics — Phase A.5 · item 3.3 (Regression + Health Dashboard).

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN)
§7 · read-only analytical consumer of the SSOT.

    Case store + Golden Corpus + NVKC baselines
                       ▼
             compute_snapshot(db)
                       ▼
    { pipeline_health, performance, coverage,
      explainability, fingerprint_stability,
      quality, nvkc, release_history }

Contract:

  1. **Read-only.** Never mutates any case, CEM, baseline, or snapshot
     document. Persisting snapshots is a separate explicit call.
  2. **Deterministic.** Same inputs (case store + baselines) → byte-
     identical snapshot body EXCEPT the `computed_at` field.
  3. **Aggregated at query time.** No incremental counter — the
     dashboard always shows the true current state.
  4. **Graceful degradation.** Missing fields, absent collections,
     or empty baseline files each degrade to `null` metrics rather
     than raising.

The 8 owner-locked sections (2026-02-16) are computed by dedicated
private helpers so future metric additions stay localized.
"""
from __future__ import annotations

import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PLATFORM_METRICS_VERSION = "1.0"

# Paths of the on-disk baselines the dashboard reads.
GOLDEN_BASELINES = Path("/app/backend/tests/golden_corpus/baselines")
NVKC_CORPUS_ROOT = Path("/app/backend/nvkc/corpus")


def compute_snapshot(db) -> Dict[str, Any]:
    """Compute the current platform-health snapshot."""
    return {
        "platform_metrics_version": PLATFORM_METRICS_VERSION,
        "computed_at":              datetime.now(timezone.utc).isoformat(),
        "pipeline_health":          _pipeline_health(db),
        "performance":              _performance(db),
        "coverage":                 _coverage(db),
        "explainability":           _explainability(db),
        "fingerprint_stability":    _fingerprint_stability(),
        "quality":                  _quality(db),
        "nvkc":                     _nvkc(),
        # release_history is filled in by the router from persisted snapshots.
    }


def snapshot_body_hash(snapshot: Dict[str, Any]) -> str:
    """Stable content hash for drift detection between snapshots."""
    body = {k: v for k, v in snapshot.items()
            if k not in ("computed_at", "release_history")}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


# =====================================================================
# 1 · Pipeline health
# =====================================================================
def _pipeline_health(db) -> Dict[str, Any]:
    total = _safe_count(db, "investigations")
    if total == 0:
        return {"total_cases": 0, "decode_success_rate": None,
                "investigation_success_rate": None,
                "terminal_state_distribution": {},
                "golden_corpus_baselines": _baseline_count(GOLDEN_BASELINES),
                "architectural_gates": None}

    conv_states = ("canonical", "binary_artifact_recovered", "artifact_recovered")
    decoded = _safe_count(db, "investigations",
                          {"iedde_terminal_state": {"$in": list(conv_states)}})
    with_cem = _safe_count(db, "investigations", {"cem": {"$exists": True}})
    dist = _distribution(db, "investigations", "iedde_terminal_state", limit=12)
    return {
        "total_cases":                    total,
        "decode_success_rate":            _rate(decoded, total),
        "investigation_success_rate":     _rate(with_cem, total),
        "terminal_state_distribution":    dist,
        "golden_corpus_baselines":        _baseline_count(GOLDEN_BASELINES),
    }


# =====================================================================
# 2 · Performance
# =====================================================================
def _performance(db) -> Dict[str, Any]:
    latencies = _sample_latencies(db, "investigations", "elapsed_ms", limit=500)
    depths    = _sample_depths(db, limit=500)
    return {
        "decode_latency_ms":       _percentiles(latencies),
        "recursive_depth_stats":   _summarise(depths),
        "sample_size":             len(latencies),
    }


# =====================================================================
# 3 · Coverage
# =====================================================================
def _coverage(db) -> Dict[str, Any]:
    """Analyzer coverage — which artifact types actually appear in the
    case store. MITRE coverage — how many distinct techniques the
    platform has actually surfaced."""
    pipeline = [
        {"$project": {"iedde": 1, "cem.canonical_artifacts": 1}},
        {"$match": {"$or": [
            {"iedde.binary_artifact.routed_analysis.artifact_type": {"$exists": True}},
            {"cem.canonical_artifacts": {"$exists": True}},
        ]}},
        {"$limit": 5000},
    ]
    try:
        docs = list(db.investigations.aggregate(pipeline))
    except Exception:
        docs = []

    analyzer_types: set = set()
    for d in docs:
        ra = ((d.get("iedde") or {}).get("binary_artifact") or {}
              ).get("routed_analysis") or {}
        if ra.get("artifact_type"):
            analyzer_types.add(str(ra["artifact_type"]))
        for a in (d.get("cem") or {}).get("canonical_artifacts") or []:
            if isinstance(a, dict) and a.get("type"):
                analyzer_types.add(str(a["type"]))

    mitre_ids: set = set()
    try:
        for m in db.investigations.aggregate([
            {"$unwind": "$cem.mitre"},
            {"$group": {"_id": "$cem.mitre.id"}},
            {"$limit": 500},
        ]):
            if m.get("_id"):
                mitre_ids.add(str(m["_id"]).upper())
    except Exception:
        pass

    return {
        "analyzer_types_observed":  sorted(analyzer_types),
        "analyzer_type_count":      len(analyzer_types),
        "mitre_ids_observed":       sorted(mitre_ids),
        "mitre_id_count":           len(mitre_ids),
    }


# =====================================================================
# 4 · Explainability Coverage (owner-locked new metric family)
# =====================================================================
def _explainability(db) -> Dict[str, Any]:
    """Every metric is a percentage of the total case population where
    the required evidence trail exists."""
    total = _safe_count(db, "investigations")
    if total == 0:
        return {"total_cases": 0, "metrics": {}}

    verdicts_with_provenance = _safe_count(
        db, "investigations", {"cem.mitre.0": {"$exists": True}})
    mitre_with_evidence = _safe_count(
        db, "investigations",
        {"$and": [{"cem.mitre.0": {"$exists": True}},
                  {"cem.events.0": {"$exists": True}}]})
    decoded_with_traces = _safe_count(
        db, "investigations",
        {"cem.traces.transformation_trace.0": {"$exists": True}})
    children_analyzed = _safe_count(
        db, "investigations",
        {"cem.child_artifacts.routed_artifact_type": {"$exists": True}})
    replayable = _safe_count(
        db, "investigations",
        {"$and": [{"cem.traces.transformation_trace.0": {"$exists": True}},
                  {"cem.events.0": {"$exists": True}}]})
    findings_with_evidence = _safe_count(
        db, "investigations",
        {"cem.events.provenance": {"$exists": True}})

    return {
        "total_cases": total,
        "metrics": {
            "verdicts_with_provenance":   _rate(verdicts_with_provenance, total),
            "mitre_mappings_backed":      _rate(mitre_with_evidence, total),
            "decoded_stages_traced":      _rate(decoded_with_traces, total),
            "child_artifacts_analyzed":   _rate(children_analyzed, total),
            "investigations_replayable":  _rate(replayable, total),
            "findings_linked_to_evidence": _rate(findings_with_evidence, total),
        },
    }


# =====================================================================
# 5 · Fingerprint stability (Golden Corpus + NVKC baselines)
# =====================================================================
def _fingerprint_stability() -> Dict[str, Any]:
    total = 0
    with_afp = 0
    if GOLDEN_BASELINES.exists():
        for p in GOLDEN_BASELINES.glob("*.json"):
            try:
                d = json.loads(p.read_text())
            except Exception:
                continue
            total += 1
            if d.get("attack_fingerprint_hash"):
                with_afp += 1
    nvkc_total = 0
    nvkc_with_hash = 0
    if NVKC_CORPUS_ROOT.exists():
        import yaml
        for p in NVKC_CORPUS_ROOT.rglob("*.nvkc.yaml"):
            try:
                d = yaml.safe_load(p.read_text()) or {}
            except Exception:
                continue
            nvkc_total += 1
            if (d.get("expected") or {}).get("attack_fingerprint_hash"):
                nvkc_with_hash += 1
    return {
        "golden_corpus": {"total": total, "with_attack_fingerprint": with_afp,
                          "coverage": _rate(with_afp, total)},
        "nvkc":          {"total": nvkc_total, "with_attack_fingerprint": nvkc_with_hash,
                          "coverage": _rate(nvkc_with_hash, nvkc_total)},
    }


# =====================================================================
# 6 · Quality (verdict / risk distribution)
# =====================================================================
def _quality(db) -> Dict[str, Any]:
    dist = _distribution(db, "investigations", "verdict_card.verdict", limit=10)
    risks = _sample_latencies(db, "investigations", "verdict_card.risk_score",
                              limit=500)
    return {
        "verdict_distribution":   dist,
        "risk_score_distribution": _percentiles(risks),
        "sample_size":            len(risks),
    }


# =====================================================================
# 7 · NVKC
# =====================================================================
def _nvkc() -> Dict[str, Any]:
    if not NVKC_CORPUS_ROOT.exists():
        return {"total_samples": 0, "by_track": {}}
    import yaml
    by_track: Dict[str, int] = {}
    by_tag: Dict[str, int] = {}
    total = 0
    for p in sorted(NVKC_CORPUS_ROOT.rglob("*.nvkc.yaml")):
        try:
            d = yaml.safe_load(p.read_text()) or {}
        except Exception:
            continue
        total += 1
        by_track[d.get("track", "unknown")] = by_track.get(d.get("track", "unknown"), 0) + 1
        for t in d.get("tags") or []:
            by_tag[t] = by_tag.get(t, 0) + 1
    return {
        "total_samples": total,
        "by_track":      dict(sorted(by_track.items())),
        "top_tags":      dict(sorted(by_tag.items(), key=lambda kv: -kv[1])[:15]),
    }


# =====================================================================
# Utilities
# =====================================================================
def _safe_count(db, coll: str, filt: Optional[dict] = None) -> int:
    try:
        return db[coll].count_documents(filt or {})
    except Exception:
        return 0


def _distribution(db, coll: str, field: str, limit: int = 10) -> Dict[str, int]:
    try:
        cur = db[coll].aggregate([
            {"$group": {"_id": f"${field}", "n": {"$sum": 1}}},
            {"$sort": {"n": -1}},
            {"$limit": limit},
        ])
        return {(str(d["_id"]) if d["_id"] is not None else "null"): d["n"]
                for d in cur}
    except Exception:
        return {}


def _sample_latencies(db, coll: str, field: str, limit: int) -> List[float]:
    try:
        cur = db[coll].find({field: {"$type": "number"}},
                            {field: 1}).sort("_id", -1).limit(limit)
    except Exception:
        return []
    out: List[float] = []
    for d in cur:
        v = d
        for part in field.split("."):
            v = v.get(part) if isinstance(v, dict) else None
        if isinstance(v, (int, float)):
            out.append(float(v))
    return out


def _sample_depths(db, limit: int) -> List[int]:
    try:
        cur = db.investigations.find(
            {"iedde.recursive_children.depth": {"$exists": True}},
            {"iedde.recursive_children.depth": 1}
        ).sort("_id", -1).limit(limit)
    except Exception:
        return []
    out: List[int] = []
    for d in cur:
        kids = (d.get("iedde") or {}).get("recursive_children") or []
        max_depth = 0
        for k in kids:
            if isinstance(k, dict):
                max_depth = max(max_depth, int(k.get("depth") or 0))
        if max_depth > 0:
            out.append(max_depth)
    return out


def _percentiles(values: List[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"n": 0, "min": None, "p50": None, "p90": None,
                "p99": None, "max": None, "mean": None}
    s = sorted(values)
    def _q(p): return s[min(len(s) - 1, int(len(s) * p))]
    return {
        "n":    len(s),
        "min":  round(s[0], 2),
        "p50":  round(_q(0.50), 2),
        "p90":  round(_q(0.90), 2),
        "p99":  round(_q(0.99), 2),
        "max":  round(s[-1], 2),
        "mean": round(statistics.mean(s), 2),
    }


def _summarise(values: List[int]) -> Dict[str, Optional[float]]:
    if not values:
        return {"n": 0, "max": None, "mean": None}
    return {"n": len(values), "max": max(values),
            "mean": round(statistics.mean(values), 2)}


def _rate(numerator: int, denominator: int) -> Optional[float]:
    if not denominator:
        return None
    return round(100.0 * numerator / denominator, 2)


def _baseline_count(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for _ in root.glob("*.json"))


__all__ = ["PLATFORM_METRICS_VERSION", "compute_snapshot",
           "snapshot_body_hash"]
