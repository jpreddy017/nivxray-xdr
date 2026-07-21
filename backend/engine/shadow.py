"""RC5 · Phase 9 · Shadow-Run Delta Analyzer.

Compares RC4 (legacy) and RC5 (semantic) outputs for every sample fed
through the pipeline and records the delta. See § 15 (Feature Flag +
Shadow Run Strategy) and § 9 (Shadow-Run Metrics list) of
`/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`.

Tracked delta dimensions (12):

  1. Verdict tier      — RC4.verdict vs RC5.verdict_v2.verdict
  2. MITRE mappings    — added / removed / kept technique_id set
  3. LOLBIN attrib     — old scan vs new 3-state model
  4. Behaviors         — count, tactic distribution
  5. Confidence        — per-stage (5 stages) breakdown
  6. Reconstruction    — node count, unresolved count
  7. Latency           — p50/p95/p99 delta
  8. Graph completeness — nodes + edges + dangling refs
  9. Parser failures   — SIR warnings + exceptions
  10. FP changes       — v2=Malicious/Critical where v1=Benign/Suspicious
  11. FN changes       — v2=Benign/Suspicious where v1=Malicious/Critical
  12. Unsupported nodes — count of `NodeKind.unresolved`

Storage: MongoDB collection `rc5_shadow_runs` (one document per analysis).
Reports:
  * `daily_report(day)`   — aggregate of a single UTC calendar day
  * `cumulative_report()` — since the beginning of the shadow run

Both reports are the source of truth for the Phase 10 cutover gate.
"""
from __future__ import annotations

import hashlib
import statistics
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


COLLECTION = "rc5_shadow_runs"


# ---------------------------------------------------------------------------
# Snapshot model — one row per analysis
# ---------------------------------------------------------------------------
class ShadowSnapshot(BaseModel):
    """One RC4 vs RC5 comparison per input sample."""
    model_config = ConfigDict(extra="forbid")

    sample_hash: str
    day: str                             # YYYY-MM-DD (UTC)
    ts: datetime
    language: str

    # RC4 (legacy) fields — captured before cutover.
    rc4_verdict: Optional[str] = None
    rc4_mitre: List[str] = Field(default_factory=list)         # technique IDs
    rc4_lolbas: List[str] = Field(default_factory=list)        # binary names
    rc4_latency_ms: Optional[float] = None
    rc4_exception: Optional[str] = None

    # RC5 (new) fields.
    rc5_verdict: Optional[str] = None
    rc5_mitre: List[str] = Field(default_factory=list)
    rc5_lolbins_executed:  List[str] = Field(default_factory=list)
    rc5_lolbins_expanded:  List[str] = Field(default_factory=list)
    rc5_lolbins_referenced: List[str] = Field(default_factory=list)
    rc5_behavior_count: int = 0
    rc5_tactics: List[str] = Field(default_factory=list)
    rc5_node_count: int = 0
    rc5_unresolved_count: int = 0
    rc5_dangling_refs: int = 0
    rc5_confidence: Dict[str, int] = Field(default_factory=dict)  # 5-stage
    rc5_latency_ms: Optional[float] = None
    rc5_exception: Optional[str] = None
    rc5_parser_warnings: List[str] = Field(default_factory=list)

    # Corpus label (optional — populated when the sample came from a labelled corpus).
    corpus_label: Optional[str] = None   # "benign" | "malicious"


# ---------------------------------------------------------------------------
# Snapshot builder — pure function, no DB access.
# ---------------------------------------------------------------------------
_TIER_RANK = {"Benign": 0, "Suspicious": 1, "Malicious": 2, "Critical": 3}


def make_snapshot(
    *,
    original_input: str,
    language: str,
    # RC4 side (all optional — caller may compute or pass None)
    rc4_verdict: Optional[str] = None,
    rc4_mitre: Optional[List[str]] = None,
    rc4_lolbas: Optional[List[str]] = None,
    rc4_latency_ms: Optional[float] = None,
    rc4_exception: Optional[str] = None,
    # RC5 side (structured output of `/api/rc5/parse`)
    rc5_response: Optional[Dict[str, Any]] = None,
    rc5_exception: Optional[str] = None,
    rc5_latency_ms: Optional[float] = None,
    corpus_label: Optional[str] = None,
    ts: Optional[datetime] = None,
) -> ShadowSnapshot:
    ts = ts or datetime.now(timezone.utc)
    day = ts.strftime("%Y-%m-%d")
    sample_hash = hashlib.sha256(original_input.encode("utf-8")).hexdigest()[:16]

    snap = ShadowSnapshot(
        sample_hash=sample_hash, day=day, ts=ts, language=language,
        rc4_verdict=rc4_verdict,
        rc4_mitre=list(rc4_mitre or []),
        rc4_lolbas=list(rc4_lolbas or []),
        rc4_latency_ms=rc4_latency_ms,
        rc4_exception=rc4_exception,
        rc5_exception=rc5_exception,
        rc5_latency_ms=rc5_latency_ms,
        corpus_label=corpus_label,
    )
    if rc5_response and not rc5_exception:
        snap = _populate_rc5(snap, rc5_response)
    return snap


def _populate_rc5(snap: ShadowSnapshot, r: Dict[str, Any]) -> ShadowSnapshot:
    mitre = r.get("mitre", []) or []
    lolbins = r.get("lolbins_v2", []) or []
    behaviors = r.get("behaviors", []) or []
    graph = r.get("exec_graph", {}) or {}
    nodes = graph.get("nodes", []) or []
    verdict = r.get("verdict_v2", {}) or {}
    explain = r.get("explain", {}) or {}
    conf = (explain.get("confidence_breakdown", {}) or {})

    return snap.model_copy(update={
        "rc5_verdict": verdict.get("verdict"),
        "rc5_mitre": sorted({m.get("technique_id") for m in mitre if m.get("technique_id")}),
        "rc5_lolbins_executed":   [l["binary"] for l in lolbins if l.get("state") == "executed"],
        "rc5_lolbins_expanded":   [l["binary"] for l in lolbins if l.get("state") == "expanded"],
        "rc5_lolbins_referenced": [l["binary"] for l in lolbins if l.get("state") == "referenced"],
        "rc5_behavior_count": len(behaviors),
        "rc5_tactics": sorted({b.get("tactic") for b in behaviors if b.get("tactic")}),
        "rc5_node_count": len(nodes),
        "rc5_unresolved_count": sum(1 for n in nodes if n.get("kind") == "UnresolvedNode"),
        "rc5_dangling_refs": 0,   # populated by caller if desired
        "rc5_confidence": {
            k: conf.get(k, 0) for k in
            ("decode", "semantic_reconstruction", "behavior",
             "mitre", "verdict", "weighted_overall")
        },
        "rc5_parser_warnings": list(r.get("warnings") or []),
    })


# ---------------------------------------------------------------------------
# Delta report — pure function over a list of snapshots
# ---------------------------------------------------------------------------
def compute_delta_report(snaps: List[ShadowSnapshot]) -> Dict[str, Any]:
    """Compute the 12-dimension delta over a snapshot slice.

    All metrics are deterministic (median / count / set operations). No DB
    access — caller loads snapshots and hands them in.
    """
    total = len(snaps)
    if total == 0:
        return {"total": 0}

    # 1. Verdict tier changes
    verdict_pairs = Counter()
    verdict_matrix: Dict[str, Dict[str, int]] = {}
    fp_delta = 0
    fn_delta = 0
    for s in snaps:
        pair = (s.rc4_verdict, s.rc5_verdict)
        verdict_pairs[pair] += 1
        verdict_matrix.setdefault(str(s.rc4_verdict), {}).setdefault(str(s.rc5_verdict), 0)
        verdict_matrix[str(s.rc4_verdict)][str(s.rc5_verdict)] += 1
        # FP change: v2 more severe than v1, corpus label = benign
        if (s.corpus_label == "benign"
            and _rank(s.rc5_verdict) > _rank(s.rc4_verdict)
            and _rank(s.rc5_verdict) >= 2):
            fp_delta += 1
        # FN change: v2 less severe than v1, corpus label = malicious
        if (s.corpus_label == "malicious"
            and _rank(s.rc5_verdict) < _rank(s.rc4_verdict)
            and _rank(s.rc5_verdict) < 2):
            fn_delta += 1

    # 2. MITRE technique deltas
    mitre_added = Counter()
    mitre_removed = Counter()
    mitre_kept = 0
    for s in snaps:
        rc4 = set(s.rc4_mitre or [])
        rc5 = set(s.rc5_mitre or [])
        for t in rc5 - rc4:
            mitre_added[t] += 1
        for t in rc4 - rc5:
            mitre_removed[t] += 1
        mitre_kept += len(rc4 & rc5)

    # 3. LOLBIN attribution deltas
    lolbin_executed_total = sum(len(s.rc5_lolbins_executed) for s in snaps)
    lolbin_expanded_total = sum(len(s.rc5_lolbins_expanded) for s in snaps)
    lolbin_referenced_total = sum(len(s.rc5_lolbins_referenced) for s in snaps)
    # RC4 legacy list was flat with no state — compare against `executed`.
    rc4_lolbas_total = sum(len(s.rc4_lolbas) for s in snaps)
    lolbin_new_executed_hits = sum(
        len(set(s.rc5_lolbins_executed) - set(s.rc4_lolbas)) for s in snaps
    )
    lolbin_missing_hits = sum(
        len(set(s.rc4_lolbas) - set(s.rc5_lolbins_executed)) for s in snaps
    )

    # 4. Behaviors
    behaviors_total = sum(s.rc5_behavior_count for s in snaps)
    behavior_tactic_hist = Counter()
    for s in snaps:
        for t in s.rc5_tactics or []:
            behavior_tactic_hist[t] += 1

    # 5. Confidence per stage
    per_stage: Dict[str, List[int]] = {
        k: [] for k in ("decode", "semantic_reconstruction",
                        "behavior", "mitre", "verdict", "weighted_overall")
    }
    for s in snaps:
        for k, vs in per_stage.items():
            if k in s.rc5_confidence:
                vs.append(int(s.rc5_confidence[k]))
    confidence_medians = {k: (int(statistics.median(v)) if v else 0)
                          for k, v in per_stage.items()}

    # 6. Reconstruction
    unresolved_counts = [s.rc5_unresolved_count for s in snaps]
    node_counts = [s.rc5_node_count for s in snaps]
    reconstruction = {
        "median_nodes": int(statistics.median(node_counts)) if node_counts else 0,
        "median_unresolved": int(statistics.median(unresolved_counts)) if unresolved_counts else 0,
        "max_unresolved": max(unresolved_counts) if unresolved_counts else 0,
    }

    # 7. Latency
    rc4_lats = [s.rc4_latency_ms for s in snaps if s.rc4_latency_ms is not None]
    rc5_lats = [s.rc5_latency_ms for s in snaps if s.rc5_latency_ms is not None]
    latency = {
        "rc4_p50": _percentile(rc4_lats, 50),
        "rc4_p95": _percentile(rc4_lats, 95),
        "rc4_p99": _percentile(rc4_lats, 99),
        "rc5_p50": _percentile(rc5_lats, 50),
        "rc5_p95": _percentile(rc5_lats, 95),
        "rc5_p99": _percentile(rc5_lats, 99),
        "rc5_regression_ratio_p95": (
            round((_percentile(rc5_lats, 95) or 0) / (_percentile(rc4_lats, 95) or 1), 3)
            if rc4_lats else None
        ),
    }

    # 8. Graph completeness
    graph = {
        "median_node_count": int(statistics.median(node_counts)) if node_counts else 0,
        "total_dangling_refs": sum(s.rc5_dangling_refs for s in snaps),
    }

    # 9. Parser failures
    parser_warnings_total = sum(len(s.rc5_parser_warnings) for s in snaps)
    exceptions_rc4 = sum(1 for s in snaps if s.rc4_exception)
    exceptions_rc5 = sum(1 for s in snaps if s.rc5_exception)

    # 12. Unsupported nodes = median unresolved (already in reconstruction).

    return {
        "total": total,
        "verdict_matrix": verdict_matrix,
        "verdict_change_summary": {
            "unchanged": sum(v for (a, b), v in verdict_pairs.items() if a == b),
            "upgraded": sum(v for (a, b), v in verdict_pairs.items()
                            if _rank(b) > _rank(a)),
            "downgraded": sum(v for (a, b), v in verdict_pairs.items()
                              if _rank(b) < _rank(a)),
        },
        "fp_change": fp_delta,
        "fn_change": fn_delta,
        "mitre": {
            "added_top": mitre_added.most_common(15),
            "removed_top": mitre_removed.most_common(15),
            "kept_total": mitre_kept,
        },
        "lolbins": {
            "executed_total": lolbin_executed_total,
            "expanded_total": lolbin_expanded_total,
            "referenced_total": lolbin_referenced_total,
            "rc4_flat_total": rc4_lolbas_total,
            "new_executed_hits_vs_rc4": lolbin_new_executed_hits,
            "missed_vs_rc4": lolbin_missing_hits,
        },
        "behaviors": {
            "total": behaviors_total,
            "tactic_histogram": dict(behavior_tactic_hist),
        },
        "confidence_medians": confidence_medians,
        "reconstruction": reconstruction,
        "latency_ms": latency,
        "graph_completeness": graph,
        "parser": {
            "warnings_total": parser_warnings_total,
            "rc4_exceptions": exceptions_rc4,
            "rc5_exceptions": exceptions_rc5,
            "crash_delta_per_1000": (
                round(((exceptions_rc5 - exceptions_rc4) / total) * 1000, 3)
                if total else 0
            ),
        },
    }


def _rank(tier: Optional[str]) -> int:
    if not tier:
        return -1
    return _TIER_RANK.get(tier, -1)


def _percentile(values: List[float], pct: int) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    idx = int(round((pct / 100.0) * (len(s) - 1)))
    return round(float(s[idx]), 3)


# ---------------------------------------------------------------------------
# Storage helpers (Mongo)
# ---------------------------------------------------------------------------
async def ensure_shadow_indexes(db) -> None:
    coll = db[COLLECTION]
    await coll.create_index("sample_hash")
    await coll.create_index("day")
    await coll.create_index("ts")


async def record_snapshot(db, snap: ShadowSnapshot) -> str:
    doc = snap.model_dump(mode="python")
    r = await db[COLLECTION].insert_one(doc)
    return str(r.inserted_id)


async def load_snapshots(
    db, *, day: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: Optional[int] = None,
) -> List[ShadowSnapshot]:
    q: Dict[str, Any] = {}
    if day:
        q["day"] = day
    if since:
        q["ts"] = {"$gte": since}
    cur = db[COLLECTION].find(q).sort("ts", 1)
    if limit:
        cur = cur.limit(limit)
    out: List[ShadowSnapshot] = []
    async for d in cur:
        d.pop("_id", None)
        try:
            out.append(ShadowSnapshot(**d))
        except Exception:
            continue
    return out


async def daily_report(db, day: Optional[str] = None) -> Dict[str, Any]:
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snaps = await load_snapshots(db, day=day)
    return {
        "scope": "daily",
        "day": day,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **compute_delta_report(snaps),
    }


async def cumulative_report(
    db, *, since_days: int = 30
) -> Dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    snaps = await load_snapshots(db, since=since)
    return {
        "scope": "cumulative",
        "since": since.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days": since_days,
        **compute_delta_report(snaps),
    }


__all__ = [
    "COLLECTION",
    "ShadowSnapshot",
    "make_snapshot",
    "compute_delta_report",
    "ensure_shadow_indexes",
    "record_snapshot",
    "load_snapshots",
    "daily_report",
    "cumulative_report",
]
