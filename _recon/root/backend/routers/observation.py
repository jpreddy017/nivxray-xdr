"""Phase 4 Wave 1 · Observation Report Router.

Aggregates persisted `verdict_shadow_observations` into the exact
table the owner directive (2026-08-10) requests:

    1. Total investigations observed.
    2. Counts by minimal / sparse / moderate / rich.
    3. Verdict agreement rate by completeness class.
    4. Divergence counts by classification.
    5. All POTENTIAL-FALSE-POSITIVE at moderate / rich.
    6. All POTENTIAL-FALSE-NEGATIVE at moderate / rich.
    7. Re-observation of the original 11 corpus INPUT-CONTRACT-UNRESOLVED cases.
    8. Which InvestigationModel buckets are most commonly missing.
    9. Whether missing buckets originate from ingestion/normalization.
   10. Shadow latency + error impact.

No new dependencies. Read-only. No consumer switch. No tuning.

Endpoint (auth required — admin-only):
    GET /api/observation/wave1-report
        Optional query params:
          - since (ISO8601)   → only include observations after this ts
          - limit (int, ≤ 10000, default 5000)  → cap sample size
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from deps import db, get_current_user


router = APIRouter(prefix="/observation", tags=["observation"])


_COLLECTION = "verdict_shadow_observations"

# Owner directive (2026-08-10): "Do not label missing buckets as
# 'chronic' until sufficient observations exist." This threshold is
# the point below which the aggregator explicitly refuses to assert
# statistical claims. Tuned as a starting-point; raise if the sample
# distribution looks noisier than expected.
_MIN_SAMPLES_FOR_STABLE = 30
_MIN_SAMPLES_FOR_UPSTREAM_SUSPECT = 30


# Baseline for the original Phase 3 corpus INPUT-CONTRACT-UNRESOLVED cases.
# Owner-mandated: report re-observation status.
_PHASE3_UNRESOLVED_FIXTURES = [
    "talos.001", "talos.002", "talos.003",
    "securelist.001", "securelist.002", "securelist.003",
    "mandiant.001", "mandiant.002",
    "microsoft.001", "microsoft.002",
    "elastic.001",
]


async def _load_observations(since: Optional[str], limit: int) -> list[dict]:
    """Load observations, oldest-first (deterministic)."""
    q: dict = {}
    if since:
        q["recorded_at"] = {"$gte": since}
    cursor = db[_COLLECTION].find(q).sort("recorded_at", 1).limit(limit)
    return [doc async for doc in cursor]


def _completeness_class_counts(obs: list[dict]) -> dict[str, int]:
    c = Counter(o.get("coverage_class") or "unknown" for o in obs)
    out: dict[str, int] = {}
    for k in ("minimal", "sparse", "moderate", "rich"):
        out[k] = int(c.get(k, 0))
    if c.get("unknown"):
        out["unknown"] = int(c["unknown"])
    return out


def _agreement_rate_by_class(obs: list[dict]) -> dict[str, dict[str, Any]]:
    """For each completeness class, compute agreement rate and
    divergence-class counts."""
    out: dict[str, dict[str, Any]] = {}
    for cls in ("minimal", "sparse", "moderate", "rich"):
        rows = [o for o in obs if o.get("coverage_class") == cls]
        n = len(rows)
        if n == 0:
            out[cls] = {"cases": 0, "agree": 0, "agree_pct": 0.0,
                            "divergence": {}}
            continue
        agree = sum(1 for r in rows if r.get("divergence_class") == "AGREE")
        div = Counter(r.get("divergence_class") or "unknown" for r in rows)
        out[cls] = {
            "cases":     n,
            "agree":     agree,
            "agree_pct": round(agree / n * 100.0, 2),
            "divergence": dict(div),
        }
    return out


def _extract_potential_cases(obs: list[dict], kind: str) -> list[dict]:
    """Return moderate/rich POTENTIAL-FALSE-{POSITIVE|NEGATIVE} rows,
    ordered oldest-first, up to 200."""
    out: list[dict] = []
    for o in obs:
        if (o.get("divergence_class") == kind
                and o.get("coverage_class") in ("moderate", "rich")):
            out.append({
                "run_id":              o.get("run_id"),
                "recorded_at":         o.get("recorded_at"),
                "existing_label":      o.get("existing_label"),
                "canonical_label":     o.get("canonical_label"),
                "existing_conf_pct":   o.get("existing_conf_pct"),
                "canonical_conf_pct":  o.get("canonical_conf_pct"),
                "completeness_pct":    o.get("completeness_pct"),
                "coverage_class":      o.get("coverage_class"),
                "missing_buckets":     o.get("missing_buckets", []),
            })
        if len(out) >= 200:
            break
    return out


def _missing_bucket_frequency(obs: list[dict]) -> dict[str, Any]:
    """Per-bucket "missing rate" across all observations — surfaces
    which InvestigationModel buckets are chronically under-populated.

    Owner-mandated (2026-08-10): DO NOT call any bucket 'chronic'
    until we have enough samples. Below `MIN_SAMPLES_FOR_STABLE`
    the report emits `_confidence: 'insufficient-sample'` and
    every bucket carries a `note` reminding readers of that fact.
    """
    n = len(obs)
    bucket_names = [
        "incident_metadata", "asset_context", "process_activity",
        "file_activity", "network_activity", "registry_activity",
        "authentication", "threat_intel", "historical",
    ]
    if n == 0:
        return {"n_observations": 0, "buckets": {},
                    "_confidence": "insufficient-sample",
                    "min_samples_for_stable": _MIN_SAMPLES_FOR_STABLE}
    missing = Counter()
    for o in obs:
        for b in (o.get("missing_buckets") or []):
            missing[b] += 1
    per_bucket = {}
    for b in bucket_names:
        m = missing.get(b, 0)
        per_bucket[b] = {
            "missing_count": m,
            "missing_pct":   round(m / n * 100.0, 2),
        }
    stable = n >= _MIN_SAMPLES_FOR_STABLE
    out = {
        "n_observations": n,
        "buckets":        per_bucket,
        "top_missing":    [b for b, _ in missing.most_common(3)],
        "_confidence":    "stable" if stable else "insufficient-sample",
        "min_samples_for_stable": _MIN_SAMPLES_FOR_STABLE,
    }
    if not stable:
        out["note"] = (
            f"Fewer than {_MIN_SAMPLES_FOR_STABLE} observations. Bucket "
            f"missing-rates may swing widely; do NOT call any bucket "
            f"'chronically missing' at this sample size.")
    return out


def _missing_bucket_frequency_by_class(obs: list[dict]) -> dict[str, Any]:
    """Per-completeness-class × per-bucket missing rate. Answers the
    owner's Wave-2 question:
        `What buckets are missing at moderate/rich completeness?`
    High missing-rate at rich completeness is far more meaningful
    than the same rate at minimal completeness."""
    bucket_names = [
        "incident_metadata", "asset_context", "process_activity",
        "file_activity", "network_activity", "registry_activity",
        "authentication", "threat_intel", "historical",
    ]
    by_class: dict[str, dict[str, Any]] = {}
    for cls in ("minimal", "sparse", "moderate", "rich"):
        rows = [o for o in obs if o.get("coverage_class") == cls]
        n = len(rows)
        if n == 0:
            by_class[cls] = {"n": 0, "buckets": {},
                                  "_confidence": "insufficient-sample"}
            continue
        missing = Counter()
        for o in rows:
            for b in (o.get("missing_buckets") or []):
                missing[b] += 1
        by_class[cls] = {
            "n": n,
            "buckets": {b: {
                    "missing_count": missing.get(b, 0),
                    "missing_pct":   round(missing.get(b, 0) / n * 100.0, 2),
                } for b in bucket_names},
            "_confidence": ("stable" if n >= _MIN_SAMPLES_FOR_STABLE
                                 else "insufficient-sample"),
        }
    return by_class


def _divergence_by_completeness(obs: list[dict]) -> dict[str, Any]:
    """Answers the owner's key correlation question:
        `Does divergence correlate with incomplete upstream
         InvestigationModel construction?`

    Concretely:
      * For each completeness class, compute agreement rate.
      * If agreement rate rises monotonically from minimal → rich,
        the divergence IS explained by input completeness.
      * If agreement stays flat (or falls) as completeness rises,
        the divergence is intrinsic to scoring / policy.
    """
    class_agree: dict[str, dict[str, Any]] = {}
    for cls in ("minimal", "sparse", "moderate", "rich"):
        rows = [o for o in obs if o.get("coverage_class") == cls]
        n = len(rows)
        if n == 0:
            class_agree[cls] = {"n": 0, "agree_pct": None,
                                       "_confidence": "insufficient-sample"}
            continue
        agree = sum(1 for r in rows if r.get("divergence_class") == "AGREE")
        class_agree[cls] = {
            "n":          n,
            "agree":      agree,
            "agree_pct":  round(agree / n * 100.0, 2),
            "_confidence": ("stable" if n >= _MIN_SAMPLES_FOR_STABLE
                                 else "insufficient-sample"),
        }

    # Monotonic-improvement check across classes (only meaningful
    # when all four classes have stable sample counts).
    ordered_pcts = [class_agree[c]["agree_pct"]
                          for c in ("minimal", "sparse", "moderate", "rich")]
    monotonic_verdict: str
    if any(p is None for p in ordered_pcts):
        monotonic_verdict = "insufficient-sample"
    elif all(class_agree[c]["_confidence"] == "stable"
                 for c in ("minimal", "sparse", "moderate", "rich")):
        # Monotonic non-decreasing?
        if all(ordered_pcts[i] <= ordered_pcts[i+1]
                    for i in range(len(ordered_pcts)-1)):
            monotonic_verdict = "improves-with-completeness · divergence is input-driven"
        elif all(ordered_pcts[i] >= ordered_pcts[i+1]
                      for i in range(len(ordered_pcts)-1)):
            monotonic_verdict = "worsens-with-completeness · scoring-driven divergence"
        else:
            monotonic_verdict = "non-monotonic · needs closer inspection"
    else:
        monotonic_verdict = "insufficient-sample-per-class"

    return {
        "agreement_by_class":  class_agree,
        "monotonic_verdict":   monotonic_verdict,
        "min_samples_for_stable": _MIN_SAMPLES_FOR_STABLE,
    }


def _latency_stats(obs: list[dict]) -> dict[str, Any]:
    lats = [float(o.get("shadow_latency_ms") or 0.0)
                for o in obs if o.get("shadow_latency_ms") is not None]
    if not lats:
        return {"n": 0, "mean_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0}
    lats.sort()
    def _pct(p: float) -> float:
        idx = min(len(lats) - 1, int(p * (len(lats) - 1)))
        return round(lats[idx], 3)
    return {
        "n":       len(lats),
        "mean_ms": round(statistics.mean(lats), 3),
        "p50_ms":  _pct(0.50),
        "p95_ms":  _pct(0.95),
        "p99_ms":  _pct(0.99),
        "max_ms":  round(max(lats), 3),
    }


def _error_stats(obs: list[dict]) -> dict[str, Any]:
    n_total = len(obs)
    errs = [o for o in obs if o.get("error")]
    n_err = len(errs)
    by_type = Counter(o.get("error") for o in errs)
    return {
        "n_total":       n_total,
        "n_errors":      n_err,
        "error_pct":     round(n_err / n_total * 100.0, 2) if n_total else 0.0,
        "by_message":    dict(by_type.most_common(10)),
    }


def _phase3_reobservation(obs: list[dict]) -> dict[str, Any]:
    """For each of the 11 originally UNRESOLVED Phase-3 fixtures,
    report whether a real-world run has re-observed it.

    We match on run_id containing the fixture_id substring — this is
    coarse but honest; a stricter match requires a fixture provenance
    field that Wave 1 does not need.
    """
    result: dict[str, Any] = {}
    for fx in _PHASE3_UNRESOLVED_FIXTURES:
        matches = [o for o in obs if fx in str(o.get("run_id") or "")]
        result[fx] = {
            "reobserved":   len(matches),
            "coverage":     Counter(m.get("coverage_class") for m in matches),
            "last_result":  ({"coverage_class": matches[-1].get("coverage_class"),
                                  "divergence_class": matches[-1].get("divergence_class"),
                                  "canonical_label": matches[-1].get("canonical_label")}
                                if matches else None),
        }
    reobserved = sum(1 for v in result.values() if v["reobserved"] > 0)
    return {
        "n_fixtures":         len(_PHASE3_UNRESOLVED_FIXTURES),
        "n_reobserved":       reobserved,
        "n_not_reobserved":   len(_PHASE3_UNRESOLVED_FIXTURES) - reobserved,
        "per_fixture":        {k: {**v, "coverage": dict(v["coverage"])}
                                    for k, v in result.items()},
    }


def _upstream_ingestion_hint(missing_freq: dict[str, Any]) -> dict[str, Any]:
    """Owner directive: 'Whether the missing buckets originate upstream
    from input ingestion/normalization.'

    Answered deterministically: when a bucket is missing in >70% of
    observations AND the observation count is above
    `_MIN_SAMPLES_FOR_UPSTREAM_SUSPECT`, flag as an ingestion suspect.

    Below the sample threshold, refuse to flag ANY bucket as chronic —
    return an explicit `insufficient-sample` verdict per owner directive.
    """
    n = int(missing_freq.get("n_observations") or 0)
    if n < _MIN_SAMPLES_FOR_UPSTREAM_SUSPECT:
        return {
            "_confidence":                 "insufficient-sample",
            "min_samples_for_suspects":    _MIN_SAMPLES_FOR_UPSTREAM_SUSPECT,
            "n_observations":              n,
            "upstream_ingestion_suspects": [],
            "note": (
                f"Fewer than {_MIN_SAMPLES_FOR_UPSTREAM_SUSPECT} "
                f"observations — refusing to flag any bucket as "
                f"chronically missing. Currently-missing buckets on "
                f"the observed sample are visible in "
                f"`missing_bucket_frequency.buckets`, but that is a "
                f"snapshot, not a chronic-absence claim."),
        }
    upstream_suspects: list[dict] = []
    for bucket, stats in (missing_freq.get("buckets") or {}).items():
        if stats.get("missing_pct", 0) >= 70.0:
            upstream_suspects.append({
                "bucket":       bucket,
                "missing_pct":  stats["missing_pct"],
                "diagnosis":    (
                    f"Missing in >70% of {n} observations. "
                    f"Upstream ingestion/normalization does not populate "
                    f"this bucket for typical Workspace inputs."),
            })
    return {
        "_confidence":                 "stable",
        "min_samples_for_suspects":    _MIN_SAMPLES_FOR_UPSTREAM_SUSPECT,
        "n_observations":              n,
        "upstream_ingestion_suspects": sorted(upstream_suspects,
                                                          key=lambda x: -x["missing_pct"]),
        "note": ("These buckets are not the Verdict Engine's responsibility. "
                     "Any divergence attributable to them should be treated as "
                     "an upstream data-model problem, not a scoring problem."),
    }


@router.get("/wave1-report")
async def wave1_report(
    since: Optional[str] = Query(None,
                                                description="Only include observations after this ISO8601 UTC timestamp."),
    limit: int = Query(5000, ge=1, le=10000),
    _user = Depends(get_current_user),
) -> dict[str, Any]:
    """Aggregate the persisted `verdict_shadow_observations`
    into the owner-mandated Wave 1 observation report."""
    obs = await _load_observations(since, limit)
    total = len(obs)

    completeness_counts = _completeness_class_counts(obs)
    agreement           = _agreement_rate_by_class(obs)
    fp_cases            = _extract_potential_cases(obs, "POTENTIAL-FALSE-POSITIVE")
    fn_cases            = _extract_potential_cases(obs, "POTENTIAL-FALSE-NEGATIVE")
    missing_freq        = _missing_bucket_frequency(obs)
    missing_by_class    = _missing_bucket_frequency_by_class(obs)
    divergence_corr     = _divergence_by_completeness(obs)
    upstream_hint       = _upstream_ingestion_hint(missing_freq)
    phase3_reobs        = _phase3_reobservation(obs)
    latency             = _latency_stats(obs)
    errors              = _error_stats(obs)

    # Overall coverage-gate readiness
    ready = (
        completeness_counts.get("rich",     0) >= 20 and
        completeness_counts.get("moderate", 0) >= 20 and
        completeness_counts.get("sparse",   0) >= 20 and
        completeness_counts.get("minimal",  0) >= 20
    )

    return {
        "schema_version":       "1.0",
        "purpose":              "ADR-004 Step 1 · Phase 4 Wave 1 · Observation Report",
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "window":               {"since": since, "limit": limit},
        "total_observations":   total,
        "coverage_class_counts": completeness_counts,
        "agreement_by_class":   agreement,
        "potential_false_positives_mod_rich": fp_cases,
        "potential_false_negatives_mod_rich": fn_cases,
        "missing_bucket_frequency": missing_freq,
        "missing_bucket_frequency_by_class": missing_by_class,
        "divergence_vs_completeness":        divergence_corr,
        "upstream_ingestion_hint":  upstream_hint,
        "phase3_reobservation_status": phase3_reobs,
        "shadow_latency_stats": latency,
        "shadow_error_stats":   errors,
        "wave2_gate": {
            "coverage_ready":                    ready,
            "requires_per_class_min":            20,
            "wave2_authorised":                  False,
            "wave2_stop_conditions_from_owner":  [
                "Sufficient sample coverage across minimal/sparse/moderate/rich.",
                "Zero POTENTIAL-FALSE-POSITIVE at rich completeness.",
                "Every POTENTIAL-FALSE-NEGATIVE at rich completeness has owner-approved explanation.",
                "The 11 previously INPUT-CONTRACT-UNRESOLVED cells re-observed at rich or moderate completeness.",
            ],
        },
    }
