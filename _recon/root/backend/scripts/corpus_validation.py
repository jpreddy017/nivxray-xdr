"""Large-Corpus Validation Harness · Architectural Coverage Report.

Runs a curated set of payloads through the full production pipeline:

    payload → UAIE Orchestrator
            → behavior_extractor.extract_behaviors      (Producer)
            → projections.mitre/kill_chain/impact       (Projections)
            → evidence_driven_recommendations           (Engine)

and emits a JSON report answering (per the P0.9 directive):

    · Evidence → Behavior coverage %, unmapped evidence, dupes
    · Behavior → Projection : behaviors without MITRE / KC / impact
    · Projection → Recommendation : dead projections
    · Fired / suppressed / unreachable rules
    · Behavior-frequency distribution
    · Orphan / dead detection
    · Latency per stage (median + p95)
    · Regression diff vs the previous report

Usage::

    python scripts/corpus_validation.py \
           --manifest corpus/manifest.json \
           --previous corpus/reports/prev.json \
           --out      corpus/reports/latest.json

This module is also importable — ``run_corpus(manifest)`` returns
the report dict directly (used by ``tests/test_corpus_validation.py``
and by the coverage-metrics endpoint in a later phase).
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import statistics
import sys
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

# Allow ``python scripts/corpus_validation.py`` execution.
_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from services.uaie import plugins as _p                        # noqa: E402,F401
from services.uaie.orchestrator import Orchestrator             # noqa: E402
from services.uaie.behavior_extractor import extract_behaviors  # noqa: E402
from services.ida.behaviors import (                              # noqa: E402
    Behavior, collect_outcome_inputs_from_behaviors,
    LOLBAS_BINARY_TO_BEHAVIORS, MALWARE_FAMILY_TO_BEHAVIORS,
    CVE_TO_BEHAVIORS,
)
from services.ida.projections.mitre       import BEHAVIOR_TO_MITRE       # noqa: E402
from services.ida.projections.kill_chain  import BEHAVIOR_TO_KILL_CHAIN  # noqa: E402
from services.ida.projections.impact      import BEHAVIOR_TO_IMPACTS     # noqa: E402
from services.mitigation.evidence_driven.investigation_outcome import (  # noqa: E402
    empty_outcome,
)
from services.mitigation.evidence_driven.engine import (             # noqa: E402
    evidence_driven_recommendations,
)
from services.mitigation.evidence_driven.attack_posture_normalizer import (
    normalize_attack_posture,                                        # noqa: E402
)
from services.mitigation.evidence_driven import rule_library         # noqa: E402


REPORT_SCHEMA_VERSION = "1.0"


# ══════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════
def run_corpus(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Execute every case in ``manifest`` and return the coverage
    report.  ``manifest`` shape::

        {"cases": [
            {"id": "certutil", "payload": "…",  "encoding": "utf-8"},
            {"id": "ransom",   "payload": "…", "encoding": "utf-8"},
            {"id": "ps_cs",    "payload": "…",  "encoding": "base64"},
         ]}
    """
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                          max_artifacts=128, max_depth=16)

    per_case: List[Dict[str, Any]] = []
    stage_lat: Dict[str, List[float]] = defaultdict(list)

    behavior_freq:          Counter = Counter()
    provenance_freq:        Counter = Counter()
    recommendation_freq:    Counter = Counter()
    behaviors_seen:         set = set()
    recommendations_seen:   set = set()
    mitre_seen:             set = set()
    unmapped_evidence:      Counter = Counter()
    duplicate_behavior_hits: int = 0

    for c in manifest.get("cases") or []:
        r = _run_one_case(c, orch, stage_lat)
        per_case.append(r)
        behavior_freq.update(r["behavior_types"])
        provenance_freq.update(r["provenance_distribution"])
        recommendation_freq.update(r["recommendation_ids"])
        behaviors_seen.update(r["behavior_types"])
        recommendations_seen.update(r["recommendation_ids"])
        mitre_seen.update(r["mitre_ids"])
        for u in r["unmapped_evidence"]:
            unmapped_evidence[u] += 1
        duplicate_behavior_hits += r["duplicate_behavior_hits"]

    # ── Layer coverage ────────────────────────────────────────
    # Benign cases are architectural true-negatives: they SHOULD
    # produce zero behaviors.  Counting them in the denominator
    # would conflate the "no false positives" property with a
    # coverage failure, so they are excluded from the coverage
    # ratio (they remain in ``per_case`` for full observability).
    scored_cases = [c for c in per_case
                        if not str(c.get("id", "")).startswith("benign")]
    total_cases = len(scored_cases) or 1
    cases_with_behaviors = sum(1 for c in scored_cases if c["behavior_types"])
    cases_with_projection = sum(1 for c in scored_cases if c["mitre_ids"]
                                     or c["kill_chain_tags"]
                                     or c["impact_tags"])
    cases_with_recs = sum(1 for c in scored_cases if c["recommendation_ids"])

    # ── Dead / orphan detection ───────────────────────────────
    all_behavior_types    = set(BEHAVIOR_TO_MITRE.keys())
    dead_behaviors        = sorted(all_behavior_types - behaviors_seen)
    orphan_behaviors      = [b for b in behaviors_seen
                                 if not BEHAVIOR_TO_MITRE.get(b)]
    behaviors_without_kc  = [b for b in behaviors_seen
                                 if not BEHAVIOR_TO_KILL_CHAIN.get(b)]
    behaviors_without_imp = [b for b in behaviors_seen
                                 if not BEHAVIOR_TO_IMPACTS.get(b)]

    all_rule_ids = _rule_id_universe()
    dead_rules   = sorted(all_rule_ids - recommendations_seen)
    dead_rule_classification = _classify_dead_rules(dead_rules, behaviors_seen)

    # ── Traceability aggregate ──────────────────────────────────
    total_behaviors = sum(c["behaviors_count"] for c in per_case)
    total_complete  = sum(c["traceability"]["complete_chains"]
                              for c in per_case)
    total_broken    = sum(len(c["traceability"]["broken_chains"])
                              for c in per_case)

    # ── Latency stats ─────────────────────────────────────────
    latency_summary: Dict[str, Dict[str, float]] = {}
    for stage, xs in stage_lat.items():
        if not xs:
            continue
        latency_summary[stage] = {
            "count":  len(xs),
            "median": round(statistics.median(xs) * 1000, 2),
            "p95":    round(sorted(xs)[max(0, int(len(xs) * 0.95) - 1)] * 1000, 2),
            "max":    round(max(xs) * 1000, 2),
        }

    # ── Rule Efficiency (P0.13) ──────────────────────────────────
    # Per-rule diagnostic: which rules match evidence, which
    # actually fire, which are shadowed by stricter rules of the
    # same category.  This is the counterpart to Consumer
    # Reachability — one is a behavior-side view, the other a
    # rule-side view of analyst value.
    rule_efficiency = _rule_efficiency(per_case, behaviors_seen,
                                             recommendation_freq)

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime()),
        "corpus_size":    len(per_case),
        "coverage": {
            "evidence_to_behavior_pct": round(
                cases_with_behaviors / total_cases * 100, 1),
            "behavior_to_projection_pct": round(
                cases_with_projection / total_cases * 100, 1),
            "projection_to_recommendation_pct": round(
                cases_with_recs / total_cases * 100, 1),
        },
        "behavior_frequency":       dict(behavior_freq.most_common()),
        "provenance_distribution":  dict(provenance_freq),
        "recommendation_frequency": dict(recommendation_freq.most_common()),
        "dead_behavior_types":      dead_behaviors,
        "orphan_behavior_types":    sorted(orphan_behaviors),
        "behaviors_missing_kill_chain_projection": sorted(behaviors_without_kc),
        "behaviors_missing_impact_projection":     sorted(behaviors_without_imp),
        "dead_recommendation_rules": dead_rules,
        "dead_rule_classification":  dead_rule_classification,
        "unmapped_evidence_summary": dict(unmapped_evidence.most_common(20)),
        "duplicate_behavior_hits":   duplicate_behavior_hits,
        "mitre_techniques_seen":     sorted(mitre_seen),
        "traceability_aggregate": {
            "total_behaviors":  total_behaviors,
            "complete_chains":  total_complete,
            "broken_chains":    total_broken,
            "complete_pct":     (round(total_complete / total_behaviors
                                          * 100, 1)
                                    if total_behaviors else 100.0),
        },
        "rule_efficiency":           rule_efficiency,
        "latency_ms":                latency_summary,
        "per_case":                  per_case,
    }


def diff_reports(prev: Dict[str, Any],
                    curr: Dict[str, Any]) -> Dict[str, Any]:
    """Return a diff highlighting regressions between two reports."""
    def _delta(k: str) -> Dict[str, Any]:
        p = (prev.get("coverage") or {}).get(k, 0.0)
        c = (curr.get("coverage") or {}).get(k, 0.0)
        return {"prev": p, "curr": c, "delta": round(c - p, 2)}
    added_dead = sorted(set(curr.get("dead_recommendation_rules") or [])
                                - set(prev.get("dead_recommendation_rules") or []))
    resolved_dead = sorted(set(prev.get("dead_recommendation_rules") or [])
                                - set(curr.get("dead_recommendation_rules") or []))
    new_orphans   = sorted(set(curr.get("orphan_behavior_types") or [])
                                 - set(prev.get("orphan_behavior_types") or []))
    return {
        "coverage_delta": {
            "evidence_to_behavior":       _delta("evidence_to_behavior_pct"),
            "behavior_to_projection":     _delta("behavior_to_projection_pct"),
            "projection_to_recommendation": _delta(
                                             "projection_to_recommendation_pct"),
        },
        "newly_dead_rules":       added_dead,
        "resolved_dead_rules":    resolved_dead,
        "new_orphan_behaviors":   new_orphans,
    }


# ══════════════════════════════════════════════════════════════════
# Internals
# ══════════════════════════════════════════════════════════════════
def _run_one_case(case: Dict[str, Any],
                     orch: Orchestrator,
                     stage_lat: Dict[str, List[float]]) -> Dict[str, Any]:
    # ── Structured cases (malware / CVE / LOLBAS references) ──
    # Some evidence surfaces (named malware families, CVE IDs)
    # don't come from UAIE — they arrive from Stage-4 report
    # extractors on URL-ingested reports.  The harness lets a case
    # skip UAIE entirely and inject the ``extract_all()``-shaped
    # dict directly.  This exercises malware_reference and
    # cve_reference provenance without needing a real URL.
    structured = case.get("structured")
    if structured is not None:
        from services.ida.behaviors import generate_behaviors
        t0 = time.perf_counter()
        behaviors = generate_behaviors(structured)
        stage_lat["behavior_extraction"].append(
            time.perf_counter() - t0)
        orch_result_evidence: List[Any] = []
    else:
        payload = _decode_payload(case)
        t0 = time.perf_counter()
        orch_result = orch.run(payload,
                                 filename=case.get("id", "case") + ".txt")
        stage_lat["uaie_orchestrator"].append(
            time.perf_counter() - t0)
        t0 = time.perf_counter()
        behaviors = extract_behaviors(orch_result)
        stage_lat["behavior_extraction"].append(
            time.perf_counter() - t0)
        orch_result_evidence = list(getattr(orch_result, "evidence", None) or [])

    # Stage · Aggregate projections
    t0 = time.perf_counter()
    inputs = collect_outcome_inputs_from_behaviors(behaviors)
    stage_lat["projection_aggregation"].append(time.perf_counter() - t0)

    # Stage · Recommendation engine
    outcome = empty_outcome()
    outcome["behaviors"]        = inputs["behaviors"]
    outcome["impacts"]          = inputs["impacts"]
    outcome["mitre_techniques"] = inputs["mitre_techniques"]
    outcome = normalize_attack_posture(outcome)
    t0 = time.perf_counter()
    engine_result = evidence_driven_recommendations(
        investigation_outcome=outcome)
    stage_lat["engine"].append(time.perf_counter() - t0)

    behavior_types = [b.behavior_type for b in behaviors]
    provenance_bag = [b.provenance    for b in behaviors]

    # ── Duplicate detection ─────────────────────────────────────
    seen: Dict[str, int] = defaultdict(int)
    for b in behaviors:
        seen[b.behavior_type] += 1
    dup_hits = sum(1 for _, n in seen.items() if n > 1)

    # ── Unmapped evidence · UAIE only ───────────────────────────
    consumed_kinds = {"commandline", "text", "lolbas"}
    unmapped: List[str] = []
    for ev in orch_result_evidence:
        kind = getattr(ev, "kind", None)
        if kind and kind not in consumed_kinds:
            unmapped.append(kind)

    # ── Traceability Completeness ──────────────────────────────
    # A "complete chain" is a Behavior that has at least one MITRE
    # id + at least one kill-chain tag AND is traceable to at
    # least one fired recommendation.  Broken chains carry a
    # standardized ``broken_at`` taxonomy so dashboards / CI /
    # reports share vocabulary.
    complete_chains = 0
    broken_chains:  List[Dict[str, Any]] = []
    for b in behaviors:
        m  = list(BEHAVIOR_TO_MITRE.get(b.behavior_type, ()))
        kc = list(BEHAVIOR_TO_KILL_CHAIN.get(b.behavior_type, ()))
        im = list(BEHAVIOR_TO_IMPACTS.get(b.behavior_type, ()))
        if not m and not kc:
            broken_chains.append({
                "behavior_id":     b.id,
                "behavior_type":   b.behavior_type,
                "broken_at":       "BROKEN_AT_PROJECTION",
                "last_successful": "BEHAVIOR",
                "reason":          "no MITRE/kill-chain projection for "
                                       "this behavior_type",
            })
            continue
        if not m:
            broken_chains.append({
                "behavior_id":     b.id,
                "behavior_type":   b.behavior_type,
                "broken_at":       "BROKEN_AT_PROJECTION",
                "last_successful": "BEHAVIOR",
                "reason":          "MITRE map missing for behavior_type",
                "has_kill_chain":  True, "has_mitre": False,
            })
            continue
        matched = False
        for r in engine_result.get("recommendations", []):
            r_mitre = set(r.get("mitre") or ())
            r_evid  = set(r.get("evidence_dims") or ())
            if set(m) & r_mitre or set(kc) & r_evid or set(im) & r_evid:
                matched = True
                break
        if matched:
            complete_chains += 1
        else:
            broken_chains.append({
                "behavior_id":     b.id,
                "behavior_type":   b.behavior_type,
                "broken_at":       "BROKEN_AT_RECOMMENDATION",
                "last_successful": "PROJECTION",
                "reason":          "no rule consumes any of the projected "
                                       "MITRE / kill-chain / impact tags",
                "projections":     {"mitre": m, "kill_chain": kc,
                                       "impacts": im},
            })

    return {
        "id":                       case.get("id"),
        "behaviors_count":          len(behaviors),
        "behavior_types":           behavior_types,
        "provenance_distribution":  provenance_bag,
        "kill_chain_tags":          inputs["behaviors"],
        "impact_tags":              inputs["impacts"],
        "mitre_ids":                inputs["mitre_techniques"],
        "recommendation_ids":       sorted(r["id"] for r in
                                                engine_result.get(
                                                     "recommendations", [])),
        "verdict":                  engine_result.get("verdict"),
        "duplicate_behavior_hits":  dup_hits,
        "unmapped_evidence":        unmapped,
        "traceability": {
            "complete_chains":  complete_chains,
            "broken_chains":    broken_chains,
            "complete_pct":     (round(complete_chains / len(behaviors) * 100, 1)
                                    if behaviors else 100.0),
        },
    }


def _decode_payload(case: Dict[str, Any]) -> bytes:
    p = case.get("payload") or ""
    enc = (case.get("encoding") or "utf-8").lower()
    if enc == "base64":
        return base64.b64decode(p)
    if isinstance(p, (bytes, bytearray)):
        return bytes(p)
    return str(p).encode("utf-8")


def _rule_id_universe() -> set:
    ids: set = set()
    for group in ("INVESTIGATE_RULES", "HUNT_RULES", "CONTAIN_RULES",
                    "ERADICATE_RULES", "RECOVER_RULES", "HARDEN_RULES"):
        for r in getattr(rule_library, group, []):
            ids.add(r.id)
    return ids


def _classify_dead_rules(dead_rules: List[str],
                              behaviors_seen: set) -> Dict[str, List[str]]:
    """Categorise dead rules per user directive (P0.10):

        legitimately_dormant : rare or specialised condition
        corpus_gap           : the pipeline CAN produce the required
                                signal — corpus just doesn't exercise
                                it yet (MITRE tid IS reachable from
                                some Behavior)
        behavior_gap         : rule's MITRE tid is NOT reachable from
                                any Behavior (extractor gap)
        logic_gap            : rule has no MITRE tid at all — trigger
                                depends on evidence dims / bags only
        mapping_gap          : reserved — surfaced when a Behavior
                                exists but its MITRE mapping is empty

    """
    # ATT&CK ids reachable from ANY Behavior in the vocab.
    reachable_mitre: set = set()
    for _btype, tids in BEHAVIOR_TO_MITRE.items():
        reachable_mitre.update(tids)
    # ATT&CK ids reachable from Behaviors we've SEEN in this corpus.
    seen_mitre: set = set()
    for btype in behaviors_seen:
        seen_mitre.update(BEHAVIOR_TO_MITRE.get(btype, ()))

    classified: Dict[str, List[str]] = {
        "legitimately_dormant": [],
        "corpus_gap":            [],
        "behavior_gap":          [],
        "logic_gap":             [],
        "mapping_gap":           [],
    }
    for rid in dead_rules:
        rule = _find_rule(rid)
        rule_mitre = set(getattr(rule, "mitre", None) or ())
        if not rule_mitre:
            classified["logic_gap"].append(rid)
            continue
        if rule_mitre & seen_mitre:
            # Rule's MITRE overlapped a seen Behavior but no rec
            # fired · trigger has additional guards → dormant.
            classified["legitimately_dormant"].append(rid)
        elif rule_mitre & reachable_mitre:
            # Pipeline CAN produce this signal · corpus doesn't.
            classified["corpus_gap"].append(rid)
        else:
            classified["behavior_gap"].append(rid)
    return classified


def _find_rule(rule_id: str) -> Any:
    for group in ("INVESTIGATE_RULES", "HUNT_RULES", "CONTAIN_RULES",
                    "ERADICATE_RULES", "RECOVER_RULES", "HARDEN_RULES"):
        for r in getattr(rule_library, group, []):
            if r.id == rule_id:
                return r
    return None


def _rule_efficiency(per_case: List[Dict[str, Any]],
                        behaviors_seen: set,
                        recommendation_freq: Counter) -> Dict[str, Any]:
    """Per-rule Triggered / Fired / Suppressed / Shadowed table.

        · triggered  — rule's ATT&CK tuple overlapped ≥ 1 seen
                        behavior's MITRE projection (its precondition
                        was met by evidence in at least one case)
        · fired      — the rule actually emitted a recommendation in
                        ≥ 1 case (``recommendation_freq[rule.id] > 0``)
        · suppressed — triggered but never fired · guards blocked it
        · shadowed   — fired, but always alongside ≥ 1 higher-priority
                        rule of the SAME group (analyst-visible value
                        may already be delivered by the other rule)

    ``rule_shadow_pairs`` lists the specific shadowing pairs so the
    triage UI can render them.
    """
    # Behaviors → MITRE tids reachable from seen Behaviors.
    seen_mitre: set = set()
    for btype in behaviors_seen:
        seen_mitre.update(BEHAVIOR_TO_MITRE.get(btype, ()))

    # Per-case: which rules co-fired (used for shadow detection).
    co_fire_matrix: List[Tuple[str, List[str]]] = [
        (str(c.get("id")), list(c.get("recommendation_ids") or []))
        for c in per_case
    ]

    per_rule: List[Dict[str, Any]] = []
    for group in ("INVESTIGATE_RULES", "HUNT_RULES", "CONTAIN_RULES",
                    "ERADICATE_RULES", "RECOVER_RULES", "HARDEN_RULES"):
        for r in getattr(rule_library, group, []):
            rid       = r.id
            r_mitre   = set(getattr(r, "mitre", None) or ())
            fired_ct  = int(recommendation_freq.get(rid, 0))
            # Triggered = precondition met by evidence in at least
            # one case.  MITRE overlap is the primary signal;
            # actually firing also counts (rules may match on
            # kill_chain / impact / evidence_dims outside MITRE).
            triggered = bool(r_mitre & seen_mitre) or fired_ct > 0

            # Shadowed detection · rule fired but only alongside
            # another rule of the same group in every case it fired.
            shadowed_by: List[str] = []
            if fired_ct > 0:
                same_group_ids = {rr.id for rr in
                                       getattr(rule_library, group, [])
                                       if rr.id != rid}
                if same_group_ids:
                    always_paired: set = None  # type: ignore
                    for _case_id, fired_here in co_fire_matrix:
                        if rid not in fired_here:
                            continue
                        peers = set(fired_here) & same_group_ids
                        if always_paired is None:
                            always_paired = set(peers)
                        else:
                            always_paired &= peers
                    if always_paired:
                        shadowed_by = sorted(always_paired)

            status = ("fired"      if fired_ct > 0 and not shadowed_by
                       else "shadowed"   if fired_ct > 0
                       else "suppressed" if triggered
                       else "dormant")
            per_rule.append({
                "rule_id":          rid,
                "group":            group.replace("_RULES", "").lower(),
                "mitre":            sorted(r_mitre),
                "triggered":        triggered,
                "fired":            fired_ct,
                "suppressed":       triggered and fired_ct == 0,
                "shadowed_by":      shadowed_by,
                "status":           status,
            })

    total = len(per_rule) or 1
    fired      = sum(1 for r in per_rule if r["status"] == "fired")
    shadowed   = sum(1 for r in per_rule if r["status"] == "shadowed")
    suppressed = sum(1 for r in per_rule if r["status"] == "suppressed")
    dormant    = sum(1 for r in per_rule if r["status"] == "dormant")

    return {
        "per_rule": per_rule,
        "summary": {
            "total":        total,
            "fired":        fired,
            "shadowed":     shadowed,
            "suppressed":   suppressed,
            "dormant":      dormant,
            "efficiency_pct": round(fired / total * 100, 1),
        },
    }


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def _cli() -> int:
    ap = argparse.ArgumentParser(
        description="Corpus Validation Harness · Architectural Coverage Report")
    ap.add_argument("--manifest", required=True,
                        help="Path to corpus manifest JSON")
    ap.add_argument("--out",      required=True,
                        help="Path where the report JSON is written")
    ap.add_argument("--previous", default=None,
                        help="Optional previous report JSON for regression diff")
    args = ap.parse_args()

    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    report   = run_corpus(manifest)

    if args.previous:
        prev = json.loads(pathlib.Path(args.previous).read_text(encoding="utf-8"))
        report["regression_diff"] = diff_reports(prev, report)

    outp = pathlib.Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Corpus report written to {outp}")
    print(f"  cases                       : {report['corpus_size']}")
    print(f"  Evidence→Behavior           : {report['coverage']['evidence_to_behavior_pct']}%")
    print(f"  Behavior→Projection         : {report['coverage']['behavior_to_projection_pct']}%")
    print(f"  Projection→Recommendation   : {report['coverage']['projection_to_recommendation_pct']}%")
    print(f"  Dead behavior types         : {len(report['dead_behavior_types'])}")
    print(f"  Dead recommendation rules   : {len(report['dead_recommendation_rules'])}")
    return 0


if __name__ == "__main__":                          # pragma: no cover
    raise SystemExit(_cli())
