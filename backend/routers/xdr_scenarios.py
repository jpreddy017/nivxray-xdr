"""
xdr_scenarios.py — NivXRay XDR SOC-100 Scenario Intelligence layer.

Owner directive (locked, 2026-02-30):
  * Scenarios are investigation GUIDANCE only.
  * NEVER emit detection, evidence-state, or verdict from scenario data.
  * `Scenario knowledge  ≠  Incident evidence  ≠  Verdict`.
  * The corpus tells NivXRay what to LOOK for, NOT what HAPPENED.

The matcher computes a per-scenario `match_score` from the intersection
of the incident's OBSERVED technique_ids and process names with each
scenario's `attack_techniques` and `initial_observable` keywords, then
returns:

  {
    scenario_id, name, category, match_score,
    matching_techniques[],           # techniques present in evidence
    missing_techniques[],            # scenario techniques not yet seen
    recommended_pivots[],            # copy of scenario.pivots
    expected_evidence_gap[],         # evidence patterns NOT in incident
    next_step, detection_improvement
  }

The API surface:

  GET  /api/xdr/scenarios                  — full corpus (metadata)
  GET  /api/xdr/scenarios/{scenario_id}    — one scenario
  POST /api/xdr/investigation/{id}/scenario-match
                                           — matches for one incident
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Depends
from pymongo import MongoClient
import os

router = APIRouter(prefix="/api/xdr", tags=["xdr-scenarios"])

# Seed corpus is a static JSON file — the corpus is immutable at
# runtime (guidance layer only).  Never mutated by an incident.
_CORPUS_PATH = Path(__file__).resolve().parent.parent / "data" / "soc100_scenarios.json"
_CORPUS: Dict[str, Any] | None = None


def _load_corpus() -> Dict[str, Any]:
    global _CORPUS
    if _CORPUS is not None:
        return _CORPUS
    with _CORPUS_PATH.open("r", encoding="utf-8") as f:
        _CORPUS = json.load(f)
    return _CORPUS


# ── Mongo (read-only for incidents) ─────────────────────────────
def _mongo():
    client = MongoClient(os.environ["MONGO_URL"])
    return client[os.environ["DB_NAME"]]


# ── Endpoints ───────────────────────────────────────────────────
@router.get("/scenarios")
def list_scenarios(category: str | None = None) -> Dict[str, Any]:
    """Full corpus listing.  Filter by category if provided."""
    corpus = _load_corpus()
    scenarios = corpus["scenarios"]
    if category:
        scenarios = [s for s in scenarios if s.get("category") == category]
    # Return lean cards suitable for a list view; the full body is at /scenarios/{id}
    return {
        "version": corpus.get("version"),
        "count":   len(scenarios),
        "total":   len(corpus["scenarios"]),
        "categories": sorted({s["category"] for s in corpus["scenarios"]}),
        "scenarios": [
            {k: s[k] for k in ("scenario_id", "scenario_number", "category",
                                                            "name", "threat", "attack_techniques",
                                                            "source_page")}
            for s in scenarios
        ],
    }


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> Dict[str, Any]:
    corpus = _load_corpus()
    for s in corpus["scenarios"]:
        if s["scenario_id"].lower() == scenario_id.lower():
            return s
    raise HTTPException(status_code=404,
                                          detail=f"scenario {scenario_id} not found")


@router.post("/investigation/{incident_id}/scenario-match")
def scenario_match(incident_id: str) -> Dict[str, Any]:
    """Match the incident's OBSERVED evidence to scenarios.

    Semantic invariants (locked):
      * The match returns GUIDANCE only — recommended pivots,
        expected-evidence gap, next-step, detection-improvement.
      * It NEVER injects techniques or evidence into the incident.
      * `match_score` is a similarity metric, not a verdict.
    """
    db = _mongo()
    inc = db.incidents.find_one({"id": incident_id}) \
                or db.incidents.find_one({"_id": incident_id})
    if not inc:
        raise HTTPException(status_code=404,
                                              detail=f"incident {incident_id} not found")

    # Extract OBSERVED technique_ids and process names from the incident.
    observed_techs = _extract_incident_techniques(inc)
    observed_processes = _extract_incident_processes(inc)
    observed_keywords = observed_processes | _extract_incident_keywords(inc)

    corpus = _load_corpus()
    matches: List[Dict[str, Any]] = []
    for s in corpus["scenarios"]:
        stechs = set(s.get("attack_techniques") or [])
        matching_techs = list(observed_techs & stechs)
        # Keyword hits on initial_observable + expected_evidence.
        kw_text = " ".join([
            s.get("initial_observable") or "",
            s.get("threat") or "",
            " ".join(s.get("expected_evidence") or []),
        ]).lower()
        kw_hits = sum(1 for k in observed_keywords if k and k.lower() in kw_text)
        # Base score: 3 pts per matching technique + 1 pt per keyword hit.
        # Deterministic — no ML, no fabrication.
        score = 3 * len(matching_techs) + kw_hits
        if score <= 0:
            continue
        gap = [t for t in stechs if t not in observed_techs]
        matches.append({
            "scenario_id": s["scenario_id"],
            "scenario_number": s.get("scenario_number"),
            "name": s["name"],
            "category": s["category"],
            "threat": s.get("threat"),
            "match_score": score,
            "matching_techniques": matching_techs,
            "missing_techniques": gap,
            "recommended_pivots": s.get("pivots") or [],
            "expected_evidence_gap":
                [e for e in (s.get("expected_evidence") or [])
                    if not any(k for k in observed_keywords
                                    if k and k.lower() in e.lower())],
            "next_step": s.get("next_step"),
            "detection_improvement": s.get("detection_improvement"),
            "false_positive_considerations":
                s.get("false_positive_considerations") or [],
            "source_page": s.get("source_page"),
        })

    matches.sort(key=lambda m: m["match_score"], reverse=True)

    return {
        "incident_id": incident_id,
        "observed_techniques": sorted(observed_techs),
        "observed_processes":  sorted(observed_processes),
        "matches": matches[:10],
        "corpus_version": corpus.get("version"),
        "invariant":
            "Scenario knowledge ≠ Incident evidence ≠ Verdict.  "
            "The match returns guidance only — pivots, missing evidence, "
            "next-step, detection-improvement.  It NEVER injects "
            "techniques, evidence, or verdicts into the incident.",
    }


# ── Extractors — pure, deterministic, no side-effects ────────────
_TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _extract_incident_techniques(inc: Dict[str, Any]) -> set:
    out: set = set()
    # verdict_stage2 evidence rows
    for ev in (inc.get("verdict_stage2", {}) or {}).get("evidence", []) or []:
        if ev.get("technique_id"): out.add(ev["technique_id"])
    for ev in inc.get("evidence", []) or []:
        if ev.get("technique_id"): out.add(ev["technique_id"])
    # Direct arrays
    for src in (inc.get("mitre") or []):
        if isinstance(src, str) and _TECH_RE.match(src): out.add(src)
        elif isinstance(src, dict):
            for k in ("technique_id", "id"):
                v = src.get(k)
                if v and _TECH_RE.match(str(v)): out.add(v)
    for src in (inc.get("techniques") or inc.get("attack_techniques") or []):
        if isinstance(src, str) and _TECH_RE.match(src): out.add(src)
    return out


def _extract_incident_processes(inc: Dict[str, Any]) -> set:
    out: set = set()
    for ev in (inc.get("verdict_stage2", {}) or {}).get("evidence", []) or []:
        e = ev.get("entity") or ev.get("process") or {}
        for k in ("image", "process", "name"):
            v = e.get(k)
            if v: out.add(str(v).lower())
    for p in (inc.get("processes") or inc.get("process_tree") or []):
        if not isinstance(p, dict): continue
        for k in ("image", "name"):
            v = p.get(k)
            if v: out.add(str(v).lower())
    return out


def _extract_incident_keywords(inc: Dict[str, Any]) -> set:
    """Extract keywords from IOCs, hosts, users, and title/summary for
    scenario-text matching.  Only fields that carry factual evidence."""
    out: set = set()
    for k in ("title", "summary", "description"):
        v = inc.get(k)
        if v: out.update(re.findall(r"[A-Za-z][A-Za-z0-9\.\-_]{2,}", str(v).lower()))
    for ioc in inc.get("iocs") or []:
        v = ioc.get("value") if isinstance(ioc, dict) else ioc
        if v: out.add(str(v).lower())
    return out
