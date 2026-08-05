"""Confidence Provenance Ledger — Phase A · item 3.

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN)
§7 (Provider Extension Architecture), §5 (CEM boundary).

    Case (recorded verdict + CEM)
             ▼
    emit_provenance(case)
             ▼
    { provenance_hash, recorded{...}, derived{...},
      rules[...], rules_skipped[...],
      evidence_contributions[...],
      mitre_contributions[...],
      analyzer_contributions[...] }

Contract (owner-locked 2026-02-16):

  1. **Read-only.** Never modifies case, CEM, verdict, or evidence.
  2. **Deterministic.** Same case → byte-identical ledger. Rules,
     weights, ordering, and hashing are all stable.
  3. **Explains, doesn't overwrite.** The `recorded` block preserves
     whatever the upstream verdict pipeline produced. The `derived`
     block is a purely deterministic reproduction from the CEM. When
     both exist, they can be compared for scoring-drift detection.
  4. **Versioned schema.** `provenance_version = "1.0"`.
  5. **Rule library is declarative.** Each rule is a pure predicate
     over CEM fields. New rules bump the schema version.
  6. **Every contribution is auditable.** Rule fires point to the
     exact evidence (analyzer.finding event, MITRE id, artifact
     sha256) that satisfied their predicate.

Rules are intentionally simple and conservative. They form the
starting library — the intent is that the library grows over time
under owner review, with any change bumping `provenance_version`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from services.cem import emit_cem

PROVENANCE_VERSION = "1.0"

# Verdict bands — deterministic risk-score → verdict mapping.
_VERDICT_BANDS = (
    (80, "malicious"),
    (50, "suspicious"),
    (20, "low_risk"),
    (0,  "benign"),
)


# =====================================================================
# Rule library
# =====================================================================
@dataclass(frozen=True)
class Rule:
    id:          str
    description: str
    weight:      float
    # Predicate returns a list of evidence references (dicts) that
    # satisfy the rule. Empty list means the rule did not fire.
    predicate:   Callable[[Dict[str, Any]], List[Dict[str, Any]]]


def _finding_by_severity(sev: str) -> Callable[[Dict[str, Any]], List[Dict[str, Any]]]:
    def _p(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            {"kind": "analyzer.finding", "code": ev.get("code"),
             "severity": ev.get("severity"),
             "provenance": ev.get("provenance")}
            for ev in cem.get("events") or []
            if isinstance(ev, dict)
            and ev.get("kind") == "analyzer.finding"
            and (ev.get("severity") or "").lower() == sev
        ]
    return _p


def _mitre_present(technique_id: str) -> Callable[[Dict[str, Any]], List[Dict[str, Any]]]:
    tid = technique_id.upper()
    def _p(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{"kind": "mitre", "id": m.get("id")}
                for m in cem.get("mitre") or []
                if isinstance(m, dict) and str(m.get("id") or "").upper() == tid]
    return _p


def _binary_recovered_from_wrapper(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
    """RTE deterministically recovered a binary artifact from a
    decoding chain — a strong deterministic signal of packed malware."""
    conv = cem.get("convergence") or {}
    if conv.get("terminal_state") != "binary_artifact_recovered":
        return []
    hits: List[Dict[str, Any]] = []
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("kind") == "binary_artifact" and a.get("sha256"):
            hits.append({"kind": "canonical_artifact",
                         "sha256": a["sha256"], "type": a.get("type")})
    return hits


def _office_macro_script_invocation(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"kind": "analyzer.finding", "code": ev.get("code"),
         "provenance": ev.get("provenance")}
        for ev in cem.get("events") or []
        if isinstance(ev, dict)
        and ev.get("code") == "macro_script_invocation"
    ]


def _recursive_child_declared(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"kind": "child_artifact",
             "type": c.get("type"), "depth": c.get("depth")}
            for c in cem.get("child_artifacts") or [] if isinstance(c, dict)]


def _powershell_encoded_command(cem: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fired when the RTE's decode recipe includes an EncodedCommand pass."""
    recipe = (cem.get("traces") or {}).get("recipe") or []
    for step in recipe:
        s = str(step).lower()
        if "encodedcommand" in s or "encoded-command" in s or "encoded_command" in s:
            return [{"kind": "recipe_step", "step": step}]
    return []


# The deterministic rule library.  Ordering matters for output
# stability — rules are ALWAYS iterated in the order defined here.
RULES: List[Rule] = [
    Rule("analyzer.finding.critical",
         "Analyzer produced a critical-severity finding",
         30.0, _finding_by_severity("critical")),
    Rule("analyzer.finding.high",
         "Analyzer produced a high-severity finding",
         15.0, _finding_by_severity("high")),
    Rule("analyzer.finding.medium",
         "Analyzer produced a medium-severity finding",
         5.0, _finding_by_severity("medium")),
    Rule("analyzer.finding.low",
         "Analyzer produced a low-severity finding",
         1.0, _finding_by_severity("low")),
    Rule("binary_recovered_from_wrapper",
         "RTE recovered a binary artifact from a decoding chain",
         25.0, _binary_recovered_from_wrapper),
    Rule("office_macro_script_invocation",
         "Office document contains a macro invoking an external script",
         25.0, _office_macro_script_invocation),
    Rule("recursive_child_declared",
         "Artifact analyzer declared child artifact(s) for recursive analysis",
         5.0, _recursive_child_declared),
    Rule("powershell_encoded_command",
         "Decode recipe includes a PowerShell -EncodedCommand pass",
         10.0, _powershell_encoded_command),
    Rule("mitre.T1059.001",
         "MITRE T1059.001 — Command and Scripting Interpreter: PowerShell",
         10.0, _mitre_present("T1059.001")),
    Rule("mitre.T1027",
         "MITRE T1027 — Obfuscated Files or Information",
         10.0, _mitre_present("T1027")),
    Rule("mitre.T1140",
         "MITRE T1140 — Deobfuscate/Decode Files or Information",
         10.0, _mitre_present("T1140")),
    Rule("mitre.T1218",
         "MITRE T1218 — System Binary Proxy Execution (LOLBin)",
         15.0, _mitre_present("T1218")),
    Rule("mitre.T1490",
         "MITRE T1490 — Inhibit System Recovery",
         15.0, _mitre_present("T1490")),
]


# =====================================================================
# Public API
# =====================================================================
def emit_provenance(case: Dict[str, Any]) -> Dict[str, Any]:
    """Return the deterministic Confidence Provenance ledger for a case."""
    if not isinstance(case, dict):
        return _stub("input_not_dict")

    cem = case.get("cem") if isinstance(case.get("cem"), dict) else emit_cem(case)
    if not isinstance(cem, dict):
        return _stub("cem_missing")

    fired: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for rule in RULES:
        try:
            hits = rule.predicate(cem)
        except Exception as e:
            skipped.append({"id": rule.id, "reason": f"predicate_error: {e}"})
            continue
        if not hits:
            skipped.append({"id": rule.id, "reason": "predicate_no_hit"})
            continue
        contribution = round(rule.weight * len(hits), 4)
        fired.append({
            "id":            rule.id,
            "description":   rule.description,
            "weight":        rule.weight,
            "hit_count":     len(hits),
            "contribution":  contribution,
            "evidence_refs": hits,
        })

    derived_score = min(100.0, round(sum(r["contribution"] for r in fired), 4))
    derived_verdict = _band(derived_score)

    recorded_score = _recorded_risk_score(case)
    recorded_verdict = _recorded_verdict(case)

    evidence_contributions = _evidence_contributions(fired)
    mitre_contributions = _mitre_contributions(fired)
    analyzer_contributions = _analyzer_contributions(fired)

    ledger = {
        "provenance_version": PROVENANCE_VERSION,
        "recorded": {
            "verdict":    recorded_verdict,
            "risk_score": recorded_score,
        },
        "derived": {
            "verdict":    derived_verdict,
            "risk_score": derived_score,
        },
        "rules":                    fired,
        "rules_skipped":            skipped,
        "evidence_contributions":   evidence_contributions,
        "mitre_contributions":      mitre_contributions,
        "analyzer_contributions":   analyzer_contributions,
    }
    ledger["provenance_hash"] = hashlib.sha256(
        _canonical_json(ledger).encode("utf-8")).hexdigest()
    return ledger


# =====================================================================
# Aggregations
# =====================================================================
def _evidence_contributions(fired: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One entry per unique evidence artifact/finding across all rules,
    with the total contribution + set of rules that referenced it."""
    bucket: Dict[str, Dict[str, Any]] = {}
    for rule in fired:
        per_ref = rule["contribution"] / max(rule["hit_count"], 1)
        for ref in rule["evidence_refs"]:
            key = _evidence_key(ref)
            b = bucket.setdefault(key, {
                "evidence_id":  key,
                "source":       ref.get("kind"),
                "contribution": 0.0,
                "rules":        set(),
            })
            b["contribution"] += per_ref
            b["rules"].add(rule["id"])
    return [
        {"evidence_id": v["evidence_id"],
         "source":       v["source"],
         "contribution": round(v["contribution"], 4),
         "rules":        sorted(v["rules"])}
        for v in sorted(bucket.values(), key=lambda x: x["evidence_id"])
    ]


def _evidence_key(ref: Dict[str, Any]) -> str:
    kind = ref.get("kind") or "unknown"
    if kind == "analyzer.finding":
        return f"analyzer.finding:{ref.get('code')}:{ref.get('provenance') or ''}"
    if kind == "mitre":
        return f"mitre:{ref.get('id')}"
    if kind == "canonical_artifact":
        return f"canonical_artifact:{ref.get('sha256')}"
    if kind == "child_artifact":
        return f"child_artifact:{ref.get('type')}:{ref.get('depth')}"
    if kind == "recipe_step":
        return f"recipe_step:{ref.get('step')}"
    # Fallback — deterministic stringification.
    return f"{kind}:{_canonical_json(ref)}"


def _mitre_contributions(fired: List[Dict[str, Any]]) -> List[str]:
    return sorted({
        ref.get("id") for r in fired for ref in r["evidence_refs"]
        if isinstance(ref, dict) and ref.get("kind") == "mitre" and ref.get("id")
    })


def _analyzer_contributions(fired: List[Dict[str, Any]]) -> List[str]:
    return sorted({
        ref.get("provenance") for r in fired for ref in r["evidence_refs"]
        if isinstance(ref, dict) and ref.get("kind") == "analyzer.finding"
        and ref.get("provenance")
    })


# =====================================================================
# Helpers
# =====================================================================
def _band(score: float) -> str:
    for threshold, name in _VERDICT_BANDS:
        if score >= threshold:
            return name
    return "benign"


def _recorded_risk_score(case: Dict[str, Any]) -> Optional[float]:
    vc = case.get("verdict_card") or {}
    for key in ("risk_score", "risk", "score"):
        if key in vc and vc[key] is not None:
            try:
                return float(vc[key])
            except (TypeError, ValueError):
                pass
    return None


def _recorded_verdict(case: Dict[str, Any]) -> Optional[str]:
    vc = case.get("verdict_card") or {}
    for key in ("verdict", "label"):
        if vc.get(key):
            return str(vc[key])
    return None


def _canonical_json(value: Any) -> str:
    """Stable serialization ignoring the `provenance_hash` field itself
    (so hashing is self-consistent)."""
    def _strip(v):
        if isinstance(v, dict):
            return {k: _strip(vv) for k, vv in v.items() if k != "provenance_hash"}
        if isinstance(v, list):
            return [_strip(x) for x in v]
        return v
    return json.dumps(_strip(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _stub(reason: str) -> Dict[str, Any]:
    return {
        "provenance_version": PROVENANCE_VERSION,
        "provenance_hash":    None,
        "reason":             reason,
        "recorded":           {"verdict": None, "risk_score": None},
        "derived":            {"verdict": None, "risk_score": None},
        "rules":              [],
        "rules_skipped":      [],
        "evidence_contributions": [],
        "mitre_contributions":    [],
        "analyzer_contributions": [],
    }


__all__ = ["PROVENANCE_VERSION", "RULES", "Rule", "emit_provenance"]
