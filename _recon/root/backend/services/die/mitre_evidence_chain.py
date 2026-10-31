"""Phase 5.W permanent fix · P0.2 — MITRE evidence chain (2026-08-11).

Owner directive: "Every emitted MITRE technique must carry structured
evidence:  {source, event_or_rule, field, observed_value, evidence_ref}.
No valid evidence → do not emit the MITRE technique."

This module does not build a parallel evidence model. It normalises
whatever the two current emitters (canonical narrative rules +
csv_edr_analyzer) attach — free-text strings, `matched` lists,
`evidence` dicts — into the canonical structured shape and enforces
the "no evidence → no emission" gate at the final merge point.

Semantic alignment with `services/uaie/evidence.py`:
  - `source`          ~ Evidence.source_capability
  - `event_or_rule`   ~ Reason.rule + Reason.family (compact)
  - `field`           ~ Evidence.location
  - `observed_value`  ~ Evidence.value
  - `evidence_ref`    ~ Evidence.id (deterministic sha256 short)
"""
from __future__ import annotations
import hashlib
from typing import Any, Dict, List


REQUIRED_EVIDENCE_KEYS = ("source", "event_or_rule", "field",
                          "observed_value", "evidence_ref")


def _short_ref(seed: str) -> str:
    """Deterministic 12-char reference id from an evidence seed."""
    return "ev-" + hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()[:12]


def _normalise_evidence(technique: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert whatever the emitter attached into a list of structured
    evidence records. Never invents fields — leaves record-list empty
    if the emitter provided nothing citable, so the caller can drop
    the MITRE hit entirely (P0.2 gate).

    Accepted input shapes (from the two live emitters):

      1. Free-text string on `evidence`:
         `"SEP category 'Exploit Prevention' (action=detect)"`
         → produces ONE record inferring source/field/value from the
           string's shape when a clear pattern matches; otherwise
           returns [] (no invention).

      2. `matched` list from canonical narrative rules:
         `[{"family": "...", "rule": "...", "match": "...",
            "offset": N, "confidence": "high"}, ...]`
         → one record per match with source=canonical_narrative,
           event_or_rule = family.rule,
           field = "text_offset", observed_value = match.

      3. Structured dict / list already conforming — passed through
         if it contains the required keys.
    """
    raw = technique.get("evidence")
    tid = technique.get("id") or ""
    src_family = technique.get("rule_family") or ""
    records: List[Dict[str, Any]] = []

    # (3) Already structured?
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and all(k in item for k in REQUIRED_EVIDENCE_KEYS):
                records.append(dict(item))
        if records:
            return records

    # (2) canonical narrative `matched` list — accepts both shapes:
    #     - list[str]  (narrative rules from canonical_bridge)
    #     - list[dict] (structured matches with family/rule/offset)
    rule_family = str(technique.get("rule_family") or "").strip() or "canonical.narrative"
    tname       = str(technique.get("name") or "").strip()
    for m in (technique.get("matched") or []):
        if isinstance(m, str):
            match_text = m.strip()
            if not match_text:
                continue
            # Derive a rule identifier from the technique itself; the
            # match string is the observed literal (not fabricated).
            rule = f"{rule_family}.{tid}" if tid else rule_family
            seed = f"{tid}|{rule}|{match_text}"
            records.append({
                "source":         "canonical_narrative",
                "event_or_rule":  rule,
                "field":          "text_match",
                "observed_value": match_text[:200],
                "evidence_ref":   _short_ref(seed),
                "confidence":     "medium",
            })
        elif isinstance(m, dict):
            match_text = str(m.get("match") or m.get("text") or "").strip()
            rule       = f"{m.get('family','narrative')}.{m.get('rule','?')}"
            if not match_text:
                continue
            seed = f"{tid}|{rule}|{match_text}|{m.get('offset','?')}"
            records.append({
                "source":         "canonical_narrative",
                "event_or_rule":  rule,
                "field":          "text_offset",
                "observed_value": match_text[:200],
                "evidence_ref":   _short_ref(seed),
                "confidence":     str(m.get("confidence") or "medium"),
            })
    if records:
        return records

    # (1) Free-text string — accept ONLY when we can safely infer the fields.
    # Pattern: "SEP category 'X' (action=Y)" produced by csv_edr_analyzer.
    if isinstance(raw, str) and raw.strip():
        import re
        # Match "SEP category '<X>' (action=<Y>)"
        m = re.match(r"SEP category '([^']+)' \(action=([^)]+)\)", raw)
        if m:
            cat, action = m.group(1), m.group(2)
            records.append({
                "source":         "csv_edr_analyzer",
                "event_or_rule":  f"sep.{cat.lower().replace(' ', '_')}.{action}",
                "field":          "category+action",
                "observed_value": f"category={cat}; action={action}",
                "evidence_ref":   _short_ref(f"{tid}|sep|{cat}|{action}"),
                "confidence":     "medium",
            })
    return records


def enforce_evidence_chain(mitre_list: List[Dict[str, Any]]
                           ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return `(kept, suppressed)` MITRE lists.

    Every kept technique carries a non-empty `evidence: [{...}]` list
    whose items each contain all REQUIRED_EVIDENCE_KEYS.

    Suppressed items retain their original shape plus a
    `suppression_reason` field so callers can surface the count
    without exposing the (unsupported) technique itself.
    """
    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for t in mitre_list or []:
        if not isinstance(t, dict) or not t.get("id"):
            continue
        records = _normalise_evidence(t)
        if not records:
            dropped.append({
                **{k: t.get(k) for k in ("id", "name", "tactic", "kill_chain",
                                          "rule_family")},
                "suppression_reason":
                    "P0.2 evidence-chain gate: no structured citation "
                    "(source/event_or_rule/field/observed_value/evidence_ref) "
                    "available for this technique",
            })
            continue
        out = {k: v for k, v in t.items() if k not in ("matched",)}
        out["evidence"] = records
        kept.append(out)
    return kept, dropped


__all__ = ["enforce_evidence_chain", "REQUIRED_EVIDENCE_KEYS", "_normalise_evidence"]
