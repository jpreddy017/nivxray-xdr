"""Phase 5.W · DIE canonical bridge (2026-08-10).

Owner directive: bring the Workspace's real /api/die/analyze path into
the canonical investigation architecture WITHOUT changing its external
contract or the Workspace UI behavior.

- Preserves legacy shape (`result.techniques[]`, `result.chain.steps[]`)
- Only ADDS canonical evidence (never removes or reshapes legacy)
- Feature-flag gated: NIVX_CANONICAL_DIE_ANALYZE (default OFF)
- Firewall: no import of new legacy modules; canonical-only.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

_FLAG_ENV = "NIVX_CANONICAL_DIE_ANALYZE"


def canonical_die_flag_enabled() -> bool:
    return os.environ.get(_FLAG_ENV, "off").strip().lower() == "on"


def _canonical_techniques_from_text(text: str) -> List[Dict[str, Any]]:
    """Run the canonical narrative MITRE rules on `text` and return a
    list of techniques in the LEGACY DIE shape:
        [{"id": "T1219", "name": "Remote Access Software",
          "evidence": "<snippet>"}, ...]
    Pure function; no I/O, no clock, no random.
    """
    if not text:
        return []
    # Import lazily to keep module import cheap when flag is OFF.
    from canonical.executor.capabilities import (
        _NARRATIVE_RULES,
        _match_narrative_rule,
    )
    out: List[Dict[str, Any]] = []
    lowered = text.lower()
    for tid, rule in _NARRATIVE_RULES.items():
        matched = _match_narrative_rule(lowered, rule)
        if not matched:
            continue
        first = matched[0]
        idx = lowered.find(first)
        start = max(0, idx - 80)
        end = min(len(lowered), idx + 160)
        snippet = lowered[start:end]
        out.append({
            "id": tid,
            "name": rule["name"],
            "evidence": snippet,
            "matched": matched,
            "rule_family": "canonical.narrative_vendor_report",
        })
    # Deterministic ordering.
    out.sort(key=lambda x: x["id"])
    return out


def augment_die_result(result: Dict[str, Any], raw_input: str) -> Dict[str, Any]:
    """Augment an existing legacy DIE `result` dict with canonical
    narrative MITRE evidence when the flag is on.

    Contract:
      - If legacy already produced a technique with the same id ⇒ keep
        legacy entry, don't duplicate.
      - Otherwise append the canonical technique to result.techniques.
      - If result has no chain, synthesise a single-step chain so
        the Workspace AttackChainView renders.
      - result.language, result.ast, result.lolbins, result.iocs
        remain untouched.
    """
    if not canonical_die_flag_enabled():
        return result
    if not isinstance(result, dict):
        return result

    canonical_techs = _canonical_techniques_from_text(raw_input or "")
    if not canonical_techs:
        return result

    # Merge into result.techniques (dedup by technique id).
    existing = result.get("techniques") or []
    if not isinstance(existing, list):
        existing = []
    existing_ids = {t.get("id") for t in existing if isinstance(t, dict)}
    added: List[Dict[str, Any]] = []
    for t in canonical_techs:
        if t["id"] in existing_ids:
            continue
        existing.append(t)
        added.append(t)
        existing_ids.add(t["id"])
    result["techniques"] = existing

    # Synthesize / augment chain so the Workspace attack-chain graph
    # renders. Legacy shape: {"steps": [{"techniques": [...], ...}]}.
    chain = result.get("chain")
    if not isinstance(chain, dict):
        chain = {}
    steps = chain.get("steps")
    if not isinstance(steps, list) or not steps:
        steps = [{
            "index": 0,
            "kind": "canonical.narrative",
            "source": "root",
            "artifact_type": "narrative",
            "verdict": "malicious",
            "techniques": canonical_techs,
            "evidence": "canonical narrative MITRE mapping",
        }]
    else:
        step0 = steps[0]
        if isinstance(step0, dict):
            step_techs = step0.get("techniques") or []
            if not isinstance(step_techs, list):
                step_techs = []
            step_ids = {t.get("id") for t in step_techs if isinstance(t, dict)}
            for t in added:
                if t["id"] not in step_ids:
                    step_techs.append(t)
                    step_ids.add(t["id"])
            step0["techniques"] = step_techs
    chain["steps"] = steps
    result["chain"] = chain

    # Attach canonical provenance marker (non-breaking additive field).
    result["canonical_augmented"] = {
        "wave": "5.W",
        "lifecycle": "canonical_bridge",
        "added_techniques": [t["id"] for t in added],
    }
    return result


__all__ = [
    "canonical_die_flag_enabled",
    "augment_die_result",
]
