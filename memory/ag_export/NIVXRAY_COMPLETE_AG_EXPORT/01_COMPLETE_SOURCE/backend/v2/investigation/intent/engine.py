"""Semantic Intent Engine · deterministic intent inference.

``assess(text, *, meta)`` runs every registered IntentRule against
the artefact, aggregates the fired intents, and produces an
``IntentAssessment`` with a deterministic analyst-facing summary.

The engine is intentionally simple — its complexity lives in the
individual rules under ``rules/``. Adding a new intent category is
a one-file change; the engine remains stable.
"""
from __future__ import annotations

import hashlib
import json

from .models import Intent, IntentAssessment, IntentCategory
from .rules import INTENT_RULE_REGISTRY


# Deterministic category ordering used for tie-breaking. Matches the
# analyst's usual reading order (staging → execute → evade → discover
# → persist → creds → move → collect → exfil → impact → unknown).
_CATEGORY_ORDER: dict[IntentCategory, int] = {
    IntentCategory.STAGING:           0,
    IntentCategory.REMOTE_EXECUTION:  1,
    IntentCategory.DEFENSE_EVASION:   2,
    IntentCategory.DISCOVERY:         3,
    IntentCategory.PERSISTENCE:       4,
    IntentCategory.CREDENTIAL_ACCESS: 5,
    IntentCategory.LATERAL_MOVEMENT:  6,
    IntentCategory.COLLECTION:        7,
    IntentCategory.EXFILTRATION:      8,
    IntentCategory.IMPACT:            9,
    IntentCategory.RUNTIME_DEPENDENT: 10,
}


def assess(text: str, *, meta: dict | None = None) -> IntentAssessment:
    """Run the intent-rule chain against ``text`` and return the
    resulting :class:`IntentAssessment`.

    ``meta`` carries any context the caller wants to expose to rules
    (IU classification, CRE dispatch hint, RTE stop reason, layer
    count). Rules must treat ``meta`` as read-only.
    """
    meta = dict(meta or {})
    fired: list[Intent] = []
    for rule in INTENT_RULE_REGISTRY:
        try:
            for intent in rule.detect(text or "", meta):
                fired.append(intent)
        except Exception:
            # Rules MUST NOT raise on well-formed input; but a bug in
            # a single rule must not derail the whole assessment.
            continue

    fired.sort(key=lambda i: (-i.confidence, _CATEGORY_ORDER.get(i.category, 99)))

    summary = _build_summary(fired)
    result = IntentAssessment(intents=fired, summary=summary)
    result.determinism_hash = _hash(result)
    return result


def _build_summary(intents: list[Intent]) -> str:
    """Deterministic one-paragraph analyst-facing synthesis.

    Never speculates. Just names the fired intent categories in
    reading order plus the count of supporting evidence pieces so
    the analyst can gauge weight at a glance.
    """
    if not intents:
        return ("No high-signal analyst intent could be inferred from "
                "the effective payload. The artefact may be benign, "
                "or its intent may depend on runtime context that is "
                "not visible in the static input.")

    by_cat: dict[IntentCategory, list[Intent]] = {}
    for i in intents:
        by_cat.setdefault(i.category, []).append(i)

    parts: list[str] = []
    for cat in sorted(by_cat, key=lambda c: _CATEGORY_ORDER.get(c, 99)):
        items = by_cat[cat]
        evidence_count = sum(len(i.evidence) for i in items)
        parts.append(
            f"{cat.value.replace('_', ' ').title()} "
            f"({len(items)} intent · {evidence_count} evidence)"
        )
    joined = "; ".join(parts)
    return f"The effective payload exhibits: {joined}."


def _hash(assessment: IntentAssessment) -> str:
    blob = json.dumps({
        "intents": [{
            "category":   i.category.value,
            "purpose":    i.purpose,
            "risk":       i.risk.value,
            "confidence": i.confidence,
            "mitre_ids":  i.mitre_ids,
        } for i in assessment.intents],
        "summary": assessment.summary,
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


__all__ = ["assess"]
