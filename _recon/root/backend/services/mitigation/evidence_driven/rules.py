"""Rule model + engine · trigger-conditioned recommendations.

Every rule declares:
    · id                     — stable identifier
    · trigger                — predicate over ``CaseContext``
    · action                 — free-form analyst-facing action text
    · reason                 — WHY this action was proposed
    · category               — investigate / hunt / contain / eradicate
                                / recover / harden
    · mitre                  — techniques the trigger covers
    · scope                  — target(s) the action applies to
    · priority               — critical / high / medium / low
    · requires_confirmation  — analyst must acknowledge before running

The engine evaluates every rule against a ``CaseContext`` and emits
ONLY the ones whose trigger predicate returns True.  No trigger →
no recommendation.  This is the load-bearing invariant.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Callable, Dict, List, Sequence, Tuple

from .case_context import CaseContext


CATEGORIES: Tuple[str, ...] = (
    "investigate", "hunt", "contain", "eradicate", "recover", "harden",
)
PRIORITIES: Tuple[str, ...] = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class RecommendationRule:
    """A single trigger-conditioned recommendation."""
    id:                    str
    trigger:               Callable[[CaseContext], bool]
    action:                str
    reason:                str
    category:              str
    mitre:                 Tuple[str, ...] = ()
    scope:                 Tuple[str, ...] = ()
    priority:              str = "medium"
    requires_confirmation: bool = False
    # Optional — machine-readable list of what the analyst must have
    # verified before this action is executed.  Empty when trivial.
    prerequisites:         Tuple[str, ...] = ()

    def evaluate(self, ctx: CaseContext) -> bool:
        try:
            return bool(self.trigger(ctx))
        except Exception:
            # A rule with a broken predicate must NEVER take down the
            # engine — bugs in one rule can't withhold recommendations
            # from another.  Log-and-skip semantics.
            return False


@dataclass(frozen=True)
class Recommendation:
    """The materialised output of a fired rule."""
    id:                    str
    action:                str
    reason:                str
    category:              str
    priority:              str
    mitre:                 Tuple[str, ...] = ()
    scope:                 Tuple[str, ...] = ()
    evidence:              Tuple[str, ...] = ()
    confidence:            str = "low"
    requires_confirmation: bool = False
    prerequisites:         Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id":                    self.id,
            "action":                self.action,
            "reason":                self.reason,
            "category":              self.category,
            "priority":              self.priority,
            "mitre":                 list(self.mitre),
            "scope":                 list(self.scope),
            "evidence":              list(self.evidence),
            "confidence":            self.confidence,
            "requires_confirmation": self.requires_confirmation,
            "prerequisites":         list(self.prerequisites),
        }


# ══════════════════════════════════════════════════════════════════
# Engine
# ══════════════════════════════════════════════════════════════════
def evaluate_rules(rules:  Sequence[RecommendationRule],
                    ctx:    CaseContext) -> List[Recommendation]:
    """Return every recommendation whose trigger fires — nothing more.

    Evidence-linking is derived here (not in each rule) so rule
    authors only need to write the predicate.  Every recommendation
    carries the *observed* evidence for auditability.
    """
    out: List[Recommendation] = []
    for r in rules:
        if not r.evaluate(ctx):
            continue
        out.append(Recommendation(
            id                    = r.id,
            action                = r.action,
            reason                = r.reason,
            category              = r.category,
            priority              = r.priority,
            mitre                 = r.mitre,
            scope                 = r.scope,
            evidence              = _evidence_for(r, ctx),
            confidence            = ctx.detection_confidence,
            requires_confirmation = r.requires_confirmation,
            prerequisites         = r.prerequisites,
        ))
    return out


def _evidence_for(rule: RecommendationRule,
                    ctx:  CaseContext) -> Tuple[str, ...]:
    """Collect the specific evidence strings that justified this rule.
    Every string here can be shown to the analyst as "here is exactly
    what tripped this recommendation."  Pure derivation."""
    ev: List[str] = []
    # MITRE alignment — only if the rule declares techniques.
    matched_mitre = [t for t in rule.mitre if t in ctx.mitre_techniques]
    if matched_mitre:
        ev.append(f"MITRE techniques observed: {', '.join(sorted(matched_mitre))}")
    if ctx.malware_family and "family" in rule.reason.lower():
        ev.append(f"Malware family fingerprinted: {ctx.malware_family}")
    if ctx.reached_shellcode and "shellcode" in rule.reason.lower():
        ev.append("Shellcode terminal payload reached (reached_shellcode=True)")
    for ip in ctx.ips:
        if ip in rule.action:
            ev.append(f"IP promoted from decoded payload: {ip}")
    for url in ctx.urls:
        if url in rule.action:
            ev.append(f"URL promoted from decoded payload: {url}")
    for dom in ctx.domains:
        if dom in rule.action:
            ev.append(f"Domain promoted from decoded payload: {dom}")
    for lb in ctx.lolbas_hits:
        if lb.lower() in rule.action.lower() or lb.lower() in rule.reason.lower():
            ev.append(f"LOLBAS abuse observed: {lb}")
    return tuple(ev)


__all__ = [
    "RecommendationRule", "Recommendation", "evaluate_rules",
    "CATEGORIES", "PRIORITIES",
]
