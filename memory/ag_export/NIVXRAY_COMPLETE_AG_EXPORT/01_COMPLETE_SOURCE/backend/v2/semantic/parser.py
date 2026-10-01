"""Semantic command parser.

parse_command(text) → list[Evidence]

Every Evidence object carries the (entity → action → target)
triple plus deterministic provenance: rule id, confidence, MITRE
techniques, and the exact source substring that fired the rule.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict, field
from typing import Any

from v2.semantic.rules import RULES


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    event_kind: str          # CEM v1 event kind
    action: str              # canonical verb (executed / dumped / written / …)
    target: str              # extracted target string
    entity: str              # actor / process name that produced the action
    confidence: str          # "high" | "medium" | "low"
    mitre: tuple[str, ...] = ()
    source: str = "command-line-parser"
    matched_span: str = ""
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mitre"] = list(self.mitre)
        return d


_BACKREF = re.compile(r"\$(?:(\d+)|([A-Za-z_][A-Za-z0-9_]*))")


def _resolve(expr: str, match: re.Match) -> str:
    """Resolve `$1`, `$named` backrefs against a regex Match. Literal
    strings pass through untouched. Missing groups fall back to the
    raw expression (never crashes)."""
    def rep(m: re.Match) -> str:
        num, name = m.group(1), m.group(2)
        try:
            if num is not None:
                return match.group(int(num)) or ""
            if name in (match.groupdict() or {}):
                return match.group(name) or ""
        except (IndexError, KeyError):
            return ""
        return m.group(0)
    return _BACKREF.sub(rep, expr)


def _entity_for(cmd: str, target: str) -> str:
    """Best-effort actor extraction — first .exe / .ps1 / .dll
    encountered in the command, otherwise the target itself."""
    m = re.search(r"([A-Za-z0-9_.-]+\.(?:exe|ps1|dll|bat|cmd|sh))", cmd, re.IGNORECASE)
    if m:
        return m.group(1)
    return target


def parse_command(text: str) -> list[Evidence]:
    """Return the deterministic evidence set produced by `text`.

    Always deterministic: identical input → identical Evidence list
    (order preserved, no wall-clock reads).
    """
    out: list[Evidence] = []
    seen_keys: set[tuple[str, str, str]] = set()  # dedupe by (kind, action, target)
    for rule in RULES:
        m = rule.pattern.search(text)
        if not m:
            continue
        matched_span = m.group(0)
        for kind, action, target_expr in rule.emits:
            target = _resolve(target_expr, m)
            entity = _entity_for(text, target)
            key = (kind, action, target)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            out.append(Evidence(
                rule_id=rule.id,
                event_kind=kind,
                action=action,
                target=target or "",
                entity=entity,
                confidence=rule.confidence,
                mitre=rule.mitre,
                matched_span=matched_span[:200],
                label=rule.label,
            ))
    return out
