"""
DKP · Matching engine
─────────────────────
Deterministic matcher over the DIE ``analyze`` envelope.  Every rule
is evaluated over the same inputs, so repeated invocations against
the same envelope always yield an identical ``MatchedPattern`` list
in the same order.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Pattern, Signature, MatchedPattern
from .seed_patterns import SEED_PATTERNS

_JSON_PATH = Path(__file__).parent / "extra_patterns.json"
_CACHE:  Optional[List[Pattern]] = None
_MATCH_THRESHOLD = 0.35   # blended-confidence gate for inclusion


# ── loader ────────────────────────────────────────────────────────
def load_patterns() -> List[Pattern]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    patterns = list(SEED_PATTERNS)
    if _JSON_PATH.exists():
        try:
            extra_raw = json.loads(_JSON_PATH.read_text(encoding="utf-8"))
            for p in extra_raw or []:
                patterns.append(_from_dict(p))
        except Exception:
            # A malformed JSON must not break DIE.  Fall back to
            # built-ins silently — matches DIE's frozen policy.
            pass
    _CACHE = patterns
    return patterns


def add_pattern(p: Pattern) -> None:
    """Runtime append — mainly for tests and NVKC harnesses."""
    load_patterns()
    assert _CACHE is not None
    _CACHE.append(p)


def pattern_by_id(pid: str) -> Optional[Pattern]:
    for p in load_patterns():
        if p.id == pid:
            return p
    return None


def _from_dict(d: Dict[str, Any]) -> Pattern:
    sigs = [_sig_from_dict(s) for s in d.get("signatures", [])]
    return Pattern(
        id=d["id"], name=d["name"], intent=d.get("intent", ""),
        signatures=sigs, mitre=d.get("mitre", []),
        enterprise_uses=d.get("enterprise_uses", []),
        malware_uses=d.get("malware_uses", []),
        families=d.get("families", []),
        typical_parent=d.get("typical_parent"),
        typical_child=d.get("typical_child"),
        common_followon=d.get("common_followon"),
        confidence=d.get("confidence", 80),
        narrative_template=d.get("narrative_template", ""),
        investigation=d.get("investigation", []),
        detection_logic=d.get("detection_logic"),
        references=d.get("references", []),
    )


def _sig_from_dict(d: Dict[str, Any]) -> Signature:
    of = d.get("of")
    return Signature(
        kind=d["kind"], weight=float(d.get("weight", 1.0)),
        pattern=d.get("pattern"), against=d.get("against"),
        flag=d.get("flag"), id=d.get("id"),
        binary=d.get("binary"), language=d.get("language"),
        of=[_sig_from_dict(x) for x in of] if of else None,
    )


# ── matcher ───────────────────────────────────────────────────────
def match(envelope: Dict[str, Any]) -> List[MatchedPattern]:
    """Return every pattern that fires against ``envelope``.

    ``envelope`` is a DIE ``analyze(...)`` return value.  Ordering is
    deterministic: patterns are evaluated in registration order and
    ties broken by pattern id.
    """
    if not envelope:
        return []
    matched: List[MatchedPattern] = []
    for p in load_patterns():
        hits, evidence, weight_sum, weight_hit = [], [], 0.0, 0.0
        for sig in p.signatures:
            weight_sum += sig.weight
            fired, why = _fire(sig, envelope)
            if fired:
                hits.append(sig)
                if why:
                    evidence.append(why)
                weight_hit += sig.weight
        if not hits or weight_sum == 0:
            continue
        rule_ratio = weight_hit / weight_sum
        # Blend pattern's own base confidence (0-100) with rule ratio.
        blended = rule_ratio * (p.confidence / 100.0)
        if blended < _MATCH_THRESHOLD:
            continue
        matched.append(MatchedPattern(
            pattern=p, matched_signatures=hits,
            confidence=blended,
            evidence=_dedupe_evidence(evidence)[:8],
        ))
    # Stable ordering — highest confidence first, then id for ties.
    matched.sort(key=lambda m: (-m.confidence, m.pattern.id))
    return matched


# ── signature evaluators ──────────────────────────────────────────
def _fire(sig: Signature, env: Dict[str, Any]):
    """Return ``(fired, evidence_snippet)`` for a single signature."""
    if sig.kind == "regex":
        return _fire_regex(sig, env)
    if sig.kind == "flag":
        return _fire_flag(sig, env)
    if sig.kind == "mitre":
        return _fire_mitre(sig, env)
    if sig.kind == "lolbin":
        return _fire_lolbin(sig, env)
    if sig.kind == "family":
        return _fire_family(sig, env)
    if sig.kind == "all" and sig.of:
        results = [_fire(child, env) for child in sig.of]
        fired = all(r[0] for r in results)
        return fired, "; ".join(r[1] for r in results if r[1])
    if sig.kind == "any" and sig.of:
        results = [_fire(child, env) for child in sig.of]
        fired = any(r[0] for r in results)
        return fired, next((r[1] for r in results if r[0] and r[1]), "")
    return False, ""


def _regex_haystack(env: Dict[str, Any], against: Optional[str]) -> str:
    ast = env.get("ast") or {}
    # Reuse the raw source when the caller stashed it on the envelope
    # under the conventional key; fall back to string-flattening the
    # AST.
    raw = env.get("_raw_source") or ""
    if raw and (against in (None, "raw")):
        return raw
    if against == "decoded":
        payloads = ast.get("encoded_payloads") or []
        return "\n".join(p.get("preview","") for p in payloads)
    # As last resort, join every string-ish field so signatures still
    # have something to hit against.
    bits = []
    for c in ast.get("cmdlets", []) or []:
        bits.append(c.get("name",""))
        bits.extend(str(v) for v in (c.get("params") or {}).values())
    for cmd in ast.get("commands", []) or []:
        bits.append(cmd.get("text",""))
    bits.extend(ast.get("variables", []) or [])
    for lb in env.get("lolbins", []) or []:
        bits.append(lb.get("binary",""))
    return " ".join(str(b) for b in bits if b)


def _fire_regex(sig: Signature, env: Dict[str, Any]):
    if not sig.pattern:
        return False, ""
    hay = _regex_haystack(env, sig.against)
    if not hay:
        return False, ""
    m = re.search(sig.pattern, hay, re.MULTILINE)
    if not m:
        return False, ""
    snippet = m.group(0)
    if len(snippet) > 160:
        snippet = snippet[:157] + "…"
    return True, snippet


def _fire_flag(sig: Signature, env: Dict[str, Any]):
    if not sig.flag:
        return False, ""
    ast = env.get("ast") or {}
    flags = ast.get("flags") or {}
    if flags.get(sig.flag):
        return True, f"flag {sig.flag}=true"
    return False, ""


def _fire_mitre(sig: Signature, env: Dict[str, Any]):
    if not sig.id:
        return False, ""
    techs = env.get("techniques") or []
    if any(t.get("id") == sig.id for t in techs):
        return True, f"MITRE {sig.id}"
    return False, ""


def _fire_lolbin(sig: Signature, env: Dict[str, Any]):
    if not sig.binary:
        return False, ""
    b = sig.binary.lower()
    for lb in env.get("lolbins") or []:
        if lb.get("binary","").lower() == b:
            return True, f"LOLBAS {b}"
    return False, ""


def _fire_family(sig: Signature, env: Dict[str, Any]):
    if not sig.language:
        return False, ""
    if (env.get("language") or "").lower() == sig.language.lower():
        return True, f"language={sig.language}"
    return False, ""


def _dedupe_evidence(items):
    seen = set(); out = []
    for i in items:
        if not i or i in seen:
            continue
        seen.add(i); out.append(i)
    return out
