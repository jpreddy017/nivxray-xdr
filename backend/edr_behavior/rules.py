"""Versioned SequenceRule contract, strict parser and lifecycle registry."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import predicates as P
from .contracts import (KIND_AUTH, KIND_DETECTION, KIND_DNS, KIND_FILE,
                        KIND_NETWORK, KIND_PROCESS, KIND_PROCESS_TERMINATION,
                        KIND_REGISTRY, LINK_GUID, LINK_PID_SURROGATE, sha)

STAGE_TYPES = {"PROCESS": KIND_PROCESS, "COMMAND": KIND_PROCESS,
               "PROCESS_TERMINATION": KIND_PROCESS_TERMINATION, "FILE": KIND_FILE,
               "REGISTRY": KIND_REGISTRY, "DNS": KIND_DNS, "NETWORK": KIND_NETWORK,
               "AUTH": KIND_AUTH, "DETECTION": KIND_DETECTION, "INTEL": None}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SCOPES = ("process", "device", "user", "file")
LIFECYCLE = ("DRAFT", "TESTING", "ACTIVE", "DISABLED", "DEPRECATED")
TRANSITIONS = {"DRAFT": {"TESTING", "DEPRECATED"},
               "TESTING": {"ACTIVE", "DISABLED", "DEPRECATED", "DRAFT"},
               "ACTIVE": {"DISABLED", "DEPRECATED"},
               "DISABLED": {"ACTIVE", "TESTING", "DEPRECATED"},
               "DEPRECATED": set()}
RULE_SOURCES = ("NATIVE", "CUSTOMER", "SIGMA_DERIVED", "ML_SIGNAL", "TI_TRIGGERED")
REL_TYPES = ("parent_child", "same_process", "same_user", "same_value", "dns_to_ip")
_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
MAX_STAGES, MAX_RELS, MAX_EXCL, MAX_WINDOW = 10, 20, 32, 86400
INTEL_VERDICTS = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN")
RULE_KEYS = {"rule_id", "version", "name", "description", "enabled", "lifecycle",
             "severity", "confidence", "time_window_seconds", "entity_scope",
             "ordered", "stages", "relationships", "exclusions",
             "confidence_adjustments", "mitre", "evidence_requirements",
             "provenance", "created_at", "updated_at"}
STAGE_KEYS = {"id", "type", "predicate", "optional", "negate", "min_count",
              "confidence_bonus", "observable_field", "observable_type",
              "verdict_in", "min_confidence", "on_types"}


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Stage:
    id: str
    type: str
    kinds: Tuple[str, ...]
    predicate: Optional[Dict[str, Any]]
    optional: bool = False
    negate: bool = False
    min_count: int = 1
    confidence_bonus: int = 0
    intel: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class SequenceRule:
    rule_id: str
    version: int
    name: str
    description: str
    enabled: bool
    lifecycle: str
    severity: str
    confidence: int
    time_window_seconds: int
    entity_scope: str
    ordered: bool
    stages: Tuple[Stage, ...]
    relationships: Tuple[Dict[str, Any], ...]
    exclusions: Tuple[Dict[str, Any], ...]
    confidence_adjustments: Tuple[Dict[str, Any], ...]
    mitre: Tuple[Dict[str, str], ...]
    evidence_requirements: Tuple[str, ...]
    provenance: Dict[str, Any]
    created_at: str
    updated_at: str
    content_hash: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def positive_stages(self) -> Tuple[Stage, ...]:
        return tuple(s for s in self.stages if not s.negate)

    @property
    def negative_stages(self) -> Tuple[Stage, ...]:
        return tuple(s for s in self.stages if s.negate)

    def stage(self, sid: str) -> Stage:
        for s in self.stages:
            if s.id == sid:
                return s
        raise KeyError(sid)

    def kinds(self) -> Tuple[str, ...]:
        return tuple(sorted({k for s in self.stages for k in s.kinds}))


def content_hash(doc: Dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items()
            if k not in ("lifecycle", "enabled", "updated_at", "created_at")}
    return "rc_" + sha(json.dumps(body, sort_keys=True, separators=(",", ":")))[:32]


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise RuleError(msg)


def _int(v: Any, lo: int, hi: int, name: str) -> int:
    _req(isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi,
         f"{name} must be an integer in [{lo}, {hi}]")
    return v


def _pred(node: Any, where: str) -> Dict[str, Any]:
    try:
        P.validate(node)
    except P.PredicateError as e:
        raise RuleError(f"{where}: {e}") from None
    return node


def _stage(d: Any) -> Stage:
    _req(isinstance(d, dict), "stage must be an object")
    _req(set(d) <= STAGE_KEYS, f"unknown stage keys: {sorted(set(d) - STAGE_KEYS)}")
    sid = d.get("id")
    _req(isinstance(sid, str) and bool(_ID.fullmatch(sid)), f"bad stage id {sid!r}")
    st = d.get("type")
    _req(st in STAGE_TYPES, f"stage {sid}: bad type {st!r}")
    pred = _pred(d["predicate"], f"stage {sid}") if "predicate" in d else None
    intel = None
    if st == "INTEL":
        on = d.get("on_types")
        _req(isinstance(on, list) and on and all(t in STAGE_TYPES and t != "INTEL" for t in on),
             f"stage {sid}: INTEL needs on_types")
        kinds = tuple(sorted({STAGE_TYPES[t] for t in on}))
        of = d.get("observable_field")
        _req(isinstance(of, str) and of.startswith(P.FIELD_PREFIXES), f"stage {sid}: observable_field")
        vin = d.get("verdict_in", ["MALICIOUS"])
        _req(isinstance(vin, list) and vin and set(vin) <= set(INTEL_VERDICTS), f"stage {sid}: verdict_in")
        intel = {"observable_field": of, "observable_type": str(d.get("observable_type", ""))[:32],
                 "verdict_in": tuple(vin),
                 "min_confidence": _int(d.get("min_confidence", 0), 0, 100, "min_confidence")}
    else:
        _req(pred is not None, f"stage {sid}: predicate required")
        kinds = (STAGE_TYPES[st],)
        if st == "COMMAND":
            pred = {"all": [{"field": "process.command_line", "op": "exists"}, pred]} \
                if "process.command_line" not in P.fields_of(pred) else pred
    neg = bool(d.get("negate", False))
    opt = bool(d.get("optional", False))
    _req(not (neg and opt), f"stage {sid}: negate and optional are exclusive")
    return Stage(id=sid, type=st, kinds=kinds, predicate=pred, optional=opt, negate=neg,
                 min_count=_int(d.get("min_count", 1), 1, 100, "min_count"),
                 confidence_bonus=_int(d.get("confidence_bonus", 0), 0, 50, "confidence_bonus"),
                 intel=intel)


def _rel(d: Any, ids: set) -> Dict[str, Any]:
    _req(isinstance(d, dict) and d.get("type") in REL_TYPES, f"bad relationship {d!r}")
    t = d["type"]
    if t == "parent_child":
        _req(d.get("parent") in ids and d.get("child") in ids, "parent_child stages")
        _req(d.get("min_linkage", LINK_PID_SURROGATE) in (LINK_GUID, LINK_PID_SURROGATE),
             "min_linkage")
    elif t in ("same_process", "same_user"):
        st = d.get("stages")
        _req(isinstance(st, list) and len(st) >= 2 and set(st) <= ids, f"{t} stages")
    elif t == "same_value":
        for side in ("left", "right"):
            v = d.get(side)
            _req(isinstance(v, str) and ":" in v, f"same_value {side} must be stage:field")
            s, f = v.split(":", 1)
            _req(s in ids and f.startswith(P.FIELD_PREFIXES), f"same_value {side}")
    elif t == "dns_to_ip":
        _req(d.get("dns") in ids and d.get("network") in ids, "dns_to_ip stages")
    return dict(d)


def parse_rule(doc: Dict[str, Any]) -> SequenceRule:
    _req(isinstance(doc, dict), "rule must be an object")
    _req(set(doc) <= RULE_KEYS, f"unknown rule keys: {sorted(set(doc) - RULE_KEYS)}")
    rid = doc.get("rule_id")
    _req(isinstance(rid, str) and bool(_ID.fullmatch(rid)), f"bad rule_id {rid!r}")
    stages = doc.get("stages")
    _req(isinstance(stages, list) and 1 <= len(stages) <= MAX_STAGES, "stages: 1..10")
    parsed = tuple(_stage(s) for s in stages)
    ids = {s.id for s in parsed}
    _req(len(ids) == len(parsed), "duplicate stage ids")
    _req(not parsed[0].negate and not parsed[0].optional, "first stage must be required")
    rels = doc.get("relationships", [])
    _req(isinstance(rels, list) and len(rels) <= MAX_RELS, "relationships")
    excl = doc.get("exclusions", [])
    _req(isinstance(excl, list) and len(excl) <= MAX_EXCL, "exclusions")
    for e in excl:
        _req(isinstance(e, dict) and (e.get("stage") == "*" or e.get("stage") in ids)
             and isinstance(e.get("reason"), str), "exclusion needs stage, predicate, reason")
        _pred(e.get("predicate"), "exclusion")
    adj = doc.get("confidence_adjustments", [])
    _req(isinstance(adj, list) and len(adj) <= MAX_EXCL, "confidence_adjustments")
    for a in adj:
        _req(isinstance(a, dict) and (a.get("stage") == "*" or a.get("stage") in ids)
             and isinstance(a.get("reason"), str), "adjustment needs stage, predicate, reason")
        _int(a.get("delta"), -100, 100, "delta")
        _pred(a.get("predicate"), "adjustment")
    mitre = doc.get("mitre", [])
    _req(isinstance(mitre, list) and all(isinstance(m, dict) and m.get("technique_id") for m in mitre),
         "mitre entries need technique_id")
    reqs = doc.get("evidence_requirements", [])
    _req(isinstance(reqs, list) and all(isinstance(r, str) and r.startswith(P.FIELD_PREFIXES)
                                        for r in reqs), "evidence_requirements")
    prov = doc.get("provenance", {})
    _req(isinstance(prov, dict) and prov.get("source", "NATIVE") in RULE_SOURCES, "provenance.source")
    lc = doc.get("lifecycle", "DRAFT")
    _req(lc in LIFECYCLE, "lifecycle")
    sev = doc.get("severity")
    _req(sev in SEVERITIES, "severity")
    scope = doc.get("entity_scope", "device")
    _req(scope in SCOPES, "entity_scope")
    for k in ("name", "description"):
        _req(isinstance(doc.get(k), str) and 0 < len(doc[k]) <= 1024, f"{k}")
    return SequenceRule(
        rule_id=rid, version=_int(doc.get("version"), 1, 10**6, "version"),
        name=doc["name"], description=doc["description"],
        enabled=bool(doc.get("enabled", True)), lifecycle=lc, severity=sev,
        confidence=_int(doc.get("confidence"), 0, 100, "confidence"),
        time_window_seconds=_int(doc.get("time_window_seconds"), 1, MAX_WINDOW, "time_window_seconds"),
        entity_scope=scope, ordered=bool(doc.get("ordered", True)), stages=parsed,
        relationships=tuple(_rel(r, ids) for r in rels), exclusions=tuple(excl),
        confidence_adjustments=tuple(adj), mitre=tuple(dict(m) for m in mitre),
        evidence_requirements=tuple(reqs), provenance=dict(prov),
        created_at=str(doc.get("created_at", "")), updated_at=str(doc.get("updated_at", "")),
        content_hash=content_hash(doc), raw=dict(doc))


class RuleRegistry:
    """In-process registry. Versions are immutable; lifecycle is per version."""

    def __init__(self) -> None:
        self._rules: Dict[Tuple[str, int], SequenceRule] = {}

    def register(self, rule: SequenceRule) -> SequenceRule:
        key = (rule.rule_id, rule.version)
        prev = self._rules.get(key)
        if prev is not None and prev.content_hash != rule.content_hash:
            raise RuleError(f"{rule.rule_id} v{rule.version} already registered with different content")
        if prev is None:
            self._rules[key] = rule
        return self._rules[key]

    def get(self, rule_id: str, version: int) -> SequenceRule:
        return self._rules[(rule_id, version)]

    def set_lifecycle(self, rule_id: str, version: int, state: str) -> SequenceRule:
        cur = self.get(rule_id, version)
        if state not in TRANSITIONS[cur.lifecycle]:
            raise RuleError(f"illegal transition {cur.lifecycle} -> {state}")
        if state == "ACTIVE":
            for (rid, v), r in list(self._rules.items()):
                if rid == rule_id and v != version and r.lifecycle == "ACTIVE":
                    self._rules[(rid, v)] = _with(r, "DEPRECATED")
        self._rules[(rule_id, version)] = _with(cur, state)
        return self._rules[(rule_id, version)]

    def live_rules(self) -> List[SequenceRule]:
        return sorted((r for r in self._rules.values()
                       if r.enabled and r.lifecycle in ("ACTIVE", "TESTING")),
                      key=lambda r: (r.rule_id, r.version))

    def all(self) -> List[SequenceRule]:
        return sorted(self._rules.values(), key=lambda r: (r.rule_id, r.version))


def _with(rule: SequenceRule, state: str) -> SequenceRule:
    from dataclasses import replace
    return replace(rule, lifecycle=state)
