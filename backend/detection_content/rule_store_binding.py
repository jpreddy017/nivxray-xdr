"""P0-F.3 · bind the AUTHORED rule store to the ONE runtime evaluator.

The ownership audit found a content/runtime split: `xdr_detection_rules`
holds 98 authored SigmaHQ rules that **no runtime path ever read**, while
detection ran only from the in-code library. This module removes the
split WITHOUT adding an engine: it parses each stored rule with the
existing `sigma_strict.strict_parse` and evaluates it with the existing
`nivxray_native_sigma.evaluate`. There is no second evaluator, no second
rule model and no second registry.

Two honesty rules shape the design:

* **A rule is not "active" because it exists.** Every stored rule is
  classified — BOUND, PARSE_FAILED, UNSUPPORTED_BY_EVALUATOR,
  NO_TELEMETRY, LICENSE_BLOCKED, NOT_VALIDATED, DISABLED — and only BOUND
  rules are evaluated. The classification is exposed over the API so
  "which authored rules can actually fire?" is answerable.
* **A Windows rule must never judge Linux evidence.** Rules are gated on
  their own declared `logsource.product`. A rule whose product is not
  collected is reported as NO_TELEMETRY, which is a visibility gap — not
  a rule that passed.
"""
from __future__ import annotations

import ast
import json
import time
import uuid
from typing import Any, Dict, List

import yaml

from .nivxray_native_sigma import evaluate as nx_evaluate
from .sigma_strict import strict_parse

COLLECTION = "xdr_detection_rules"
#: Fixed namespace, so a stored rule's Sigma identity is deterministic.
_SIGMA_ID_NS = uuid.UUID("6f1b0c2e-0000-5000-8000-6e6976787261")
BINDING_ENGINE_ID = "nivxray::detection_content::rule_store_binding"
#: The evaluator is the EXISTING one; this id only names the binding.
RUNTIME_EVALUATOR_ID = "nivxray::detection_content::nivxray_native_sigma"
_CACHE_TTL_SECONDS = 300

_SEVERITY_FROM_LEVEL = {"critical": "critical", "high": "high",
                        "medium": "medium", "low": "low",
                        "informational": "informational"}

#: Sigma field → canonical evidence path. Only fields the platform can
#: actually produce are mapped; an unmapped field yields absent evidence
#: and therefore no match, never a fabricated empty string.
_FIELD_MAP = {
    "Image": ("process", "executable_path"),
    "OriginalFileName": ("process", "name"),
    "CommandLine": ("process", "command_line"),
    "ParentImage": ("process", "parent_executable_path"),
    "ParentCommandLine": ("process", "parent_command_line"),
    "User": ("identity", "username"),
    "TargetFilename": ("file", "path"),
    "DestinationIp": ("network", "dest_ip"),
    "DestinationPort": ("network", "dest_port"),
    "SourceIp": ("network", "src_ip"),
    "TargetObject": ("registry", "key"),
    "Details": ("registry", "value"),
}

#: Which products this platform collects endpoint telemetry for today.
_COLLECTED_PRODUCTS = {"linux"}


def _literal(v: Any) -> Any:
    """The store round-trips nested structures as Python reprs."""
    if isinstance(v, (dict, list)):
        return v
    if not isinstance(v, str):
        return v
    for loader in (json.loads, ast.literal_eval):
        try:
            return loader(v)
        except (ValueError, SyntaxError, TypeError):
            continue
    return v


def flatten_for_sigma(canonical: Dict[str, Any]) -> Dict[str, Any]:
    """Project canonical evidence into the Sigma field namespace.

    A field the evidence does not carry is OMITTED, so a Sigma
    `CommandLine|contains` cannot match on a value we never observed.
    """
    flat: Dict[str, Any] = {}
    for field, (section, key) in _FIELD_MAP.items():
        val = (canonical.get(section) or {}).get(key)
        if val not in (None, ""):
            flat[field] = val
    sig = (canonical.get("security") or {}).get("signature") or {}
    if sig.get("id") is not None:
        flat["security_signature_id"] = sig.get("id")
    return flat


def _selection_fields(detection: Dict[str, Any]) -> set:
    """Every field name the rule inspects, modifiers stripped."""
    out: set = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "condition":
                    continue
                # The key IS the field, whatever the value's shape — a
                # list of alternatives is still one field.
                out.add(str(k).split("|")[0])
                if isinstance(v, dict):
                    walk(v)
        elif isinstance(node, list):
            for i in node:
                walk(i)

    for name, sel in detection.items():
        if name == "condition":
            continue
        walk(sel)
    return {f for f in out if f and not f.startswith("condition")}


def _event_product(canonical: Dict[str, Any]) -> str:
    prod = str(canonical.get("source_product") or "").lower()
    if "linux" in prod:
        return "linux"
    if "windows" in prod:
        return "windows"
    return prod


class _Binding:
    __slots__ = ("rule_id", "upstream_id", "title", "level", "product",
                 "category", "state", "reason", "parsed", "techniques",
                 "sigma_id")

    def __init__(self, doc: Dict[str, Any]):
        self.rule_id = doc.get("id")
        self.upstream_id = doc.get("upstream_id")
        self.title = doc.get("title") or self.upstream_id or self.rule_id
        self.level = str(doc.get("level") or "medium").lower()
        logsource = _literal(doc.get("logsource")) or {}
        self.product = str((logsource or {}).get("product") or "").lower()
        self.category = str((logsource or {}).get("category") or "").lower()
        self.techniques = _literal(doc.get("attack_techniques")) or []
        self.parsed = None
        self.sigma_id = None
        self.state, self.reason = self._bind(doc, logsource)

    def _bind(self, doc, logsource):
        if str(doc.get("license_policy_state") or "").upper() != "PERMITTED":
            return "LICENSE_BLOCKED", "licence policy does not permit runtime use"
        if str(doc.get("state") or "").upper() != "VALIDATED":
            return "NOT_VALIDATED", f"store state={doc.get('state')}"
        if str(doc.get("enabled")) not in ("True", "true", "1"):
            return "DISABLED", "rule is disabled in the store"
        detection = _literal(doc.get("detection"))
        if not isinstance(detection, dict) or not detection:
            return ("STORE_CONTENT_INCOMPLETE",
                    "the stored rule carries no detection block — an "
                    "authoring-data defect, not a parser fault")
        if not logsource:
            return ("STORE_CONTENT_INCOMPLETE",
                    "the stored rule declares no logsource; inventing one "
                    "could let it judge telemetry it was never written for")
        # pySigma requires a UUID identifier; the store's `upstream_id`
        # is SigmaHQ's slug. Derive a STABLE uuid5 from it so the same
        # authored rule always binds to the same Sigma identity, and keep
        # `upstream_id` for traceability back to the store.
        sigma_id = str(uuid.uuid5(_SIGMA_ID_NS,
                                  str(self.upstream_id or self.rule_id)))
        text = yaml.safe_dump({"title": self.title,
                               "id": sigma_id,
                               "logsource": logsource or {},
                               "detection": detection,
                               "level": self.level}, sort_keys=True)
        result = strict_parse(text)
        if result.status != "PARSED":
            return ("PARSE_FAILED",
                    f"{result.error_type}: {result.error_message}"[:200])
        self.parsed = result.rule
        self.sigma_id = sigma_id
        try:
            nx_evaluate(result.rule, {})
        except Exception as e:                                  # noqa: BLE001
            return ("UNSUPPORTED_BY_EVALUATOR",
                    f"{type(e).__name__}: {str(e)[:160]}")
        if self.product and self.product not in _COLLECTED_PRODUCTS:
            return ("NO_TELEMETRY",
                    f"no {self.product} endpoint telemetry is collected "
                    f"today — this is a visibility gap, not a clean result")
        # A rule none of whose fields this platform can produce cannot
        # fire. Reporting it as active would be a lie of omission.
        fields = _selection_fields(detection)
        if not fields:
            return ("NO_TELEMETRY",
                    "keyword-only rule: it matches free text in a raw log "
                    "body, which canonical evidence does not carry")
        if not (fields & set(_FIELD_MAP)):
            return ("NO_TELEMETRY",
                    "none of the fields this rule inspects "
                    f"({', '.join(sorted(fields)[:4])}) are produced by any "
                    "collected telemetry today")
        return "BOUND", "parsed, supported by the runtime evaluator"

    def as_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "upstream_id": self.upstream_id,
                "sigma_id": self.sigma_id,
                "title": self.title, "level": self.level,
                "product": self.product or None,
                "category": self.category or None,
                "binding_state": self.state, "reason": self.reason,
                "mitre_attack": self.techniques,
                "runtime_evaluator": (RUNTIME_EVALUATOR_ID
                                      if self.state == "BOUND" else None)}


_cache: Dict[str, Any] = {"at": 0.0, "bindings": []}


def load_bindings(force: bool = False) -> List[_Binding]:
    """Bind every authored rule in the store. Cached, because binding
    parses Sigma and must not run per event."""
    if not force and _cache["bindings"] and (
            time.time() - _cache["at"] < _CACHE_TTL_SECONDS):
        return _cache["bindings"]
    from deps import sync_collection
    bindings = [_Binding(d) for d in
                sync_collection(COLLECTION).find({}, {"_id": 0})]
    _cache.update({"at": time.time(), "bindings": bindings})
    return bindings


def binding_report() -> Dict[str, Any]:
    bindings = load_bindings()
    by_state: Dict[str, int] = {}
    for b in bindings:
        by_state[b.state] = by_state.get(b.state, 0) + 1
    return {
        "store_collection": COLLECTION,
        "authored_rules": len(bindings),
        "runtime_evaluator": RUNTIME_EVALUATOR_ID,
        "binding_engine": BINDING_ENGINE_ID,
        "by_binding_state": by_state,
        "evaluated_at_runtime": by_state.get("BOUND", 0),
        "rules": [b.as_dict() for b in bindings],
        "honesty_note": (
            "Only BOUND rules are evaluated at runtime. NO_TELEMETRY means "
            "the rule is valid and supported but the platform collects no "
            "telemetry for its product — a visibility gap, never a pass. "
            "No second evaluator exists: BOUND rules run through "
            + RUNTIME_EVALUATOR_ID + "."),
    }


def evaluate_store_rules(canonical: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate the BOUND authored rules against one canonical event.

    Returned rows use the SAME shape as the in-code library's matches, so
    downstream IUE/VEEE cannot tell the two content sources apart — which
    is the point: one engine, one verdict path, two content origins.
    """
    flat = flatten_for_sigma(canonical)
    if not flat:
        return []
    product = _event_product(canonical)
    out: List[Dict[str, Any]] = []
    for b in load_bindings():
        if b.state != "BOUND":
            continue
        if b.product and product and b.product != product:
            continue          # a Windows rule never judges Linux evidence
        try:
            if not nx_evaluate(b.parsed, flat):
                continue
        except Exception:                                       # noqa: BLE001
            continue          # unsupported at evaluation time → no verdict
        out.append({
            "rule_id": b.rule_id,
            "name": b.title,
            "tactic": (b.category or "unknown"),
            "technique_id": (b.techniques[0] if b.techniques else ""),
            "technique_name": "",
            "severity": _SEVERITY_FROM_LEVEL.get(b.level, "medium"),
            "confidence": "high",
            "lane": "endpoint" if b.product == "linux" else (b.product
                                                             or "unknown"),
            "mitre_attack": b.techniques,
            "content_origin": "authored_store",
            "upstream_id": b.upstream_id,
        })
    return out
