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

from . import ioc_watchlist
from .dcr1_product_neutral import contract_report as _neutral_contract_report
from .dcr1_product_neutral import (evidence_admissible, neutral_eligibility)
from .detection_estate import estate as _estate
from .nivxray_native_sigma import _eval_selection
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

#: Sigma field → candidate canonical evidence paths, first PRESENT one wins.
#: Only fields the platform can actually produce are mapped; an unmapped
#: field yields absent evidence and therefore no match, never a fabricated
#: empty string. A field being mapped says nothing about which rules may
#: read it — see `dcr1_product_neutral`.
_FIELD_MAP = {
    "Image": (("process", "executable_path"),),
    "OriginalFileName": (("process", "name"),),
    "CommandLine": (("process", "command_line"),),
    "ParentImage": (("process", "parent_executable_path"),),
    "ParentCommandLine": (("process", "parent_command_line"),),
    "User": (("identity", "username"),),
    "TargetFilename": (("file", "path"),),
    "DestinationIp": (("network", "dest_ip"),),
    "DestinationPort": (("network", "dest_port"),),
    "SourceIp": (("network", "src_ip"),),
    "TargetObject": (("registry", "key"),),
    "Details": (("registry", "value"),),
    # DCR-1 · canonical fields N1 (Zeek) and N2.1 already emit.
    "QueryName": (("network", "dns_query"),),
    "SourcePort": (("network", "src_port"),),
    "Protocol": (("network", "protocol"),),
    "sha256": (("process", "hashes", "sha256"), ("file", "hashes", "sha256")),
    "SHA256": (("process", "hashes", "sha256"), ("file", "hashes", "sha256")),
    "sha1": (("process", "hashes", "sha1"), ("file", "hashes", "sha1")),
    "SHA1": (("process", "hashes", "sha1"), ("file", "hashes", "sha1")),
    "md5": (("process", "hashes", "md5"), ("file", "hashes", "md5")),
    "MD5": (("process", "hashes", "md5"), ("file", "hashes", "md5")),
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


def _resolve_path(canonical: Dict[str, Any], path) -> Any:
    node: Any = canonical
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def flatten_with_paths(canonical: Dict[str, Any]):
    """Project canonical evidence into the Sigma field namespace.

    Returns `(flat, paths)` where `paths[field]` is the canonical path the
    value genuinely came from — that path is what a citation reports, so no
    match ever claims a field it did not read. A field the evidence does not
    carry is OMITTED, so a Sigma `CommandLine|contains` cannot match on a
    value we never observed.
    """
    flat: Dict[str, Any] = {}
    paths: Dict[str, str] = {}
    for field, candidates in _FIELD_MAP.items():
        for path in candidates:
            val = _resolve_path(canonical, path)
            if val not in (None, "", [], {}):
                flat[field] = val
                paths[field] = ".".join(path)
                break
    sig = (canonical.get("security") or {}).get("signature") or {}
    if sig.get("id") is not None:
        flat["security_signature_id"] = sig.get("id")
        paths["security_signature_id"] = "security.signature.id"
    return flat, paths


def flatten_for_sigma(canonical: Dict[str, Any]) -> Dict[str, Any]:
    return flatten_with_paths(canonical)[0]


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


def _predicates(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The rule's leaf predicates: (selection, raw key, declared value).

    Used only to build a citation. The verdict stays with the evaluator —
    each predicate is re-checked by the SAME evaluator over a single-key
    selection, so a citation can never disagree with the match.
    """
    out: List[Dict[str, Any]] = []
    for name, sel in (detection or {}).items():
        if name == "condition" or not isinstance(sel, dict):
            continue
        for key, expected in sel.items():
            if isinstance(expected, dict):
                continue
            out.append({"selection": name, "key": str(key),
                        "field": str(key).split("|")[0],
                        "declared_value": expected})
    return out


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
                 "sigma_id", "rule_type", "contract", "product_neutral",
                 "inspected_fields", "ioc_predicates", "predicates",
                 "rule_version")

    def __init__(self, doc: Dict[str, Any]):
        self.rule_id = doc.get("id")
        self.upstream_id = doc.get("upstream_id")
        self.title = doc.get("title") or self.upstream_id or self.rule_id
        self.level = str(doc.get("level") or "medium").lower()
        logsource = _literal(doc.get("logsource")) or {}
        self.product = str((logsource or {}).get("product") or "").lower()
        self.category = str((logsource or {}).get("category") or "").lower()
        self.techniques = _literal(doc.get("attack_techniques")) or []
        self.rule_type = str(doc.get("rule_type") or "").lower()
        self.rule_version = str(doc.get("upstream_version") or "1")
        self.parsed = None
        self.sigma_id = None
        self.contract = "sigma"
        self.product_neutral = False
        self.inspected_fields = set()
        self.ioc_predicates = []
        self.predicates = []
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
        # DCR-1 · the IOC lane has its own contract: its `|watchlist`
        # predicate is not Sigma and is deliberately not made Sigma.
        if self.rule_type == "ioc":
            preds, reason = ioc_watchlist.bind_predicates(detection)
            if not preds:
                return "UNSUPPORTED_BY_IOC_CONTRACT", reason
            self.contract = "ioc"
            self.ioc_predicates = preds
            return "BOUND", reason
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
        # A rule none of whose fields this platform can produce cannot
        # fire. Reporting it as active would be a lie of omission.
        fields = _selection_fields(detection)
        self.inspected_fields = fields
        self.predicates = _predicates(detection)
        if not fields:
            return ("NO_TELEMETRY",
                    "keyword-only rule: it matches free text in a raw log "
                    "body, which canonical evidence does not carry")
        if not (fields & set(_FIELD_MAP)):
            return ("NO_TELEMETRY",
                    "none of the fields this rule inspects "
                    f"({', '.join(sorted(fields)[:4])}) are produced by any "
                    "collected telemetry today")
        if self.product and self.product not in _COLLECTED_PRODUCTS:
            # DCR-1 · an allowlisted product-neutral category may read
            # another source's evidence, but ONLY under the contract in
            # `dcr1_product_neutral` — never because a field exists.
            neutral, why = neutral_eligibility(self.category, fields)
            if neutral:
                self.product_neutral = True
                return "BOUND", (f"{why}; its declared product "
                                 f"'{self.product}' is not collected, so it "
                                 f"evaluates only category-admissible "
                                 f"evidence with real provenance")
            return ("NO_TELEMETRY",
                    f"no {self.product} endpoint telemetry is collected "
                    f"today — this is a visibility gap, not a clean result "
                    f"({why})")
        return "BOUND", "parsed, supported by the runtime evaluator"

    def as_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "upstream_id": self.upstream_id,
                "sigma_id": self.sigma_id,
                "title": self.title, "level": self.level,
                "product": self.product or None,
                "category": self.category or None,
                "binding_state": self.state, "reason": self.reason,
                "mitre_attack": self.techniques,
                "evaluation_contract": self.contract,
                "product_neutral": self.product_neutral,
                "runtime_evaluator": (self._runtime_id()
                                      if self.state == "BOUND" else None)}

    def _runtime_id(self) -> str:
        return (ioc_watchlist.IOC_CONTRACT_ID if self.contract == "ioc"
                else RUNTIME_EVALUATOR_ID)


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
    from deps import sync_collection
    estate = _estate(sync_collection(COLLECTION).find({}, {"_id": 0}))
    neutral = [b.as_dict() for b in bindings if b.product_neutral]
    return {
        "store_collection": COLLECTION,
        "authored_rules": len(bindings),
        "runtime_evaluator": RUNTIME_EVALUATOR_ID,
        "binding_engine": BINDING_ENGINE_ID,
        "by_binding_state": by_state,
        "evaluated_at_runtime": by_state.get("BOUND", 0),
        "detection_estate": estate,
        "product_neutral_contract": _neutral_contract_report(),
        "ioc_contract": ioc_watchlist.contract_report(),
        "product_neutral_bound": neutral,
        "rules": [b.as_dict() for b in bindings],
        "honesty_note": (
            "Only BOUND rules are evaluated at runtime. NO_TELEMETRY means "
            "the rule is valid and supported but the platform collects no "
            "telemetry for its product — a visibility gap, never a pass. "
            "No second evaluator exists: BOUND Sigma rules run through "
            + RUNTIME_EVALUATOR_ID + ", and the IOC lane runs under its own "
            "declared contract. `authored_rules` counts STORE ROWS; the "
            "detection denominator is "
            "detection_estate.authored_detections_distinct."),
    }


def _sigma_citation(b: "_Binding", flat: Dict[str, Any],
                    paths: Dict[str, str], evidence_ref) -> Dict[str, Any]:
    """D8 · what the rule declared, what was observed, and from where."""
    if not b.predicates:
        return {"declaration_state": "NOT_DECLARED",
                "citation_completeness": "NOT_DECLARED",
                "evaluated_conditions": [], "matched_conditions": [],
                "unmatched_conditions": [],
                "note": ("the stored rule exposes no leaf predicate, so no "
                         "citation can be produced; the matched field is "
                         "NOT inferred")}
    evaluated: List[Dict[str, Any]] = []
    for p in b.predicates:
        field = p["field"]
        row = {"predicate": p["key"], "selection": p["selection"],
               "declared_value": p["declared_value"],
               "canonical_field": paths.get(field),
               "observed_value": flat.get(field),
               "evidence_ref": evidence_ref}
        if field not in flat:
            row.update({"field_state": "ABSENT", "result": "FIELD_ABSENT"})
        else:
            row["field_state"] = "PRESENT"
            try:
                row["result"] = ("MATCH" if _eval_selection(
                    {p["key"]: p["declared_value"]}, flat) else "NO_MATCH")
            except Exception as e:                              # noqa: BLE001
                row["result"] = "EVALUATION_ERROR"
                row["error"] = str(e)[:200]
        evaluated.append(row)
    matched = [r for r in evaluated if r["result"] == "MATCH"]
    return {"declaration_state": "DECLARED",
            "citation_completeness": (
                "CITED" if matched
                else "NO_DECLARED_CONDITION_MATCHED_DESPITE_RULE_MATCH"),
            "evaluated_conditions": evaluated,
            "matched_conditions": matched,
            "unmatched_conditions": [r for r in evaluated
                                     if r["result"] != "MATCH"]}


def _match_row(b: "_Binding", citation: Dict[str, Any],
               evidence_ref) -> Dict[str, Any]:
    return {
        "rule_id": b.rule_id,
        "rule_version": b.rule_version,
        "name": b.title,
        "tactic": (b.category or ("ioc" if b.contract == "ioc"
                                  else "unknown")),
        "technique_id": (b.techniques[0] if b.techniques else ""),
        "technique_name": "",
        "severity": _SEVERITY_FROM_LEVEL.get(b.level, "medium"),
        "confidence": "high",
        "lane": ("ioc" if b.contract == "ioc"
                 else "endpoint" if b.product == "linux"
                 else (b.category or b.product or "unknown")),
        "mitre_attack": b.techniques,
        "content_origin": "authored_store",
        "upstream_id": b.upstream_id,
        "evaluation_contract": b.contract,
        "product_neutral": b.product_neutral,
        "evidence_ref": evidence_ref,
        "citation": citation,
    }


def evaluate_store_rules(canonical: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate the BOUND authored rules against one canonical event.

    Returned rows use the SAME shape as the in-code library's matches, so
    downstream IUE/VEEE cannot tell the two content sources apart — which
    is the point: one engine, one verdict path, two content origins.
    """
    flat, paths = flatten_with_paths(canonical)
    product = _event_product(canonical)
    evidence_ref = (f"xdr_canonical_evidence/{canonical.get('event_id')}"
                    if canonical.get("event_id") else None)
    out: List[Dict[str, Any]] = []
    for b in load_bindings():
        if b.state != "BOUND":
            continue
        if b.contract == "ioc":
            citation = ioc_watchlist.evaluate(b.ioc_predicates, canonical,
                                              evidence_ref)
            if citation:
                out.append(_match_row(b, citation, evidence_ref))
            continue
        if not flat:
            continue
        if b.product_neutral:
            # DCR-1 · cross-product evaluation is admissible only for the
            # allowlisted category, on category-semantic evidence, with
            # every inspected field GENUINELY observed.
            admissible, _why = evidence_admissible(b.category, canonical)
            if not admissible:
                continue
            if not b.inspected_fields.issubset(set(flat)):
                continue
        elif b.product and product and b.product != product:
            continue          # a Windows rule never judges Linux evidence
        try:
            if not nx_evaluate(b.parsed, flat):
                continue
        except Exception:                                       # noqa: BLE001
            continue          # unsupported at evaluation time → no verdict
        out.append(_match_row(b, _sigma_citation(b, flat, paths,
                                                 evidence_ref),
                              evidence_ref))
    return out
