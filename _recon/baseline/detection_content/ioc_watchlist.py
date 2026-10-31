"""DCR-1 · the IOC watchlist contract.

The two authored IOC rules (`ioc_file_hash_watchlist`, `ioc_network_watchlist`)
were never bound: their predicates use a `|watchlist` modifier the Sigma
evaluator does not (and should not) implement, and they declare no logsource.
They are bound here under their **own explicit contract** rather than by
widening Sigma or by declaring hashes "product-neutral".

The contract is deliberately narrow:

* only the three declared watchlist namespaces exist; any other namespace or
  modifier is refused at binding time;
* each predicate reads a NAMED canonical path. An absent value is never
  defaulted, and no value is ever derived — a connection record does not
  acquire a domain because some earlier DNS answer mentioned its peer;
* the IP predicate is admissible only on connection-semantics evidence and
  the domain predicate only on DNS-semantics evidence, so a resolver address
  is never judged as a C2 peer;
* the declared semantics are ANY_OF: the rule fires when at least one
  declared predicate matches a genuinely observed value. This differs from
  Sigma's AND-within-a-selection and is stated here rather than implied;
* a watchlist entry scoped to a tenant may only judge that tenant's
  evidence. Unscoped entries are platform threat intel and are cited with
  their source.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

WATCHLIST_COLLECTION = "iocs"
IOC_MODIFIER = "watchlist"
IOC_CONTRACT_ID = "nivxray::detection_content::ioc_watchlist_contract"
DECLARED_SEMANTICS = "ANY_OF"

#: field → (declared namespace, watchlist kind, canonical paths,
#:          admissible canonical event types, normalizer)
IOC_CONTRACT: Dict[str, Dict[str, Any]] = {
    "hash.sha256": {
        "namespace": "ioc.file.sha256",
        "kind": "sha256",
        "paths": [("process", "hashes", "sha256"),
                  ("file", "hashes", "sha256")],
        "event_types": None,          # a hash is a hash on any source
        "lower": True,
    },
    "dst_ip": {
        "namespace": "ioc.network.ip",
        "kind": "ip",
        "paths": [("network", "dest_ip")],
        "event_types": {"network_connect", "network_flow", "network_alert"},
        "lower": False,
    },
    "dst_domain": {
        "namespace": "ioc.network.domain",
        "kind": "domain",
        "paths": [("network", "dns_query")],
        "event_types": {"dns_query", "dns_response"},
        "lower": True,
    },
}


def _resolve(canonical: Dict[str, Any], path: Tuple[str, ...]) -> Any:
    node: Any = canonical
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def bind_predicates(detection: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """Bind an authored IOC detection block to the contract, or refuse."""
    preds: List[Dict[str, Any]] = []
    for sel_name, sel in (detection or {}).items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for raw_key, declared in sel.items():
            parts = str(raw_key).split("|")
            field, mods = parts[0], [m.lower() for m in parts[1:]]
            if mods != [IOC_MODIFIER]:
                return [], (f"predicate '{raw_key}' does not use the single "
                            f"'{IOC_MODIFIER}' modifier the IOC contract "
                            f"defines")
            spec = IOC_CONTRACT.get(field)
            if not spec:
                return [], f"field '{field}' is not in the IOC contract"
            if str(declared) != spec["namespace"]:
                return [], (f"field '{field}' declares watchlist "
                            f"'{declared}', but the contract binds it to "
                            f"'{spec['namespace']}'")
            preds.append({"field": field, **spec})
    if not preds:
        return [], "the stored IOC rule declares no watchlist predicate"
    return preds, (f"bound to {IOC_CONTRACT_ID} with {DECLARED_SEMANTICS} "
                   f"semantics over {len(preds)} declared predicate(s)")


def _lookup(kind: str, value: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    from deps import sync_collection
    doc = sync_collection(WATCHLIST_COLLECTION).find_one(
        {"kind": kind, "value": value}, {"_id": 0})
    if not doc:
        return None
    scoped = doc.get("tenant_id")
    if scoped and scoped != tenant_id:
        return None                     # a tenant's IOC never judges another
    return doc


def evaluate(predicates: List[Dict[str, Any]], canonical: Dict[str, Any],
             evidence_ref: Optional[str]) -> Optional[Dict[str, Any]]:
    """ANY_OF over the declared predicates. Returns a citation or None."""
    from .dcr1_product_neutral import provenance_state

    ok, prov_reason = provenance_state(canonical)
    if not ok:
        return None
    tenant_id = canonical.get("tenant_id")
    etype = str(canonical.get("event_type") or "").lower()
    evaluated: List[Dict[str, Any]] = []
    for p in predicates:
        row: Dict[str, Any] = {
            "predicate": f"{p['field']}|{IOC_MODIFIER}",
            "declared_watchlist": p["namespace"],
            "watchlist_kind": p["kind"],
            "evidence_ref": evidence_ref,
        }
        if p["event_types"] is not None and etype not in p["event_types"]:
            row.update({"result": "EVIDENCE_TYPE_NOT_ADMISSIBLE",
                        "canonical_field": None, "observed_value": None,
                        "field_state": "NOT_ADMISSIBLE",
                        "reason": (f"event_type '{etype or 'none'}' does not "
                                   f"carry {p['field']} semantics")})
            evaluated.append(row)
            continue
        observed, source_path = None, None
        for path in p["paths"]:
            val = _resolve(canonical, path)
            if val not in (None, "", [], {}):
                observed, source_path = val, ".".join(path)
                break
        row["canonical_field"] = source_path
        row["observed_value"] = observed
        if observed is None:
            row.update({"result": "FIELD_ABSENT", "field_state": "ABSENT"})
            evaluated.append(row)
            continue
        row["field_state"] = "PRESENT"
        needle = str(observed)
        if p["lower"]:
            needle = needle.lower()
        hit = _lookup(p["kind"], needle, tenant_id)
        if hit:
            row.update({"result": "MATCH",
                        "watchlist_entry": {
                            "source": hit.get("source"),
                            "severity": hit.get("severity"),
                            "confidence": hit.get("confidence"),
                            "tags": (hit.get("tags") or [])[:6],
                            "first_seen": hit.get("first_seen"),
                            "tenant_scope": hit.get("tenant_id") or "platform"}})
        else:
            row["result"] = "NO_MATCH"
        evaluated.append(row)
    matched = [r for r in evaluated if r["result"] == "MATCH"]
    if not matched:
        return None
    return {"declaration_state": "DECLARED",
            "declared_semantics": DECLARED_SEMANTICS,
            "contract_id": IOC_CONTRACT_ID,
            "citation_completeness": "CITED",
            "provenance_state": prov_reason,
            "evaluated_conditions": evaluated,
            "matched_conditions": matched,
            "unmatched_conditions": [r for r in evaluated
                                     if r["result"] != "MATCH"]}


def contract_report() -> Dict[str, Any]:
    return {"contract_id": IOC_CONTRACT_ID,
            "declared_semantics": DECLARED_SEMANTICS,
            "watchlist_collection": WATCHLIST_COLLECTION,
            "predicates": {f: {"watchlist": s["namespace"],
                               "kind": s["kind"],
                               "canonical_paths": [".".join(p)
                                                   for p in s["paths"]],
                               "admissible_event_types":
                                   sorted(s["event_types"])
                                   if s["event_types"] else "any"}
                           for f, s in IOC_CONTRACT.items()}}
