"""DCR-1 · the product-neutral evaluation ALLOWLIST.

The store triage surfaced one design question: `_COLLECTED_PRODUCTS` gates a
rule on its declared `logsource.product`, so a **DNS** rule authored with
`product: windows` cannot evaluate DNS evidence from Zeek even though
`network.dns_query` is the same observed value with the same meaning.

The owner decision was option (b), narrowed: an **explicit allowlist of
product-neutral categories**, not a generic "the field exists, therefore any
rule may evaluate" bypass. Four things must all hold before a rule authored
for one product may read another source's evidence:

1. the rule's declared `logsource.category` is on this allowlist;
2. every field the rule inspects is inside that category's field contract —
   a category is not neutral for fields it does not own, so a rule mixing
   `QueryName` with `CommandLine` is NOT eligible and stays product-gated;
3. the evidence is semantically of that category (a `network_connect`
   record is not a DNS observation, even when it carries a `dns_query`
   value copied from a destination-hostname field);
4. the evidence carries real ingest provenance and a tenant.

A canonical field is therefore never automatically product-neutral, and
process/execution behaviour is deliberately absent from the allowlist: a
command line is product-specific, a DNS question is not.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Tuple

#: EXPLICIT allowlist. Adding a category here is a security decision, not a
#: convenience. `process_creation`, `registry_set`, `file`, `proxy`, `ids`
#: and every product-specific category are intentionally excluded.
PRODUCT_NEUTRAL_CATEGORIES = {"dns", "network"}

#: Per-category contract. `fields` is the CLOSED set of Sigma fields the
#: category owns; `evidence_event_types` is the closed set of canonical
#: event types that genuinely carry that category's semantics.
CATEGORY_CONTRACT: Dict[str, Dict[str, Any]] = {
    "dns": {
        "fields": {"QueryName", "SourceIp", "DestinationIp",
                   "DestinationPort", "Protocol"},
        "required_observed_fields": {"QueryName"},
        "evidence_event_types": {"dns_query", "dns_response"},
        "semantic_note": ("a DNS question is the same observed value on any "
                          "platform; only records whose canonical event type "
                          "IS a DNS observation are admissible"),
    },
    "network": {
        "fields": {"SourceIp", "SourcePort", "DestinationIp",
                   "DestinationPort", "Protocol"},
        "required_observed_fields": set(),
        "evidence_event_types": {"network_connect", "network_flow"},
        "semantic_note": ("a 5-tuple is product-neutral; a connection record "
                          "is not a DNS observation and vice versa"),
    },
}

NOT_ELIGIBLE = "NOT_ELIGIBLE"


def neutral_eligibility(category: str, fields: Iterable[str]) -> Tuple[bool, str]:
    """May a rule of `category` inspecting `fields` evaluate cross-product?"""
    cat = (category or "").lower()
    if cat not in PRODUCT_NEUTRAL_CATEGORIES:
        return False, (f"category '{cat or 'none'}' is not on the "
                       f"product-neutral allowlist")
    contract = CATEGORY_CONTRACT[cat]
    fields = {f for f in fields}
    if not fields:
        return False, "the rule inspects no field"
    outside = fields - contract["fields"]
    if outside:
        return False, (f"the rule also inspects {sorted(outside)[:3]}, which "
                       f"the '{cat}' category does not own — a canonical "
                       f"field is not automatically product-neutral")
    missing = contract["required_observed_fields"] - fields
    if missing:
        return False, (f"the rule does not inspect {sorted(missing)}, the "
                       f"defining observation of the '{cat}' category")
    return True, (f"product-neutral '{cat}' rule: every field it inspects is "
                  f"owned by the allowlisted category")


def provenance_state(canonical: Dict[str, Any]) -> Tuple[bool, str]:
    prov = canonical.get("provenance") or {}
    if not prov.get("dsm_id"):
        return False, "evidence carries no dsm_id provenance"
    if not (prov.get("collector_id") or prov.get("trace_id")):
        return False, "evidence carries no collector/trace provenance"
    if not canonical.get("tenant_id"):
        return False, "evidence carries no tenant"
    return True, "provenance and tenant present"


def evidence_admissible(category: str,
                        canonical: Dict[str, Any]) -> Tuple[bool, str]:
    """Is this canonical record genuinely an observation of `category`?"""
    cat = (category or "").lower()
    contract = CATEGORY_CONTRACT.get(cat)
    if not contract:
        return False, f"category '{cat or 'none'}' has no neutral contract"
    etype = str(canonical.get("event_type") or "").lower()
    if etype not in contract["evidence_event_types"]:
        return False, (f"evidence event_type '{etype or 'none'}' is not a "
                       f"'{cat}' observation — canonicalization is not "
                       f"permission to reinterpret evidence")
    return provenance_state(canonical)


def contract_report() -> Dict[str, Any]:
    return {
        "product_neutral_categories": sorted(PRODUCT_NEUTRAL_CATEGORIES),
        "categories": {c: {"fields": sorted(v["fields"]),
                           "required_observed_fields":
                               sorted(v["required_observed_fields"]),
                           "evidence_event_types":
                               sorted(v["evidence_event_types"]),
                           "semantic_note": v["semantic_note"]}
                       for c, v in CATEGORY_CONTRACT.items()},
        "not_neutral": ("process/execution, registry, file and hash fields "
                        "are NOT product-neutral; hashes are consumed only "
                        "by product-gated rules or the explicit IOC "
                        "watchlist contract"),
    }
