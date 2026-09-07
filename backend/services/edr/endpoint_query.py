"""P0-2C · the single endpoint-identity query invariant.

The F-1 defect class recurred three times because endpoint identity
resolution was written PER QUERY SITE.  A surface that queried an
endpoint-keyed store with the raw string the caller happened to supply
returned an empty array for an endpoint that genuinely has evidence —
a false-honest empty state.

This module is the one place that expresses the invariant:

    external identifier
        -> tenant-scoped resolution (device_identity.resolve)
        -> canonical endpoint identity + VALIDATED alias set
                                  (device_identity.identity_refs)
        -> downstream evidence query built from the store's own
           registered identity fields

It creates NO second resolver: `resolve_endpoint` delegates to
`services.edr.device_identity`, which remains the only authority.  It
widens identifiers, never authorisation, and never infers an identifier
from a name, a pid or a timestamp.

`ENDPOINT_KEYED_STORES` is a CONTRACT, not documentation: the structural
regression guard (`tests/edr/test_p0_2c_alias_invariant.py`) reads it to
find live query sites, so a newly added store or field has to be
declared here before it can be queried.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from services.edr import device_identity as dir_svc

ENDPOINT_NOT_RESOLVED = "ENDPOINT_NOT_RESOLVED"

# store -> the fields that key a record to ONE endpoint identity.
# Every field listed here may legitimately hold a historical alias, so a
# query must address the validated alias set and not one canonical
# string.
ENDPOINT_KEYED_STORES: Dict[str, List[str]] = {
    "v2_shadow_observations": [
        "event.device_iid", "device_iid",
        "collector_id", "connector_id",
        "event.computer", "event.raw.computer", "event.raw.hostname",
    ],
    "edr_raw_events":        ["endpoint_ref"],
    "edr_response_commands": ["endpoint_id"],
    "edr_endpoints":         ["endpoint_id", "device_iid", "hostname"],
    "workspace_cases":       ["endpoint_campaign.endpoint_id",
                              "endpoint_campaign.hostname"],
}

UNRESOLVED_NOTE = ("no endpoint you are authorised for resolves to this "
                   "reference — this is an authorisation or identity "
                   "outcome, not a statement about the evidence")


@dataclass(frozen=True)
class EndpointResolution:
    """One resolved endpoint and every identifier that addresses it."""
    supplied: str
    identity: Dict[str, Any]
    refs: List[str] = field(default_factory=list)

    @property
    def device_iid(self) -> Optional[str]:
        return self.identity.get("device_iid")

    @property
    def hostname(self) -> Optional[str]:
        return self.identity.get("hostname")

    @property
    def resolved_via(self) -> Optional[str]:
        return self.identity.get("resolved_via")

    def descriptor(self) -> Dict[str, Any]:
        """What the surface discloses about how it addressed the store."""
        return {
            "resolved":      True,
            "resolved_via":  self.resolved_via,
            "device_iid":    self.device_iid,
            "hostname":      self.hostname,
            "endpoint_id":   self.identity.get("endpoint_id"),
            "tenant_id":     self.identity.get("tenant_id"),
            "addressed_by":  list(self.refs),
        }

    def predicate(self, store: str,
                  fields: Optional[List[str]] = None) -> Dict[str, Any]:
        return endpoint_predicate(self.refs, store, fields)


def resolve_endpoint(supplied: Optional[str],
                     scope: Any) -> Optional[EndpointResolution]:
    """Resolve a caller-supplied endpoint identifier under ITS OWN scope.

    Returns ``None`` when nothing the principal is authorised for
    resolves — the caller must then emit `ENDPOINT_NOT_RESOLVED`, never
    an empty collection.
    """
    if not supplied or not str(supplied).strip():
        return None
    supplied = str(supplied).strip()
    identity = dir_svc.resolve(supplied, scope)
    if not identity:
        return None
    refs = dir_svc.identity_refs(identity, supplied,
                                 tenant_ids=_authorised_tenants(scope, identity))
    return EndpointResolution(supplied=supplied, identity=identity, refs=refs)


def _authorised_tenants(scope: Any,
                        identity: Dict[str, Any]) -> Optional[List[str]]:
    """The tenants whose enrolment records may contribute an alias.

    The reverse lookup (device_iid/hostname -> endpoint_id) reads the
    enrolment registry, which IS tenant-partitioned.  Without this
    constraint a hostname enrolled in two customers would hand one
    customer's surface the other customer's `endpoint_id`, and the
    downstream evidence query would then address the other customer's
    records.  Constraining it can only ever narrow the alias set.

    ``None`` means "no constraint", and is returned only for a
    cross-tenant principal reading an observation that carries no
    tenant at all.
    """
    tenant = identity.get("tenant_id")
    if tenant:
        return [str(tenant)]
    if isinstance(scope, dict):
        if scope.get("all_tenants"):
            return None
        ids = [str(t) for t in (scope.get("tenant_ids") or [])]
        return ids or []
    return None if scope else []


def endpoint_predicate(refs: List[str], store: str,
                       fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """A query predicate over the VALIDATED alias set for one store.

    `fields` narrows the registered field list (a projection may only
    care about two of them); it can never introduce a field that is not
    registered for the store, so an undeclared identity field cannot be
    queried through this helper.
    """
    known = ENDPOINT_KEYED_STORES.get(store)
    if known is None:
        raise KeyError(f"{store} is not a declared endpoint-keyed store — "
                       f"declare its identity fields in "
                       f"ENDPOINT_KEYED_STORES before querying it")
    use = [f for f in (fields or known) if f in known]
    if not use:
        raise KeyError(f"none of {fields} are declared identity fields of "
                       f"{store}")
    refs = [str(r) for r in (refs or []) if r]
    if not refs:
        # Never degrade to an unfiltered read of an endpoint-keyed store.
        return {"_nivx_unresolved_endpoint": {"$exists": True}}
    if len(use) == 1:
        return {use[0]: {"$in": refs}}
    return {"$or": [{f: {"$in": refs}} for f in use]}


def unresolved_envelope(supplied: Optional[str], *,
                        engine_id: Optional[str] = None,
                        **extra: Any) -> Dict[str, Any]:
    """The one shape every surface returns for a supplied-but-unresolved
    endpoint identifier.  It is explicitly NOT an empty result set."""
    out: Dict[str, Any] = {
        "endpoint_id": supplied,
        "state": ENDPOINT_NOT_RESOLVED,
        "reason": ENDPOINT_NOT_RESOLVED,
        "identity": {"resolved": False, "resolved_via": None,
                     "addressed_by": []},
        "note": UNRESOLVED_NOTE,
    }
    if engine_id:
        out["engine_id"] = engine_id
    out.update(extra)
    return out
