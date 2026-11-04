"""X1 · Entity resolution — ONE place that decides what an entity is.

Before this module, identity logic lived in at least three places:
`xdr_spread_watchlist` (owner-locked spread keys), `xdr_ice` (signal
fields) and the `edr_plane` contracts. Each was correct in its own lane and
none of them could answer the question an XDR must answer: *is this thing
over here the same thing as that thing over there?*

The rule that makes this safe is the one N1 and N2.1 already established:
an entity is AUTHORITATIVE only when a source minted an identity that is
unique by construction. Everything a source merely *observed* — an address,
a hostname, a bare username — is DECLARED. Declared entities are real
evidence and are worth recording; they are simply never allowed to decide
that two things are the same.

    AUTHORITATIVE   endpoint_id, ProcessGuid / process_iid, sha256,
                    cloud principal id
    DECLARED        hostname, address, domain, bare username
    NOT_OBSERVED    the evidence did not carry it

Relationships carry their own truth, which is NOT the same question as
entity identity:

    AUTHORITATIVE   one source stated both ends in the SAME record, and
                    both ends are authoritative identities
    SUPPORTED       the source stated the relationship, but one end is a
                    declared identity (a DNS answer, a user on a host)
    AMBIGUOUS       the relationship is real as an observation but cannot
                    be trusted as identity (an endpoint's address)
    CONTRADICTED    two pieces of evidence disagree; BOTH are kept
    UNRESOLVED      asserted and later retracted, or never established
    FORBIDDEN       structurally unsafe (address → endpoint identity).
                    Recorded ON PURPOSE, so the refusal is visible rather
                    than being an absence someone later "fixes".
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Entity types ──────────────────────────────────────────────────
ENDPOINT = "endpoint"
PROCESS = "process"
USER = "user"
IP = "ip"
DOMAIN = "domain"
FILE_HASH = "file_hash"
APPLICATION = "application"
CLOUD_IDENTITY = "cloud_identity"

ENTITY_TYPES = (ENDPOINT, PROCESS, USER, IP, DOMAIN, FILE_HASH,
                APPLICATION, CLOUD_IDENTITY)

# ── Identity states ───────────────────────────────────────────────
AUTHORITATIVE = "AUTHORITATIVE"
DECLARED = "DECLARED"
NOT_OBSERVED = "NOT_OBSERVED"

#: Types that can NEVER be authoritative, whatever a source claims. An
#: address is a lease and a domain is a name; neither identifies a thing.
NEVER_AUTHORITATIVE = (IP, DOMAIN)

# ── Relationship states ───────────────────────────────────────────
REL_AUTHORITATIVE = "AUTHORITATIVE"
REL_SUPPORTED = "SUPPORTED"
REL_AMBIGUOUS = "AMBIGUOUS"
REL_CONTRADICTED = "CONTRADICTED"
REL_UNRESOLVED = "UNRESOLVED"
REL_FORBIDDEN = "FORBIDDEN"

RELATIONSHIP_STATES = (REL_AUTHORITATIVE, REL_SUPPORTED, REL_AMBIGUOUS,
                       REL_CONTRADICTED, REL_UNRESOLVED, REL_FORBIDDEN)

#: Only these may compose evidence into one incident. Stated here, once.
MERGEABLE_IDENTITY_STATES = (AUTHORITATIVE,)


def _digest(*parts: Any) -> str:
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:24]


def entity_id(tenant_id: str, etype: str, key: str) -> str:
    """Deterministic and tenant-scoped: the same real thing always resolves
    to the same id, and no two tenants can ever collide."""
    return f"ent_{etype}_{_digest(tenant_id, etype, key)}"


@dataclass
class Entity:
    tenant_id: str
    entity_type: str
    key: str
    identity_state: str
    identity_basis: str
    evidence_refs: List[str] = field(default_factory=list)
    first_observed: str = ""
    last_observed: str = ""
    sources: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return entity_id(self.tenant_id, self.entity_type, self.key)

    def to_doc(self) -> Dict[str, Any]:
        return {"entity_id": self.id, "tenant_id": self.tenant_id,
                "entity_type": self.entity_type, "key": self.key,
                "identity_state": self.identity_state,
                "identity_basis": self.identity_basis,
                "evidence_refs": list(self.evidence_refs),
                "first_observed": self.first_observed,
                "last_observed": self.last_observed,
                "sources": list(self.sources),
                "attributes": dict(self.attributes)}


@dataclass
class Relationship:
    tenant_id: str
    relationship_type: str
    source_entity: str
    target_entity: str
    state: str
    identity_basis: str
    reason: str
    evidence_refs: List[str] = field(default_factory=list)
    first_observed: str = ""
    last_observed: str = ""
    sources: List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return "rel_" + _digest(self.tenant_id, self.relationship_type,
                                self.source_entity, self.target_entity)

    def to_doc(self) -> Dict[str, Any]:
        return {"relationship_id": self.id, "tenant_id": self.tenant_id,
                "relationship_type": self.relationship_type,
                "source_entity": self.source_entity,
                "target_entity": self.target_entity,
                "state": self.state, "identity_basis": self.identity_basis,
                "reason": self.reason,
                "evidence_refs": list(self.evidence_refs),
                "first_observed": self.first_observed,
                "last_observed": self.last_observed,
                "sources": list(self.sources)}


def _times(canonical: Dict[str, Any]) -> str:
    return (canonical.get("event_time") or canonical.get("timestamp")
            or datetime.now(timezone.utc).isoformat())


def _ref(canonical: Dict[str, Any]) -> Optional[str]:
    eid = canonical.get("event_id")
    return f"xdr_canonical_evidence/{eid}" if eid else None


def _source(canonical: Dict[str, Any]) -> str:
    return (canonical.get("source_product") or canonical.get("source_vendor")
            or (canonical.get("provenance") or {}).get("dsm_id") or "unknown")


def resolve_entities(canonical: Dict[str, Any],
                     tenant_id: Optional[str] = None) -> List[Entity]:
    """Typed entities for one canonical event. Absent stays absent."""
    if not isinstance(canonical, dict):
        return []
    tid = tenant_id or canonical.get("tenant_id") or ""
    at, ref, src = _times(canonical), _ref(canonical), _source(canonical)
    refs = [ref] if ref else []
    out: List[Entity] = []

    def add(etype, key, state, basis, **attrs):
        if not key:
            return
        if etype in NEVER_AUTHORITATIVE:
            state = DECLARED if state == AUTHORITATIVE else state
        out.append(Entity(tid, etype, str(key), state, basis, list(refs),
                          at, at, [src], attrs))

    host = canonical.get("host") or {}
    extra = canonical.get("additional_fields") or {}
    proc = canonical.get("process") or {}
    net = canonical.get("network") or {}
    ident = canonical.get("identity") or {}
    fil = canonical.get("file") or {}

    # Endpoint — an authenticated enrolment is identity; a hostname a log
    # record happened to contain is not.
    if extra.get("endpoint_id"):
        add(ENDPOINT, extra["endpoint_id"], AUTHORITATIVE,
            "authenticated enrolment (edr_endpoints.endpoint_id)")
    elif host.get("host_id") or host.get("hostname"):
        add(ENDPOINT, host.get("host_id") or host.get("hostname"), DECLARED,
            "hostname reported inside a log record; hostnames are reused, "
            "renamed and spoofable, so this is context, not identity")

    # Process — N2.1 already decided this question; it is not re-litigated.
    if proc.get("attribution_state") == "SOURCE_PROCESS_IDENTITY":
        add(PROCESS, proc.get("process_guid") or proc.get("process_iid"),
            AUTHORITATIVE,
            proc.get("attribution_reason") or "source process identity",
            pid=proc.get("pid"), image=proc.get("executable_path")
            or proc.get("name"))
    elif proc.get("pid") is not None:
        # Deliberately NOT an entity: a PID is not a process. The fact is
        # kept on the evidence, where it already lives.
        pass

    # User — a bare username is a name, not a principal.
    if ident.get("principal_id") and "@" in str(ident.get("principal_id")):
        add(CLOUD_IDENTITY, ident["principal_id"], AUTHORITATIVE,
            "cloud principal (UPN) minted by the identity provider")
    if ident.get("username"):
        add(USER, ident["username"], DECLARED,
            "username as reported by the source; not unique across "
            "directories and not a principal id")

    # Addresses and names — evidence, never identity.
    for key in ("src_ip", "dest_ip"):
        if net.get(key):
            add(IP, net[key], DECLARED,
                f"network.{key} as observed; an address is a lease, not a "
                "device")
    for ip in (net.get("dns_response_ips") or []):
        add(IP, ip, DECLARED, "dns answer address")
    if net.get("dns_query"):
        add(DOMAIN, net["dns_query"], DECLARED, "dns query name")

    # File — content addressing is genuinely unique.
    sha = (fil.get("hashes") or {}).get("sha256") or \
        (proc.get("hashes") or {}).get("sha256")
    if sha:
        add(FILE_HASH, sha, AUTHORITATIVE, "sha256 content hash")

    if extra.get("workload") or canonical.get("source_product"):
        app = extra.get("workload") or canonical.get("source_product")
        add(APPLICATION, app, DECLARED,
            "application/workload named by the source record")
    return out


def _by_type(entities: List[Entity]) -> Dict[str, Entity]:
    out: Dict[str, Entity] = {}
    for e in entities:
        out.setdefault(e.entity_type, e)
    return out


def derive_relationships(canonical: Dict[str, Any],
                         entities: List[Entity]) -> List[Relationship]:
    """Relationships this ONE record actually states.

    Nothing here looks across records. A relationship between two things
    observed at different times by different sources is exactly the
    coincidence this platform refuses to manufacture.
    """
    tid = entities[0].tenant_id if entities else (
        canonical.get("tenant_id") or "")
    at, ref, src = _times(canonical), _ref(canonical), _source(canonical)
    refs = [ref] if ref else []
    idx = _by_type(entities)
    net = canonical.get("network") or {}
    out: List[Relationship] = []

    def rel(rtype, a: Optional[Entity], b: Optional[Entity], state, basis,
            reason):
        if not (a and b):
            return
        out.append(Relationship(tid, rtype, a.id, b.id, state, basis,
                                reason, list(refs), at, at, [src]))

    ep, proc = idx.get(ENDPOINT), idx.get(PROCESS)
    user, dom = idx.get(USER), idx.get(DOMAIN)
    cloud, fh = idx.get(CLOUD_IDENTITY), idx.get(FILE_HASH)

    if ep and proc:
        authoritative = ep.identity_state == AUTHORITATIVE
        rel("endpoint_runs_process", ep, proc,
            REL_AUTHORITATIVE if authoritative else REL_SUPPORTED,
            ep.identity_basis,
            "one record states both the endpoint and an identified process"
            if authoritative else
            "the process identity is authoritative but the endpoint scope "
            "is only a declared hostname")

    # process → the peer it contacted, from the SAME record.
    dest = net.get("dest_ip")
    if proc and dest and canonical.get("event_type") in (
            "network_connect", "network_alert"):
        peer = next((e for e in entities
                     if e.entity_type == IP and e.key == dest), None)
        rel("process_connected_to", proc, peer, REL_AUTHORITATIVE,
            proc.identity_basis,
            "the source stated the process and the connection in one record")

    # DNS: a query resolved to an address. Stated by the source, but an
    # address is a declared identity — SUPPORTED, never AUTHORITATIVE.
    for ip in (net.get("dns_response_ips") or []):
        answer = next((e for e in entities
                       if e.entity_type == IP and e.key == ip), None)
        rel("domain_resolved_to", dom, answer, REL_SUPPORTED,
            "dns answer stated by the resolver",
            "the resolver stated this answer; addresses rotate and are "
            "shared, so the relationship is supported, not identity")
        if proc:
            rel("process_resolved_domain", proc, dom, REL_AUTHORITATIVE,
                proc.identity_basis,
                "the source stated the process and the query in one record")

    if user and ep:
        rel("user_active_on_endpoint", user, ep, REL_SUPPORTED,
            "username reported alongside the activity",
            "the source reported a username with this activity; a username "
            "is not a principal id, so the relationship is supported")
    if cloud and user:
        rel("cloud_identity_of_user", cloud, user, REL_SUPPORTED,
            "principal id and username on one record",
            "the identity provider stated both")
    if proc and fh:
        rel("process_image_hash", proc, fh, REL_AUTHORITATIVE,
            "sha256 of the executed image",
            "content hash recorded on the same record as the process")

    # The refusal, made visible. An endpoint's address is recorded as a
    # FORBIDDEN identity edge so that nobody later mistakes its absence
    # for an oversight and "fixes" it.
    src_ip = net.get("src_ip")
    if ep and src_ip:
        addr = next((e for e in entities
                     if e.entity_type == IP and e.key == src_ip), None)
        rel("endpoint_used_address", ep, addr, REL_AMBIGUOUS,
            "address observed on this endpoint's own evidence",
            "the endpoint was observed using this address at this time; "
            "DHCP, NAT, VPN, proxies, containers and shared hosts mean it "
            "can never establish which endpoint an address is")
        rel("address_identifies_endpoint", addr, ep, REL_FORBIDDEN,
            "structurally unsafe",
            "an address may never identify an endpoint. Recorded as "
            "FORBIDDEN rather than omitted, so the refusal is explicit")
    return out
