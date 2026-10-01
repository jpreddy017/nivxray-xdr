"""Gate X1 · entity resolution + the multi-evidence incident.

The safety argument in one line: **evidence composes into one incident only
when it shares an AUTHORITATIVE entity.** Everything below either
demonstrates that, or demonstrates the platform refusing to compose on a
shared address, hostname, username or instant.

Runs against the real database, in a tenant unique to the run, and cleans
up after itself.
"""
from __future__ import annotations

import os
import uuid

import pytest

from services import entity_resolution as er
from services import multi_evidence_incident as mei

pytestmark = pytest.mark.asyncio

EP = "ep_x1_aaa111"
OTHER_EP = "ep_x1_bbb222"
GUID = "{x1-proc-0001}"
OTHER_GUID = "{x1-proc-9999}"
PEER = "203.0.113.90"
HOSTIP = "10.50.0.9"
DOMAIN = "x1-proof.example-cdn.net"
SHA = "a" * 64


@pytest.fixture
def tenant():
    return f"t-x1-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def db():
    from motor.motor_asyncio import AsyncIOMotorClient
    return AsyncIOMotorClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]


@pytest.fixture(scope="module", autouse=True)
def _cleanup_x1_tenants():
    yield
    from pymongo import MongoClient
    database = MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    for coll in (mei.ENTITIES, mei.RELATIONSHIPS, mei.INCIDENTS):
        database[coll].delete_many({"tenant_id": {"$regex": "^t-x1-"}})


def dns_evidence(tenant, *, endpoint=EP, guid=GUID, event_id="cev-x1-dns",
                 domain=DOMAIN, answers=(PEER,)):
    return {
        "event_id": event_id, "tenant_id": tenant, "event_type": "dns_query",
        "event_time": "2026-06-08T10:00:00+00:00",
        "source_product": "Sysmon",
        "host": {"host_id": "WS-X1", "hostname": "WS-X1"},
        "additional_fields": {"endpoint_id": endpoint},
        "identity": {"username": "alice"},
        "process": {"attribution_state": "SOURCE_PROCESS_IDENTITY",
                    "attribution_reason": "ProcessGuid on the same record",
                    "process_guid": guid, "pid": 4711,
                    "executable_path": "C:\\curl.exe"},
        "network": {"src_ip": HOSTIP, "dns_query": domain,
                    "dns_response_ips": list(answers)},
    }


def conn_evidence(tenant, *, endpoint=EP, guid=GUID,
                  event_id="cev-x1-conn", peer=PEER):
    return {
        "event_id": event_id, "tenant_id": tenant,
        "event_type": "network_connect",
        "event_time": "2026-06-08T10:00:20+00:00",
        "source_product": "Sysmon",
        "host": {"host_id": "WS-X1", "hostname": "WS-X1"},
        "additional_fields": {"endpoint_id": endpoint},
        "process": {"attribution_state": "SOURCE_PROCESS_IDENTITY",
                    "attribution_reason": "ProcessGuid on the same record",
                    "process_guid": guid, "pid": 4711,
                    "hashes": {"sha256": SHA}},
        "network": {"src_ip": HOSTIP, "dest_ip": peer, "dest_port": 443},
    }


def zeek_evidence(tenant, *, event_id="cev-x1-zeek", peer=PEER):
    """A network-only source: no endpoint, no process — on purpose."""
    return {"event_id": event_id, "tenant_id": tenant,
            "event_type": "network_connect",
            "event_time": "2026-06-08T10:00:25+00:00",
            "source_product": "Zeek / Corelight network sensor",
            "host": {}, "additional_fields": {},
            "network": {"src_ip": HOSTIP, "dest_ip": peer, "dest_port": 443}}


# ── Entity model ──────────────────────────────────────────────────
async def test_the_entity_model_states_what_each_identity_is(tenant):
    ents = {e.entity_type: e for e in
            er.resolve_entities(dns_evidence(tenant), tenant)}
    assert ents[er.ENDPOINT].identity_state == er.AUTHORITATIVE
    assert "enrolment" in ents[er.ENDPOINT].identity_basis
    assert ents[er.PROCESS].identity_state == er.AUTHORITATIVE
    assert ents[er.USER].identity_state == er.DECLARED
    assert ents[er.IP].identity_state == er.DECLARED
    assert ents[er.DOMAIN].identity_state == er.DECLARED


async def test_addresses_and_domains_can_never_be_authoritative(tenant):
    for e in er.resolve_entities(dns_evidence(tenant), tenant):
        if e.entity_type in er.NEVER_AUTHORITATIVE:
            assert e.identity_state != er.AUTHORITATIVE


async def test_a_hostname_only_endpoint_is_declared_not_authoritative(tenant):
    ev = dns_evidence(tenant)
    ev["additional_fields"] = {}
    ep = next(e for e in er.resolve_entities(ev, tenant)
              if e.entity_type == er.ENDPOINT)
    assert ep.identity_state == er.DECLARED
    assert "spoofable" in ep.identity_basis


async def test_a_pid_only_process_is_not_an_entity_at_all(tenant):
    ev = conn_evidence(tenant)
    ev["process"] = {"pid": 4711,
                     "attribution_state": "PID_ONLY_NOT_AUTHORITATIVE"}
    assert not [e for e in er.resolve_entities(ev, tenant)
                if e.entity_type == er.PROCESS]


async def test_entity_ids_are_deterministic_and_tenant_scoped(tenant):
    a = er.resolve_entities(dns_evidence(tenant), tenant)[0]
    b = er.resolve_entities(dns_evidence(tenant), tenant)[0]
    other = er.resolve_entities(dns_evidence("t-x1-other"), "t-x1-other")[0]
    assert a.id == b.id and a.id != other.id


# ── Relationship truth ────────────────────────────────────────────
async def test_relationships_carry_their_own_truth(tenant):
    ev = dns_evidence(tenant)
    ents = er.resolve_entities(ev, tenant)
    rels = {r.relationship_type: r for r in er.derive_relationships(ev, ents)}
    assert rels["endpoint_runs_process"].state == er.REL_AUTHORITATIVE
    assert rels["process_resolved_domain"].state == er.REL_AUTHORITATIVE
    assert rels["domain_resolved_to"].state == er.REL_SUPPORTED
    assert rels["user_active_on_endpoint"].state == er.REL_SUPPORTED
    assert rels["endpoint_used_address"].state == er.REL_AMBIGUOUS
    assert rels["address_identifies_endpoint"].state == er.REL_FORBIDDEN
    for r in rels.values():
        assert r.evidence_refs and r.first_observed and r.last_observed
        assert r.identity_basis and r.reason and r.sources


async def test_every_relationship_state_is_one_of_the_declared_six(tenant):
    ev = dns_evidence(tenant)
    for r in er.derive_relationships(ev, er.resolve_entities(ev, tenant)):
        assert r.state in er.RELATIONSHIP_STATES


async def test_the_forbidden_edge_is_recorded_not_omitted(tenant):
    ev = dns_evidence(tenant)
    forbidden = [r for r in er.derive_relationships(
        ev, er.resolve_entities(ev, tenant))
        if r.state == er.REL_FORBIDDEN]
    assert forbidden and "may never identify" in forbidden[0].reason


# ── Positive merge ────────────────────────────────────────────────
async def test_evidence_sharing_an_authoritative_entity_composes(db, tenant):
    a = await mei.compose(db, tenant_id=tenant,
                          canonical=dns_evidence(tenant),
                          detections=[{"rule_id": "DET-X1"}])
    b = await mei.compose(db, tenant_id=tenant,
                          canonical=conn_evidence(tenant),
                          correlations=[{"correlation_id": "CORR-EP-001"}])
    assert a["composed"] and b["composed"]
    assert b["merged_into_existing"] is True
    inc = b["incident"]
    assert set(inc["event_ids"]) == {"cev-x1-dns", "cev-x1-conn"}
    assert inc["detections"] and inc["correlations"]
    assert "authoritative" in inc["composition_basis"]
    assert inc["capability_not_verdict"] is True


async def test_the_incident_keeps_every_entity_and_relationship(db, tenant):
    await mei.compose(db, tenant_id=tenant, canonical=dns_evidence(tenant))
    out = await mei.compose(db, tenant_id=tenant,
                            canonical=conn_evidence(tenant))
    traced = await mei.trace(db, tenant_id=tenant,
                             incident_id=out["incident"]["incident_id"])
    types = {e["entity_type"] for e in traced["entities"]}
    assert {er.ENDPOINT, er.PROCESS, er.IP, er.DOMAIN} <= types
    assert traced["every_relationship_cites_evidence"] is True
    assert not traced["untraceable_relationship_ids"]


# ── False merges ──────────────────────────────────────────────────
async def test_a_shared_address_alone_does_not_merge(db, tenant):
    """Zeek and the endpoint see the same addresses at the same time and
    still do not become one incident."""
    a = await mei.compose(db, tenant_id=tenant,
                          canonical=conn_evidence(tenant))
    b = await mei.compose(db, tenant_id=tenant,
                          canonical=zeek_evidence(tenant))
    assert b["merged_into_existing"] is False
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]
    assert "stands alone" in b["incident"]["composition_basis"]


async def test_a_different_process_does_not_join_the_incident(db, tenant):
    a = await mei.compose(db, tenant_id=tenant,
                          canonical=dns_evidence(tenant))
    b = await mei.compose(db, tenant_id=tenant, canonical=conn_evidence(
        tenant, guid=OTHER_GUID, endpoint=OTHER_EP,
        event_id="cev-x1-other"))
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]


async def test_a_shared_hostname_does_not_merge(db, tenant):
    """Same hostname, same username, same address — different endpoints."""
    one = dns_evidence(tenant, endpoint=EP)
    two = dns_evidence(tenant, endpoint=OTHER_EP, guid=OTHER_GUID,
                       event_id="cev-x1-host2")
    a = await mei.compose(db, tenant_id=tenant, canonical=one)
    b = await mei.compose(db, tenant_id=tenant, canonical=two)
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]


async def test_unrelated_evidence_stays_separate(db, tenant):
    a = await mei.compose(db, tenant_id=tenant, canonical=dns_evidence(
        tenant, domain="unrelated-a.example", event_id="cev-a"))
    b = await mei.compose(db, tenant_id=tenant, canonical=dns_evidence(
        tenant, endpoint=OTHER_EP, guid=OTHER_GUID,
        domain="unrelated-b.example", event_id="cev-b"))
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]


async def test_evidence_with_no_authoritative_entity_stands_alone(db, tenant):
    out = await mei.compose(db, tenant_id=tenant,
                            canonical=zeek_evidence(tenant))
    assert out["anchor_entity_ids"] == []
    assert "no authoritative entity" in out["reason"]


# ── Tenant isolation ──────────────────────────────────────────────
async def test_two_tenants_never_resolve_to_the_same_entity(db, tenant):
    other = f"{tenant}-x"
    a = await mei.compose(db, tenant_id=tenant, canonical=dns_evidence(tenant))
    b = await mei.compose(db, tenant_id=other,
                          canonical=dns_evidence(other))
    ids_a = {e["entity_id"] for e in a["entities"]}
    ids_b = {e["entity_id"] for e in b["entities"]}
    assert not (ids_a & ids_b)
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]
    assert b["merged_into_existing"] is False


async def test_an_incident_is_never_visible_to_another_tenant(db, tenant):
    out = await mei.compose(db, tenant_id=tenant,
                            canonical=dns_evidence(tenant))
    assert (await mei.trace(db, tenant_id=f"{tenant}-x",
                            incident_id=out["incident"]["incident_id"])
            )["found"] is False


# ── Replay / idempotency ──────────────────────────────────────────
async def test_replayed_evidence_creates_no_duplicates(db, tenant):
    ev = dns_evidence(tenant)
    first = await mei.compose(db, tenant_id=tenant, canonical=ev)
    await mei.compose(db, tenant_id=tenant, canonical=ev)
    third = await mei.compose(db, tenant_id=tenant, canonical=ev)
    assert third["incident"]["incident_id"] == \
        first["incident"]["incident_id"]
    assert third["incident"]["event_ids"] == ["cev-x1-dns"]
    assert await db[mei.ENTITIES].count_documents(
        {"tenant_id": tenant, "entity_type": er.PROCESS}) == 1
    ent = await db[mei.ENTITIES].find_one({"tenant_id": tenant,
                                           "entity_type": er.PROCESS})
    assert len(ent["evidence_refs"]) == 1
    assert ent["first_observed"] == ent["last_observed"]


# ── Contradiction ─────────────────────────────────────────────────
async def test_contradictory_evidence_is_kept_not_overwritten(db, tenant):
    ev = dns_evidence(tenant)
    await mei.compose(db, tenant_id=tenant, canonical=ev)
    # The same two entities, now related with a weaker claim.
    ents = er.resolve_entities(ev, tenant)
    rel = next(r for r in er.derive_relationships(ev, ents)
               if r.relationship_type == "endpoint_runs_process")
    rel.state = er.REL_SUPPORTED
    rel.evidence_refs = ["xdr_canonical_evidence/cev-x1-contradict"]
    stored = await mei._upsert_relationship(db, rel)
    assert stored["state"] == er.REL_CONTRADICTED
    assert stored["contradictions"][0]["previous_state"] == \
        er.REL_AUTHORITATIVE
    assert stored["contradictions"][0]["asserted_state"] == er.REL_SUPPORTED
    # BOTH sides' evidence survives.
    assert len(stored["evidence_refs"]) == 2


async def test_a_contradicted_relationship_never_merges_incidents(db, tenant):
    """A contradiction is not a licence to compose: composition depends on
    authoritative ENTITIES, which a contradicted edge does not create."""
    a = await mei.compose(db, tenant_id=tenant,
                          canonical=zeek_evidence(tenant))
    b = await mei.compose(db, tenant_id=tenant, canonical=zeek_evidence(
        tenant, event_id="cev-x1-zeek2"))
    assert a["incident"]["incident_id"] != b["incident"]["incident_id"]


# ── Retraction ────────────────────────────────────────────────────
async def test_retracting_a_relationship_preserves_the_evidence(db, tenant):
    out = await mei.compose(db, tenant_id=tenant,
                            canonical=dns_evidence(tenant))
    rel = next(r for r in out["relationships"]
               if r["relationship_type"] == "user_active_on_endpoint")
    before = rel["evidence_refs"]
    after = await mei.retract_relationship(
        db, tenant_id=tenant, relationship_id=rel["relationship_id"],
        reason="the username was a service account, not a person")
    assert after["state"] == er.REL_UNRESOLVED
    assert after["evidence_refs"] == before
    assert "still observed" in after["retraction_note"]
    # The evidence and the entities behind it are untouched.
    assert await db[mei.ENTITIES].count_documents(
        {"tenant_id": tenant}) == len(out["entities"])


# ── Provenance ────────────────────────────────────────────────────
async def test_every_entity_and_relationship_cites_its_evidence(db, tenant):
    out = await mei.compose(db, tenant_id=tenant, canonical=dns_evidence(
        tenant))
    for e in out["entities"]:
        assert e["evidence_refs"] == ["xdr_canonical_evidence/cev-x1-dns"]
        assert e["identity_basis"] and e["sources"]
    for r in out["relationships"]:
        assert r["evidence_refs"] and r["identity_basis"] and r["reason"]
