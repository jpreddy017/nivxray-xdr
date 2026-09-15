"""D21 · routing visibility — the projection must not become an authority.

What is actually being tested:

  * tenant scope comes from the AUTHENTICATED principal. A tenant-scoped
    principal that asks for another tenant (query param) is answered with
    its OWN scope and told the request was ignored; `X-Tenant-Id` has no
    path into the filter at all.
  * a cross-tenant role may scope itself to one tenant deliberately, and
    that is labelled as such rather than looking like ordinary access.
  * the collector→declared-source relationship is REPORTED, not recomputed:
    every relationship value is derived from the stored decision, including
    the honest "no authenticated collector" case for internal callers.
  * a refused delivery has no evidence reference, and the reason it has none
    is carried with it instead of rendering as an empty cell.
  * the surface is read-only: the router exposes GET only.

No fixture invents a routing decision shape: the documents below are the
shapes D15 actually persists (`services/source_routing._decision`).
"""
from __future__ import annotations

from routers import xdr_ingest_routing as viz


def _scope(role, tenant_ids, requested=None, all_tenants=False):
    return viz.TenantScope(
        {"authorized": True, "all_tenants": all_tenants, "role": role,
         "tenant_ids": tenant_ids}, requested)


# ── tenant scope ──────────────────────────────────────────────────
def test_tenant_scoped_principal_cannot_request_another_tenant():
    s = _scope("analyst", ["default"], requested="nivx-live")
    assert s.filter() == {"tenant_id": {"$in": ["default"]}}
    assert s.requested_honoured is False
    assert "not authorized for the requested tenant" in \
        s.describe()["requested_tenant_id_ignored_reason"]


def test_tenant_scoped_principal_may_restate_its_own_tenant():
    s = _scope("analyst", ["default"], requested="default")
    assert s.filter() == {"tenant_id": {"$in": ["default"]}}
    assert s.requested_honoured is True


def test_cross_tenant_role_is_unfiltered_unless_it_scopes_itself():
    allc = _scope("admin", [], all_tenants=True)
    assert allc.filter() == {}
    assert allc.describe()["basis"] == "CROSS_TENANT_ROLE"
    one = _scope("admin", [], requested="nivx-live", all_tenants=True)
    assert one.filter() == {"tenant_id": {"$in": ["nivx-live"]}}
    assert one.requested_honoured is True


def test_unauthorized_principal_matches_nothing():
    s = viz.TenantScope({"authorized": False}, None)
    assert s.filter() == {"tenant_id": {"$in": []}}


def test_scope_description_states_the_header_is_ignored():
    assert "X-Tenant-Id is ignored" in \
        _scope("analyst", ["default"]).describe()["header_note"]


# ── the authorization relationship is reported, never recomputed ──
def test_relationship_in_allowlist():
    assert viz._relationship({
        "declared_source": "linux-auditd",
        "declared_source_resolved": "linux-auditd",
        "collector_authorized_sources": ["linux-auditd"],
    }) == "DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST"


def test_relationship_not_in_allowlist():
    assert viz._relationship({
        "declared_source": "aws-cloudtrail",
        "declared_source_resolved": "aws-cloudtrail",
        "collector_authorized_sources": ["linux-auditd"],
    }) == "DECLARED_SOURCE_NOT_IN_COLLECTOR_ALLOWLIST"


def test_relationship_no_declaration_and_unknown_declaration():
    assert viz._relationship({
        "declared_source": None, "declared_source_resolved": None,
        "collector_authorized_sources": ["linux-auditd"],
    }) == "NO_DECLARATION_MADE"
    assert viz._relationship({
        "declared_source": "totally-made-up",
        "declared_source_resolved": None,
        "collector_authorized_sources": ["linux-auditd"],
    }) == "DECLARED_SOURCE_NOT_IN_CATALOG"


def test_internal_caller_is_not_dressed_up_as_an_authorized_collector():
    assert viz._relationship({
        "declared_source": None, "declared_source_resolved": None,
        "collector_authorized_sources": None,
    }) == "NOT_APPLICABLE_NO_AUTHENTICATED_COLLECTOR"


# ── row projection ────────────────────────────────────────────────
ACCEPTED_DOC = {
    "event_id": "cev_d21_accept",
    "tenant_id": "t-d21",
    "ingest_time": "2026-09-16T10:00:02+00:00",
    "provenance": {
        "trace_id": "live_d21accept",
        "timestamps": {"nivx_received_at": {
            "value": "2026-09-16T10:00:01+00:00", "status": "AVAILABLE"}},
        "ingest": {"payload_shape": "LINE", "collector_id": "col_d21",
                   "collector_id_source": "envelope.collector_id, verified "
                                          "against xdr_collectors.tenant_id",
                   "collection_method": "syslog",
                   "declared_payload_format": "auditd",
                   "raw_envelope_ref": {"collection": "edr_raw_events",
                                        "id": "abc"}},
        "routing": {"routing_result": "ACCEPTED",
                    "routing_authority": "AUTHENTICATED_COLLECTOR_DECLARATION",
                    "declared_source": "linux-auditd",
                    "declared_source_resolved": "linux-auditd",
                    "collector_authorized_sources": ["linux-auditd"],
                    "selected_dsm_id": "linux-auditd",
                    "content_compatible": True, "mismatch_reason": None,
                    "reason": "authorized and consistent"},
    },
}

BLOCKED_DOC = {
    "tenant_id": "t-d21",
    "collector_id": "col_d21",
    "source_event_id": "d21:blocked:1",
    "trace_id": "blocked_d21",
    "at": "2026-09-16T10:00:05+00:00",
    "nivx_received_at": "2026-09-16T10:00:04+00:00",
    "collection_method": "rest",
    "payload_shape": "DOCUMENT",
    "payload_keys": ["EventID", "TimeCreated"],
    "payload_excerpt": "",
    "routing": {"routing_result": "BLOCKED",
                "routing_authority": "AUTHENTICATED_COLLECTOR_DECLARATION",
                "declared_source": "aws-cloudtrail",
                "declared_source_resolved": "aws-cloudtrail",
                "collector_authorized_sources": ["linux-auditd"],
                "selected_dsm_id": None, "content_compatible": None,
                "mismatch_reason": "SOURCE_NOT_AUTHORIZED",
                "reason": "this collector is not authorized to send the "
                          "declared source"},
    "honesty_note": "no raw row, no idempotency claim and no canonical "
                    "evidence exist for this delivery",
}


def test_accepted_row_cites_the_evidence_it_produced():
    row = viz._accepted_row(ACCEPTED_DOC)
    assert row["delivery"] == "ACCEPTED"
    assert row["evidence_ref"] == "xdr_canonical_evidence/cev_d21_accept"
    assert row["evidence_ref_absent_reason"] is None
    # the receipt instant, not a nearby stage
    assert row["at"] == "2026-09-16T10:00:01+00:00"
    assert row["at_basis"] == "provenance.timestamps.nivx_received_at"
    assert row["collector_id"] == "col_d21"
    assert row["payload_shape"] == "LINE"
    assert row["selected_dsm_id"] == "linux-auditd"
    assert row["reason_code"] is None
    assert row["authorization_relationship"] == \
        "DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST"


def test_accepted_row_does_not_invent_a_collector_event_id():
    row = viz._accepted_row(ACCEPTED_DOC)
    assert row["source_event_id"] is None
    assert "NOT_CARRIED_INTO_CANONICAL_EVIDENCE" in row["source_event_id_basis"]


def test_refused_row_has_no_evidence_and_says_why():
    row = viz._blocked_row(BLOCKED_DOC)
    assert row["delivery"] == "BLOCKED"
    assert row["evidence_ref"] is None
    assert "no canonical evidence" in row["evidence_ref_absent_reason"]
    assert row["reason_code"] == "SOURCE_NOT_AUTHORIZED"
    assert row["collector_authorized_sources"] == ["linux-auditd"]
    assert row["authorization_relationship"] == \
        "DECLARED_SOURCE_NOT_IN_COLLECTOR_ALLOWLIST"
    assert row["payload_keys"] == ["EventID", "TimeCreated"]
    assert row["source_event_id"] == "d21:blocked:1"


def test_not_evaluated_is_reported_as_itself():
    doc = {**BLOCKED_DOC, "routing": {**BLOCKED_DOC["routing"],
                                      "routing_result": "NOT_EVALUATED",
                                      "mismatch_reason": None}}
    assert viz._blocked_row(doc)["delivery"] == "NOT_EVALUATED"


# ── read-only ─────────────────────────────────────────────────────
def test_router_exposes_read_methods_only():
    methods = {m for r in viz.router.routes for m in getattr(r, "methods", [])}
    assert methods <= {"GET", "HEAD", "OPTIONS"}, methods


def test_every_route_declares_the_read_only_projection():
    paths = {r.path for r in viz.router.routes}
    assert paths == {"/api/xdr/ingest/routing/deliveries",
                     "/api/xdr/ingest/routing/summary",
                     "/api/xdr/ingest/routing/catalog"}
    assert "not a routing authority" in viz._READ_ONLY_NOTE
