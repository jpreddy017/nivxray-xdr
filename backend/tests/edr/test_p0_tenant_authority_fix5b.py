"""P0 · TENANT AUTHORITY · FIX 5B — no implicit `"default"` tenant fallback.

What this proves
----------------
Two residues silently substituted the literal string `"default"` when NO
authoritative tenant had been resolved:

* `session_context.authorised_incident()` — `doc.get("tenant_id") or
  doc.get("user_email") or "default"`. An incident naming no owner became the
  customer `default`, so the principal holding the REAL registered tenant
  `default` was handed unowned evidence, and a cross-tenant principal got it
  outright.
* `session_context.list_customers()` — `$ifNull` chain terminating in
  `"default"`, which manufactured a customer called `default` out of
  unattributed cases and inflated the real tenant's counts.

Fix 5B removes the FALLBACK, not the tenant: a case or incident whose tenant
genuinely IS `default` behaves exactly as before.

EVIDENCE LABELLING — TEST/SYNTHETIC. Synthetic documents in a throwaway
collection; no production document is read, written or migrated.
"""
from __future__ import annotations

import inspect
import uuid

import pytest

from deps import sync_collection
from services import session_context as sc
from services import tenant_registry as reg

REAL_DEFAULT = "default"          # a legitimate registered ACTIVE tenant
OTHER = "ten_other000000000000000000"

CROSS = "vendor@nivxray.test"
HOLDS_DEFAULT = "analyst@default-customer.test"
HOLDS_OTHER = "analyst@other-customer.test"

_SCOPES = {
    CROSS: {"authorized": True, "all_tenants": True, "role": "platform_admin"},
    HOLDS_DEFAULT: {"authorized": True, "all_tenants": False,
                    "tenant_ids": [REAL_DEFAULT], "role": "l2_investigator"},
    HOLDS_OTHER: {"authorized": True, "all_tenants": False,
                  "tenant_ids": [OTHER], "role": "l2_investigator"},
}

INC_REAL_DEFAULT = "inc_5b_real_default"
INC_OTHER = "inc_5b_other_tenant"
INC_UNOWNED = "inc_5b_unowned"
INC_EMPTY = "inc_5b_empty_tenant"
INC_EMAIL_ONLY = "inc_5b_email_only"

_DOCS = [
    {"id": INC_REAL_DEFAULT, "tenant_id": REAL_DEFAULT,
     "incident_state": "open"},
    {"id": INC_OTHER, "tenant_id": OTHER, "incident_state": "open"},
    {"id": INC_UNOWNED, "incident_state": "open"},
    {"id": INC_EMPTY, "tenant_id": "", "user_email": None,
     "incident_state": "open"},
    {"id": INC_EMAIL_ONLY, "user_email": "legacy@owner.test",
     "incident_state": "resolved"},
]


@pytest.fixture(autouse=True)
def _corpus(monkeypatch):
    """A throwaway synthetic case corpus, dropped on teardown."""
    name = f"t5b_cases_{uuid.uuid4().hex[:8]}"
    coll = sync_collection(name)
    coll.insert_many([dict(d) for d in _DOCS])
    monkeypatch.setattr(sc, "_cases", coll)
    monkeypatch.setattr(sc, "_scope", lambda q, email: dict(q or {}))
    monkeypatch.setattr(sc, "resolve_tenant_scope",
                        lambda email: dict(_SCOPES.get(email or "",
                                                       {"authorized": False})))
    yield coll
    coll.drop()


def _inc(incident_id, email):
    return sc.authorised_incident(incident_id, email)


# ── 1/2/3 · an unresolved tenant is never "default" ───────────────
def test_1_missing_tenant_never_becomes_default():
    for email in (CROSS, HOLDS_DEFAULT, HOLDS_OTHER):
        got = _inc(INC_UNOWNED, email)
        assert got["state"] == "INCIDENT_TENANT_UNRESOLVED", (email, got)
        assert got["doc"] is None
        assert got.get("tenant") is None


def test_2_empty_tenant_never_becomes_default():
    got = _inc(INC_EMPTY, CROSS)
    assert got["state"] == "INCIDENT_TENANT_UNRESOLVED"
    assert got["doc"] is None


def test_3_unresolved_authority_is_a_denial_not_a_default():
    got = _inc(INC_UNOWNED, "nobody@unauthorized.test")
    assert got["state"] == "NOT_AUTHORIZED"
    assert got["doc"] is None


# ── 4 · the REAL tenant named "default" still works ───────────────
def test_4_legitimate_default_tenant_still_works():
    got = _inc(INC_REAL_DEFAULT, HOLDS_DEFAULT)
    assert got["state"] == "AUTHORIZED"
    assert got["tenant"] == REAL_DEFAULT
    assert got["doc"]["id"] == INC_REAL_DEFAULT
    cross = _inc(INC_REAL_DEFAULT, CROSS)
    assert cross["state"] == "AUTHORIZED" and cross["tenant"] == REAL_DEFAULT


def test_4_legacy_email_attribution_is_preserved():
    got = _inc(INC_EMAIL_ONLY, CROSS)
    assert got["state"] == "AUTHORIZED"
    assert got["tenant"] == "legacy@owner.test"


# ── 5 · omission cannot grant the tenant "default" ────────────────
def test_5_unowned_incident_cannot_be_claimed_by_the_default_holder():
    got = _inc(INC_UNOWNED, HOLDS_DEFAULT)
    assert got["state"] == "INCIDENT_TENANT_UNRESOLVED"
    assert got["doc"] is None


# ── 6 · cross-tenant incident access stays refused ────────────────
def test_6_cross_tenant_incident_is_refused_without_leaking_the_document():
    got = _inc(INC_OTHER, HOLDS_DEFAULT)
    assert got["state"] == "INCIDENT_TENANT_OUT_OF_SCOPE"
    assert got["doc"] is None
    assert "tenant" not in got
    missing = _inc("inc_does_not_exist", HOLDS_DEFAULT)
    assert missing["state"] == "INCIDENT_NOT_FOUND" and missing["doc"] is None


# ── 7 · list_customers cannot manufacture a default customer ──────
def test_7_list_customers_drops_unattributed_cases():
    rows = {r["customer"]: r for r in sc.list_customers(CROSS)}
    # the REAL tenant is present with only its OWN case
    assert REAL_DEFAULT in rows
    assert rows[REAL_DEFAULT]["incidents"] == 1
    assert rows[REAL_DEFAULT]["open_incidents"] == 1
    # the two unowned cases became NO customer at all
    assert sum(r["incidents"] for r in rows.values()) == 3
    assert None not in rows and "" not in rows
    # legacy email attribution preserved, closed case not counted as open
    assert rows["legacy@owner.test"]["incidents"] == 1
    assert rows["legacy@owner.test"]["open_incidents"] == 0


def test_7_unauthorized_principal_gets_no_customers():
    assert sc.tenant_context("nobody@unauthorized.test")["customers"] == []


def test_7_no_default_fallback_survives_in_the_source():
    src = inspect.getsource(sc.list_customers)
    code = src.replace(sc.list_customers.__doc__ or "", "")
    assert '"default"' not in code
    code_inc = "\n".join(
        l for l in inspect.getsource(sc.authorised_incident).splitlines()
        if not l.strip().startswith("#"))
    code_inc = code_inc.replace(sc.authorised_incident.__doc__ or "", "")
    assert 'or "default"' not in code_inc


# ── 8/10 · Fix 5A and the non-EDR planes are untouched ────────────
def test_8_authoritative_required_is_unchanged():
    params = list(inspect.signature(reg.authoritative_required).parameters)
    assert params == ["tenant_id", "purpose"]
    code = inspect.getsource(reg.authoritative_required).replace(
        reg.authoritative_required.__doc__ or "", "")
    assert "compat_default" not in code and "enforcing" not in code


def test_10_legacy_flag_gated_resolver_keeps_its_compat_default():
    """XDR / collector / ingest semantics are deliberately unchanged."""
    sig = inspect.signature(reg.authoritative)
    assert sig.parameters["compat_default"].default == "default"
    assert "enforcing" in inspect.getsource(reg.authoritative)
