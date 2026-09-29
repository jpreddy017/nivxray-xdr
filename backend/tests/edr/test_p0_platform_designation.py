"""P0 · explicit PLATFORM designation bootstrap (Option A, owner-approved).

What this proves
----------------
The production auth store carried NO authority-bearing principal after Fix
6B-2 retired role-derived breadth, so the Super Admin was refused every
tenant. This bootstrap writes the missing explicit designation — one field,
one principal, named only by server-side configuration — and refuses on every
ambiguity rather than guessing.

Security invariants re-proved here: `role` still confers nothing, grants are
never auto-added, `X-Tenant-Id` never self-authorises, and a conflicting or
ambiguous designation fails closed.

EVIDENCE LABELLING — TEST/SYNTHETIC. Stubbed async collection and stubbed
principals; no credential, no live account, no production write.
"""
from __future__ import annotations

import asyncio
import copy

import pytest

from services import dashboard_lenses as dl
from services import platform_designation as pd

PRINCIPAL = "superadmin@nivxforge.test"
OTHER = "analyst@customer-a.test"
TEN_A = "ten_a0000000000000000000000a"
TEN_B = "ten_b0000000000000000000000b"


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    async def to_list(self, n):
        return self._docs[:n]


class FakeUsers:
    """Minimal async stand-in for `db.users` with the two calls we make."""

    def __init__(self, docs, fail=False):
        self.docs = [copy.deepcopy(d) for d in docs]
        for i, d in enumerate(self.docs):
            d.setdefault("_id", f"oid{i}")
        self.fail = fail
        self.updates = []

    def _match(self, flt):
        email = flt.get("email")
        if isinstance(email, dict):
            import re
            pat = re.compile(email["$regex"], re.I)
            return [d for d in self.docs if pat.match(d.get("email", ""))]
        if "_id" in flt:
            return [d for d in self.docs if d["_id"] == flt["_id"]]
        return [d for d in self.docs if d.get("email") == email]

    def find(self, flt, proj=None):
        if self.fail:
            raise RuntimeError("auth store unreachable")
        return _Cursor(self._match(flt))

    async def find_one(self, flt, proj=None):
        hits = self._match(flt)
        return hits[0] if hits else None

    async def update_one(self, flt, update):
        if self.fail:
            raise RuntimeError("auth store unreachable")
        self.updates.append((flt, update))
        for d in self._match(flt):
            d.update(update["$set"])


def _run(users, monkeypatch, principal=PRINCIPAL, logger=None):
    if principal is None:
        monkeypatch.delenv(pd.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(pd.ENV_VAR, principal)
    return asyncio.get_event_loop().run_until_complete(
        pd.designate_platform_principal(users, logger))


# ---------------------------------------------------------------- A · writes
def test_configured_principal_receives_platform_authority(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    out = _run(users, monkeypatch)
    assert out["result"] == pd.UPDATED
    assert out["previous_authority_scope"] == "ABSENT"
    assert out["new_authority_scope"] == "PLATFORM"
    assert users.docs[0]["authority_scope"] == "PLATFORM"


def test_the_write_touches_only_authority_scope(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin",
                        "password": "hash", "tenant_ids": [TEN_A]}])
    _run(users, monkeypatch)
    assert len(users.updates) == 1
    assert users.updates[0][1] == {"$set": {"authority_scope": "PLATFORM"}}


def test_the_designated_principal_then_resolves_platform(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    _run(users, monkeypatch)
    assert dl.authority_scope(users.docs[0]) == "PLATFORM"


# ------------------------------------------------------------ B · idempotent
def test_second_execution_is_a_no_op(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    _run(users, monkeypatch)
    out = _run(users, monkeypatch)
    assert out["result"] == pd.ALREADY_CONFIGURED
    assert len(users.updates) == 1


def test_case_insensitive_configuration_still_finds_one_principal(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    out = _run(users, monkeypatch, principal=PRINCIPAL.upper())
    assert out["result"] == pd.UPDATED


# ----------------------------------------------- C/D/E · role is not authority
def test_role_admin_without_designation_gets_no_breadth():
    user = {"email": OTHER, "role": "admin"}
    assert dl.authority_scope(user) == "CUSTOMER"
    assert dl.resolve_tenant_scope is not None


def test_customer_admin_stays_customer_scoped(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"},
                       {"email": OTHER, "role": "admin",
                        "tenant_ids": [TEN_A]}])
    _run(users, monkeypatch)
    other = [d for d in users.docs if d["email"] == OTHER][0]
    assert "authority_scope" not in other
    assert dl.authority_scope(other) == "CUSTOMER"


def test_customer_analyst_stays_customer_scoped(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"},
                       {"email": "analyst@b.test", "role": "analyst",
                        "tenant_ids": [TEN_B]}])
    _run(users, monkeypatch)
    analyst = [d for d in users.docs if d["email"] == "analyst@b.test"][0]
    assert dl.authority_scope(analyst) == "CUSTOMER"
    assert analyst["tenant_ids"] == [TEN_B]


def test_only_the_designated_principal_is_touched(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"},
                       {"email": OTHER, "role": "soc_manager"},
                       {"email": "mssp@x.test", "role": "mssp_operator"}])
    _run(users, monkeypatch)
    holders = [d["email"] for d in users.docs if d.get("authority_scope")]
    assert holders == [PRINCIPAL]


def test_the_retired_role_set_is_not_reintroduced():
    assert not hasattr(dl, "_CROSS_TENANT_ROLES")
    assert dl._LEGACY_ROLE_BREADTH_RETIRED == frozenset(
        {"admin", "platform_admin", "soc_manager", "mssp_operator"})


# ------------------------------------------- F · X-Tenant-Id cannot authorise
def test_naming_a_tenant_never_authorises_it():
    from services import session_context as sc
    with pytest.raises(sc.ScopeDenied) as exc:
        sc.authorize_requested_tenant(
            {"authorized": True, "authority_scope": "CUSTOMER",
             "all_tenants": False, "tenant_ids": [TEN_A], "role": "admin"},
            TEN_B)
    assert exc.value.code == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


# -------------------------------------------------- G/H · fails closed loudly
def test_unknown_configured_principal_fails_closed(monkeypatch):
    users = FakeUsers([{"email": OTHER, "role": "admin"}])
    out = _run(users, monkeypatch)
    assert out["result"] == pd.REFUSED_NOT_FOUND
    assert not users.updates
    assert not any(d.get("authority_scope") for d in users.docs)


def test_ambiguous_principal_fails_closed(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"},
                       {"email": PRINCIPAL.upper(), "role": "admin"}])
    out = _run(users, monkeypatch)
    assert out["result"] == pd.REFUSED_AMBIGUOUS
    assert not users.updates


def test_conflicting_authority_scope_fails_closed(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin",
                        "authority_scope": "platform_admin"}])
    out = _run(users, monkeypatch)
    assert out["result"] == pd.REFUSED_CONFLICT
    assert not users.updates
    assert users.docs[0]["authority_scope"] == "platform_admin"
    assert dl.authority_scope(users.docs[0]) == "CUSTOMER"


def test_malformed_configuration_fails_closed(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    for bad in ("not-an-email", "@nivxforge.test", "a b@c.test", "   "):
        out = _run(users, monkeypatch, principal=bad)
        assert out["result"] in (pd.REFUSED_MALFORMED, pd.NOT_CONFIGURED)
    assert not users.updates


def test_unreachable_auth_store_is_a_refusal_not_a_crash(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}], fail=True)
    out = _run(users, monkeypatch)
    assert out["result"] == pd.REFUSED_STORE_UNREACHABLE


def test_every_refusal_is_machine_readable():
    assert pd.REFUSALS == frozenset({
        pd.REFUSED_MALFORMED, pd.REFUSED_NOT_FOUND, pd.REFUSED_AMBIGUOUS,
        pd.REFUSED_CONFLICT, pd.REFUSED_STORE_UNREACHABLE, pd.REFUSED_VERIFY})


# ------------------------------------------------------ I/J · nothing else moves
def test_no_tenant_ids_are_ever_added(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    _run(users, monkeypatch)
    assert "tenant_ids" not in users.docs[0]


def test_existing_grants_are_preserved_untouched(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin",
                        "tenant_ids": ["default", "nivx-live"]}])
    _run(users, monkeypatch)
    assert users.docs[0]["tenant_ids"] == ["default", "nivx-live"]


def test_role_and_password_are_preserved_untouched(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin",
                        "password": "bcrypt-hash", "must_change_password": False}])
    _run(users, monkeypatch)
    assert users.docs[0]["role"] == "admin"
    assert users.docs[0]["password"] == "bcrypt-hash"
    assert users.docs[0]["must_change_password"] is False


def test_unconfigured_env_writes_nothing_and_is_not_a_failure(monkeypatch):
    users = FakeUsers([{"email": PRINCIPAL, "role": "admin"}])
    out = _run(users, monkeypatch, principal=None)
    assert out == {"result": pd.NOT_CONFIGURED}
    assert not users.updates


def test_only_the_env_var_names_the_principal(monkeypatch):
    """The client cannot influence the designation — it is server-side only."""
    monkeypatch.setenv(pd.ENV_VAR, PRINCIPAL)
    assert pd.configured_principal() == PRINCIPAL
    monkeypatch.delenv(pd.ENV_VAR)
    assert pd.configured_principal() is None
