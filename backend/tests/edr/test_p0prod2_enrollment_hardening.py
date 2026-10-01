"""P0-PROD-2 · endpoint-enrolment hardening (production gate).

What this file proves, beyond the accepted P0-A.2 suite:

  * an UNUSED enrolment token can be revoked, a CONSUMED one cannot, and
    revoking a token is never a retroactive revocation of the endpoint
    identity it already minted;
  * the token state model is truthful (ACTIVE / CONSUMED / EXPIRED /
    REVOKED) and a malformed document never resolves to ACTIVE;
  * the enrolment lifecycle is audited and the audit store cannot
    physically hold token or credential material;
  * the Linux supervised launcher no longer performs an
    administrator-credential bootstrap under
    `NIVX_DEPLOYMENT_ENV=production` — proven by running it, not by
    reading it.

Run against real Mongo, same `_Scope` pattern as the P0-A.2 suite.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.enrollment import audit, rejection, store
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from edr_plane.enrollment.security import (PREFIX_CREDENTIAL,
                                           PREFIX_ENROLLMENT, PREFIX_SESSION)
from edr_plane.enrollment.store import EnrollmentError

REPO = Path("/app")
LAUNCHER = REPO / "scripts" / "nivxforge_sensor_supervise.py"
WIN_INSTALLER = REPO / "agents" / "nivxforge-windows" / \
    "Install-NivXForgeSensor.ps1"
LINUX_SENSOR = REPO / "agents" / "nivxforge-linux" / "nivxforge_sensor.py"
WIN_SENSOR = REPO / "agents" / "nivxforge-windows" / "nivxforge_sensor.py"


class _Scope:
    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await store.ensure_indexes(self.db)
        await rejection.ensure_indexes(self.db)
        self.tenant = f"p0prod2-{uuid.uuid4().hex[:8]}"
        return self.db, self.tenant

    async def __aexit__(self, *exc):
        for c in (store.TOKENS, store.CREDENTIALS, store.SESSIONS,
                  store.ENDPOINTS, audit.AUDIT):
            await self.db[c].delete_many(
                {"tenant_id": {"$regex": f"^{self.tenant}"}})
        self.client.close()
        return False


async def _mint(db, tenant, **kw):
    return await store.mint_enrollment_token(db, tenant_id=tenant,
                                              issued_by="owner@test", **kw)


# ── 1 · token generation ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_is_prefixed_high_entropy_and_unique():
  async with _Scope() as (db, tenant):
    seen = set()
    for _ in range(25):
        t = await _mint(db, tenant)
        secret = t["enrollment_token"]
        assert secret.startswith(f"{PREFIX_ENROLLMENT}_")
        # 32 CSPRNG bytes → 43 urlsafe chars, no padding.
        assert len(secret.split("_", 1)[1]) >= 43
        assert t["token_id"].startswith("tok_")
        assert secret not in seen
        seen.add(secret)


@pytest.mark.asyncio
async def test_plaintext_token_is_never_persisted():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    secret = t["enrollment_token"]
    async for doc in db[store.TOKENS].find({"tenant_id": tenant}):
        assert secret not in str(doc)
    rows = await store.list_tokens(db, tenant_id=tenant)
    assert rows and all("token_hash" not in r for r in rows)
    assert all(secret not in str(r) for r in rows)


# ── 2 · truthful state model ──────────────────────────────────────

@pytest.mark.asyncio
async def test_token_state_vocabulary_and_precedence():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    rows = await store.list_tokens(db, tenant_id=tenant)
    assert rows[0]["state"] == store.TOKEN_STATE_ACTIVE
    assert rows[0]["usable"] is True

    await store.revoke_enrollment_token(
        db, tenant_id=tenant, token_id=t["token_id"],
        revoked_by="owner@test", reason="provisioning aborted")
    rows = await store.list_tokens(db, tenant_id=tenant)
    assert rows[0]["state"] == store.TOKEN_STATE_REVOKED
    assert rows[0]["usable"] is False

    # A consumed token stays CONSUMED even once its TTL has passed: the
    # fact outranks the clock.
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    assert store.token_state({"used_at": past.isoformat(),
                              "expires_at": past.isoformat()}) == \
        store.TOKEN_STATE_CONSUMED


def test_a_malformed_token_document_is_never_active():
    assert store.token_state({}) == store.TOKEN_STATE_EXPIRED
    assert store.token_state({"expires_at": "not-a-date"}) == \
        store.TOKEN_STATE_EXPIRED
    assert store.token_state({"expires_at": None}) == \
        store.TOKEN_STATE_EXPIRED


# ── 3 · single use, replay, concurrency ───────────────────────────

@pytest.mark.asyncio
async def test_enrollment_consumes_the_token_and_replay_is_refused():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    first = await store.enroll(db, tenant_id=tenant,
                               presented_token=t["enrollment_token"],
                               endpoint_id="ep_single", hostname="H1")
    assert first["agent_credential"].startswith(f"{PREFIX_CREDENTIAL}_")
    assert first["agent_credential"] != t["enrollment_token"]

    rows = await store.list_tokens(db, tenant_id=tenant)
    assert rows[0]["state"] == store.TOKEN_STATE_CONSUMED
    assert rows[0]["used_by_endpoint_id"] == "ep_single"

    before = await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant})
    with pytest.raises(EnrollmentError) as e:
        await store.enroll(db, tenant_id=tenant,
                           presented_token=t["enrollment_token"],
                           endpoint_id="ep_replay", hostname="H2")
    assert e.value.code == "ENROLLMENT_TOKEN_INVALID"
    assert await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant}) == before


@pytest.mark.asyncio
async def test_concurrent_consumption_yields_exactly_one_success():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)

    async def attempt(i):
        try:
            return await store.enroll(
                db, tenant_id=tenant,
                presented_token=t["enrollment_token"],
                endpoint_id=f"ep_race_{i}", hostname=f"H{i}")
        except EnrollmentError:
            return None

    results = await asyncio.gather(*[attempt(i) for i in range(25)])
    winners = [r for r in results if r]
    assert len(winners) == 1, f"{len(winners)} enrolments on one token"
    assert await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant}) == 1


# ── 4 · expiry and revocation ─────────────────────────────────────

@pytest.mark.asyncio
async def test_expired_token_is_refused_on_server_time():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant, ttl_seconds=60)
    past = datetime.now(timezone.utc) - timedelta(seconds=5)
    await db[store.TOKENS].update_one(
        {"tenant_id": tenant, "token_id": t["token_id"]},
        {"$set": {"expires_at_dt": past, "expires_at": past.isoformat()}})
    with pytest.raises(EnrollmentError) as e:
        await store.enroll(db, tenant_id=tenant,
                           presented_token=t["enrollment_token"],
                           endpoint_id="ep_exp", hostname="H")
    assert e.value.code == "ENROLLMENT_TOKEN_INVALID"
    rows = await store.list_tokens(db, tenant_id=tenant)
    assert rows[0]["state"] == store.TOKEN_STATE_EXPIRED


@pytest.mark.asyncio
async def test_revoked_unused_token_cannot_enroll():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    out = await store.revoke_enrollment_token(
        db, tenant_id=tenant, token_id=t["token_id"],
        revoked_by="owner@test", reason="laptop never shipped")
    assert out["state"] == store.TOKEN_STATE_REVOKED
    with pytest.raises(EnrollmentError):
        await store.enroll(db, tenant_id=tenant,
                           presented_token=t["enrollment_token"],
                           endpoint_id="ep_rev", hostname="H")
    assert await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant}) == 0


@pytest.mark.asyncio
async def test_consumed_token_is_not_revocable_and_identity_survives():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    enrolled = await store.enroll(db, tenant_id=tenant,
                                  presented_token=t["enrollment_token"],
                                  endpoint_id="ep_keep", hostname="H")
    with pytest.raises(EnrollmentError) as e:
        await store.revoke_enrollment_token(
            db, tenant_id=tenant, token_id=t["token_id"],
            revoked_by="owner@test", reason="second thoughts")
    assert e.value.code == "ENROLLMENT_TOKEN_NOT_REVOCABLE"
    assert e.value.status == 409
    # The endpoint credential is untouched: token revocation and endpoint
    # revocation are different security decisions.
    sess = await store.open_session(
        db, tenant_id=tenant,
        agent_credential=enrolled["agent_credential"])
    assert sess["endpoint_id"] == "ep_keep"


@pytest.mark.asyncio
async def test_unknown_token_id_revocation_is_a_truthful_404():
  async with _Scope() as (db, tenant):
    with pytest.raises(EnrollmentError) as e:
        await store.revoke_enrollment_token(
            db, tenant_id=tenant, token_id="tok_does_not_exist",
            revoked_by="owner@test", reason="typo")
    assert e.value.code == "ENROLLMENT_TOKEN_NOT_FOUND"
    assert e.value.status == 404


# ── 5 · tenant isolation and non-disclosure ───────────────────────

@pytest.mark.asyncio
async def test_token_cannot_enroll_into_another_tenant():
  async with _Scope() as (db, tenant):
    other = f"{tenant}-b"
    t = await _mint(db, tenant)
    with pytest.raises(EnrollmentError) as e:
        await store.enroll(db, tenant_id=other,
                           presented_token=t["enrollment_token"],
                           endpoint_id="ep_cross", hostname="H")
    assert e.value.code == "ENROLLMENT_TOKEN_INVALID"
    assert await db[store.ENDPOINTS].count_documents(
        {"tenant_id": other}) == 0
    # Still usable by its own tenant: the wrong-tenant attempt must not
    # burn someone else's token either.
    ok = await store.enroll(db, tenant_id=tenant,
                            presented_token=t["enrollment_token"],
                            endpoint_id="ep_ok", hostname="H")
    assert ok["endpoint_id"] == "ep_ok"


@pytest.mark.asyncio
async def test_no_oracle_between_unknown_expired_used_and_foreign():
  async with _Scope() as (db, tenant):
    messages = set()
    # unknown
    try:
        await store.consume_enrollment_token(
            db, tenant_id=tenant,
            presented=f"{PREFIX_ENROLLMENT}_" + "x" * 43)
    except EnrollmentError as e:
        messages.add((e.code, e.status, e.reason))
    # malformed
    try:
        await store.consume_enrollment_token(db, tenant_id=tenant,
                                             presented="not-a-token")
    except EnrollmentError as e:
        messages.add((e.code, e.status, e.reason))
    # consumed
    t = await _mint(db, tenant)
    await store.enroll(db, tenant_id=tenant,
                       presented_token=t["enrollment_token"],
                       endpoint_id="ep_o", hostname="H")
    try:
        await store.consume_enrollment_token(
            db, tenant_id=tenant, presented=t["enrollment_token"])
    except EnrollmentError as e:
        messages.add((e.code, e.status, e.reason))
    # foreign tenant
    try:
        await store.consume_enrollment_token(
            db, tenant_id=f"{tenant}-b", presented=t["enrollment_token"])
    except EnrollmentError as e:
        messages.add((e.code, e.status, e.reason))
    assert len(messages) == 1, f"failure modes are distinguishable: {messages}"


@pytest.mark.asyncio
async def test_endpoint_credential_is_tenant_bound():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    enrolled = await store.enroll(db, tenant_id=tenant,
                                  presented_token=t["enrollment_token"],
                                  endpoint_id="ep_bound", hostname="H")
    with pytest.raises(EnrollmentError):
        await store.open_session(
            db, tenant_id=f"{tenant}-b",
            agent_credential=enrolled["agent_credential"])


# ── 6 · endpoint identity privilege boundary ──────────────────────

def test_endpoint_identity_carries_no_console_authority():
    fields = set(AuthenticatedEndpoint.model_fields)
    assert fields == {"tenant_id", "endpoint_id", "credential_id",
                      "session_id", "auth_method", "device_iid",
                      "authenticated_at"}
    for forbidden in ("role", "roles", "permissions", "scopes", "is_admin",
                      "email", "user_id", "approval_authority"):
        assert forbidden not in fields


def test_agent_routes_never_depend_on_a_platform_user():
    src = Path("/app/backend/routers/edr_enrollment.py").read_text()
    agent_block = src.split("# ── agent surface")[1]
    assert "get_current_user" not in agent_block, (
        "an agent route must not accept a platform user identity")
    admin_block = src.split("# ── agent surface")[0]
    assert admin_block.count("Depends(get_current_user)") >= 5


@pytest.mark.asyncio
async def test_session_identity_drives_heartbeat_without_any_user():
  async with _Scope() as (db, tenant):
    t = await _mint(db, tenant)
    enrolled = await store.enroll(db, tenant_id=tenant,
                                  presented_token=t["enrollment_token"],
                                  endpoint_id="ep_hb", hostname="H")
    sess = await store.open_session(
        db, tenant_id=tenant,
        agent_credential=enrolled["agent_credential"])
    assert sess["session_token"].startswith(f"{PREFIX_SESSION}_")
    resolved = await store.resolve_session(db,
                                           presented=sess["session_token"])
    assert resolved["session"]["tenant_id"] == tenant
    out = await store.mark_heartbeat(
        db, tenant_id=resolved["session"]["tenant_id"],
        endpoint_id=resolved["session"]["endpoint_id"],
        at=datetime.now(timezone.utc).isoformat())
    assert out["link_state"] == "CONNECTED"
    ep = await store.get_endpoint(db, tenant_id=tenant,
                                  endpoint_id="ep_hb")
    # Liveness is not delivery.
    assert ep["last_heartbeat_at"] and ep["event_count"] == 0


# ── 7 · audit and redaction ───────────────────────────────────────

@pytest.mark.asyncio
async def test_lifecycle_is_audited_without_any_secret_material():
  async with _Scope() as (db, tenant):
    t1 = await _mint(db, tenant, label="revoke-me")
    await store.revoke_enrollment_token(
        db, tenant_id=tenant, token_id=t1["token_id"],
        revoked_by="owner@test", reason="cancelled")
    t2 = await _mint(db, tenant)
    enrolled = await store.enroll(db, tenant_id=tenant,
                                  presented_token=t2["enrollment_token"],
                                  endpoint_id="ep_aud", hostname="H")
    events = await audit.list_events(db, tenant_id=tenant)
    kinds = {e["event"] for e in events}
    assert {audit.TOKEN_CREATED, audit.TOKEN_REVOKED,
            audit.ENROLLMENT_SUCCEEDED} <= kinds

    blob = str(events)
    for secret in (t1["enrollment_token"], t2["enrollment_token"],
                   enrolled["agent_credential"]):
        assert secret not in blob
    assert f"{PREFIX_ENROLLMENT}_" not in blob
    assert f"{PREFIX_CREDENTIAL}_" not in blob
    assert f"{PREFIX_SESSION}_" not in blob


@pytest.mark.asyncio
async def test_audit_store_refuses_to_write_secret_material():
  async with _Scope() as (db, tenant):
    with pytest.raises(audit.AuditRedactionError):
        await audit.record(db, tenant_id=tenant,
                           event=audit.ENROLLMENT_REJECTED,
                           actor="ep", outcome="REJECTED",
                           detail={"presented": f"{PREFIX_ENROLLMENT}_abc"})
    assert await db[audit.AUDIT].count_documents({"tenant_id": tenant}) == 0


@pytest.mark.asyncio
async def test_rejection_records_a_fingerprint_not_the_token():
  async with _Scope() as (db, tenant):
    bad = f"{PREFIX_ENROLLMENT}_" + "y" * 43
    rec = await audit.record(db, tenant_id=tenant,
                             event=audit.ENROLLMENT_REJECTED,
                             actor="ep_x", outcome="REJECTED",
                             reason_code="ENROLLMENT_TOKEN_INVALID",
                             presented_secret=bad)
    assert rec["secret_fingerprint"] and bad not in str(rec)
    assert len(rec["secret_fingerprint"]) == 16


# ── 8 · sensor bootstrap (production removal of admin credentials) ─

def _launcher_module():
    spec = importlib.util.spec_from_file_location("nivx_sup", LAUNCHER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_production_launcher_refuses_admin_credential_bootstrap(tmp_path):
    env = {**os.environ,
           "NIVX_DEPLOYMENT_ENV": "production",
           "NIVXFORGE_SENSOR_STATE": str(tmp_path / "state"),
           "NIVXFORGE_SENSOR_API": "http://127.0.0.1:1",
           "NIVXFORGE_SENSOR_TENANT": "default",
           "ADMIN_EMAIL": "admin@nivxray.com",
           "ADMIN_PASSWORD": "would-have-been-used-before-p0prod2"}
    env.pop("NIVXFORGE_ENROLLMENT_TOKEN", None)
    env.pop("NIVXFORGE_ENROLLMENT_TOKEN_FILE", None)
    p = subprocess.run([sys.executable, str(LAUNCHER)], env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode != 0
    out = p.stdout + p.stderr
    assert "NIVX_DEPLOYMENT_ENV=production" in out
    assert "REMOVED" in out
    assert "NIVXFORGE_ENROLLMENT_TOKEN" in out
    # It must not have attempted an operator login.
    assert "access token" not in out


def test_launcher_consumes_a_provisioned_token_file_once(tmp_path):
    m = _launcher_module()
    f = tmp_path / "enrollment.token"
    secret = f"{PREFIX_ENROLLMENT}_" + "z" * 43
    f.write_text(secret + "\n")
    os.environ.pop("NIVXFORGE_ENROLLMENT_TOKEN", None)
    os.environ["NIVXFORGE_ENROLLMENT_TOKEN_FILE"] = str(f)
    try:
        assert m._provisioned_token() == secret
        assert not f.exists(), "a spent token must not stay on disk"
        assert m._provisioned_token() is None
    finally:
        os.environ.pop("NIVXFORGE_ENROLLMENT_TOKEN_FILE", None)


def test_launcher_admin_path_is_gated_behind_the_production_check():
    src = LAUNCHER.read_text()
    prod_guard = src.index("if _production():")
    first_admin = src.index("ADMIN_PASSWORD")
    assert prod_guard < first_admin, (
        "the operator-credential path must be unreachable in production")
    assert "NON-PRODUCTION ONLY" in src


def test_windows_bootstrap_takes_a_token_and_no_operator_credential():
    src = WIN_INSTALLER.read_text()
    assert "$EnrollmentToken" in src and "--token" in src
    for forbidden in ("ADMIN_PASSWORD", "$AdminPassword", "$Password",
                      "auth/login", "$Credential"):
        assert forbidden not in src, f"{forbidden} in the Windows installer"


def test_both_sensors_enrol_with_a_token_only():
    for sensor in (LINUX_SENSOR, WIN_SENSOR):
        src = sensor.read_text()
        assert "/api/edr/agent/enroll" in src
        assert "enrollment_token" in src
        for forbidden in ("ADMIN_PASSWORD", "auth/login", "access_token"):
            assert forbidden not in src, f"{forbidden} in {sensor.name}"


def test_linux_sensor_protects_its_credential_at_rest():
    src = LINUX_SENSOR.read_text()
    assert "IDENTITY_FILE.chmod(0o600)" in src
