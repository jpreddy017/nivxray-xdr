"""P0-A.2 acceptance tests — the 13 owner-required cases, against real Mongo.

Acceptance criterion being proven: *a real endpoint can be enrolled with a
one-time bootstrap token, receive its durable per-agent credential,
authenticate, be represented by authoritative endpoint identity, and be
revoked deterministically — with no ambiguity about trust state.*

The two most important tests here are the ones that are easy to skip:
`test_concurrent_enrollment_yields_exactly_one_credential` (a read-then-
write implementation passes every other test in this file and still lets
two agents enrol on one token) and
`test_revocation_kills_an_in_flight_unexpired_session` (a TTL-only
implementation looks correct until someone actually revokes an agent).
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.enrollment import rejection, store
from edr_plane.enrollment.identity import (CredentialState, EndpointRecord,
                                           EnrollmentState, SensorState)
from edr_plane.enrollment.security import (PREFIX_CREDENTIAL,
                                           PREFIX_ENROLLMENT, PREFIX_SESSION,
                                           digest, fingerprint, new_secret,
                                           redact, safe_equal)
from edr_plane.enrollment.store import EnrollmentError

CEF = "CEF:0|NivXForge|LinuxSensor|0.1.0|100|process start|5|dproc=bash"


class _Scope:
    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await store.ensure_indexes(self.db)
        await rejection.ensure_indexes(self.db)
        self.tenant = f"p0a2-{uuid.uuid4().hex[:8]}"
        return self.db, self.tenant

    async def __aexit__(self, *exc):
        for c in (store.TOKENS, store.CREDENTIALS, store.SESSIONS,
                  store.ENDPOINTS):
            await self.db[c].delete_many(
                {"tenant_id": {"$regex": f"^{self.tenant}"}})
        self.client.close()
        return False


async def _enrol(db, tenant, *, hostname="LAB-01", cpu="CPU-1"):
    tok = await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="test")
    from edr_plane.contracts.identity import EndpointIdentity
    eid = EndpointIdentity.mint(tenant_id=tenant, processor_id=cpu,
                                hostname=hostname)
    res = await store.enroll(db, tenant_id=tenant,
                             presented_token=tok["enrollment_token"],
                             endpoint_id=eid, hostname=hostname,
                             platform="LINUX", sensor_version="0.1.0")
    return tok, res


# ── 1 · successful enrolment ──────────────────────────────────────

@pytest.mark.asyncio
async def test_successful_enrollment_issues_a_durable_credential():
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    assert res["agent_credential"].startswith(f"{PREFIX_CREDENTIAL}_")
    assert res["enrollment_state"] == "ENROLLED"
    # Enrolment is NOT visibility. This is the honest starting state.
    assert res["sensor_state"] == SensorState.ENROLLED_NEVER_REPORTED.value
    assert "not evidence of visibility" in res["honesty_note"]

    ep = await store.get_endpoint(db, tenant_id=tenant,
                                  endpoint_id=res["endpoint_id"])
    assert ep["trust"]["telemetry_trusted"] is True
    assert ep["credential_state"] == "ACTIVE"


# ── 2 · expired token ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_expired_token_is_refused():
  async with _Scope() as (db, tenant):
    tok = await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="t", ttl_seconds=60)
    # Force expiry without waiting.
    from datetime import datetime, timedelta, timezone
    past = datetime.now(timezone.utc) - timedelta(seconds=120)
    await db[store.TOKENS].update_one(
        {"tenant_id": tenant}, {"$set": {"expires_at_dt": past}})
    with pytest.raises(EnrollmentError) as e:
        await store.consume_enrollment_token(
            db, tenant_id=tenant, presented=tok["enrollment_token"])
    assert e.value.code == "ENROLLMENT_TOKEN_INVALID"


# ── 3 · reused token ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_cannot_be_reused():
  async with _Scope() as (db, tenant):
    tok, _ = await _enrol(db, tenant)
    with pytest.raises(EnrollmentError) as e:
        await store.consume_enrollment_token(
            db, tenant_id=tenant, presented=tok["enrollment_token"])
    assert e.value.code == "ENROLLMENT_TOKEN_INVALID"


# ── 4 · invalid token, and the same message for every failure ─────

@pytest.mark.asyncio
async def test_invalid_token_is_refused_with_a_non_revealing_message():
  async with _Scope() as (db, tenant):
    reasons = set()
    # unknown
    for presented in (new_secret(PREFIX_ENROLLMENT), "not-even-prefixed",
                      f"{PREFIX_ENROLLMENT}_garbage"):
        with pytest.raises(EnrollmentError) as e:
            await store.consume_enrollment_token(db, tenant_id=tenant,
                                                  presented=presented)
        reasons.add(e.value.reason)
    tok, _ = await _enrol(db, tenant)
    with pytest.raises(EnrollmentError) as e:
        await store.consume_enrollment_token(
            db, tenant_id=tenant, presented=tok["enrollment_token"])
    reasons.add(e.value.reason)
    # Unknown, malformed and already-used must be INDISTINGUISHABLE, or the
    # error message becomes an oracle.
    assert len(reasons) == 1
    assert "does not say which" in reasons.pop()


# ── 5 · rotation ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_credential_rotation_retires_the_old_secret_immediately():
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    old_cred = res["agent_credential"]
    sess = await store.open_session(db, tenant_id=tenant,
                                    agent_credential=old_cred)

    rot = await store.rotate_credential(db, tenant_id=tenant,
                                         endpoint_id=res["endpoint_id"],
                                         rotated_by="test")
    assert rot["agent_credential"] != old_cred
    assert rot["previous_credential_id"] == res["credential_id"]

    # Old credential is dead.
    with pytest.raises(EnrollmentError) as e:
        await store.open_session(db, tenant_id=tenant,
                                  agent_credential=old_cred)
    assert e.value.code == "AGENT_CREDENTIAL_REVOKED"
    # A session minted under the old credential is dead too.
    with pytest.raises(EnrollmentError):
        await store.resolve_session(db, presented=sess["session_token"])
    # New credential works.
    assert await store.open_session(
        db, tenant_id=tenant, agent_credential=rot["agent_credential"])


# ── 6 · revocation ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_revocation_is_deterministic_with_no_ambiguous_trust_state():
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    out = await store.revoke_endpoint(db, tenant_id=tenant,
                                       endpoint_id=res["endpoint_id"],
                                       revoked_by="test", reason="proof")
    assert out["credentials_revoked"] == 1
    assert "not retroactive distrust of past evidence" in out["honesty_note"]

    ep = await store.get_endpoint(db, tenant_id=tenant,
                                  endpoint_id=res["endpoint_id"])
    t = ep["trust"]
    assert t["enrollment_state"] == "REVOKED"
    assert t["credential_state"] == "REVOKED"
    assert t["sensor_state"] == "REVOKED"
    assert t["telemetry_trusted"] is False
    assert "revoked" in t["reason"]


# ── 7 · revoked agent cannot re-authenticate ──────────────────────

@pytest.mark.asyncio
async def test_revoked_credential_cannot_open_a_session():
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    await store.revoke_endpoint(db, tenant_id=tenant,
                                 endpoint_id=res["endpoint_id"],
                                 revoked_by="t", reason="r")
    with pytest.raises(EnrollmentError) as e:
        await store.open_session(db, tenant_id=tenant,
                                  agent_credential=res["agent_credential"])
    assert e.value.status == 403


# ── 8 · in-flight session dies on revocation (the hard one) ───────

@pytest.mark.asyncio
async def test_revocation_kills_an_in_flight_unexpired_session():
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    sess = await store.open_session(db, tenant_id=tenant,
                                    agent_credential=res["agent_credential"])
    # Valid right now.
    assert await store.resolve_session(db, presented=sess["session_token"])

    await store.revoke_endpoint(db, tenant_id=tenant,
                                 endpoint_id=res["endpoint_id"],
                                 revoked_by="t", reason="r")
    # Still well inside its TTL, and must nonetheless be refused.
    with pytest.raises(EnrollmentError) as e:
        await store.resolve_session(db, presented=sess["session_token"])
    assert e.value.code in ("SESSION_REVOKED", "SESSION_SUPERSEDED",
                            "AGENT_CREDENTIAL_REVOKED", "ENDPOINT_REVOKED")


@pytest.mark.asyncio
async def test_auth_epoch_alone_invalidates_a_session_that_was_not_rewritten():
  """The epoch must be a guarantee that does not depend on the second
  write succeeding. Simulate a partial revocation where the session
  document was never touched."""
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    sess = await store.open_session(db, tenant_id=tenant,
                                    agent_credential=res["agent_credential"])
    # Bump only the credential epoch; leave the session document pristine.
    await db[store.CREDENTIALS].update_one(
        {"tenant_id": tenant, "credential_id": res["credential_id"]},
        {"$inc": {"auth_epoch": 1}})
    with pytest.raises(EnrollmentError) as e:
        await store.resolve_session(db, presented=sess["session_token"])
    assert e.value.code == "SESSION_SUPERSEDED"


# ── 9 · tenant isolation ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_token_cannot_be_used_against_another_tenant():
  async with _Scope() as (db, tenant):
    other = f"{tenant}-other"
    tok = await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="t")
    with pytest.raises(EnrollmentError):
        await store.consume_enrollment_token(
            db, tenant_id=other, presented=tok["enrollment_token"])


@pytest.mark.asyncio
async def test_a_credential_cannot_be_used_against_another_tenant():
  async with _Scope() as (db, tenant):
    other = f"{tenant}-other"
    _, res = await _enrol(db, tenant)
    with pytest.raises(EnrollmentError):
        await store.open_session(db, tenant_id=other,
                                  agent_credential=res["agent_credential"])


@pytest.mark.asyncio
async def test_session_resolution_derives_the_tenant_and_never_accepts_it():
  """The tenant is an OUTPUT of authentication. resolve_session takes no
  tenant argument at all, so a valid agent cannot present its own token
  against somebody else's tenant."""
  import inspect
  assert "tenant_id" not in inspect.signature(store.resolve_session).parameters
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    sess = await store.open_session(db, tenant_id=tenant,
                                    agent_credential=res["agent_credential"])
    resolved = await store.resolve_session(db, presented=sess["session_token"])
    assert resolved["session"]["tenant_id"] == tenant


# ── 10 · endpoint-scoped enforcement ──────────────────────────────

@pytest.mark.asyncio
async def test_a_credential_is_scoped_to_exactly_one_endpoint():
  async with _Scope() as (db, tenant):
    _, a = await _enrol(db, tenant, hostname="A", cpu="CPU-A")
    _, b = await _enrol(db, tenant, hostname="B", cpu="CPU-B")
    assert a["endpoint_id"] != b["endpoint_id"]
    assert a["agent_credential"] != b["agent_credential"]
    sa = await store.open_session(db, tenant_id=tenant,
                                  agent_credential=a["agent_credential"])
    # A's credential resolves to A and can never resolve to B.
    assert sa["endpoint_id"] == a["endpoint_id"]
    ra = await store.resolve_session(db, presented=sa["session_token"])
    assert ra["session"]["endpoint_id"] == a["endpoint_id"]
    # Revoking B leaves A untouched.
    await store.revoke_endpoint(db, tenant_id=tenant,
                                 endpoint_id=b["endpoint_id"],
                                 revoked_by="t", reason="r")
    assert await store.resolve_session(db, presented=sa["session_token"])


# ── 11 · no secret leakage ────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_plaintext_secret_is_ever_stored():
  async with _Scope() as (db, tenant):
    tok, res = await _enrol(db, tenant)
    sess = await store.open_session(db, tenant_id=tenant,
                                    agent_credential=res["agent_credential"])
    secrets_used = [tok["enrollment_token"], res["agent_credential"],
                    sess["session_token"]]
    for coll in (store.TOKENS, store.CREDENTIALS, store.SESSIONS,
                 store.ENDPOINTS):
        blob = str(await db[coll].find({"tenant_id": tenant}).to_list(50))
        for s in secrets_used:
            assert s not in blob, f"{s[:8]}… leaked into {coll}"


@pytest.mark.asyncio
async def test_no_route_returns_a_token_digest_or_plaintext():
  async with _Scope() as (db, tenant):
    tok, _ = await _enrol(db, tenant)
    rows = await store.list_tokens(db, tenant_id=tenant)
    blob = str(rows)
    assert tok["enrollment_token"] not in blob
    assert "token_hash" not in blob
    assert digest(tok["enrollment_token"]) not in blob
    assert rows[0]["state"] == "USED" and rows[0]["single_use"] is True


def test_redact_never_reveals_any_fragment_of_the_secret():
    s = new_secret(PREFIX_SESSION)
    out = redact(s)
    assert s.split("_", 1)[1] not in out
    assert out.startswith(f"{PREFIX_SESSION}_[REDACTED:")
    assert redact(None) == "⊘ NONE PRESENTED"


def test_fingerprint_correlates_without_revealing():
    s = new_secret(PREFIX_CREDENTIAL)
    assert fingerprint(s) == fingerprint(s)          # correlatable
    assert fingerprint(s) != fingerprint(new_secret(PREFIX_CREDENTIAL))
    assert s not in fingerprint(s)                   # not reversible
    assert len(fingerprint(s)) == 16


def test_secrets_are_high_entropy_and_prefixed():
    vals = {new_secret(PREFIX_CREDENTIAL) for _ in range(200)}
    assert len(vals) == 200
    for v in list(vals)[:5]:
        assert v.startswith(f"{PREFIX_CREDENTIAL}_")
        assert len(v.split("_", 1)[1]) >= 40   # 32 bytes url-safe


def test_comparison_is_constant_time_not_equality():
    a = new_secret(PREFIX_SESSION)
    assert safe_equal(a, a)
    assert not safe_equal(a, new_secret(PREFIX_SESSION))


# ── 12 · restart / persistence ────────────────────────────────────

@pytest.mark.asyncio
async def test_credentials_survive_a_client_restart():
  """Authentication must not depend on in-process state — a restart that
  invalidated every agent would be an outage disguised as security."""
  async with _Scope() as (db, tenant):
    _, res = await _enrol(db, tenant)
    fresh = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    try:
        sess = await store.open_session(
            fresh, tenant_id=tenant,
            agent_credential=res["agent_credential"])
        assert (await store.resolve_session(
            fresh, presented=sess["session_token"]))["session"][
                "endpoint_id"] == res["endpoint_id"]
    finally:
        fresh.client.close()


# ── 13 · concurrency / idempotency (the one that catches races) ───

@pytest.mark.asyncio
async def test_concurrent_enrollment_yields_exactly_one_credential():
  async with _Scope() as (db, tenant):
    tok = await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="t")
    async def attempt(i):
        try:
            return await store.enroll(
                db, tenant_id=tenant,
                presented_token=tok["enrollment_token"],
                endpoint_id=f"ep_race_{i}", hostname=f"H{i}")
        except EnrollmentError:
            return None

    results = await asyncio.gather(*[attempt(i) for i in range(25)])
    winners = [r for r in results if r]
    assert len(winners) == 1, f"{len(winners)} agents enrolled on one token"
    assert await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant}) == 1


@pytest.mark.asyncio
async def test_concurrent_token_consumption_has_exactly_one_winner():
  async with _Scope() as (db, tenant):
    tok = await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="t")
    async def consume():
        try:
            return await store.consume_enrollment_token(
                db, tenant_id=tenant, presented=tok["enrollment_token"])
        except EnrollmentError:
            return None
    res = await asyncio.gather(*[consume() for _ in range(50)])
    assert len([r for r in res if r]) == 1


# ── rejected telemetry is a security signal, never evidence ───────

@pytest.mark.asyncio
async def test_rejection_is_recorded_as_a_signal_and_never_as_evidence():
  async with _Scope() as (db, tenant):
    bad = new_secret(PREFIX_SESSION)
    rec = await rejection.record_rejection(
        db, tenant_id=None, presented_secret=bad, source_ip="203.0.113.9",
        code="SENSOR_UNAUTHENTICATED", reason="no standing",
        path="/api/edr/agent/telemetry")
    assert rec["evidence_eligibility"] == "NEVER_EVIDENCE"
    assert rec["trust_state"] == "REJECTED"
    assert rec["payload_retained"] is False
    # The tenant is UNRESOLVED, not guessed — attributing an unauthenticated
    # attempt to a tenant on the attacker's word would be a fabrication.
    assert rec["tenant_resolution"] == "UNRESOLVED"
    assert rec["credential_fingerprint"] == fingerprint(bad)
    assert bad not in str(rec)
    assert rec["signal_class"] == "UNAUTHORISED_SENSOR_INGEST_ATTEMPT"


@pytest.mark.asyncio
async def test_a_revoked_agent_still_transmitting_is_escalated_to_high():
  async with _Scope() as (db, tenant):
    rec = await rejection.record_rejection(
        db, tenant_id=tenant, presented_secret=new_secret(PREFIX_SESSION),
        source_ip="10.0.0.5", code="AGENT_CREDENTIAL_REVOKED",
        reason="revoked", endpoint_id="ep_x")
    assert rec["severity"] == "HIGH"
    assert rec["signal_class"] == "REVOKED_AGENT_STILL_TRANSMITTING"


def test_rejected_telemetry_lives_outside_the_evidence_collections():
    from edr_plane import raw_events
    assert rejection.COLLECTION != raw_events.COLLECTION
    assert rejection.COLLECTION == "edr_rejected_telemetry"


# ── the atomic boundary ───────────────────────────────────────────

def test_authenticated_endpoint_is_frozen_and_carries_no_secret():
    from edr_plane.enrollment.identity import AuthenticatedEndpoint
    who = AuthenticatedEndpoint(
        tenant_id="t", endpoint_id="ep_1", credential_id="cred_1",
        session_id="sess_1", auth_method="bearer_session",
        authenticated_at="2026-06-01T00:00:00Z")
    with pytest.raises(Exception):
        who.endpoint_id = "ep_2"        # frozen: identity cannot be edited
    blob = str(who.model_dump()).lower()
    for forbidden in ("token", "secret", "password", "authorization", "hash"):
        assert forbidden not in blob
    prov = who.provenance()
    assert prov["authenticated_endpoint_id"] == "ep_1"
    assert set(prov) == {"authenticated_endpoint_id", "credential_id",
                         "session_id", "auth_method", "device_iid"}


def test_the_three_lifecycles_are_never_collapsed():
    rec = EndpointRecord(tenant_id="t", endpoint_id="e",
                         enrollment_state=EnrollmentState.ENROLLED,
                         credential_state=CredentialState.ACTIVE,
                         sensor_state=SensorState.ENROLLED_NEVER_REPORTED)
    t = rec.trust_summary()
    # Trusted to send, but has sent nothing. Both facts, side by side.
    assert t["telemetry_trusted"] is True
    assert t["sensor_state"] == "ENROLLED_NEVER_REPORTED"
    assert "status" not in EndpointRecord.model_fields
    assert "health" not in EndpointRecord.model_fields


def test_transport_is_pluggable_and_mtls_is_honestly_unregistered():
    from edr_plane.enrollment.transport import transport_status
    st = transport_status()
    assert st["active"] == "bearer_session"
    assert "mtls" in st["reserved"]
    assert "mtls" not in st["registered"]
    assert "!=" in st["boundary"]


def test_missing_pepper_fails_loudly_instead_of_degrading():
    import importlib
    from edr_plane.enrollment import security as sec
    saved = os.environ.pop("EDR_AUTH_PEPPER", None)
    try:
        with pytest.raises(RuntimeError, match="unkeyed digest"):
            sec.digest("anything")
    finally:
        if saved:
            os.environ["EDR_AUTH_PEPPER"] = saved
        importlib.reload(sec)
