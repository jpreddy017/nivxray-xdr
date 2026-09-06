"""Enrolment store — tokens, credentials, sessions, endpoint records.

Every function here takes `tenant_id` explicitly and every query filters
on it. Cross-tenant use is not a check bolted on at the edge; it is
impossible to express.

Two things worth reading carefully:

  * `consume_enrollment_token()` matches and invalidates in ONE
    `find_one_and_update`. MongoDB guarantees single-document atomicity,
    so 100 concurrent presentations of the same token yield exactly one
    success — the losers cannot match once `used_at` is set. A
    read-then-write would have a race window wide enough to enrol twice.

  * `auth_epoch`. Revoking a credential increments it, and every session
    carries the epoch it was minted under. So an in-flight session token
    that is still inside its TTL is rejected at its very next
    authorisation check, without needing to find and rewrite every
    session document first (we do that too, but the epoch is the
    guarantee that does not depend on a second write succeeding).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from pymongo import ASCENDING, ReturnDocument

from .identity import (CredentialState, EndpointRecord, EnrollmentState,
                       SensorState)
from .security import (PREFIX_CREDENTIAL, PREFIX_ENROLLMENT, PREFIX_SESSION,
                       digest, has_prefix, new_secret)

TOKENS = "edr_enrollment_tokens"
CREDENTIALS = "edr_agent_credentials"
SESSIONS = "edr_agent_sessions"
ENDPOINTS = "edr_endpoints"


class EnrollmentError(Exception):
    """Carries a machine code plus an HTTP status.

    All token failures deliberately share ONE code and message. Telling a
    caller whether a token was unknown, expired or already used is an
    oracle: it lets an attacker with a stolen token learn whether it was
    ever valid, and whether someone else already used it.
    """

    def __init__(self, code: str, status: int = 401,
                 reason: str | None = None):
        self.code, self.status, self.reason = code, status, reason
        super().__init__(code)


GENERIC_TOKEN_FAILURE = (
    "enrollment token is not valid. It may be unknown, expired, already "
    "used, or issued to a different tenant — the platform deliberately "
    "does not say which.")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _token_ttl() -> int:
    return int(os.environ["EDR_ENROLLMENT_TOKEN_TTL_SECONDS"])


def _session_ttl() -> int:
    return int(os.environ["EDR_AGENT_SESSION_TTL_SECONDS"])


async def ensure_indexes(db: Any) -> None:
    await db[TOKENS].create_index(
        [("tenant_id", ASCENDING), ("token_hash", ASCENDING)], unique=True,
        name="uniq_tenant_token")
    # TTL is CLEANUP, not authorisation. Every read also checks expires_at,
    # because MongoDB's TTL monitor runs on a delay and an expired document
    # can still be present.
    await db[TOKENS].create_index("expires_at_dt", expireAfterSeconds=0)
    await db[CREDENTIALS].create_index(
        [("tenant_id", ASCENDING), ("secret_hash", ASCENDING)], unique=True,
        name="uniq_tenant_secret")
    await db[CREDENTIALS].create_index(
        [("tenant_id", ASCENDING), ("endpoint_id", ASCENDING),
         ("status", ASCENDING)])
    await db[SESSIONS].create_index(
        [("tenant_id", ASCENDING), ("token_hash", ASCENDING)], unique=True,
        name="uniq_tenant_session")
    await db[SESSIONS].create_index("expires_at_dt", expireAfterSeconds=0)
    await db[ENDPOINTS].create_index(
        [("tenant_id", ASCENDING), ("endpoint_id", ASCENDING)], unique=True,
        name="uniq_tenant_endpoint")


# ── stage 1 · one-time enrolment token ────────────────────────────

async def mint_enrollment_token(db: Any, *, tenant_id: str, issued_by: str,
                                label: str | None = None,
                                ttl_seconds: int | None = None) -> dict:
    """Mint a single-use token. The plaintext is in this return value and
    NOWHERE else — not in Mongo, not in a log, not in any later GET."""
    plaintext = new_secret(PREFIX_ENROLLMENT)
    now = _now()
    ttl = ttl_seconds or _token_ttl()
    expires = now + timedelta(seconds=ttl)
    await db[TOKENS].insert_one({
        "tenant_id": tenant_id,
        "token_id": f"tok_{uuid4().hex[:16]}",
        "token_hash": digest(plaintext),
        "label": label,
        "issued_by": issued_by,
        "created_at": _iso(now),
        "expires_at": _iso(expires),
        "expires_at_dt": expires,
        "ttl_seconds": ttl,
        "used_at": None,
        "used_by_endpoint_id": None,
    })
    return {"enrollment_token": plaintext, "expires_at": _iso(expires),
            "ttl_seconds": ttl, "single_use": True,
            "warning": ("Shown once. It cannot be retrieved again. Store it "
                        "in the agent's protected configuration.")}


async def consume_enrollment_token(db: Any, *, tenant_id: str,
                                   presented: str) -> dict:
    """Atomically match and burn the token. One winner, always."""
    if not has_prefix(presented, PREFIX_ENROLLMENT):
        raise EnrollmentError("ENROLLMENT_TOKEN_INVALID", 401,
                              GENERIC_TOKEN_FAILURE)
    now = _now()
    doc = await db[TOKENS].find_one_and_update(
        {"tenant_id": tenant_id, "token_hash": digest(presented),
         "used_at": None, "expires_at_dt": {"$gt": now}},
        {"$set": {"used_at": _iso(now)}},
        projection={"_id": 0, "token_id": 1, "label": 1},
        return_document=ReturnDocument.BEFORE)
    if not doc:
        raise EnrollmentError("ENROLLMENT_TOKEN_INVALID", 401,
                              GENERIC_TOKEN_FAILURE)
    return doc


# ── stage 2 · enrol and issue the durable credential ──────────────

async def enroll(db: Any, *, tenant_id: str, presented_token: str,
                 endpoint_id: str, hostname: str | None = None,
                 platform: str | None = None,
                 sensor_version: str | None = None,
                 device_iid: str | None = None) -> dict:
    """Consume the token, create the endpoint record, issue the credential.

    Idempotency note: the token is burned FIRST. If anything after it
    fails, the token is still spent — which is the safe direction. A token
    that could be retried after a partial enrolment is a token that can
    enrol twice.
    """
    token = await consume_enrollment_token(
        db, tenant_id=tenant_id, presented=presented_token)

    now = _now()
    credential = new_secret(PREFIX_CREDENTIAL)
    credential_id = f"cred_{uuid4().hex[:16]}"

    await db[CREDENTIALS].insert_one({
        "tenant_id": tenant_id,
        "endpoint_id": endpoint_id,
        "credential_id": credential_id,
        "secret_hash": digest(credential),
        "status": CredentialState.ACTIVE.value,
        "auth_epoch": 1,
        "created_at": _iso(now),
        "revoked_at": None,
        "rotated_at": None,
        "enrollment_token_id": token.get("token_id"),
    })

    record = EndpointRecord(
        tenant_id=tenant_id, endpoint_id=endpoint_id, device_iid=device_iid,
        credential_id=credential_id,
        enrollment_state=EnrollmentState.ENROLLED,
        credential_state=CredentialState.ACTIVE,
        sensor_state=SensorState.ENROLLED_NEVER_REPORTED,
        hostname=hostname, platform=platform, sensor_version=sensor_version,
        enrolled_at=_iso(now), last_seen=_iso(now))
    await db[ENDPOINTS].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": record.model_dump()}, upsert=True)

    return {
        "endpoint_id": endpoint_id,
        "credential_id": credential_id,
        "agent_credential": credential,   # the only time it ever appears
        "enrollment_state": EnrollmentState.ENROLLED.value,
        "sensor_state": SensorState.ENROLLED_NEVER_REPORTED.value,
        "warning": ("The durable credential is shown once and is not "
                    "retrievable. It is never returned by any other route."),
        "honesty_note": (
            "The endpoint is now enrolled and trusted to send telemetry. It "
            "has NOT sent any — sensor_state is ENROLLED_NEVER_REPORTED. "
            "Enrolment is not evidence of visibility."),
    }


# ── stage 3 · exchange the credential for a short-lived session ───

async def _active_credential(db: Any, *, tenant_id: str,
                             presented: str) -> dict:
    if not has_prefix(presented, PREFIX_CREDENTIAL):
        raise EnrollmentError("AGENT_CREDENTIAL_INVALID", 401,
                              "agent credential is not valid")
    doc = await db[CREDENTIALS].find_one(
        {"tenant_id": tenant_id, "secret_hash": digest(presented)},
        {"_id": 0})
    if not doc:
        raise EnrollmentError("AGENT_CREDENTIAL_INVALID", 401,
                              "agent credential is not valid")
    if doc["status"] != CredentialState.ACTIVE.value or doc.get("revoked_at"):
        raise EnrollmentError(
            "AGENT_CREDENTIAL_REVOKED", 403,
            "this agent credential has been revoked; the endpoint must "
            "re-enrol with a new one-time token")
    return doc


async def open_session(db: Any, *, tenant_id: str,
                       agent_credential: str) -> dict:
    cred = await _active_credential(db, tenant_id=tenant_id,
                                    presented=agent_credential)
    now = _now()
    expires = now + timedelta(seconds=_session_ttl())
    token = new_secret(PREFIX_SESSION)
    session_id = f"sess_{uuid4().hex[:16]}"
    await db[SESSIONS].insert_one({
        "tenant_id": tenant_id,
        "endpoint_id": cred["endpoint_id"],
        "session_id": session_id,
        "token_hash": digest(token),
        "credential_id": cred["credential_id"],
        "auth_epoch": cred["auth_epoch"],
        "created_at": _iso(now),
        "expires_at": _iso(expires),
        "expires_at_dt": expires,
        "revoked_at": None,
    })
    return {"session_token": token, "session_id": session_id,
            "endpoint_id": cred["endpoint_id"],
            "expires_at": _iso(expires), "ttl_seconds": _session_ttl()}


async def resolve_session(db: Any, *, presented: str) -> dict:
    """Resolve a session token to its server-side identity.

    Deliberately does NOT take a tenant_id argument: on the TELEMETRY leg
    the tenant is an OUTPUT of authentication, never an input. Accepting a
    caller-supplied tenant here would let a valid agent present its own
    token against someone else's tenant.

    Note the asymmetry with `open_session()`, which DOES take a tenant_id —
    it needs it to hit the `(tenant_id, secret_hash)` index, and a wrong
    tenant there simply fails to match. The guarantee that matters is that
    the tenant stamped on evidence comes from this function's output, not
    from anything a caller asserted.
    """
    if not has_prefix(presented, PREFIX_SESSION):
        raise EnrollmentError("SESSION_INVALID", 401,
                              "session token is not valid")
    now = _now()
    session = await db[SESSIONS].find_one({"token_hash": digest(presented)},
                                          {"_id": 0})
    if not session:
        raise EnrollmentError("SESSION_INVALID", 401,
                              "session token is not valid")
    if session.get("revoked_at"):
        raise EnrollmentError("SESSION_REVOKED", 401,
                              "session was revoked")
    if session["expires_at_dt"].replace(tzinfo=timezone.utc) <= now:
        raise EnrollmentError(
            "SESSION_EXPIRED", 401,
            "session token expired; exchange the durable credential for a "
            "new one")

    cred = await db[CREDENTIALS].find_one(
        {"tenant_id": session["tenant_id"],
         "credential_id": session["credential_id"]}, {"_id": 0})
    if not cred:
        raise EnrollmentError("AGENT_UNENROLLED", 403,
                              "no credential backs this session")
    if cred["status"] != CredentialState.ACTIVE.value or cred.get("revoked_at"):
        raise EnrollmentError(
            "AGENT_CREDENTIAL_REVOKED", 403,
            "the credential behind this session has been revoked")
    if cred["auth_epoch"] != session["auth_epoch"]:
        # The epoch is what invalidates an in-flight, still-unexpired
        # session the moment its credential is revoked or rotated.
        raise EnrollmentError(
            "SESSION_SUPERSEDED", 403,
            "the credential was revoked or rotated after this session was "
            "issued")

    endpoint = await db[ENDPOINTS].find_one(
        {"tenant_id": session["tenant_id"],
         "endpoint_id": session["endpoint_id"]}, {"_id": 0}) or {}
    if endpoint.get("enrollment_state") == EnrollmentState.REVOKED.value:
        raise EnrollmentError("ENDPOINT_REVOKED", 403,
                              "this endpoint's enrolment was revoked")
    return {"session": session, "credential": cred, "endpoint": endpoint}


# ── rotation and revocation ───────────────────────────────────────

async def rotate_credential(db: Any, *, tenant_id: str, endpoint_id: str,
                            rotated_by: str) -> dict:
    """Issue a new credential and retire the old one in the same step.

    The old credential's epoch is incremented, so every session minted
    under it dies at its next check. There is no overlap window: an
    overlap that is not explicitly acknowledged by the agent is just two
    live credentials with only one of them being watched.
    """
    old = await db[CREDENTIALS].find_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "status": CredentialState.ACTIVE.value}, {"_id": 0})
    if not old:
        raise EnrollmentError("NO_ACTIVE_CREDENTIAL", 404,
                              "this endpoint has no active credential to "
                              "rotate")
    now = _now()
    credential = new_secret(PREFIX_CREDENTIAL)
    credential_id = f"cred_{uuid4().hex[:16]}"
    await db[CREDENTIALS].insert_one({
        "tenant_id": tenant_id, "endpoint_id": endpoint_id,
        "credential_id": credential_id, "secret_hash": digest(credential),
        "status": CredentialState.ACTIVE.value, "auth_epoch": 1,
        "created_at": _iso(now), "revoked_at": None, "rotated_at": None,
        "rotated_from": old["credential_id"], "rotated_by": rotated_by,
    })
    await db[CREDENTIALS].update_one(
        {"tenant_id": tenant_id, "credential_id": old["credential_id"]},
        {"$set": {"status": CredentialState.REVOKED.value,
                  "revoked_at": _iso(now), "rotated_at": _iso(now)},
         "$inc": {"auth_epoch": 1}})
    await db[SESSIONS].update_many(
        {"tenant_id": tenant_id, "credential_id": old["credential_id"],
         "revoked_at": None},
        {"$set": {"revoked_at": _iso(now)}})
    await db[ENDPOINTS].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": {"credential_id": credential_id,
                  "credential_state": CredentialState.ACTIVE.value}})
    return {"endpoint_id": endpoint_id, "credential_id": credential_id,
            "agent_credential": credential,
            "previous_credential_id": old["credential_id"],
            "warning": "Shown once. Sessions from the old credential are "
                       "already dead."}


async def revoke_endpoint(db: Any, *, tenant_id: str, endpoint_id: str,
                          revoked_by: str, reason: str) -> dict:
    now = _now()
    creds = await db[CREDENTIALS].update_many(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "status": CredentialState.ACTIVE.value},
        {"$set": {"status": CredentialState.REVOKED.value,
                  "revoked_at": _iso(now), "revoked_by": revoked_by,
                  "revoke_reason": reason},
         "$inc": {"auth_epoch": 1}})
    sessions = await db[SESSIONS].update_many(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "revoked_at": None},
        {"$set": {"revoked_at": _iso(now)}})
    ep = await db[ENDPOINTS].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": {"enrollment_state": EnrollmentState.REVOKED.value,
                  "credential_state": CredentialState.REVOKED.value,
                  "sensor_state": SensorState.REVOKED.value,
                  "revoked_at": _iso(now)}})
    if not ep.matched_count:
        raise EnrollmentError("ENDPOINT_NOT_ENROLLED", 404,
                              "no such enrolled endpoint")
    return {
        "endpoint_id": endpoint_id, "revoked_at": _iso(now),
        "credentials_revoked": creds.modified_count,
        "sessions_killed": sessions.modified_count,
        "honesty_note": (
            "Telemetry from this endpoint is now REFUSED and recorded as a "
            "security signal. Evidence it produced while trusted is "
            "retained and remains valid — revocation is not retroactive "
            "distrust of past evidence."),
    }


# ── endpoint records ──────────────────────────────────────────────

async def mark_reported(db: Any, *, tenant_id: str, endpoint_id: str,
                        at: str) -> None:
    await db[ENDPOINTS].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        {"$set": {"sensor_state": SensorState.REPORTING.value,
                  "last_seen": at, "last_telemetry_at": at},
         "$inc": {"event_count": 1}})


async def list_endpoints(db: Any, *, tenant_id: str) -> list[dict]:
    rows = await db[ENDPOINTS].find({"tenant_id": tenant_id}, {"_id": 0}) \
        .sort("enrolled_at", -1).to_list(length=500)
    out = []
    for r in rows:
        rec = EndpointRecord(**r)
        out.append({**rec.model_dump(), "trust": rec.trust_summary()})
    return out


async def get_endpoint(db: Any, *, tenant_id: str,
                       endpoint_id: str) -> Optional[dict]:
    r = await db[ENDPOINTS].find_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id}, {"_id": 0})
    if not r:
        return None
    rec = EndpointRecord(**r)
    return {**rec.model_dump(), "trust": rec.trust_summary()}


async def list_tokens(db: Any, *, tenant_id: str) -> list[dict]:
    """Token metadata only. There is no route, anywhere, that returns a
    token's plaintext or its hash."""
    rows = await db[TOKENS].find(
        {"tenant_id": tenant_id},
        {"_id": 0, "token_hash": 0}).sort("created_at", -1).to_list(length=200)
    now = _now()
    for r in rows:
        expired = datetime.fromisoformat(r["expires_at"]) <= now
        r["state"] = ("USED" if r.get("used_at")
                      else "EXPIRED" if expired else "PENDING")
        r["single_use"] = True
    return rows
