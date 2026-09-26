"""P0-PROD-2 · the authoritative enrolment-lifecycle audit record.

Append-only. Written by the operation itself (mint / revoke / enrol /
reject) so the console cannot disagree with what happened.

The one rule that is enforced in code rather than trusted: **no secret
material may enter this store.** `_assert_no_secret()` inspects every
value for an enrolment-token, credential or session prefix and raises
before the write. A redaction promise that is only a convention is a
redaction promise that eventually gets broken by a well-meaning
`detail={...}`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pymongo import ASCENDING

from .security import (PREFIX_CREDENTIAL, PREFIX_ENROLLMENT, PREFIX_SESSION,
                       fingerprint)

AUDIT = "edr_enrollment_audit"

TOKEN_CREATED = "TOKEN_CREATED"
TOKEN_REVOKED = "TOKEN_REVOKED"
ENROLLMENT_SUCCEEDED = "ENROLLMENT_SUCCEEDED"
ENROLLMENT_REJECTED = "ENROLLMENT_REJECTED"

_SECRET_PREFIXES = (f"{PREFIX_ENROLLMENT}_", f"{PREFIX_CREDENTIAL}_",
                    f"{PREFIX_SESSION}_")


class AuditRedactionError(RuntimeError):
    """Raised when secret material would have been persisted."""


def _assert_no_secret(value: Any, *, path: str = "record") -> None:
    if isinstance(value, str):
        for p in _SECRET_PREFIXES:
            if p in value:
                raise AuditRedactionError(
                    f"refusing to write enrolment audit: {path} contains "
                    f"material with the '{p}' secret prefix")
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_no_secret(v, path=f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _assert_no_secret(v, path=f"{path}[{i}]")


async def ensure_indexes(db: Any) -> None:
    await db[AUDIT].create_index([("tenant_id", ASCENDING), ("at", ASCENDING)])
    await db[AUDIT].create_index([("tenant_id", ASCENDING),
                                  ("event", ASCENDING)])


async def record(db: Any, *, tenant_id: str, event: str,
                 actor: str, outcome: str,
                 token_id: Optional[str] = None,
                 endpoint_id: Optional[str] = None,
                 reason_code: Optional[str] = None,
                 source_ip: Optional[str] = None,
                 presented_secret: Optional[str] = None,
                 detail: Optional[dict] = None) -> dict:
    """Append one lifecycle event.

    `presented_secret` is NEVER stored — only its non-reversible
    fingerprint, so repeated attempts by the same bad token correlate
    without the platform ever holding the value.
    """
    rec = {
        "tenant_id": tenant_id,
        "at": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
        "outcome": outcome,
        "token_id": token_id,
        "endpoint_id": endpoint_id,
        "reason_code": reason_code,
        "source_ip": source_ip,
        "secret_fingerprint": (fingerprint(presented_secret)
                               if presented_secret else None),
        "detail": detail or {},
    }
    _assert_no_secret(rec)
    await db[AUDIT].insert_one(dict(rec))
    return rec


async def record_safe(db: Any, **kw: Any) -> Optional[dict]:
    """Same record, but never raises.

    Used ONLY on the unauthenticated rejection path, where the
    authoritative security signal is already written to
    `edr_rejected_telemetry`: a failure to append the audit mirror must
    not turn a correct 401 into a 500, which would itself be an oracle.
    A redaction violation still raises, because that is a programming
    error and not an availability concern.
    """
    try:
        return await record(db, **kw)
    except AuditRedactionError:
        raise
    except Exception:
        return None


async def list_events(db: Any, *, tenant_id: str, since: str | None = None,
                      limit: int = 200) -> list[dict]:
    q: dict[str, Any] = {"tenant_id": tenant_id}
    if since:
        q["at"] = {"$gte": since}
    return await db[AUDIT].find(q, {"_id": 0}).sort("at", -1) \
        .to_list(length=limit)
