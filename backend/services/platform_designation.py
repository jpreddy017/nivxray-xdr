"""P0 · explicit PLATFORM principal designation (owner-approved 2026-09-29).

WHY THIS EXISTS
---------------
Fix 6B-2 retired role-derived tenant breadth: a free-text ``role`` string no
longer authorises every customer tenant. Breadth now comes ONLY from
``users.authority_scope == "PLATFORM"`` (explicit designation) or the explicit
grant list ``users.tenant_ids[]``. The designation, however, was only ever
written by a script bound to a workspace ``.env`` — so the production auth
store carried NO authority-bearing principal, and the Super Admin was
(correctly) refused every tenant after the rollout.

This module performs that one designation as part of the normal, controlled
bootstrap, against whatever auth store the running backend is already using.
It writes EXACTLY one field on EXACTLY one principal named by an explicit
server-side configuration value, and refuses on every ambiguity.

WHAT IT IS NOT
--------------
It does not restore ``_CROSS_TENANT_ROLES``. ``role == "admin"`` still confers
no breadth whatsoever. It never reads, writes or infers ``tenant_ids``, roles,
passwords, tenants, endpoints or evidence. The client cannot influence it: the
principal comes from the server environment only.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

#: The canonical field/value pair enforced by `services.dashboard_lenses`.
FIELD = "authority_scope"
PLATFORM_SCOPE = "PLATFORM"

#: The explicit, server-side designation. Absent ⇒ this module does nothing.
ENV_VAR = "NIVX_PLATFORM_PRINCIPAL"

NOT_CONFIGURED = "NOT_CONFIGURED"
UPDATED = "UPDATED"
ALREADY_CONFIGURED = "ALREADY_CONFIGURED"
REFUSED_MALFORMED = "REFUSED_MALFORMED_PRINCIPAL"
REFUSED_NOT_FOUND = "REFUSED_PRINCIPAL_NOT_FOUND"
REFUSED_AMBIGUOUS = "REFUSED_PRINCIPAL_AMBIGUOUS"
REFUSED_CONFLICT = "REFUSED_CONFLICTING_AUTHORITY_SCOPE"
REFUSED_STORE_UNREACHABLE = "REFUSED_AUTH_STORE_UNREACHABLE"
REFUSED_VERIFY = "REFUSED_DESIGNATION_NOT_VERIFIED"

REFUSALS = frozenset({REFUSED_MALFORMED, REFUSED_NOT_FOUND, REFUSED_AMBIGUOUS,
                      REFUSED_CONFLICT, REFUSED_STORE_UNREACHABLE,
                      REFUSED_VERIFY})

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Last outcome, for operator observability. Never holds a secret.
LAST_RESULT: Dict[str, Any] = {"result": NOT_CONFIGURED}

_PROJ = {"_id": 1, "email": 1, FIELD: 1}


def configured_principal() -> Optional[str]:
    raw = os.environ.get(ENV_VAR)
    return raw.strip().lower() if isinstance(raw, str) and raw.strip() else None


def _refuse(result: str, logger, **extra: Any) -> Dict[str, Any]:
    out = {"result": result, **extra}
    LAST_RESULT.clear()
    LAST_RESULT.update(out)
    if logger is not None:
        logger.error("[platform-designation] result=%s %s", result,
                     " ".join(f"{k}={v}" for k, v in extra.items()))
    return out


async def designate_platform_principal(users, logger=None) -> Dict[str, Any]:
    """Idempotently designate the configured principal as PLATFORM.

    Returns a machine-readable outcome and never raises: an authorization
    designation failure must not convert into a total API outage, and the
    authorization path stays fail-closed on its own (absent designation ⇒
    CUSTOMER) whatever happens here.
    """
    principal = configured_principal()
    if principal is None:
        LAST_RESULT.clear()
        LAST_RESULT.update({"result": NOT_CONFIGURED})
        return dict(LAST_RESULT)

    if not _EMAIL.match(principal):
        return _refuse(REFUSED_MALFORMED, logger, env_var=ENV_VAR)

    exact_ci = {"email": {"$regex": f"^{re.escape(principal)}$",
                          "$options": "i"}}
    try:
        matches = await users.find(exact_ci, _PROJ).to_list(3)
    except Exception as exc:  # noqa: BLE001 — store unreachable is a refusal
        return _refuse(REFUSED_STORE_UNREACHABLE, logger,
                       error=type(exc).__name__)

    if not matches:
        return _refuse(REFUSED_NOT_FOUND, logger, principal=principal)
    if len(matches) > 1:
        return _refuse(REFUSED_AMBIGUOUS, logger, principal=principal,
                       matches=len(matches))

    doc = matches[0]
    before = doc.get(FIELD)
    if isinstance(before, str) and before.strip() == PLATFORM_SCOPE:
        out = {"result": ALREADY_CONFIGURED, "principal": principal,
               "previous_authority_scope": PLATFORM_SCOPE,
               "new_authority_scope": PLATFORM_SCOPE}
        LAST_RESULT.clear()
        LAST_RESULT.update(out)
        if logger is not None:
            logger.info("[platform-designation] result=%s principal=%s",
                        ALREADY_CONFIGURED, principal)
        return out
    if before is not None:
        return _refuse(REFUSED_CONFLICT, logger, principal=principal,
                       previous_authority_scope=repr(before))

    try:
        await users.update_one({"_id": doc["_id"]},
                               {"$set": {FIELD: PLATFORM_SCOPE}})
        read_back = await users.find_one({"_id": doc["_id"]}, _PROJ) or {}
    except Exception as exc:  # noqa: BLE001
        return _refuse(REFUSED_STORE_UNREACHABLE, logger,
                       error=type(exc).__name__)

    if read_back.get(FIELD) != PLATFORM_SCOPE:
        return _refuse(REFUSED_VERIFY, logger, principal=principal,
                       read_back=repr(read_back.get(FIELD)))

    out = {"result": UPDATED, "principal": principal,
           "previous_authority_scope": "ABSENT",
           "new_authority_scope": PLATFORM_SCOPE}
    LAST_RESULT.clear()
    LAST_RESULT.update(out)
    if logger is not None:
        logger.info("[platform-designation] result=%s principal=%s "
                    "previous_authority_scope=ABSENT new_authority_scope=%s",
                    UPDATED, principal, PLATFORM_SCOPE)
    return out
