"""GATE 7 · exclusion contracts.

Every field the owner required is mandatory by construction, not by
convention: tenant, scope, type, value, reason, creator, approval,
affected engine, policy version binding, affected endpoints/groups,
effective time, expiry/review, audit.

An exclusion is inert until it is APPROVED. That is what stops "someone
added a record" from becoming "the product stopped looking".
"""
from __future__ import annotations

import fnmatch
import re
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ExclusionType(str, Enum):
    PATH = "PATH"
    FILE_HASH = "FILE_HASH"
    PROCESS = "PROCESS"
    PROCESS_COMMANDLINE = "PROCESS_COMMANDLINE"
    NETWORK_ADDRESS = "NETWORK_ADDRESS"
    FILE_EXTENSION = "FILE_EXTENSION"


class MatchKind(str, Enum):
    EXACT = "EXACT"
    PREFIX = "PREFIX"
    SUFFIX = "SUFFIX"
    GLOB = "GLOB"
    CONTAINS = "CONTAINS"


class ExclusionEngine(str, Enum):
    """The engines an exclusion may be aimed at. `deterministic.rule` is
    the fabric analyzer that exists today; the endpoint engines exist as
    delivery targets whose support is read from the connector release."""
    SERVER_DETERMINISTIC_RULE = "server.deterministic.rule"
    ENDPOINT_PREVENTION = "endpoint.prevention"
    ENDPOINT_COLLECTION = "endpoint.collection"


SERVER_ENGINES = (ExclusionEngine.SERVER_DETERMINISTIC_RULE.value,)
ENDPOINT_ENGINES = (ExclusionEngine.ENDPOINT_PREVENTION.value,
                    ExclusionEngine.ENDPOINT_COLLECTION.value)

#: engine -> the connector capability key that must be true for endpoint
#: enforcement to be possible at all.
ENDPOINT_ENGINE_CAPABILITY = {
    ExclusionEngine.ENDPOINT_PREVENTION.value: "endpoint_exclusions",
    ExclusionEngine.ENDPOINT_COLLECTION.value: "endpoint_exclusions",
}


class EnforcementPoint(str, Enum):
    SERVER_FABRIC = "SERVER_FABRIC"
    ENDPOINT = "ENDPOINT"


class TruthState(str, Enum):
    EXCLUDED = "EXCLUDED"
    NOT_EVALUATED_DUE_TO_EXCLUSION = "NOT_EVALUATED_DUE_TO_EXCLUSION"
    SERVER_EXCLUSION_APPLIED = "SERVER_EXCLUSION_APPLIED"
    ENDPOINT_EXCLUSION_APPLIED = "ENDPOINT_EXCLUSION_APPLIED"
    EXCLUSION_PENDING_POLICY = "EXCLUSION_PENDING_POLICY"
    EXCLUSION_NOT_SUPPORTED_BY_ENGINE = "EXCLUSION_NOT_SUPPORTED_BY_ENGINE"


class ApprovalState(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class LifecycleState(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE_PENDING_APPROVAL = "INACTIVE_PENDING_APPROVAL"
    NOT_YET_EFFECTIVE = "NOT_YET_EFFECTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    REVIEW_OVERDUE = "REVIEW_OVERDUE"


class ScopeType(str, Enum):
    TENANT = "TENANT"
    GROUP = "GROUP"
    ENDPOINT = "ENDPOINT"


class ExclusionScope(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    type: ScopeType = ScopeType.TENANT
    ids: List[str] = Field(default_factory=list)

    @field_validator("ids")
    @classmethod
    def _ids_required(cls, v, info):
        return v


class ExclusionDraft(BaseModel):
    """What an operator submits. Nothing optional that the owner required."""
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    set_id: str
    type: ExclusionType
    value: str = Field(min_length=1, max_length=1024)
    match: MatchKind = MatchKind.EXACT
    reason: str = Field(min_length=10, max_length=2000,
                        description="Why this protection blind spot is "
                                    "accepted. Recorded verbatim.")
    affected_engines: List[ExclusionEngine] = Field(min_length=1)
    scope: ExclusionScope = Field(default_factory=ExclusionScope)
    effective_from: Optional[str] = None
    expires_at: Optional[str] = None
    review_at: Optional[str] = None

    @field_validator("value")
    @classmethod
    def _hash_shape(cls, v, info):
        if (info.data.get("type") == ExclusionType.FILE_HASH.value
                and not re.fullmatch(r"[A-Fa-f0-9]{64}", v.strip())):
            raise ValueError("a FILE_HASH exclusion value must be a SHA-256 "
                             "hex digest")
        return v.strip()


def new_exclusion_id() -> str:
    return "exc_" + secrets.token_hex(8)


def new_set_id() -> str:
    return "exs_" + secrets.token_hex(8)


def _parse(iso: Optional[str]) -> Optional[datetime]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None


def lifecycle_state(doc: Dict[str, Any],
                    now: Optional[datetime] = None) -> Dict[str, str]:
    """The exclusion's own state, computed from its recorded facts."""
    now = now or datetime.now(timezone.utc)
    if doc.get("revoked_at"):
        return {"state": LifecycleState.REVOKED.value,
                "basis": f"revoked by {doc.get('revoked_by')}: "
                         f"{doc.get('revoke_reason')}"}
    if doc.get("approval_state") != ApprovalState.APPROVED.value:
        return {"state": LifecycleState.INACTIVE_PENDING_APPROVAL.value,
                "basis": ("an unapproved exclusion is inert: no engine "
                          "consults it, so protection is unchanged")}
    eff = _parse(doc.get("effective_from"))
    if eff and eff > now:
        return {"state": LifecycleState.NOT_YET_EFFECTIVE.value,
                "basis": f"becomes effective at {doc.get('effective_from')}"}
    exp = _parse(doc.get("expires_at"))
    if exp and exp <= now:
        return {"state": LifecycleState.EXPIRED.value,
                "basis": f"expired at {doc.get('expires_at')}; it no longer "
                         "affects any engine"}
    rev = _parse(doc.get("review_at"))
    if rev and rev <= now:
        return {"state": LifecycleState.REVIEW_OVERDUE.value,
                "basis": (f"review was due at {doc.get('review_at')}; the "
                          "exclusion is STILL ENFORCED and is flagged for "
                          "review")}
    return {"state": LifecycleState.ACTIVE.value,
            "basis": "approved, effective and not expired"}


#: Only these lifecycle states may reach an engine.
ENFORCEABLE_STATES = (LifecycleState.ACTIVE.value,
                      LifecycleState.REVIEW_OVERDUE.value)


def matches(doc: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    """Does this exclusion match the observed activity?

    Absent evidence never matches. An exclusion cannot silently swallow
    activity whose relevant attribute was not observed.
    """
    field = {
        ExclusionType.PATH.value: "path",
        ExclusionType.FILE_HASH.value: "file_hash",
        ExclusionType.PROCESS.value: "process",
        ExclusionType.PROCESS_COMMANDLINE.value: "command_line",
        ExclusionType.NETWORK_ADDRESS.value: "network_address",
        ExclusionType.FILE_EXTENSION.value: "path",
    }.get(doc.get("type"))
    if not field:
        return False
    observed = candidate.get(field)
    if not observed:
        return False
    observed = str(observed)
    value = str(doc.get("value") or "")
    if doc.get("type") == ExclusionType.FILE_HASH.value:
        return observed.lower() == value.lower()
    o, v = observed.lower(), value.lower()
    kind = doc.get("match") or MatchKind.EXACT.value
    if doc.get("type") == ExclusionType.FILE_EXTENSION.value:
        return o.endswith(v if v.startswith(".") else "." + v)
    if kind == MatchKind.EXACT.value:
        return o == v
    if kind == MatchKind.PREFIX.value:
        return o.startswith(v)
    if kind == MatchKind.SUFFIX.value:
        return o.endswith(v)
    if kind == MatchKind.CONTAINS.value:
        return v in o
    if kind == MatchKind.GLOB.value:
        return fnmatch.fnmatch(o, v)
    return False


def in_scope(doc: Dict[str, Any], *, endpoint_id: Optional[str],
             group_id: Optional[str]) -> bool:
    scope = doc.get("scope") or {}
    stype = scope.get("type") or ScopeType.TENANT.value
    ids = [str(i) for i in (scope.get("ids") or [])]
    if stype == ScopeType.TENANT.value:
        return True
    if stype == ScopeType.GROUP.value:
        return bool(group_id) and group_id in ids
    if stype == ScopeType.ENDPOINT.value:
        return bool(endpoint_id) and endpoint_id in ids
    return False


AUTHORITY_CONTRACT = (
    "An exclusion record alone is not an exclusion. It must be APPROVED, "
    "effective, in scope, and it must change what a named engine does. "
    "Server-side exclusions are enforced by the detection fabric before "
    "an analyzer runs; endpoint-side exclusions are delivered through the "
    "authoritative policy mechanism and report "
    "EXCLUSION_PENDING_POLICY or EXCLUSION_NOT_SUPPORTED_BY_ENGINE until "
    "the endpoint proves otherwise.")
