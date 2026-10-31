"""D14 · Tenant authority — one answer to "whose evidence is this?"

The authenticated delivery establishes the tenant. Nothing else may.

    authenticated delivery tenant
              ↓
       authoritative tenant
              ↓
           normalizer

A tenant named inside the payload is a CLAIM by whoever sent it. It is
recorded so the claim itself remains visible as evidence, and it is never
used: not to override, not to select, and not as a fallback when the
authenticated tenant is absent. An absent authenticated tenant is a refusal,
never a default.

This matters beyond ownership. The tenant participates in deterministic
canonical identity (D10), in evidence partitioning and in every downstream
authorization decision, so untrusted tenant material must never reach any of
them.

This module does NOT establish the authenticated tenant — the existing
ingest guards do that, and they are untouched. It only makes sure that once
established, nothing downstream can talk over it.
"""
from __future__ import annotations

from typing import Any

UNTRUSTED_SOURCE_CLAIM = "UNTRUSTED_SOURCE_CLAIM"


class TenantAuthorityError(ValueError):
    """No authenticated tenant, so no evidence. Fail closed."""


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def resolve(authenticated: Any,
            *claims: tuple[Any, str]) -> tuple[str, dict[str, Any] | None]:
    """``(authoritative_tenant, claim_record_or_None)``.

    `claims` are ``(value, where_it_came_from)`` pairs — payload fields that
    name a tenant. They are reported, never believed.

    Raises `TenantAuthorityError` when the authenticated tenant is missing,
    blank or whitespace-only. A payload claim cannot rescue that, and there
    is no `"default"`.
    """
    if authenticated is not None and not isinstance(authenticated, str):
        # A non-string tenant is a programming error, not a tenant. `0` and
        # `False` must not become the string "0"/"False" and then pass for
        # an established identity.
        raise TenantAuthorityError(
            f"tenant_id must be a string, got {type(authenticated).__name__}")
    tenant = _clean(authenticated)
    if not tenant:
        raise TenantAuthorityError(
            "tenant_id is required: NO tenant fallback permitted — the "
            "authenticated delivery is the only authority on ownership, and "
            "a payload-supplied tenant is never substituted for it")

    for value, source in claims:
        claimed = _clean(value)
        if not claimed:
            continue
        return tenant, {
            "state": UNTRUSTED_SOURCE_CLAIM,
            "claimed_tenant_id": claimed,
            "claim_source": source,
            "used": False,
            "agrees_with_authenticated": claimed == tenant,
            "reason": ("recorded as evidence of what the payload asserted; "
                       "the authenticated delivery tenant is authoritative "
                       "and this value influenced nothing — not ownership, "
                       "not canonical identity, not partitioning"),
        }
    return tenant, None


def payload_claims(raw: Any) -> tuple[tuple[Any, str], ...]:
    """Tenant values a SOURCE or a COLLECTOR supplied, in claim order.

    NivX's own assembled `tenant_id` is deliberately NOT a claim — it is
    the answer, and echoing it back as an "untrusted claim" would be a
    dishonest label. The three shapes a normalizer can be handed:

    * a DOCUMENT event (`_nivx` present) — the source's own `tenant_id`,
      including the value the ingest boundary withheld;
    * a NivX-assembled LINE event (`raw` nested) — the collector payload is
      the nested dict; the outer `tenant_id` is ours;
    * the payload itself (direct callers, the sensor path).
    """
    if not isinstance(raw, dict):
        return ()
    claims: list[tuple[Any, str]] = []
    nivx = raw.get("_nivx") if isinstance(raw.get("_nivx"), dict) else None
    if nivx is not None:
        withheld = nivx.get("source_fields_withheld") or {}
        if withheld.get("tenant_id"):
            claims.append((withheld["tenant_id"],
                           "source document tenant_id, withheld at the "
                           "ingest boundary"))
        if raw.get("tenant_id"):
            claims.append((raw["tenant_id"], "source document tenant_id"))
        return tuple(claims)
    inner = raw.get("raw") if isinstance(raw.get("raw"), dict) else None
    if inner is not None:
        if inner.get("tenant_id"):
            claims.append((inner["tenant_id"],
                           "collector envelope raw.tenant_id"))
        return tuple(claims)
    if raw.get("tenant_id"):
        claims.append((raw["tenant_id"], "source payload tenant_id"))
    return tuple(claims)


def record(canonical: dict[str, Any], claim: dict[str, Any] | None) -> None:
    """Publish the claim beside the evidence it failed to influence."""
    if not claim:
        return
    extra = canonical.setdefault("additional_fields", {})
    if isinstance(extra, dict):
        extra["tenant_claim"] = claim
