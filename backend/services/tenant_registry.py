"""Authoritative organization / tenant registry — ONE tenancy authority.

    request
      -> authenticated principal
      -> requested tenant
      -> authoritative registry lookup      (this module)
      -> tenant exists
      -> tenant ACTIVE (and its organization ACTIVE)
      -> principal authorized for tenant    (existing RBAC, unchanged)
      -> tenant-scoped operation

Before this module a tenant was IMPLIED by whichever document happened to be
written first: `POST /api/xdr/collectors` accepted any `X-Tenant-Id` string
with no existence check (B4), and the EDR admin plane derived its tenant from
`users["customer"]`, a field nothing ever writes, so every enrolment landed in
the literal string `"default"` (B5). Two products, two accidental authorities.

Rules this module exists to enforce:

* tenancy is ASSERTED by an administrative act, never implied by a data-plane
  write. Collector creation, API-key creation, endpoint enrolment, telemetry
  and incident creation may CONSUME a tenant; none of them may create one;
* the security identifier is opaque and immutable (`org_…` / `ten_…`). Slug
  and display name are mutable labels and are never an authorization key;
* `tenant_id` values already persisted are NEVER rewritten — the value is part
  of `services.ingest_idempotency.event_identity()` and of the EDR raw-event
  dedupe digest, so a rename would silently re-partition existing evidence.
  Legacy strings are ADOPTED as tenants keeping their own id.

Enforcement is gated by ``NIVX_TENANT_REGISTRY_ENFORCE``:

* OFF (default) — resolution is observational. Behaviour is byte-identical to
  the pre-registry code path, including the historical `"default"` fallback,
  and every deviation is logged once per process/reason.
* ON            — unknown tenant, inactive tenant, inactive organization and a
                  missing tenant header all FAIL CLOSED. There is no branch in
                  which enforcement turns into permission.

The flag can only make the platform stricter; it can never open a path that is
closed with it off.
"""
from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from deps import sync_collection

log = logging.getLogger("nivxray.tenant_registry")

ORGANIZATIONS = "organizations"
TENANTS = "tenants"

ORG_PREFIX = "org_"
TEN_PREFIX = "ten_"

ORG_KINDS = ("VENDOR", "CUSTOMER", "MSSP")
TENANT_KINDS = ("INTERNAL_VALIDATION", "CUSTOMER", "LAB", "LEGACY_ADOPTED")
STATES = ("ACTIVE", "SUSPENDED", "ARCHIVED")

#: Reasons a tenant may never be asserted from a data-plane write.
IMPLICIT_TENANT_FORBIDDEN = (
    "tenancy is established only by POST /api/xdr/tenants; collector "
    "creation, API-key creation, endpoint enrolment, telemetry and incident "
    "creation never create a tenant")


class TenantRegistryError(Exception):
    """Fail-closed tenancy refusal, carrying a machine code and a status."""

    def __init__(self, code: str, reason: str, *, http: int = 403,
                 tenant_id: str | None = None):
        self.code, self.reason, self.http = code, reason, http
        self.tenant_id = tenant_id
        super().__init__(reason)

    def detail(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "reason": self.reason}
        if self.tenant_id is not None:
            d["tenant_id"] = self.tenant_id
        return d


def enforcing() -> bool:
    """Read at call time, never cached, so the flag is auditable per request."""
    return (os.environ.get("NIVX_TENANT_REGISTRY_ENFORCE") or "").strip().lower() \
        in ("1", "true", "yes", "on")


def _orgs():
    return sync_collection(ORGANIZATIONS)


def _tenants():
    return sync_collection(TENANTS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_org_id() -> str:
    return ORG_PREFIX + secrets.token_hex(13)


def new_tenant_id() -> str:
    return TEN_PREFIX + secrets.token_hex(13)


# ── registry reads ────────────────────────────────────────────────
def get_organization(org_id: str) -> dict[str, Any] | None:
    return _orgs().find_one({"id": org_id}, {"_id": 0})


def get_tenant(tenant_id: str) -> dict[str, Any] | None:
    return _tenants().find_one({"id": tenant_id}, {"_id": 0})


def list_organizations(limit: int = 200) -> list[dict[str, Any]]:
    return list(_orgs().find({}, {"_id": 0}).limit(limit))


def list_tenants(organization_id: str | None = None,
                 limit: int = 500) -> list[dict[str, Any]]:
    q = {"organization_id": organization_id} if organization_id else {}
    return list(_tenants().find(q, {"_id": 0}).limit(limit))


# ── the single authority call ─────────────────────────────────────
def authoritative(tenant_id: str | None, *, purpose: str,
                  compat_default: str = "default") -> str:
    """Resolve the tenant a request may act in, or fail closed.

    `purpose` names the call site so a refusal (or, with enforcement off, a
    deviation) is attributable. `compat_default` is the value the pre-registry
    code used when nothing named a tenant; it is returned ONLY while
    enforcement is off, and never invented when it is on.
    """
    requested = (tenant_id or "").strip()
    if not enforcing():
        if not requested:
            log.info("[tenant_registry] compat fallback %r at %s "
                     "(enforcement off)", compat_default, purpose)
            return compat_default
        doc = None
        try:
            doc = get_tenant(requested)
        except Exception:                                   # noqa: BLE001
            pass
        if doc is None:
            log.info("[tenant_registry] unregistered tenant %r at %s "
                     "(enforcement off; would be refused when on)",
                     requested, purpose)
        elif doc.get("state") != "ACTIVE":
            log.info("[tenant_registry] tenant %r state=%s at %s "
                     "(enforcement off; would be refused when on)",
                     requested, doc.get("state"), purpose)
        return requested

    if not requested:
        raise TenantRegistryError(
            "TENANT_REQUIRED",
            f"no tenant named for {purpose}: the authoritative tenant must be "
            "presented explicitly; there is no default tenant")
    doc = get_tenant(requested)
    if doc is None:
        raise TenantRegistryError(
            "TENANT_NOT_FOUND",
            f"tenant is not registered ({purpose}). {IMPLICIT_TENANT_FORBIDDEN}",
            tenant_id=requested)
    if doc.get("state") != "ACTIVE":
        raise TenantRegistryError(
            "TENANT_NOT_ACTIVE",
            f"tenant state is {doc.get('state')!r} ({purpose})",
            tenant_id=requested)
    org = get_organization(str(doc.get("organization_id") or ""))
    if org is None:
        raise TenantRegistryError(
            "ORGANIZATION_NOT_FOUND",
            f"tenant's organization is not registered ({purpose})",
            tenant_id=requested)
    if org.get("state") != "ACTIVE":
        raise TenantRegistryError(
            "ORGANIZATION_NOT_ACTIVE",
            f"organization state is {org.get('state')!r} ({purpose})",
            tenant_id=requested)
    return requested


# ── administrative writes (the ONLY way tenancy is created) ───────
def create_organization(*, slug: str, display_name: str, kind: str,
                        created_by: str) -> dict[str, Any]:
    slug = (slug or "").strip().lower()
    if not slug:
        raise TenantRegistryError("ORGANIZATION_SLUG_REQUIRED",
                                  "slug is required", http=400)
    if kind not in ORG_KINDS:
        raise TenantRegistryError(
            "ORGANIZATION_KIND_INVALID",
            f"kind must be one of {list(ORG_KINDS)}", http=400)
    if _orgs().find_one({"slug": slug}):
        raise TenantRegistryError("ORGANIZATION_SLUG_EXISTS",
                                  f"organization slug {slug!r} already exists",
                                  http=409)
    now = _now()
    doc = {"id": new_org_id(), "slug": slug,
           "display_name": display_name or slug, "kind": kind,
           "state": "ACTIVE", "created_at": now, "updated_at": now,
           "created_by": created_by}
    _orgs().insert_one(dict(doc))
    return doc


def create_tenant(*, organization_id: str, slug: str, display_name: str,
                  kind: str, products: list[str], created_by: str,
                  tenant_id: str | None = None) -> dict[str, Any]:
    """Create a tenant. `tenant_id` is only supplied by legacy adoption."""
    org = get_organization(organization_id)
    if org is None:
        raise TenantRegistryError("ORGANIZATION_NOT_FOUND",
                                  "organization_id does not exist", http=400)
    if org.get("state") != "ACTIVE":
        raise TenantRegistryError("ORGANIZATION_NOT_ACTIVE",
                                  "organization is not ACTIVE", http=409)
    slug = (slug or "").strip().lower()
    if not slug:
        raise TenantRegistryError("TENANT_SLUG_REQUIRED",
                                  "slug is required", http=400)
    if kind not in TENANT_KINDS:
        raise TenantRegistryError(
            "TENANT_KIND_INVALID",
            f"kind must be one of {list(TENANT_KINDS)}", http=400)
    if _tenants().find_one({"organization_id": organization_id, "slug": slug}):
        raise TenantRegistryError(
            "TENANT_SLUG_EXISTS",
            f"tenant slug {slug!r} already exists in this organization",
            http=409)
    tid = tenant_id or new_tenant_id()
    if _tenants().find_one({"id": tid}):
        raise TenantRegistryError("TENANT_EXISTS",
                                 f"tenant {tid!r} already exists", http=409)
    now = _now()
    doc = {"id": tid, "organization_id": organization_id, "slug": slug,
           "display_name": display_name or slug, "kind": kind,
           "state": "ACTIVE", "products": list(products or []),
           "created_at": now, "updated_at": now, "created_by": created_by}
    _tenants().insert_one(dict(doc))
    return doc


def set_state(kind: str, object_id: str, state: str) -> dict[str, Any]:
    if state not in STATES:
        raise TenantRegistryError("STATE_INVALID",
                                  f"state must be one of {list(STATES)}",
                                  http=400)
    coll = _orgs() if kind == "organization" else _tenants()
    doc = coll.find_one({"id": object_id}, {"_id": 0})
    if doc is None:
        raise TenantRegistryError(
            "ORGANIZATION_NOT_FOUND" if kind == "organization"
            else "TENANT_NOT_FOUND", f"{kind} {object_id!r} not found",
            http=404)
    coll.update_one({"id": object_id},
                    {"$set": {"state": state, "updated_at": _now()}})
    return {**doc, "state": state}


def adopt_legacy(*, tenant_id: str, organization_id: str, slug: str,
                 display_name: str, created_by: str) -> dict[str, Any]:
    """Register an EXISTING tenant string without changing its value.

    Deliberate, explicit and idempotent — never run at startup, never
    automatic. The id is preserved so `event_identity()` digests, the EDR
    dedupe digests and every index stay byte-identical.
    """
    existing = get_tenant(tenant_id)
    if existing is not None:
        return existing
    return create_tenant(organization_id=organization_id, slug=slug,
                         display_name=display_name, kind="LEGACY_ADOPTED",
                         products=[], created_by=created_by,
                         tenant_id=tenant_id)
