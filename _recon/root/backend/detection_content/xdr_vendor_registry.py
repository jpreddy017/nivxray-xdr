"""
Round 28 · Vendor Registry.
============================

Single lookup table  vendor_key → VendorAdapter subclass.
Consumers (wizard, executor, response console) call
`get_vendor_class(vendor_key)` and never import concrete vendor
modules themselves.

Owner-locked guardrail (Round 28):
  · Adapters flagged `lifecycle=INTERNAL_TEST_ONLY` are HIDDEN by
    default from `list_production_vendors()` — the customer-facing
    vendor catalogue MUST use that helper.
  · Framework-internal callers can pass `include_internal=True` to
    exercise the stub adapter in tests.
"""
from __future__ import annotations

from typing import Optional

from .xdr_vendor_adapter import VendorAdapter


_REGISTRY: dict[str, type[VendorAdapter]] = {}


def register_vendor(cls: type[VendorAdapter]) -> type[VendorAdapter]:
    """Class decorator that installs the adapter into the registry.
    Fails loudly on duplicate keys — mis-registration must never be
    a silent runtime hazard."""
    key = cls.vendor_key
    if not key:
        raise ValueError(f"{cls.__name__}: vendor_key must be set")
    if key in _REGISTRY:
        raise ValueError(f"vendor_key already registered: {key}")
    _REGISTRY[key] = cls
    return cls


def get_vendor_class(vendor_key: str) -> type[VendorAdapter]:
    if vendor_key not in _REGISTRY:
        raise LookupError(f"unknown_vendor: {vendor_key}")
    return _REGISTRY[vendor_key]


def has_vendor(vendor_key: str) -> bool:
    return vendor_key in _REGISTRY


def list_production_vendors() -> list[dict]:
    """Return the metadata payload for every PRODUCTION adapter.
    This is the customer-facing catalogue source of truth."""
    return [cls.metadata() for cls in _REGISTRY.values()
              if cls.metadata().get("lifecycle") == "PRODUCTION"]


def list_all_vendors(*, include_internal: bool = False) -> list[dict]:
    return [cls.metadata() for cls in _REGISTRY.values()
              if include_internal
                  or cls.metadata().get("lifecycle") == "PRODUCTION"]


# ── Register built-in adapters at import time ──────────────
# Ordering matters only for enumeration; retrieval is O(1).
def _install():
    from . import xdr_cortex_vendor_adapter      as _cortex   # noqa: F401
    from . import xdr_falcon_vendor_adapter      as _falcon   # noqa: F401
    from . import xdr_mde_vendor_adapter         as _mde      # noqa: F401
    from . import xdr_sentinelone_vendor_adapter as _s1       # noqa: F401
    from . import xdr_stub_adapter               as _stub     # noqa: F401


_install()
