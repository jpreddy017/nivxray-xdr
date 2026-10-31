"""Vendor → normalizer routing.

Given a `VendorDetection`, dispatch to the right adapter and emit
CEMv1. Never fails: falls back to `GenericNormalizer` so downstream
stages always receive a well-formed CEM.
"""
from __future__ import annotations

from nivxforge.investigation.cem import CanonicalEventModel

from ..parser import ParsedInput
from ..vendor_detection import Vendor, VendorDetection
from .cisco_secure_endpoint import CiscoSecureEndpointNormalizer
from .generic import GenericNormalizer
from .microsoft_defender import MicrosoftDefenderNormalizer
from .sysmon import SysmonNormalizer


_ROUTES = {
    Vendor.CISCO_SECURE_ENDPOINT: CiscoSecureEndpointNormalizer,
    Vendor.SYSMON: SysmonNormalizer,
    Vendor.DEFENDER: MicrosoftDefenderNormalizer,
}


def normalize(parsed: ParsedInput,
              detection: VendorDetection) -> CanonicalEventModel:
    """Route to the vendor normalizer. Always returns CEMv1."""
    cls = _ROUTES.get(detection.vendor)
    if cls is None:
        return GenericNormalizer().normalize(parsed)
    return cls().normalize(parsed)


__all__ = ["normalize"]
