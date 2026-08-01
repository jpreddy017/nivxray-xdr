"""Stage 4 · Vendor Normalizers.

Each normalizer consumes a `ParsedInput` + `VendorDetection` and
returns a fully-populated `CanonicalEventModel` (CEMv1). Downstream
stages read ONLY the CEM.
"""
from .cisco_secure_endpoint import CiscoSecureEndpointNormalizer
from .sysmon import SysmonNormalizer
from .generic import GenericNormalizer
from .router import normalize

__all__ = [
    "CiscoSecureEndpointNormalizer",
    "SysmonNormalizer",
    "GenericNormalizer",
    "normalize",
]
