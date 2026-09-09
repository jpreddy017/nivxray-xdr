"""NivXRay v2 · Universal Threat Investigation Platform (namespace root).

This package is an ISOLATED expansion namespace per
/app/memory/GOVERNANCE.md §3. Nothing under `engine/` (RC5) imports
from here. This module is inert on import — no side effects.

All v2 capabilities are behind 3-state feature flags in `v2.flags`.
When every flag is `disabled`, the application MUST behave
byte-identically to the frozen RC5 release (§12 Feature-Flag Contract).
"""
