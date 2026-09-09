"""Intent Rule registry.

Each rule implements the ``IntentRule`` protocol and is registered
here. Adding a new intent detector is a one-file change:

    1. Create ``rules/my_intent.py`` implementing the protocol.
    2. Import its ``RULE`` singleton here and append it to
       ``INTENT_RULE_REGISTRY``.

Rules are DETECTORS, not decoders — they operate on the already-
decoded final artefact plus the IU classification and CRE effective
payload. They never re-decode.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Intent


@runtime_checkable
class IntentRule(Protocol):
    """Contract every intent rule must honour.

    ``detect()`` inspects an artefact and returns zero or more Intent
    objects. It must:
        * never execute user code,
        * never fabricate evidence,
        * cite canonical Evidence for every intent it emits,
        * be deterministic and side-effect-free.
    """

    NAME: str

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        """Return every intent this rule fires against the artefact.
        Empty list when no signals match. ``meta`` carries the IU
        classification / CRE hint / RTE stop reason so rules can
        specialise without re-parsing."""
        ...


# ── Registry ────────────────────────────────────────────────────
from .staging import RULE as _R_STAGING                          # noqa: E402
from .remote_execution import RULE as _R_REMOTE_EXEC             # noqa: E402
from .defense_evasion import RULE as _R_DEFENSE                  # noqa: E402
from .discovery import RULE as _R_DISCOVERY                      # noqa: E402
from .persistence import RULE as _R_PERSISTENCE                  # noqa: E402
from .credential_access import RULE as _R_CREDS                  # noqa: E402
from .runtime_dependent import RULE as _R_RUNTIME_DEP            # noqa: E402
from .lateral_admin import (                                     # noqa: E402
    PSEXEC_RULE      as _R_PSEXEC,
    REMOTE_MGMT_RULE as _R_REMOTE_MGMT,
    FIREWALL_RULE    as _R_FIREWALL,
)


INTENT_RULE_REGISTRY: list[IntentRule] = [
    _R_STAGING,
    _R_REMOTE_EXEC,
    _R_DEFENSE,
    _R_DISCOVERY,
    _R_PERSISTENCE,
    _R_CREDS,
    _R_RUNTIME_DEP,
    _R_PSEXEC,
    _R_REMOTE_MGMT,
    _R_FIREWALL,
]

__all__ = ["IntentRule", "INTENT_RULE_REGISTRY"]
