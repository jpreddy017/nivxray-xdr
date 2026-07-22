"""NivXRay v2 · Feature-Flag Registry (3-state).

Per /app/memory/GOVERNANCE.md §12 (Feature-Flag Contract) with the
Round-5 amendment introducing tri-state semantics:

    DISABLED  →  code path is off. Zero runtime cost. Byte-identical
                 RC5 behaviour required.

    SHADOW    →  code path runs SIDE-BY-SIDE with the RC5 pipeline
                 but MUST NOT influence any output. Used for
                 collecting evidence, dual-write validation, and
                 quality-gate measurement before promotion.

    ENABLED   →  code path is authoritative. Only reached after the
                 shadow phase closes its regression gate.

Boot-time source of truth: environment variables prefixed with
`NIVX_FLAG_`. Values are case-insensitive. Unknown values fall back
to `disabled`.

Example:
    NIVX_FLAG_CASE_ENGINE=shadow
    NIVX_FLAG_TIMELINE_V2=disabled

Runtime toggles are Phase-4+ (admin API). Until then, flags are
read once at process start.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Final


class FlagState(str, Enum):
    """Tri-state feature flag."""
    DISABLED = "disabled"
    SHADOW = "shadow"
    ENABLED = "enabled"

    @classmethod
    def parse(cls, raw: str | None) -> "FlagState":
        if not raw:
            return cls.DISABLED
        v = raw.strip().lower()
        if v in ("on", "true", "1", "enabled"):
            return cls.ENABLED
        if v in ("shadow", "sidecar", "observe"):
            return cls.SHADOW
        return cls.DISABLED


# ─── Registered flags ────────────────────────────────────────────────
# The keys below are the ONLY recognised v2 capability switches.
# Adding a new capability requires a governance amendment.
FLAG_NAMES: Final[tuple[str, ...]] = (
    "CASE_ENGINE",
    "GRAPH_ENGINE",
    "TIMELINE_V2",
    "TRAJECTORY_ENGINE",
    "ADAPTERS",
    "REPLAY",
    "NOTEBOOK",
    "ARTIFACT_STORE",
    "KNOWLEDGE_LAYER",
    "NEGATIVE_EVIDENCE",
    "COPILOT",
)


@dataclass(frozen=True)
class FeatureFlag:
    name: str
    state: FlagState
    env_key: str

    def disabled(self) -> bool: return self.state is FlagState.DISABLED
    def shadow(self)   -> bool: return self.state is FlagState.SHADOW
    def enabled(self)  -> bool: return self.state is FlagState.ENABLED

    def observable(self) -> bool:
        """True when the code path may run (shadow or enabled)."""
        return self.state is not FlagState.DISABLED


def _read(name: str) -> FeatureFlag:
    env_key = f"NIVX_FLAG_{name}"
    return FeatureFlag(name=name, env_key=env_key,
                       state=FlagState.parse(os.environ.get(env_key)))


# Snapshot captured at process start. Deterministic across module
# imports within the same process.
FLAGS: Final[dict[str, FeatureFlag]] = {n: _read(n) for n in FLAG_NAMES}


def get(name: str) -> FeatureFlag:
    """Return the registered flag or a DISABLED sentinel for unknowns."""
    if name not in FLAGS:
        return FeatureFlag(name=name, env_key=f"NIVX_FLAG_{name}",
                           state=FlagState.DISABLED)
    return FLAGS[name]


def all_disabled() -> bool:
    """True iff every registered flag is DISABLED.

    Governance contract §12: when this returns True, the process
    MUST behave byte-identically to the frozen RC5 release.
    """
    return all(f.state is FlagState.DISABLED for f in FLAGS.values())


def summary() -> dict[str, str]:
    return {n: f.state.value for n, f in FLAGS.items()}


__all__ = [
    "FlagState", "FeatureFlag", "FLAG_NAMES", "FLAGS",
    "get", "all_disabled", "summary",
]
